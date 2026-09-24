"""A DynamoDB-backed approval store, behind the same interface as the SQLite one.

Why this exists: SQLite gives the one-shot guarantee only across processes that
share one file, so a horizontally scaled gate -- many Fargate tasks, no shared
disk -- needs a store whose atomic claim holds across hosts. DynamoDB's
conditional writes provide exactly that (R27).

The whole file is written to satisfy `gate.storage.ApprovalStore` structurally;
it adds nothing to that surface. boto3 is imported lazily inside `__init__`, not
at module import, so that `import gate.approvals`, the factory, and the entire
SQLite path never require boto3 to be installed (R44).

Key schema (single table, two GSIs). Every access pattern is a GetItem or a
Query with a key condition -- never a Scan, and never a filter standing in for a
key:

    Grant        PK = GRANT#<args_hash>          SK = GRANT
                 caller, tool, expires_at (epoch seconds), ttl (native TTL attr)
    Pending      PK = PENDING#<id>               SK = PENDING
                 caller, tool, arguments, args_hash, created_at, state
                 GSI1PK = PENDING                GSI1SK = <created_at, zero-padded>
                 GSI2PK = PENDINGHASH#<args_hash> GSI2SK = <id>
    Release      PK = RELEASE#<caller>           SK = <released_at, zero-padded>#<args_hash>

* consume     -> conditional DeleteItem on the Grant item's exact key, so of any
                 number of concurrent callers exactly one deletes it and sees
                 success. The same condition rejects an expired grant that TTL
                 has not yet swept (R28).
* list_pending-> Query GSI1 (GSI1PK = PENDING), ordered by created_at.
* create dedup-> Query GSI2 (GSI2PK = PENDINGHASH#<hash>) for an existing pending
                 row before inserting a new one.
* approve/deny-> GetItem / conditional UpdateItem by the Pending item's key.
* approved_in_window -> Query the RELEASE#<caller> partition with an SK range
                 condition `SK > cutoff`. A key range, not a Scan, not a filter.
* reset       -> Query then delete that caller's RELEASE partition.
"""

from __future__ import annotations

import os
import time
import uuid
from typing import Any, Callable, Mapping

from gate.approvals import (
    APPROVED,
    CONSUMED,
    DENIED,
    EXPIRED,
    PENDING,
    RATE_WINDOW_SECONDS,
    PendingApproval,
    args_hash,
    canonical_arguments,
)
from gate.dynamodb_keys import numeric_sk as _numeric_sk


class DynamoDBApprovalStore:
    """Approval state on DynamoDB, matching `gate.storage.ApprovalStore` exactly.

    The clock is injectable for the same reason the SQLite store's is: TTL and
    rolling-window behaviour must be testable without waiting real minutes.
    """

    def __init__(
        self,
        table_name: str,
        *,
        ttl_minutes: int = 10,
        clock: Callable[[], float] = time.time,
        region_name: str | None = None,
    ) -> None:
        # Lazy import: boto3 is an optional extra, so nothing that only touches
        # the SQLite path should pay for it. Import failure here means the
        # operator selected the DynamoDB backend without installing the extra,
        # and the message says exactly that.
        try:
            import boto3
        except ImportError as error:  # pragma: no cover - exercised via message
            raise RuntimeError(
                "the DynamoDB backend requires the 'aws' extra: "
                "install with `pip install mcp-bouncer[aws]`"
            ) from error

        # Region comes from the standard AWS environment (AWS_REGION /
        # AWS_DEFAULT_REGION), not a bespoke variable, so the container inherits
        # it like every other AWS SDK call does.
        self._ttl_seconds = float(ttl_minutes) * 60.0
        self._clock = clock
        self._client = boto3.client(
            "dynamodb",
            region_name=region_name or os.environ.get("AWS_REGION")
            or os.environ.get("AWS_DEFAULT_REGION"),
        )
        self._table = table_name

    @property
    def ttl_seconds(self) -> float:
        return self._ttl_seconds

    def create(
        self, caller: str, tool: str, arguments: Mapping[str, Any]
    ) -> PendingApproval:
        """Park a call, reusing an existing pending row for an identical call.

        Dedup is a GSI2 Query on the args_hash, mirroring the SQLite store's
        "reuse the pending row" behaviour so a retrying agent does not stack up
        duplicate approvals for one call.

        One deliberate difference from SQLite: global secondary indexes are
        eventually consistent, so an agent retrying within milliseconds can miss
        a pending row that was just written and park a second one. That is
        cosmetic -- a duplicate row for a human to look at -- and it cannot
        weaken the one-shot guarantee, because releasing a call goes through the
        conditional delete in `consume`, which is strongly consistent and keyed
        on the item itself rather than on an index.
        """
        digest = args_hash(caller, tool, arguments)
        existing = self._pending_for_hash(digest)
        if existing is not None:
            return existing

        record = PendingApproval(
            id=uuid.uuid4().hex[:12],
            caller=caller,
            tool=tool,
            arguments=canonical_arguments(arguments),
            args_hash=digest,
            created_at=self._clock(),
            state=PENDING,
        )
        self._client.put_item(
            TableName=self._table,
            Item={
                "PK": {"S": f"PENDING#{record.id}"},
                "SK": {"S": "PENDING"},
                "id": {"S": record.id},
                "caller": {"S": record.caller},
                "tool": {"S": record.tool},
                "arguments": {"S": record.arguments},
                "args_hash": {"S": record.args_hash},
                "created_at": {"N": repr(record.created_at)},
                "state": {"S": record.state},
                "GSI1PK": {"S": "PENDING"},
                "GSI1SK": {"S": _numeric_sk(record.created_at)},
                "GSI2PK": {"S": f"PENDINGHASH#{digest}"},
                "GSI2SK": {"S": record.id},
            },
        )
        return record

    def approve(self, approval_id: str) -> PendingApproval | None:
        """Grant one retry of the parked call. Returns None if there is nothing to grant.

        Moving the pending row to APPROVED is a conditional update guarded on the
        row still being PENDING, so a denied or already-approved id yields None
        rather than resurrecting a decision.
        """
        item = self._get_pending(approval_id)
        if item is None or item.get("state", {}).get("S") != PENDING:
            return None

        try:
            self._client.update_item(
                TableName=self._table,
                Key={"PK": {"S": f"PENDING#{approval_id}"}, "SK": {"S": "PENDING"}},
                UpdateExpression="SET #s = :approved",
                ConditionExpression="#s = :pending",
                ExpressionAttributeNames={"#s": "state"},
                ExpressionAttributeValues={
                    ":approved": {"S": APPROVED},
                    ":pending": {"S": PENDING},
                },
            )
        except self._client.exceptions.ConditionalCheckFailedException:
            return None

        expires_at = self._clock() + self._ttl_seconds
        # The grant item carries both `expires_at` (checked in the claim
        # condition) and `ttl` (DynamoDB's native TTL attribute). TTL cleans up
        # eventually; the claim condition enforces expiry immediately (R28).
        self._client.put_item(
            TableName=self._table,
            Item={
                "PK": {"S": f"GRANT#{item['args_hash']['S']}"},
                "SK": {"S": "GRANT"},
                "approval_id": {"S": approval_id},
                "caller": {"S": item["caller"]["S"]},
                "tool": {"S": item["tool"]["S"]},
                "args_hash": {"S": item["args_hash"]["S"]},
                "expires_at": {"N": repr(expires_at)},
                "ttl": {"N": str(int(expires_at))},
                # A constant GSI1 partition lets the eager sweep enumerate grants
                # with a Query rather than a Scan; the SK orders them by expiry.
                "GSI1PK": {"S": "GRANT"},
                "GSI1SK": {"S": _numeric_sk(expires_at)},
            },
        )
        return _as_pending(item, state=APPROVED)

    def deny(self, approval_id: str) -> bool:
        try:
            self._client.update_item(
                TableName=self._table,
                Key={"PK": {"S": f"PENDING#{approval_id}"}, "SK": {"S": "PENDING"}},
                UpdateExpression="SET #s = :denied",
                ConditionExpression="#s = :pending",
                ExpressionAttributeNames={"#s": "state"},
                ExpressionAttributeValues={
                    ":denied": {"S": DENIED},
                    ":pending": {"S": PENDING},
                },
            )
        except self._client.exceptions.ConditionalCheckFailedException:
            return False
        return True

    def consume(self, caller: str, tool: str, arguments: Mapping[str, Any]) -> bool:
        """Claim the grant for this exact call, at most once, ever.

        This is the whole point of the DynamoDB backend. The claim is a single
        conditional DeleteItem: DynamoDB evaluates the condition and removes the
        item atomically, so of any number of concurrent tasks -- on any number of
        hosts -- exactly one sees the delete succeed and every other gets
        ConditionalCheckFailed. There is no read-then-delete window for two tasks
        to both pass.

        The condition also enforces expiry in the same breath (`expires_at > now`
        and matching caller/tool), so a grant that TTL has not yet physically
        removed is still refused the instant it is stale (R28).
        """
        digest = args_hash(caller, tool, arguments)
        now = self._clock()
        try:
            self._client.delete_item(
                TableName=self._table,
                Key={"PK": {"S": f"GRANT#{digest}"}, "SK": {"S": "GRANT"}},
                ConditionExpression=(
                    "attribute_exists(PK) AND caller = :caller AND tool = :tool"
                    " AND expires_at > :now"
                ),
                ExpressionAttributeValues={
                    ":caller": {"S": caller},
                    ":tool": {"S": tool},
                    ":now": {"N": repr(now)},
                },
            )
        except self._client.exceptions.ConditionalCheckFailedException:
            # Also the path taken if the SDK retried a delete whose success
            # response was lost: the item is already gone, so the condition fails
            # and the true winner is told no. That over-denies -- the call parks
            # again and a human re-approves -- which is the safe direction. It can
            # never release twice, which is the guarantee that matters.
            return False

        # Only the single winner reaches here, so recording the release and
        # marking the pending row consumed happen exactly once per grant.
        #
        # The sort key carries the argument digest as well as the timestamp. Two
        # different grants claimed by one caller within the same clock tick would
        # otherwise write the same PK and SK, and the second PutItem would
        # silently overwrite the first -- undercounting the rolling window and
        # letting the caller slip past the destructive rate cap (R14). The digest
        # cannot itself collide here, because a grant is one-shot: the same
        # digest can only be claimed once.
        self._client.put_item(
            TableName=self._table,
            Item={
                "PK": {"S": f"RELEASE#{caller}"},
                "SK": {"S": f"{_numeric_sk(now)}#{digest}"},
                "caller": {"S": caller},
                "tool": {"S": tool},
                "released_at": {"N": repr(now)},
            },
        )
        self._mark_consumed(digest)
        return True

    def expire(self) -> int:
        """Drop grants past their TTL and mark stale pending rows expired.

        DynamoDB's native TTL is asynchronous and can lag by hours, so this
        method does the same eager sweep the SQLite store does rather than
        trusting TTL for correctness. Returns the number of grants dropped.
        """
        now = self._clock()
        dropped = 0
        for grant in self._all_grants():
            if float(grant["expires_at"]["N"]) <= now:
                self._client.delete_item(
                    TableName=self._table,
                    Key={"PK": grant["PK"], "SK": grant["SK"]},
                )
                dropped += 1

        cutoff = now - self._ttl_seconds
        for item in self._all_pending():
            if item.get("state", {}).get("S") in (PENDING, APPROVED) and float(
                item["created_at"]["N"]
            ) <= cutoff:
                self._client.update_item(
                    TableName=self._table,
                    Key={"PK": item["PK"], "SK": item["SK"]},
                    UpdateExpression="SET #s = :expired",
                    ExpressionAttributeNames={"#s": "state"},
                    ExpressionAttributeValues={":expired": {"S": EXPIRED}},
                )
        return dropped

    def reset(self, caller: str) -> int:
        """Clear a caller's rolling destructive count after a human intervenes."""
        cleared = 0
        for release in self._query_releases(caller, since=None):
            self._client.delete_item(
                TableName=self._table,
                Key={"PK": release["PK"], "SK": release["SK"]},
            )
            cleared += 1
        return cleared

    def list_pending(self) -> list[PendingApproval]:
        pending = [
            _as_pending(item)
            for item in self._all_pending()
            if item.get("state", {}).get("S") == PENDING
        ]
        pending.sort(key=lambda record: (record.created_at, record.id))
        return pending

    def approved_in_window(
        self, caller: str, window_seconds: float = RATE_WINDOW_SECONDS
    ) -> int:
        """Count a caller's released destructive actions in the rolling window.

        A Query on the RELEASE#<caller> partition with the sort-key range
        condition `SK > cutoff`. Because releases are stored under a per-caller
        partition keyed by time, this is a bounded key-range read of one caller's
        recent activity -- never a Scan, never a filter over the whole table.
        """
        cutoff = self._clock() - window_seconds
        return len(self._query_releases(caller, since=cutoff))

    # --- internals -------------------------------------------------------

    def _pending_for_hash(self, digest: str) -> PendingApproval | None:
        response = self._client.query(
            TableName=self._table,
            IndexName="GSI2",
            KeyConditionExpression="GSI2PK = :pk",
            ExpressionAttributeValues={":pk": {"S": f"PENDINGHASH#{digest}"}},
        )
        for item in response.get("Items", []):
            if item.get("state", {}).get("S") == PENDING:
                return _as_pending(item)
        return None

    def _get_pending(self, approval_id: str) -> dict[str, Any] | None:
        response = self._client.get_item(
            TableName=self._table,
            Key={"PK": {"S": f"PENDING#{approval_id}"}, "SK": {"S": "PENDING"}},
        )
        return response.get("Item")

    def _mark_consumed(self, digest: str) -> None:
        # Best-effort: the release is already recorded, so a pending row that was
        # already swept must not turn a successful claim into a failure.
        for item in self._all_pending():
            if (
                item.get("args_hash", {}).get("S") == digest
                and item.get("state", {}).get("S") == APPROVED
            ):
                self._client.update_item(
                    TableName=self._table,
                    Key={"PK": item["PK"], "SK": item["SK"]},
                    UpdateExpression="SET #s = :consumed",
                    ExpressionAttributeNames={"#s": "state"},
                    ExpressionAttributeValues={":consumed": {"S": CONSUMED}},
                )
                return

    def _all_pending(self) -> list[dict[str, Any]]:
        return self._query_all(
            IndexName="GSI1",
            KeyConditionExpression="GSI1PK = :pk",
            ExpressionAttributeValues={":pk": {"S": "PENDING"}},
        )

    def _all_grants(self) -> list[dict[str, Any]]:
        # Grants share no partition, so enumerating them for the eager sweep uses
        # a Query on a dedicated GSI keyed by a constant partition value.
        return self._query_all(
            IndexName="GSI1",
            KeyConditionExpression="GSI1PK = :pk",
            ExpressionAttributeValues={":pk": {"S": "GRANT"}},
        )

    def _query_releases(
        self, caller: str, *, since: float | None
    ) -> list[dict[str, Any]]:
        if since is None:
            key = "PK = :pk"
            values = {":pk": {"S": f"RELEASE#{caller}"}}
        else:
            # The cutoff has no digest suffix, so a release recorded at exactly
            # the cutoff instant sorts after it and counts as inside the window.
            # The SQLite store excludes that single instant; at microsecond
            # resolution the difference is not observable, and counting a release
            # as inside the window is the stricter of the two readings.
            key = "PK = :pk AND SK > :cutoff"
            values = {
                ":pk": {"S": f"RELEASE#{caller}"},
                ":cutoff": {"S": _numeric_sk(since)},
            }
        return self._query_all(KeyConditionExpression=key, ExpressionAttributeValues=values)

    def _query_all(self, **kwargs: Any) -> list[dict[str, Any]]:
        items: list[dict[str, Any]] = []
        start_key: dict[str, Any] | None = None
        while True:
            if start_key is not None:
                kwargs["ExclusiveStartKey"] = start_key
            response = self._client.query(TableName=self._table, **kwargs)
            items.extend(response.get("Items", []))
            start_key = response.get("LastEvaluatedKey")
            if not start_key:
                return items


def _as_pending(item: Mapping[str, Any], state: str | None = None) -> PendingApproval:
    return PendingApproval(
        id=item["id"]["S"],
        caller=item["caller"]["S"],
        tool=item["tool"]["S"],
        arguments=item["arguments"]["S"],
        args_hash=item["args_hash"]["S"],
        created_at=float(item["created_at"]["N"]),
        state=state if state is not None else item["state"]["S"],
    )
