"""A DynamoDB-backed approval store, behind the same interface as SQLite.

A scaled gate has no shared disk, so the atomic claim must hold across hosts via
conditional writes. boto3 is imported lazily and every access is a key read.
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
    """Approval state on DynamoDB, matching gate.storage.ApprovalStore exactly.

    The clock is injectable, like the SQLite store's, so TTL and rolling-window
    behaviour can be tested without waiting real minutes.
    """

    def __init__(
        self,
        table_name: str,
        *,
        ttl_minutes: int = 10,
        clock: Callable[[], float] = time.time,
        region_name: str | None = None,
    ) -> None:
        # Lazy import: boto3 is an optional extra, so the SQLite path should not
        # pay for it. A failure here means the operator selected DynamoDB without
        # installing the extra, and the message says exactly that.
        try:
            import boto3
        except ImportError as error:  # pragma: no cover - exercised via message
            raise RuntimeError(
                "the DynamoDB backend requires the 'aws' extra: "
                "install with `pip install mcp-bouncer[aws]`"
            ) from error

        # Region comes from the standard AWS environment, so the container
        # inherits it like every other AWS SDK call does.
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

    def _effective_ttl(self, stored: Mapping[str, Any] | None) -> float:
        """Resolve a stored TTL attribute, falling back to the store default.

        An item carries no ttl_seconds when written before this change or stamped
        with none; absent means the store default, as in the SQLite store.
        """
        return float(stored["N"]) if stored is not None else self._ttl_seconds

    def create(
        self,
        caller: str,
        tool: str,
        arguments: Mapping[str, Any],
        *,
        ttl_seconds: float | None = None,
    ) -> PendingApproval:
        """Park a call, reusing an existing pending row for an identical call.

        Dedup is a GSI2 Query on the args_hash so a retry does not stack approvals.
        ttl_seconds is persisted for approve and on reuse only tightens down.
        """
        digest = args_hash(caller, tool, arguments)
        existing = self._pending_item_for_hash(digest)
        if existing is not None:
            self._tighten_pending_ttl(existing, ttl_seconds)
            refreshed = self._get_pending(existing["id"]["S"])
            return _as_pending(refreshed if refreshed is not None else existing)

        record = PendingApproval(
            id=uuid.uuid4().hex[:12],
            caller=caller,
            tool=tool,
            arguments=canonical_arguments(arguments),
            args_hash=digest,
            created_at=self._clock(),
            state=PENDING,
            ttl_seconds=ttl_seconds,
        )
        item = {
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
        }
        # Only write the TTL attribute when one was stamped; its absence is how a
        # row signals "use the store default", read back as None.
        if ttl_seconds is not None:
            item["ttl_seconds"] = {"N": repr(float(ttl_seconds))}
        self._client.put_item(TableName=self._table, Item=item)
        return record

    def _tighten_pending_ttl(
        self, existing: Mapping[str, Any], incoming_ttl: float | None
    ) -> None:
        """Lower a reused pending item's stored TTL to incoming_ttl if stricter.

        Mirrors the SQLite dedup rule: None never tightens, and we only shorten,
        never widen, so a reused row never becomes looser than the caller's team.
        """
        if incoming_ttl is None:
            return
        stored = existing.get("ttl_seconds")
        effective_stored = (
            float(stored["N"]) if stored is not None else self._ttl_seconds
        )
        if incoming_ttl < effective_stored:
            self._client.update_item(
                TableName=self._table,
                Key={"PK": existing["PK"], "SK": existing["SK"]},
                UpdateExpression="SET ttl_seconds = :ttl",
                ExpressionAttributeValues={":ttl": {"N": repr(float(incoming_ttl))}},
            )

    def approve(self, approval_id: str) -> PendingApproval | None:
        """Grant one retry of the parked call, or None if there is nothing to grant.

        A conditional update guarded on the row still being PENDING, so a denied
        or already-approved id yields None rather than resurrecting a decision.
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

        effective_ttl = self._effective_ttl(item.get("ttl_seconds"))
        expires_at = self._clock() + effective_ttl
        # The grant carries expires_at (checked in the claim condition) and ttl
        # (native TTL), both from the parked row's per-row TTL, not the store
        # default. The claim enforces expiry immediately; native TTL can lag.
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
        return _as_pending(item, state=APPROVED, ttl_seconds=effective_ttl)

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

        One conditional DeleteItem, so exactly one of many concurrent tasks wins.
        The condition also checks expires_at, so a stale grant is refused.
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
            # Also taken if a retried delete's success response was lost: the
            # item is already gone, so the winner is told no. Over-denying is the
            # safe direction; it can never release twice, which is what matters.
            return False

        # Only the winner reaches here, so the release and the consumed mark
        # happen once per grant. The SK carries the digest as well as the time so
        # two claims in the same tick cannot overwrite each other.
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

        DynamoDB's native TTL can lag by hours, so this eager sweep does not
        trust it for correctness. Returns the number of grants dropped.
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

        for item in self._all_pending():
            if item.get("state", {}).get("S") not in (PENDING, APPROVED):
                continue
            # A parked row is stale once its own TTL has elapsed since it was
            # created, falling back to the store default when it carries none.
            # Using the store default for every row is the bug this fixes.
            row_ttl = self._effective_ttl(item.get("ttl_seconds"))
            if float(item["created_at"]["N"]) + row_ttl <= now:
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

        A Query on the RELEASE#<caller> partition with the SK range SK > cutoff,
        a bounded key-range read of one caller's recent activity, never a Scan.
        """
        cutoff = self._clock() - window_seconds
        return len(self._query_releases(caller, since=cutoff))

    # --- internals -------------------------------------------------------

    def _pending_item_for_hash(self, digest: str) -> dict[str, Any] | None:
        """Return the raw pending item for an args hash, or None.

        Raw item rather than a PendingApproval so create can read the stored TTL
        and address the item's key to tighten it on dedup.
        """
        response = self._client.query(
            TableName=self._table,
            IndexName="GSI2",
            KeyConditionExpression="GSI2PK = :pk",
            ExpressionAttributeValues={":pk": {"S": f"PENDINGHASH#{digest}"}},
        )
        for item in response.get("Items", []):
            if item.get("state", {}).get("S") == PENDING:
                return item
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
            # The cutoff has no digest suffix, so a release at exactly the cutoff
            # instant sorts after it and counts as inside the window. SQLite
            # excludes that instant; the difference is not observable here.
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


def _as_pending(
    item: Mapping[str, Any],
    state: str | None = None,
    ttl_seconds: float | None = None,
) -> PendingApproval:
    # When given, ttl_seconds overrides the item's stored value so approve can
    # report the resolved grant lifetime; when not, the item's own stamped TTL
    # (or None if absent) is carried through.
    stored = item.get("ttl_seconds")
    stored_ttl = float(stored["N"]) if stored is not None else None
    return PendingApproval(
        id=item["id"]["S"],
        caller=item["caller"]["S"],
        tool=item["tool"]["S"],
        arguments=item["arguments"]["S"],
        args_hash=item["args_hash"]["S"],
        created_at=float(item["created_at"]["N"]),
        state=state if state is not None else item["state"]["S"],
        ttl_seconds=ttl_seconds if ttl_seconds is not None else stored_ttl,
    )
