"""A DynamoDB-backed decision log, append-only like the SQLite one.

Append-only is structural (only PutItem and Query) and backed by IAM.
boto3 is imported lazily so the SQLite path never needs it.
"""

from __future__ import annotations

import os
import time
import uuid
from typing import Any, Callable

from gate.audit import AuditEntry
from gate.dynamodb_keys import numeric_sk as _numeric_prefix

_AUDIT_PK = "AUDIT"


class DynamoDBAuditLog:
    """The decision log on DynamoDB, matching `gate.storage.AuditLog` exactly."""

    def __init__(
        self,
        table_name: str,
        *,
        clock: Callable[[], float] = time.time,
        region_name: str | None = None,
    ) -> None:
        # Lazy import: boto3 is an optional extra. Selecting the DynamoDB
        # backend without installing it fails here with an actionable message.
        try:
            import boto3
        except ImportError as error:  # pragma: no cover - exercised via message
            raise RuntimeError(
                "the DynamoDB backend requires the 'aws' extra: "
                "install with `pip install mcp-bouncer[aws]`"
            ) from error

        self._clock = clock
        self._client = boto3.client(
            "dynamodb",
            region_name=region_name or os.environ.get("AWS_REGION")
            or os.environ.get("AWS_DEFAULT_REGION"),
        )
        self._table = table_name

    def record(
        self,
        caller: str,
        tool: str,
        classification: str,
        decision: str,
        args_hash: str,
    ) -> None:
        recorded_at = self._clock()
        self._client.put_item(
            TableName=self._table,
            Item={
                "PK": {"S": _AUDIT_PK},
                "SK": {"S": f"{_numeric_prefix(recorded_at)}#{uuid.uuid4().hex}"},
                "recorded_at": {"N": repr(recorded_at)},
                "caller": {"S": caller},
                "tool": {"S": tool},
                "classification": {"S": classification},
                "decision": {"S": decision},
                "args_hash": {"S": args_hash},
            },
        )

    def entries(self, limit: int = 100) -> list[AuditEntry]:
        """Return the most recent entries, oldest first.

        Query the partition newest-first, cap at `limit`, then reverse so the
        caller sees oldest-first, matching the SQLite log's ordering.
        """
        response = self._client.query(
            TableName=self._table,
            KeyConditionExpression="PK = :pk",
            ExpressionAttributeValues={":pk": {"S": _AUDIT_PK}},
            ScanIndexForward=False,
            Limit=limit,
        )
        rows = response.get("Items", [])
        entries = [
            AuditEntry(
                recorded_at=float(row["recorded_at"]["N"]),
                caller=row["caller"]["S"],
                tool=row["tool"]["S"],
                classification=row["classification"]["S"],
                decision=row["decision"]["S"],
                args_hash=row["args_hash"]["S"],
            )
            for row in rows
        ]
        entries.reverse()
        return entries
