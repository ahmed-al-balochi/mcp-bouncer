"""Table provisioning for the DynamoDB backend under a moto fake.

The production tables are created by Terraform, not by the application, so the
store modules deliberately assume the table already exists. The tests therefore
have to stand the tables up themselves. Keeping the schema here -- in one place,
next to the tests that rely on it -- means the key design in
``gate.dynamodb_approvals`` and ``gate.dynamodb_audit`` has exactly one
authoritative shape to match, and a drift between the two shows up as a test
failure rather than as a silent mismatch.

Attribute types are all ``S``: sort keys that encode time are zero-padded
fixed-width strings (see ``_numeric_sk`` in the store) precisely so that a
string range comparison orders them chronologically, which is what lets the
rolling-window query be a key-range Query rather than a Scan.
"""

from __future__ import annotations

from typing import Any


def create_approvals_table(client: Any, table_name: str) -> None:
    """Create the single approvals table with the two GSIs the store queries.

    GSI1 (constant partition ``PENDING`` / ``GRANT``) backs the enumeration the
    eager expiry sweep and ``list_pending`` need without a Scan; GSI2 (partition
    ``PENDINGHASH#<hash>``) backs the create-time dedup lookup by args hash.
    """
    client.create_table(
        TableName=table_name,
        BillingMode="PAY_PER_REQUEST",
        AttributeDefinitions=[
            {"AttributeName": "PK", "AttributeType": "S"},
            {"AttributeName": "SK", "AttributeType": "S"},
            {"AttributeName": "GSI1PK", "AttributeType": "S"},
            {"AttributeName": "GSI1SK", "AttributeType": "S"},
            {"AttributeName": "GSI2PK", "AttributeType": "S"},
            {"AttributeName": "GSI2SK", "AttributeType": "S"},
        ],
        KeySchema=[
            {"AttributeName": "PK", "KeyType": "HASH"},
            {"AttributeName": "SK", "KeyType": "RANGE"},
        ],
        GlobalSecondaryIndexes=[
            {
                "IndexName": "GSI1",
                "KeySchema": [
                    {"AttributeName": "GSI1PK", "KeyType": "HASH"},
                    {"AttributeName": "GSI1SK", "KeyType": "RANGE"},
                ],
                "Projection": {"ProjectionType": "ALL"},
            },
            {
                "IndexName": "GSI2",
                "KeySchema": [
                    {"AttributeName": "GSI2PK", "KeyType": "HASH"},
                    {"AttributeName": "GSI2SK", "KeyType": "RANGE"},
                ],
                "Projection": {"ProjectionType": "ALL"},
            },
        ],
    )
    _enable_ttl(client, table_name)


def create_audit_table(client: Any, table_name: str) -> None:
    """Create the single audit table: one constant partition, time-ordered SK."""
    client.create_table(
        TableName=table_name,
        BillingMode="PAY_PER_REQUEST",
        AttributeDefinitions=[
            {"AttributeName": "PK", "AttributeType": "S"},
            {"AttributeName": "SK", "AttributeType": "S"},
        ],
        KeySchema=[
            {"AttributeName": "PK", "KeyType": "HASH"},
            {"AttributeName": "SK", "KeyType": "RANGE"},
        ],
    )


def _enable_ttl(client: Any, table_name: str) -> None:
    """Turn on native TTL on the ``ttl`` attribute the grant items carry.

    TTL is one half of the twice-enforced expiry (R28): DynamoDB removes stale
    grants eventually, while the claim condition refuses a stale grant it happens
    to read first. Enabling it here mirrors what Terraform configures in the real
    table so the schema the tests exercise is the schema that ships.
    """
    client.update_time_to_live(
        TableName=table_name,
        TimeToLiveSpecification={"Enabled": True, "AttributeName": "ttl"},
    )
