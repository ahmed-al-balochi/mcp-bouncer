"""Table provisioning for the DynamoDB backend under a moto fake.
Production tables are created by Terraform, so the store assumes they exist and
the tests stand them up here; keeping the schema here makes drift a test failure.
"""

from __future__ import annotations

from typing import Any


def create_approvals_table(client: Any, table_name: str) -> None:
    """Create the approvals table with the two GSIs the store queries.
    GSI1 backs the pending enumeration without a Scan; GSI2 backs the create-time
    dedup lookup by args hash.
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
    TTL is one half of the twice-enforced expiry: DynamoDB removes stale
    grants eventually, while the claim condition refuses one it reads first.
    """
    client.update_time_to_live(
        TableName=table_name,
        TimeToLiveSpecification={"Enabled": True, "AttributeName": "ttl"},
    )
