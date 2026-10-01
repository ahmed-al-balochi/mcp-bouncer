# The two DynamoDB tables the gate uses. Their shape is authoritative in
# tests/dynamodb_tables.py, so these mirror it attribute for attribute; a drift
# here surfaces as the store failing to Query. PAY_PER_REQUEST, no deletion lock.

# --- approvals table -------------------------------------------------------

resource "aws_dynamodb_table" "approvals" {
  name         = "${var.project_name}-approvals"
  billing_mode = "PAY_PER_REQUEST"

  hash_key  = "PK"
  range_key = "SK"

  # Only key and index attributes are declared; DynamoDB is schemaless for the
  # rest. These match tests/dynamodb_tables.py exactly.
  attribute {
    name = "PK"
    type = "S"
  }
  attribute {
    name = "SK"
    type = "S"
  }
  attribute {
    name = "GSI1PK"
    type = "S"
  }
  attribute {
    name = "GSI1SK"
    type = "S"
  }
  attribute {
    name = "GSI2PK"
    type = "S"
  }
  attribute {
    name = "GSI2SK"
    type = "S"
  }

  # GSI1 (constant partition PENDING/GRANT) backs list_pending and the expiry
  # sweep; GSI2 (partition PENDINGHASH#<hash>) backs create-time dedup. Both
  # project ALL because the store reads whole items back from the index.
  global_secondary_index {
    name            = "GSI1"
    hash_key        = "GSI1PK"
    range_key       = "GSI1SK"
    projection_type = "ALL"
  }
  global_secondary_index {
    name            = "GSI2"
    hash_key        = "GSI2PK"
    range_key       = "GSI2SK"
    projection_type = "ALL"
  }

  # Native TTL on the `ttl` attribute: DynamoDB removes stale grants eventually,
  # while the store's claim condition still refuses a stale grant it reads first
  # (twice-enforced expiry). This is the table setting the tests mirror.
  ttl {
    attribute_name = "ttl"
    enabled        = true
  }

  # Point-in-time recovery: enabled. It adds continuous backups but does not
  # block destroy (PITR backups drop with the table), and it is nearly free at
  # POC volume, so the recover-from-oops window is worth the negligible cost.
  point_in_time_recovery {
    enabled = true
  }

  tags = { Name = "${var.project_name}-approvals" }
}

# --- audit table -----------------------------------------------------------

resource "aws_dynamodb_table" "audit" {
  name         = "${var.project_name}-audit"
  billing_mode = "PAY_PER_REQUEST"

  hash_key  = "PK"
  range_key = "SK"

  # PK/SK only: the audit table has no GSI and no TTL (append-only, retained).
  attribute {
    name = "PK"
    type = "S"
  }
  attribute {
    name = "SK"
    type = "S"
  }

  # No ttl block: audit rows are never expired. No GSI: enumeration is a Query
  # on the single constant partition.

  point_in_time_recovery {
    enabled = true
  }

  tags = { Name = "${var.project_name}-audit" }
}
