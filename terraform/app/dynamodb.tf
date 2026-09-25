# The two DynamoDB tables the gate uses. Their shape is authoritative in
# tests/dynamodb_tables.py -- the store code was written against exactly this key
# design -- so these definitions mirror it attribute for attribute. A drift here
# would surface as the store failing to Query at runtime.
#
# PAY_PER_REQUEST so there is no provisioned capacity to size or pay for while
# idle; a POC's traffic is bursty and low. deletion_protection is OFF: this is
# the disposable stack and `terraform destroy` must leave nothing running or
# billable (R41). Encryption at rest is on by default with the AWS-owned key, so
# no explicit block is needed.

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
  # (R28, twice-enforced expiry). This is the table setting the tests mirror.
  ttl {
    attribute_name = "ttl"
    enabled        = true
  }

  # Point-in-time recovery: enabled. It adds continuous backups but does NOT
  # block destroy -- PITR backups are dropped with the table, so R41 still holds
  # -- and it is nearly free at POC volume. The safety of a recover-from-oops
  # window is worth more than the negligible cost. Justified per the task's
  # "optional, your call" note.
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
