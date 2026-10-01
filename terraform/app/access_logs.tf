# ALB access logs to S3. The bucket lives in the app stack so destroy removes it;
# force_destroy = true lets it go even with log objects still in it. It holds
# request metadata, so it is hardened: no public access, no ACLs, encrypted.

resource "aws_s3_bucket" "alb_logs" {
  # A stable, unique-enough name from the project name, account id and region, so
  # it is globally unique without a random suffix and nothing is hardcoded. S3
  # caps names at 63 chars, only reachable with a deliberately long project_name.
  bucket = "${var.project_name}-alb-logs-${data.aws_caller_identity.current.account_id}-${data.aws_region.current.region}"

  # Let destroy remove the bucket even with log objects still in it. The objects
  # are disposable access logs, not a system of record.
  force_destroy = true

  tags = { Name = "${var.project_name}-alb-logs" }
}

# Block every route to public access. Access logs must never be internet-readable
# (they carry source IPs and request paths). All four switches on, so neither a
# public ACL nor a public bucket policy can take effect even if one were added.
resource "aws_s3_bucket_public_access_block" "alb_logs" {
  bucket                  = aws_s3_bucket.alb_logs.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

# Ownership controls: BucketOwnerEnforced disables ACLs entirely, so ownership is
# unambiguous and no ACL grant is possible. ELB service-principal delivery writes
# objects owned by the bucket owner, so this stays compatible with it.
resource "aws_s3_bucket_ownership_controls" "alb_logs" {
  bucket = aws_s3_bucket.alb_logs.id
  rule {
    object_ownership = "BucketOwnerEnforced"
  }
}

# SSE-S3 (AES256), not SSE-KMS, on purpose: AWS supports only SSE-S3 for ALB
# access logs, and SSE-S3 needs no key grant to the delivery principal whereas
# SSE-KMS would require a kms:GenerateDataKey grant for no benefit here.
resource "aws_s3_bucket_server_side_encryption_configuration" "alb_logs" {
  bucket = aws_s3_bucket.alb_logs.id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}

# Expire objects after a short retention. Reuses var.log_retention_days so the S3
# log lifetime tracks the CloudWatch log lifetime with one knob; split it later
# if the two ever need to diverge.
resource "aws_s3_bucket_lifecycle_configuration" "alb_logs" {
  bucket = aws_s3_bucket.alb_logs.id

  rule {
    id     = "expire-access-logs"
    status = "Enabled"

    # Scope the rule to the whole bucket. An empty filter prefix matches every
    # object; stated explicitly because a rule with no filter is a provider
    # deprecation warning.
    filter {}

    expiration {
      days = var.log_retention_days
    }

    # Access logs are written once and never versioned here, but clean up any
    # aborted multipart uploads so a failed delivery cannot leave billable
    # partial objects behind.
    abort_incomplete_multipart_upload {
      days_after_initiation = 1
    }
  }
}

# --- bucket policy: grant ELB log delivery PutObject, and nothing else -------

# The service-principal form `logdelivery.elasticloadbalancing.amazonaws.com`
# with `s3:PutObject`, hardened with aws:SourceAccount and aws:SourceArn; account,
# region and ARN all come from data sources, never a literal.
data "aws_partition" "current" {}

data "aws_iam_policy_document" "alb_logs" {
  statement {
    sid     = "AllowELBLogDelivery"
    effect  = "Allow"
    actions = ["s3:PutObject"]
    # ELB writes under <prefix>/AWSLogs/<account-id>/*. Pinning the account id in
    # the resource path ensures only load balancers in this account can write
    # here. Built from data sources, so no literal account id.
    resources = [
      "${aws_s3_bucket.alb_logs.arn}/${local.alb_log_prefix}/AWSLogs/${data.aws_caller_identity.current.account_id}/*",
    ]

    principals {
      type        = "Service"
      identifiers = ["logdelivery.elasticloadbalancing.amazonaws.com"]
    }

    # aws:SourceArn already pins account and region. aws:SourceAccount uses
    # StringEqualsIfExists, not StringEquals, because the key may not be populated;
    # a plain StringEquals would deny the delivery write-test and fail the apply.
    condition {
      test     = "StringEqualsIfExists"
      variable = "aws:SourceAccount"
      values   = [data.aws_caller_identity.current.account_id]
    }

    condition {
      test     = "ArnLike"
      variable = "aws:SourceArn"
      values = [
        "arn:${data.aws_partition.current.partition}:elasticloadbalancing:${data.aws_region.current.region}:${data.aws_caller_identity.current.account_id}:loadbalancer/*",
      ]
    }
  }
}

resource "aws_s3_bucket_policy" "alb_logs" {
  bucket = aws_s3_bucket.alb_logs.id
  policy = data.aws_iam_policy_document.alb_logs.json

  # The public-access block must be in place before the policy so there is never
  # a window where a policy exists without the block guarding it.
  depends_on = [aws_s3_bucket_public_access_block.alb_logs]
}

output "alb_logs_bucket_name" {
  description = "S3 bucket holding the ALB access logs (destroyed with the stack). An operator finds the logs under the alb/AWSLogs/<account-id>/ prefix here."
  value       = aws_s3_bucket.alb_logs.id
}
