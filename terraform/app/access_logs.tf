# ALB access logs to S3 (D7.2, owner's choice (a) for platform visibility).
#
# WHY this bucket lives in the APP stack, not bootstrap: R41 says `terraform
# destroy` on app/ must leave nothing billable, so the log store must die with
# the stack. `force_destroy = true` lets destroy remove a bucket that still holds
# log objects (S3 refuses to delete a non-empty bucket otherwise). The accepted
# consequence is that the logs are gone after a teardown, which is right for a
# POC -- a production system would ship them to a separate, retained log-archive
# account instead.
#
# WHY hardened: the bucket holds request metadata (source IPs, paths, latencies),
# so it is a security-relevant store. It blocks all public access, disables ACLs,
# encrypts at rest, and expires objects after a short retention.

resource "aws_s3_bucket" "alb_logs" {
  # A stable, unique-enough name: the project name, the account id and the region
  # keep it globally unique without a random suffix, and derive entirely from
  # data sources / existing vars so no environment value is hardcoded (R2, R3).
  #
  # LENGTH CONSTRAINT (latent, not a bug at the default): an S3 bucket name is
  # capped at 63 chars. This name is project_name + "-alb-logs-"(10) + account
  # id(12) + "-" + region(~9-14). variables.tf allows project_name up to 40
  # chars, so a near-maximal project_name can push this past 63 and fail apply.
  # The default project_name ("mcp-bouncer", 11 chars) yields ~46-48 and is well
  # under the limit; this is only reachable with a deliberately long
  # project_name. Not truncated/hashed here because doing so would obscure the
  # name for the common case for a constraint that only a pathological
  # project_name hits -- if a long name is ever needed, hash the account+region
  # suffix then.
  bucket = "${var.project_name}-alb-logs-${data.aws_caller_identity.current.account_id}-${data.aws_region.current.region}"

  # Let destroy remove the bucket even with log objects still in it (R41). The
  # objects are disposable access logs, not a system of record.
  force_destroy = true

  tags = { Name = "${var.project_name}-alb-logs" }
}

# Block every route to public access. Access logs must never be internet-readable
# (they carry source IPs and request paths). All four switches on, so neither a
# public ACL nor a public bucket policy can take effect even if one were added
# later by mistake.
resource "aws_s3_bucket_public_access_block" "alb_logs" {
  bucket                  = aws_s3_bucket.alb_logs.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

# Ownership controls: BucketOwnerEnforced disables ACLs entirely, so object
# ownership is unambiguous and no ACL-based grant is possible. The ELB log
# delivery via the service principal writes objects owned by the bucket owner,
# so this is compatible with the current (service-principal) delivery mechanism.
resource "aws_s3_bucket_ownership_controls" "alb_logs" {
  bucket = aws_s3_bucket.alb_logs.id
  rule {
    object_ownership = "BucketOwnerEnforced"
  }
}

# SSE-S3 (AES256), not SSE-KMS, on purpose. AWS supports ONLY SSE-S3 for ALB
# access logs (verified in the ELB "Enable access logs" docs: "The only
# server-side encryption option that's supported is Amazon S3-managed keys
# (SSE-S3)"). SSE-S3 also needs no key grant to the delivery principal, whereas
# SSE-KMS would require granting the ELB log-delivery service kms:GenerateDataKey
# on a CMK -- more moving parts for no benefit here. bucket_key_enabled is
# irrelevant to SSE-S3 and left default.
resource "aws_s3_bucket_server_side_encryption_configuration" "alb_logs" {
  bucket = aws_s3_bucket.alb_logs.id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}

# Expire objects after a short retention. Reuses var.log_retention_days (default
# 30) so the S3 log lifetime tracks the CloudWatch log lifetime with one knob --
# both are "how long do we keep operational logs for this POC". A dedicated
# variable would be more precise but adds a knob for no POC benefit; if the two
# ever need to diverge, split it then.
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

    # Access logs are written once and never versioned on this bucket (no
    # versioning is enabled), but clean up any aborted multipart uploads so a
    # failed delivery cannot leave billable partial objects behind (R41 spirit).
    abort_incomplete_multipart_upload {
      days_after_initiation = 1
    }
  }
}

# --- bucket policy: grant ELB log delivery PutObject, and nothing else -------
#
# DELIVERY MECHANISM CHOSEN: the current service-principal form,
# `logdelivery.elasticloadbalancing.amazonaws.com` with `s3:PutObject`, hardened
# with aws:SourceAccount and aws:SourceArn conditions. VERIFIED against the AWS
# ELB docs "Enable access logs for your Application Load Balancer" (Step 2),
# which show exactly this principal and action for all Regions available since
# August 2022, and give the legacy regional ELB-account-id policy only as a
# still-supported fallback for older Regions. This project targets commercial
# `aws` in a current EU region (D6.1), so the service-principal form applies and
# NO regional account id is hardcoded -- account and region come from
# data.aws_caller_identity / data.aws_region, and the load-balancer ARN pattern
# comes from those plus the partition, never a literal.
#
# UNVERIFIED here: that the specific target Region supports the service-principal
# form (the docs assert it for "Regions available before August 2022" as the
# cutover, i.e. all newer Regions use it, but this was not exercised against the
# live account in this change -- no AWS calls were made). If a Region predates
# the cutover, the legacy regional-account-id principal would be required
# instead; the phase-8 apply is the real test.
data "aws_partition" "current" {}

data "aws_iam_policy_document" "alb_logs" {
  statement {
    sid     = "AllowELBLogDelivery"
    effect  = "Allow"
    actions = ["s3:PutObject"]
    # ELB writes under <prefix>/AWSLogs/<account-id>/*. Pinning the account id in
    # the resource path (AWS's own guidance) ensures only load balancers in THIS
    # account can write here. Built from data sources, so no literal account id.
    resources = [
      "${aws_s3_bucket.alb_logs.arn}/${local.alb_log_prefix}/AWSLogs/${data.aws_caller_identity.current.account_id}/*",
    ]

    principals {
      type        = "Service"
      identifiers = ["logdelivery.elasticloadbalancing.amazonaws.com"]
    }

    # aws:SourceArn (below) is the condition AWS documents for this delivery, and
    # it already pins the account AND the region because the account id is inside
    # the ARN pattern. aws:SourceAccount is added as belt-and-braces but with
    # StringEqualsIfExists, NOT StringEquals, deliberately: the ELB access-log
    # documentation specifies only aws:SourceArn (and aws:SourceOrgId) for this
    # service principal and never states that aws:SourceAccount is populated on
    # the delivery request. With a plain StringEquals, a request that does not
    # carry the key would be DENIED -- and because the load balancer write-tests
    # the bucket the moment access logs are enabled, that failure would surface as
    # a failed apply rather than as missing logs. IfExists keeps the tightening
    # when the key is present and cannot break delivery when it is absent, and it
    # costs no security here because SourceArn already carries the account id.
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
  description = "S3 bucket holding the ALB access logs (destroyed with the stack, R41). An operator finds the logs under the alb/AWSLogs/<account-id>/ prefix here."
  value       = aws_s3_bucket.alb_logs.id
}
