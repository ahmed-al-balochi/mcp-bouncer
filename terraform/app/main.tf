# Locals, shared naming, and the data lookups that tie this disposable stack to
# the long-lived bootstrap stack and to the applier's environment.
#
# Nothing here creates a resource. The certificate, DNS zone and ECR repository
# are all LOOKED UP, not created: they belong to the bootstrap stack that
# outlives this one (R34, D0.1). Looking them up filtered to a ready state means
# a premature apply (before the bootstrap stack is applied and the certificate
# is ISSUED) fails fast with a clear message instead of half-building.

locals {
  # Tag set inherited by every resource via the provider's default_tags. Mirrors
  # the bootstrap stack, with Stack = "app" so the two are distinguishable.
  tags = merge(
    {
      Project   = var.project_name
      Stack     = "app"
      ManagedBy = "terraform"
    },
    var.tags,
  )

  # The service is served at the zone apex (D4.2). Held as a local so the URL is
  # built in exactly one place.
  service_host = var.dns_zone_name

  # Container/target port. The image EXPOSEs 8000 and binds 0.0.0.0:8000
  # (--port 8000); the target group and SG rules all key off this one value.
  container_port = 8000

  # CloudWatch log group name for the task. Defined here so iam.tf can scope the
  # execution role's log actions to exactly this group's ARN without depending
  # on the log group resource (which would risk a cycle through the endpoint
  # policy) -- the name is deterministic.
  log_group_name = "/ecs/${var.project_name}"

  # Two AZs (D4.4). Sliced from whatever the region offers so the stack is not
  # pinned to hard-coded AZ names, which differ per account.
  azs = slice(data.aws_availability_zones.available.names, 0, 2)

  # /24 subnets carved from the VPC CIDR: two public (index 0,1) for the ALB and
  # two private (index 2,3) for the tasks. newbits = 8 turns a /16 into /24s.
  public_subnet_cidrs  = [for i in [0, 1] : cidrsubnet(var.vpc_cidr, 8, i)]
  private_subnet_cidrs = [for i in [2, 3] : cidrsubnet(var.vpc_cidr, 8, i)]

  # The container image to run: the looked-up repository URL at the chosen tag.
  container_image = "${data.aws_ecr_repository.this.repository_url}:${var.image_tag}"

  # The S3 bucket ECR serves image layers from is region-specific and AWS-owned.
  # Named here once so the S3 endpoint policy (endpoints.tf) and any reader see
  # the same value. Verified shape against the AWS ECR VPC-endpoint docs.
  ecr_layer_bucket_arn = "arn:aws:s3:::prod-${var.aws_region}-starport-layer-bucket/*"

  # Source CIDRs for the ALB. If the caller left allowed_cidrs null, allow only
  # the applier's own discovered public IP as a /32 (R37). chomp() strips the
  # trailing newline checkip returns.
  discovered_cidr = "${chomp(data.http.my_ip.response_body)}/32"
  allowed_cidrs   = var.allowed_cidrs == null ? [local.discovered_cidr] : var.allowed_cidrs
}

# --- lookups into the bootstrap stack and the account ----------------------

# The delegated hosted zone created by the bootstrap stack (D0.1). Looked up by
# name so this stack never manages the zone's lifecycle.
data "aws_route53_zone" "this" {
  name         = "${var.dns_zone_name}."
  private_zone = false
}

# The TLS certificate, filtered to ISSUED (D0.2). If the certificate is not yet
# validated -- e.g. the registrar delegation is not live -- this fails fast
# instead of the stack building an ALB listener that cannot serve. There is
# deliberately NO aws_acm_certificate or validation resource here; the
# certificate belongs to the bootstrap stack.
data "aws_acm_certificate" "this" {
  domain      = var.dns_zone_name
  statuses    = ["ISSUED"]
  most_recent = true
}

# The ECR repository created by the bootstrap stack, looked up by name.
data "aws_ecr_repository" "this" {
  name = var.project_name
}

data "aws_caller_identity" "current" {}

data "aws_region" "current" {}

data "aws_availability_zones" "available" {
  state = "available"
}

# The applier's own public IP, used only when allowed_cidrs is null (R37).
# checkip.amazonaws.com returns the caller's source address as plain text. This
# is the one outbound read Terraform itself makes; the deployed task never has
# any internet path (D4.4).
data "http" "my_ip" {
  url = "https://checkip.amazonaws.com"
}
