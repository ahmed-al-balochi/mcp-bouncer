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

  # The gateway is served at `${gateway_host_label}.${dns_zone_name}` (D6.10),
  # the only host the ALB answers. Built once here.
  gateway_host = "${var.gateway_host_label}.${var.dns_zone_name}"

  # Container/target port. The image EXPOSEs 8000 and binds 0.0.0.0:8000
  # (--port 8000); the target group and SG rules all key off this one value.
  container_port = 8000

  # The LiteLLM gateway listens on 4000 (gateway/Dockerfile --port 4000); its
  # target group and SG rules key off this.
  litellm_port = 4000

  # CloudWatch log group name for the task. Defined here so iam.tf can scope the
  # execution role's log actions to exactly this group's ARN without depending
  # on the log group resource (which would risk a cycle through the endpoint
  # policy) -- the name is deterministic.
  log_group_name = "/ecs/${var.project_name}"

  # Log groups for the LiteLLM container and for the Service Connect (Envoy)
  # sidecars, named deterministically for the same reason: iam.tf and the Logs
  # endpoint policy scope to these ARNs without depending on the resources.
  litellm_log_group_name = "/ecs/${var.project_name}-litellm"
  connect_log_group_name = "/ecs/${var.project_name}-serviceconnect"

  # Two AZs (D4.4). Sliced from whatever the region offers so the stack is not
  # pinned to hard-coded AZ names, which differ per account.
  azs = slice(data.aws_availability_zones.available.names, 0, 2)

  # /24 subnets carved from the VPC CIDR: two public (index 0,1) for the ALB and
  # two private (index 2,3) for the tasks. newbits = 8 turns a /16 into /24s.
  public_subnet_cidrs  = [for i in [0, 1] : cidrsubnet(var.vpc_cidr, 8, i)]
  private_subnet_cidrs = [for i in [2, 3] : cidrsubnet(var.vpc_cidr, 8, i)]

  # The container image to run: the looked-up repository URL at the chosen tag.
  container_image = "${data.aws_ecr_repository.this.repository_url}:${var.image_tag}"

  # The LiteLLM gateway image: the second bootstrap repository at its own tag.
  litellm_image = "${data.aws_ecr_repository.litellm.repository_url}:${var.litellm_image_tag}"

  # The EU-only Bedrock ARNs the gateway may invoke (R53), taken from the
  # inference-profile data source rather than typed: the profile ARN itself, and
  # every foundation-model ARN the profile routes to. Both IAM (iam.tf) and the
  # bedrock-runtime endpoint policy (endpoints.tf) authorise exactly this set,
  # so the three EU-only layers reference one source of truth.
  bedrock_profile_arn = data.aws_bedrock_inference_profile.this.inference_profile_arn
  bedrock_model_arns  = [for m in data.aws_bedrock_inference_profile.this.models : m.model_arn]

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

# The second bootstrap repository, for the thin LiteLLM gateway image (D6.10).
data "aws_ecr_repository" "litellm" {
  name = "${var.project_name}-litellm"
}

# The EU Bedrock inference profile the gateway routes to (R53, D6.10). Keyed by
# the variable, so the profile is looked up rather than its ARNs typed out. The
# postcondition is the third guard on EU-only: even though the variable's own
# validation requires an `eu.` id and the profile's model list is trusted, this
# asserts that EVERY foundation-model ARN the profile actually routes to lives
# in an `eu-` region -- if AWS ever pointed an `eu.` profile at a non-EU model,
# the apply fails here rather than granting a non-EU ARN in IAM.
data "aws_bedrock_inference_profile" "this" {
  inference_profile_id = var.bedrock_inference_profile_id

  lifecycle {
    postcondition {
      condition = alltrue([
        for m in self.models :
        can(regex("^arn:aws:bedrock:eu-", m.model_arn))
      ])
      error_message = "inference profile ${var.bedrock_inference_profile_id} routes to a non-EU foundation model; every routed model ARN must be in an eu- region (R53)."
    }
  }
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
