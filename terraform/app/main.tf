# Locals, shared naming, and the data lookups into the long-lived bootstrap
# stack. Nothing here creates a resource: the certificate, DNS zone and ECR
# repository are looked up, filtered to a ready state so a premature apply fails.

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

  # The gateway is served at `${gateway_host_label}.${dns_zone_name}`, the only
  # host the ALB answers. Built once here.
  gateway_host = "${var.gateway_host_label}.${var.dns_zone_name}"

  # Key prefix under which the ALB writes access logs. A prefix keeps the
  # ELB-owned `AWSLogs/<account>/...` tree under one namespace and makes the
  # bucket-policy ARN specific. It must not contain the string "AWSLogs".
  alb_log_prefix = "alb"

  # Container/target port. The image EXPOSEs 8000 and binds 0.0.0.0:8000
  # (--port 8000); the target group and SG rules all key off this one value.
  container_port = 8000

  # The LiteLLM gateway listens on 4000 (gateway/Dockerfile --port 4000); its
  # target group and SG rules key off this.
  litellm_port = 4000

  # CloudWatch log group name for the task. Defined here so iam.tf can scope the
  # execution role's log actions to this group's ARN without depending on the log
  # group resource (which would risk a cycle); the name is deterministic.
  log_group_name = "/ecs/${var.project_name}"

  # Log groups for the LiteLLM container and for the Service Connect (Envoy)
  # sidecars, named deterministically for the same reason: iam.tf and the Logs
  # endpoint policy scope to these ARNs without depending on the resources.
  litellm_log_group_name = "/ecs/${var.project_name}-litellm"
  connect_log_group_name = "/ecs/${var.project_name}-serviceconnect"

  # Two AZs, sliced from whatever the region offers so the stack is not pinned to
  # hard-coded AZ names, which differ per account.
  azs = slice(data.aws_availability_zones.available.names, 0, 2)

  # /24 subnets carved from the VPC CIDR: two public (index 0,1) for the ALB and
  # two private (index 2,3) for the tasks. newbits = 8 turns a /16 into /24s.
  public_subnet_cidrs  = [for i in [0, 1] : cidrsubnet(var.vpc_cidr, 8, i)]
  private_subnet_cidrs = [for i in [2, 3] : cidrsubnet(var.vpc_cidr, 8, i)]

  # The container image to run: the looked-up repository URL at the chosen tag.
  container_image = "${data.aws_ecr_repository.this.repository_url}:${var.image_tag}"

  # The LiteLLM gateway image: the second bootstrap repository at its own tag.
  litellm_image = "${data.aws_ecr_repository.litellm.repository_url}:${var.litellm_image_tag}"

  # The EU-only Bedrock ARNs the gateway may invoke, taken from the data source
  # rather than typed: the profile ARN and every model ARN it routes to. IAM and
  # the bedrock-runtime endpoint policy authorise exactly this one set.
  bedrock_profile_arn = data.aws_bedrock_inference_profile.this.inference_profile_arn
  bedrock_model_arns  = [for m in data.aws_bedrock_inference_profile.this.models : m.model_arn]

  # The S3 bucket ECR serves image layers from is region-specific and AWS-owned.
  # Named here once so the S3 endpoint policy (endpoints.tf) and any reader see
  # the same value. Verified shape against the AWS ECR VPC-endpoint docs.
  ecr_layer_bucket_arn = "arn:aws:s3:::prod-${var.aws_region}-starport-layer-bucket/*"

  # Source CIDRs for the ALB. If the caller left allowed_cidrs null, allow only
  # the applier's own discovered public IP as a /32. chomp() strips the trailing
  # newline checkip returns.
  discovered_cidr = "${chomp(data.http.my_ip.response_body)}/32"
  allowed_cidrs   = var.allowed_cidrs == null ? [local.discovered_cidr] : var.allowed_cidrs
}

# --- lookups into the bootstrap stack and the account ----------------------

# The delegated hosted zone created by the bootstrap stack. Looked up by name so
# this stack never manages the zone's lifecycle.
data "aws_route53_zone" "this" {
  name         = "${var.dns_zone_name}."
  private_zone = false
}

# The TLS certificate, filtered to ISSUED. If it is not yet validated (e.g. the
# registrar delegation is not live) this fails fast instead of building an ALB
# listener that cannot serve. The certificate belongs to the bootstrap stack.
data "aws_acm_certificate" "this" {
  domain      = var.dns_zone_name
  statuses    = ["ISSUED"]
  most_recent = true
}

# The ECR repository created by the bootstrap stack, looked up by name.
data "aws_ecr_repository" "this" {
  name = var.project_name
}

# The second bootstrap repository, for the thin LiteLLM gateway image.
data "aws_ecr_repository" "litellm" {
  name = "${var.project_name}-litellm"
}

# The EU Bedrock inference profile the gateway routes to, looked up by the
# variable rather than typing ARNs. The postcondition below asserts every model
# ARN it routes to lives in an `eu-` region, failing the apply otherwise.
data "aws_bedrock_inference_profile" "this" {
  inference_profile_id = var.bedrock_inference_profile_id

  lifecycle {
    postcondition {
      condition = alltrue([
        for m in self.models :
        can(regex("^arn:aws:bedrock:eu-", m.model_arn))
      ])
      error_message = "inference profile ${var.bedrock_inference_profile_id} routes to a non-EU foundation model; every routed model ARN must be in an eu- region."
    }
  }
}

data "aws_caller_identity" "current" {}

data "aws_region" "current" {}

data "aws_availability_zones" "available" {
  state = "available"
}

# The applier's own public IP, used only when allowed_cidrs is null.
# checkip.amazonaws.com returns the caller's source address as plain text. This
# is the one outbound read Terraform makes; the deployed task has no internet.
data "http" "my_ip" {
  url = "https://checkip.amazonaws.com"
}
