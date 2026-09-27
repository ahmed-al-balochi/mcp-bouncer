# All environment-specific values are variables with no default that leaks the
# owner's setup (R39). Defaults exist only where they are generic to the project
# (project_name, task size, log retention) or discovered at apply time
# (allowed_cidrs). The domain, alert email, and any account-specific value are
# required with no default and are supplied through a gitignored terraform.tfvars
# or TF_VAR_* (R2, R3).

variable "aws_region" {
  description = "Region for every resource in this stack. Must match the region the bootstrap ECR repository and ACM certificate live in."
  type        = string

  validation {
    condition     = can(regex("^[a-z]{2}(-[a-z]+)+-[0-9]$", var.aws_region))
    error_message = "aws_region must look like a region code, for example eu-west-1."
  }
}

variable "project_name" {
  description = "Name used to look up the ECR repository and to name/tag resources. Must match the bootstrap stack's project_name."
  type        = string
  default     = "mcp-bouncer"

  validation {
    condition     = can(regex("^[a-z][a-z0-9-]{1,38}[a-z0-9]$", var.project_name))
    error_message = "project_name must be lowercase alphanumeric with hyphens, 3-40 characters."
  }
}

variable "dns_zone_name" {
  description = <<-EOT
    Fully qualified name of the delegated DNS zone created by the bootstrap
    stack, e.g. "bouncer.example.com". The gateway is served at
    `$${gateway_host_label}.$${dns_zone_name}` (default `llm.<zone>`, D6.10), not
    at the apex: G1 removed the apex A alias (dns.tf). The bootstrap certificate
    is a wildcard (`*.<zone>`, bootstrap certificate.tf) so it already covers the
    gateway host and no certificate change is needed. No default -- a reader
    supplies their own (R3).
  EOT
  type        = string

  validation {
    condition     = can(regex("^([a-z0-9]([a-z0-9-]*[a-z0-9])?\\.)+[a-z]{2,}$", var.dns_zone_name))
    error_message = "dns_zone_name must be a lowercase fully qualified domain name, without a trailing dot."
  }
}

variable "alert_email" {
  description = <<-EOT
    Email address that receives the fail_closed CloudWatch alarm via SNS. No
    default (R2, R39). After apply, AWS sends a confirmation link to this address
    that MUST be clicked before any alarm notification is delivered.
  EOT
  type        = string

  validation {
    # A deliberately loose but non-trivial shape check: local-part@domain.tld.
    # It is not RFC 5322; it exists to catch a typo or a placeholder left in,
    # not to validate deliverability (SNS confirmation does that).
    condition     = can(regex("^[^@[:space:]]+@[^@[:space:]]+\\.[^@[:space:]]+$", var.alert_email))
    error_message = "alert_email must look like an email address, for example you@example.com."
  }
}

variable "allowed_cidrs" {
  description = <<-EOT
    Source IP CIDRs permitted to reach the ALB (R37). Default null means:
    discover the applier's own public IP at apply time and allow only <ip>/32.
    Override with an explicit list to allowlist known operator networks.
  EOT
  type        = list(string)
  default     = null

  validation {
    # Either null (discover) or every entry a valid CIDR. Terraform evaluates
    # this even when null, so the null case must short-circuit to true.
    condition = var.allowed_cidrs == null ? true : alltrue([
      for c in var.allowed_cidrs : can(cidrhost(c, 0))
    ])
    error_message = "every entry in allowed_cidrs must be a valid CIDR, for example 203.0.113.4/32."
  }
}

variable "image_tag" {
  description = "Tag of the image in the bootstrap ECR repository to run."
  type        = string
  default     = "latest"

  validation {
    condition     = length(trimspace(var.image_tag)) > 0
    error_message = "image_tag must not be empty."
  }
}

variable "litellm_image_tag" {
  description = "Tag of the thin LiteLLM gateway image in the bootstrap litellm ECR repository to run (G1, D6.10)."
  type        = string
  default     = "latest"

  validation {
    condition     = length(trimspace(var.litellm_image_tag)) > 0
    error_message = "litellm_image_tag must not be empty."
  }
}

variable "bedrock_inference_profile_id" {
  description = <<-EOT
    Bedrock inference profile id the gateway routes to (R53, D6.10). Must be an
    EU (`eu.`) profile so models stay EU-only; the aws_bedrock_inference_profile
    data source is keyed by this, and a lifecycle postcondition additionally
    asserts every routed foundation-model region begins with `eu-`. This is
    project design, not an environment value (it matches the model id in
    gateway/litellm.yaml), so a default is appropriate.
  EOT
  type        = string
  default     = "eu.anthropic.claude-sonnet-5"

  validation {
    condition     = startswith(var.bedrock_inference_profile_id, "eu.")
    error_message = "bedrock_inference_profile_id must be an EU inference profile (start with \"eu.\") so models stay EU-only (R53)."
  }
}

variable "gateway_host_label" {
  description = <<-EOT
    DNS label for the gateway host under the delegated zone (D6.10): the ALB
    serves the gateway at `$${gateway_host_label}.$${dns_zone_name}` and nothing
    else. Default "llm". A label, not a full name -- the zone name is a separate
    variable -- so no domain is hardcoded here (R3).
  EOT
  type        = string
  default     = "llm"

  validation {
    # A single DNS label: 1-63 chars, lowercase alphanumeric and hyphens, not
    # starting or ending with a hyphen.
    condition     = can(regex("^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$", var.gateway_host_label))
    error_message = "gateway_host_label must be a single DNS label, for example \"llm\"."
  }
}

variable "vpc_cidr" {
  description = "CIDR block for the dedicated VPC (D4.4). Large enough for two public and two private /24 subnets."
  type        = string
  default     = "10.0.0.0/16"

  validation {
    condition     = can(cidrhost(var.vpc_cidr, 0))
    error_message = "vpc_cidr must be a valid CIDR, for example 10.0.0.0/16."
  }
}

variable "log_retention_days" {
  description = "CloudWatch Logs retention for the task log group."
  type        = number
  default     = 30

  validation {
    # The set CloudWatch Logs accepts. An arbitrary number is rejected by the
    # API at apply; catch it here with a clear message instead.
    condition = contains(
      [1, 3, 5, 7, 14, 30, 60, 90, 120, 150, 180, 365, 400, 545, 731, 1096, 1827, 2192, 2557, 2922, 3288, 3653],
      var.log_retention_days
    )
    error_message = "log_retention_days must be a value CloudWatch Logs accepts (1, 3, 5, 7, 14, 30, 60, 90, ...)."
  }
}

variable "callers" {
  description = <<-EOT
    Map of caller name => team name. One bearer token is generated per entry and
    written into the token secret as { <token> = { caller = <name>, team =
    <team> } } (see secrets.tf). Every team named here MUST exist in policy.yaml
    or the gate refuses to boot; a precondition in secrets.tf enforces that at
    plan time rather than as a task crash-loop.
  EOT
  type        = map(string)
  default = {
    "customerchat-agent" = "CustomerChat"
    "devchat-agent"      = "DevChat"
  }

  validation {
    condition     = length(var.callers) > 0
    error_message = "callers must define at least one caller."
  }
}

variable "cpu_architecture" {
  description = "Fargate CPU architecture for the task's runtime platform."
  type        = string
  default     = "X86_64"

  validation {
    condition     = contains(["X86_64", "ARM64"], var.cpu_architecture)
    error_message = "cpu_architecture must be X86_64 or ARM64."
  }
}

variable "tags" {
  description = "Additional tags applied to every resource in this stack."
  type        = map(string)
  default     = {}
}
