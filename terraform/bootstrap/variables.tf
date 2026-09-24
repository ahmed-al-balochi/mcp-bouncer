variable "aws_region" {
  description = "Region for the ECR repository and the ACM certificate. Route53 is global and ignores this."
  type        = string

  validation {
    condition     = can(regex("^[a-z]{2}(-[a-z]+)+-[0-9]$", var.aws_region))
    error_message = "aws_region must look like a region code, for example eu-west-1."
  }
}

variable "project_name" {
  description = "Name used for the ECR repository and resource tags."
  type        = string
  default     = "mcp-bouncer"

  validation {
    condition     = can(regex("^[a-z][a-z0-9-]{1,38}[a-z0-9]$", var.project_name))
    error_message = "project_name must be lowercase alphanumeric with hyphens, 3-40 characters."
  }
}

variable "dns_zone_name" {
  description = <<-EOT
    Fully qualified name of the DNS zone to create, e.g. "bouncer.example.com".

    This is normally a subdomain of a domain you already own elsewhere. After
    applying, delegate it by adding NS records for the subdomain label at your
    existing registrar, pointing at this zone's name servers. Do not change your
    domain's own name servers -- that would move the whole domain.
  EOT
  type        = string

  validation {
    condition     = can(regex("^([a-z0-9]([a-z0-9-]*[a-z0-9])?\\.)+[a-z]{2,}$", var.dns_zone_name))
    error_message = "dns_zone_name must be a lowercase fully qualified domain name, without a trailing dot."
  }
}

variable "image_retention_count" {
  description = "How many tagged images to keep in ECR before expiring the oldest."
  type        = number
  default     = 5

  validation {
    condition     = var.image_retention_count >= 1
    error_message = "image_retention_count must be at least 1."
  }
}

variable "tags" {
  description = "Additional tags applied to every resource in this stack."
  type        = map(string)
  default     = {}
}
