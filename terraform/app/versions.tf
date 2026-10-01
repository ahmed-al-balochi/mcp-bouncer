terraform {
  # The floor is recent enough for the features used here (optional object
  # attributes, the `http` data source); the ceiling keeps a major provider
  # bump from silently changing behaviour on apply.
  required_version = ">= 1.5"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = ">= 5.40, < 7.0"
    }
    # Only used to discover the applier's own public IP when allowed_cidrs is
    # left null. A read from a single well-known URL; no state footprint.
    http = {
      source  = "hashicorp/http"
      version = ">= 3.4, < 4.0"
    }
    # random_password generates the bearer tokens at provision time so no human
    # authors one and none is ever committed.
    random = {
      source  = "hashicorp/random"
      version = ">= 3.5, < 4.0"
    }
  }
}

provider "aws" {
  region = var.aws_region

  # Every resource in this stack inherits these tags without repeating them.
  # Matches the bootstrap stack's approach.
  default_tags {
    tags = local.tags
  }
}
