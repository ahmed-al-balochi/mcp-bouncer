# Bootstrap stack: the two things that must outlive the application stack. The
# DNS zone must survive because the registrar delegates to its name servers; the
# image repository must survive because destroying it deletes the image.

locals {
  tags = merge(
    {
      Project   = var.project_name
      Stack     = "bootstrap"
      ManagedBy = "terraform"
    },
    var.tags,
  )
}

resource "aws_route53_zone" "this" {
  name    = var.dns_zone_name
  comment = "Delegated zone for ${var.project_name}. Created by the bootstrap stack."

  lifecycle {
    # Deliberate: this stack has no teardown path. Losing the zone means
    # re-delegating at the registrar, which is manual and easy to forget.
    prevent_destroy = true
  }
}

resource "aws_ecr_repository" "this" {
  name = var.project_name

  # MUTABLE so a rebuilt image can reuse the same tag during a POC; the previous
  # image is orphaned as untagged and reaped by the lifecycle policy below. An
  # immutable tag policy would be right for a real release process.
  image_tag_mutability = "MUTABLE"

  # Guards against `terraform destroy` silently taking the image with it.
  force_delete = false

  image_scanning_configuration {
    scan_on_push = true
  }

  encryption_configuration {
    encryption_type = "AES256"
  }

  lifecycle {
    prevent_destroy = true
  }
}

resource "aws_ecr_lifecycle_policy" "this" {
  repository = aws_ecr_repository.this.name

  policy = jsonencode({
    rules = [
      {
        rulePriority = 1
        description  = "Expire untagged images after one day."
        selection = {
          tagStatus   = "untagged"
          countType   = "sinceImagePushed"
          countUnit   = "days"
          countNumber = 1
        }
        action = { type = "expire" }
      },
      {
        rulePriority = 2
        description  = "Keep only the most recent tagged images."
        selection = {
          tagStatus   = "any"
          countType   = "imageCountMoreThan"
          countNumber = var.image_retention_count
        }
        action = { type = "expire" }
      },
    ]
  })
}

# --- LiteLLM image repository ----------------------------------------------

# A second repository, for the thin LiteLLM gateway image, kept separate from the
# gate's so the gateway's execution role pulls only this one and the two images
# never mix under a tag. Every setting mirrors aws_ecr_repository.this.
resource "aws_ecr_repository" "litellm" {
  name = "${var.project_name}-litellm"

  image_tag_mutability = "MUTABLE"

  force_delete = false

  image_scanning_configuration {
    scan_on_push = true
  }

  encryption_configuration {
    encryption_type = "AES256"
  }

  lifecycle {
    prevent_destroy = true
  }
}

# The same lifecycle policy as the gate repository: expire untagged images after
# a day and keep only the most recent tagged ones, so the repository does not
# grow without bound across rebuilds.
resource "aws_ecr_lifecycle_policy" "litellm" {
  repository = aws_ecr_repository.litellm.name

  policy = jsonencode({
    rules = [
      {
        rulePriority = 1
        description  = "Expire untagged images after one day."
        selection = {
          tagStatus   = "untagged"
          countType   = "sinceImagePushed"
          countUnit   = "days"
          countNumber = 1
        }
        action = { type = "expire" }
      },
      {
        rulePriority = 2
        description  = "Keep only the most recent tagged images."
        selection = {
          tagStatus   = "any"
          countType   = "imageCountMoreThan"
          countNumber = var.image_retention_count
        }
        action = { type = "expire" }
      },
    ]
  })
}
