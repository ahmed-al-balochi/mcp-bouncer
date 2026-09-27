# Bootstrap stack: the two things that must outlive the application stack.
#
# The DNS zone must survive because its name servers are what the registrar
# delegates to. Destroying and recreating the zone issues a different set, and
# the delegation has to be re-pasted at the registrar by hand every time. So the
# zone is created once here and the application stack only reads it.
#
# The image repository must survive for the same class of reason: destroying it
# deletes the image, and the next apply would have nothing to run until someone
# rebuilds and pushes. Keeping it here makes `terraform destroy` on the
# application stack cheap and repeatable.

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

  # MUTABLE so a rebuilt image can reuse the same tag during a POC. The previous
  # image is orphaned as untagged and reaped by rule 1 of the lifecycle policy
  # below. An immutable tag policy would be the right call for a real release
  # process, where every build gets its own tag.
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

# --- LiteLLM image repository (G1, D6.10) ----------------------------------
#
# A SECOND repository, for the thin LiteLLM gateway image, kept separate from
# the gate's repository on purpose (D6.10): the gateway's execution role can
# then be scoped to pull only this repository, and the two images never mix
# under one tag. Additive to this stack -- the existing zone, certificate and
# gate repository are untouched, so applying this changes nothing that already
# exists. Every setting mirrors aws_ecr_repository.this so the two repositories
# are governed identically (MUTABLE tags for tag reuse during a POC,
# scan_on_push, AES256 at rest, force_delete off, prevent_destroy so a teardown
# cannot take the image with it).
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
