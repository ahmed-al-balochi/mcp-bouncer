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
