output "zone_id" {
  description = "Route53 hosted zone id. The application stack looks the zone up by name, so this is for reference."
  value       = aws_route53_zone.this.zone_id
}

output "zone_name" {
  description = "Fully qualified name of the delegated zone."
  value       = aws_route53_zone.this.name
}

output "name_servers" {
  description = <<-EOT
    Add one NS record per entry at your existing registrar, all with the
    subdomain label as the record name. Verify with:
      dig +short NS <zone_name>
  EOT
  value       = aws_route53_zone.this.name_servers
}

output "ecr_repository_url" {
  description = "Push the container image here."
  value       = aws_ecr_repository.this.repository_url
}

output "ecr_repository_name" {
  description = "Repository name, for the application stack's variables."
  value       = aws_ecr_repository.this.name
}

output "certificate_arn" {
  description = <<-EOT
    ARN of the TLS certificate. The application stack looks the certificate up by
    domain name rather than consuming this, so it is here for reference and for
    checking issuance status.
  EOT
  value       = aws_acm_certificate.this.arn
}

output "certificate_status_check" {
  description = "Run this to see whether ACM has finished validating the certificate."
  value       = "aws acm describe-certificate --region ${var.aws_region} --certificate-arn ${aws_acm_certificate.this.arn} --query 'Certificate.Status' --output text"
}
