# The TLS certificate belongs to the zone's lifetime, not the application's. A
# DNS-validated certificate is issued once here and renews itself; the app stack
# only looks it up, so it is not re-requested and re-validated every apply.

# Note what is deliberately absent: aws_acm_certificate_validation. It blocks
# until the record resolves publicly, which needs the registrar delegation that
# happens after the first apply; ACM finishes validation itself once that is live.

resource "aws_acm_certificate" "this" {
  domain_name       = var.dns_zone_name
  validation_method = "DNS"

  # One extra name costs nothing and leaves room for a second service in the
  # same zone without reissuing.
  subject_alternative_names = ["*.${var.dns_zone_name}"]

  lifecycle {
    create_before_destroy = true
    prevent_destroy       = true
  }
}

# ACM returns one validation option per name, but a wildcard and its apex share
# one record. Keying by domain name would declare two resources for the same
# record, so group by record name and take one option per distinct record.
locals {
  validation_options_by_record = {
    for option in aws_acm_certificate.this.domain_validation_options :
    option.resource_record_name => option...
  }

  validation_records = {
    for record_name, options in local.validation_options_by_record :
    record_name => options[0]
  }
}

resource "aws_route53_record" "certificate_validation" {
  for_each = local.validation_records

  zone_id = aws_route53_zone.this.zone_id
  name    = each.value.resource_record_name
  type    = each.value.resource_record_type
  records = [each.value.resource_record_value]
  ttl     = 300

  # ACM reissues the same validation record on renewal; overwriting is expected
  # rather than a conflict.
  allow_overwrite = true
}
