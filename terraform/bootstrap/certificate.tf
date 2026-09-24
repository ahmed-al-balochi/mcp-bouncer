# The TLS certificate belongs to the zone's lifetime, not the application's.
#
# A DNS-validated certificate is cheap to request and free to hold, but it has to
# be validated before anything can serve traffic with it. If the certificate
# lived in the application stack it would be destroyed and re-requested on every
# apply cycle, and each cycle would wait on validation again. Here it is issued
# once, renews itself, and the application stack only looks it up.
#
# Note what is deliberately absent: aws_acm_certificate_validation. That resource
# blocks until the validation record resolves on the public internet, which
# cannot happen until the zone is delegated at the registrar -- a manual step that
# happens *after* this stack is first applied. Including it here would make the
# first apply hang until it timed out. Instead this stack requests the
# certificate and publishes the validation records, both of which work
# immediately, and ACM completes validation on its own once delegation is live.
# The application stack then looks the certificate up filtered to ISSUED, so a
# premature apply fails fast with a clear message instead of hanging.

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

# ACM returns one validation option per name on the certificate, but a wildcard
# and its apex share a single validation record. Keying the records by domain
# name would therefore declare two Terraform resources that manage the same
# record, which is a fight waiting to happen. Group by the record name instead
# and take one option per distinct record. The `...` suffix is Terraform's
# grouping mode, which tolerates duplicate keys by collecting values into a list.
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
