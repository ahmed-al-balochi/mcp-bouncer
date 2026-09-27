# The gateway is served at `${gateway_host_label}.${dns_zone_name}` (D6.10), so
# this is an A alias for that host, not the apex. The apex record is deliberately
# REMOVED: the ALB's HTTPS listener answers only the gateway host and returns 404
# for everything else, so an apex record would resolve to an endpoint that never
# serves. An alias (not a CNAME) resolves straight to the ALB's addresses.
#
# No certificate change is needed: the bootstrap certificate carries a
# `*.${dns_zone_name}` subject alternative name (terraform/bootstrap/
# certificate.tf), and `${gateway_host_label}.${dns_zone_name}` is a single
# label under the zone, so the wildcard covers it.
resource "aws_route53_record" "gateway" {
  zone_id = data.aws_route53_zone.this.zone_id
  name    = local.gateway_host
  type    = "A"

  alias {
    name                   = aws_lb.this.dns_name
    zone_id                = aws_lb.this.zone_id
    evaluate_target_health = true
  }
}
