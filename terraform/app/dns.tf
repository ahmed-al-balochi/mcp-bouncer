# An A alias for the gateway host, not the apex. The apex record is deliberately
# removed because the ALB answers only the gateway host and 404s everything else.
# The bootstrap wildcard certificate already covers this host, so no cert change.
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
