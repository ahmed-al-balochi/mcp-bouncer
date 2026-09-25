# The service is served at the zone APEX (D4.2), so the record name is the zone
# name itself. An A alias to the ALB rather than a CNAME, because a zone apex
# cannot hold a CNAME -- an alias is Route53's apex-safe equivalent and resolves
# to the ALB's addresses with no extra lookup.

resource "aws_route53_record" "apex" {
  zone_id = data.aws_route53_zone.this.zone_id
  name    = var.dns_zone_name
  type    = "A"

  alias {
    name                   = aws_lb.this.dns_name
    zone_id                = aws_lb.this.zone_id
    evaluate_target_health = true
  }
}
