# The internet-facing ALB (R36). HTTPS with the looked-up ACM certificate, HTTP
# 301-redirecting to HTTPS. The ALB is the only public entry point and it now
# fronts the LiteLLM gateway ONLY (R51): the HTTPS listener answers a single host
# and two paths and returns 404 for everything else (D6.10). The gate is not
# reachable through the ALB at all (R52) -- there is no gate target group and no
# rule that forwards to the gate.

resource "aws_lb" "this" {
  name               = var.project_name
  load_balancer_type = "application"
  internal           = false
  subnets            = [for s in aws_subnet.public : s.id]
  security_groups    = [aws_security_group.alb.id]

  # Reject requests with malformed headers rather than forwarding them. Cheap
  # hardening for a public listener.
  drop_invalid_header_fields = true

  # 300 s idle timeout (D6.10): a non-streamed completion with several model and
  # tool rounds can exceed the 60 s default. Not measured; set pre-emptively.
  idle_timeout = 300

  tags = { Name = "${var.project_name}-alb" }
}

# HTTPS listener with the certificate looked up (filtered to ISSUED) in main.tf.
# A TLS 1.3-capable policy: the -TLS13- policy negotiates 1.3 where the client
# supports it and falls back to 1.2, never below.
#
# The DEFAULT action is a fixed 404 (D6.10): a request to the bare ALB name, the
# apex, or any host/path other than the one rule below gets nothing. The shared
# master key IS LiteLLM's admin key, so shrinking the reachable surface is the
# compensating control affordable without a database.
resource "aws_lb_listener" "https" {
  load_balancer_arn = aws_lb.this.arn
  port              = 443
  protocol          = "HTTPS"
  ssl_policy        = "ELBSecurityPolicy-TLS13-1-2-2021-06"
  certificate_arn   = data.aws_acm_certificate.this.arn

  default_action {
    type = "fixed-response"

    fixed_response {
      content_type = "text/plain"
      message_body = "Not Found"
      status_code  = "404"
    }
  }
}

# The one rule that forwards traffic: only the gateway host, and only the two
# OpenAI-compatible paths the agents use (D6.10). Everything else falls through
# to the listener's 404 default. host_header AND path_pattern must both match.
resource "aws_lb_listener_rule" "gateway" {
  listener_arn = aws_lb_listener.https.arn
  priority     = 100

  condition {
    host_header {
      values = [local.gateway_host]
    }
  }

  condition {
    path_pattern {
      values = ["/v1/chat/completions", "/v1/models"]
    }
  }

  action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.litellm.arn
  }
}

# HTTP listener that does nothing but 301 to HTTPS. No target, so plaintext
# traffic is never forwarded (R36).
resource "aws_lb_listener" "http_redirect" {
  load_balancer_arn = aws_lb.this.arn
  port              = 80
  protocol          = "HTTP"

  default_action {
    type = "redirect"

    redirect {
      port        = "443"
      protocol    = "HTTPS"
      status_code = "HTTP_301"
    }
  }
}
