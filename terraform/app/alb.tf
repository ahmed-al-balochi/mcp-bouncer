# The internet-facing ALB. HTTPS with the looked-up ACM certificate, HTTP
# 301-redirecting to HTTPS. It fronts the LiteLLM gateway only, answering a
# single host and a few paths and 404ing the rest; the gate is not reachable.

resource "aws_lb" "this" {
  name               = var.project_name
  load_balancer_type = "application"
  internal           = false
  subnets            = [for s in aws_subnet.public : s.id]
  security_groups    = [aws_security_group.alb.id]

  # Reject requests with malformed headers rather than forwarding them. Cheap
  # hardening for a public listener.
  drop_invalid_header_fields = true

  # 300 s idle timeout: a non-streamed completion with several model and tool
  # rounds can exceed the 60 s default. Not measured; set pre-emptively.
  idle_timeout = 300

  # ALB access logs to S3: one line per request with source IP, path, status and
  # latency, which the per-minute CloudWatch counts cannot give and the gate's
  # audit log cannot either (it never sees what the ALB 404s or rejects).
  access_logs {
    bucket  = aws_s3_bucket.alb_logs.id
    prefix  = local.alb_log_prefix
    enabled = true
  }

  # The ALB validates the bucket policy by writing a test object when access
  # logs are enabled; without this the policy PutObject grant can be created
  # after the load balancer tries its write, failing the apply.
  depends_on = [aws_s3_bucket_policy.alb_logs]

  tags = { Name = "${var.project_name}-alb" }
}

# HTTPS listener with the certificate looked up (filtered to ISSUED) in main.tf.
# The -TLS13- policy negotiates 1.3 where supported, never below 1.2. The default
# action is a fixed 404, so anything but the one rule below gets nothing.
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

# The one rule that forwards traffic: only the gateway host, and only the
# OpenAI-compatible paths the agents use plus the single MCP tools/list path the
# demo agent's preflight needs. host_header and path_pattern must both match.
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
      # /mcp-rest/tools/list is opened for the demo agent's preflight. It is
      # matched exactly, never /mcp-rest/*, so the sibling /mcp-rest/tools/call
      # stays 404: tools/call would let a key holder invoke tools directly.
      values = ["/v1/chat/completions", "/v1/models", "/mcp-rest/tools/list"]
    }
  }

  action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.litellm.arn
  }
}

# HTTP listener that does nothing but 301 to HTTPS. No target, so plaintext
# traffic is never forwarded.
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
