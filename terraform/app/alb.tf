# The internet-facing ALB (R36). HTTPS with the looked-up ACM certificate, HTTP
# 301-redirecting to HTTPS. The ALB is the only public entry point and it now
# fronts the LiteLLM gateway ONLY (R51): the HTTPS listener answers a single host
# and a small, explicit set of paths and returns 404 for everything else (D6.10,
# D6.22). The gate is not reachable through the ALB at all (R52) -- there is no
# gate target group and no rule that forwards to the gate.

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

  # ALB access logs to S3 (D7.2, owner's choice for platform visibility). The
  # ALB's automatic CloudWatch metrics are per-minute COUNTS (RequestCount,
  # HTTPCode_ELB_4XX_Count) -- they say THAT something happened; access logs are
  # one line per request with source IP, path, status and latency -- they say WHO
  # and WHAT. Only the log can reconstruct an incident, and the gate's own audit
  # log cannot substitute: it records tool DECISIONS, and only for calls that
  # reached the gate through LiteLLM, so everything the ALB 404s or rejects is
  # invisible to it. The bucket and its policy live in access_logs.tf; the
  # dependency on the policy is explicit there so the ALB's own write-test at
  # enable time cannot race the policy attachment.
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

# The one rule that forwards traffic: only the gateway host, and only the
# OpenAI-compatible paths the agents use plus the single MCP tools/list path the
# demo agent's preflight needs (D6.10, D6.22). Everything else falls through to
# the listener's 404 default. host_header AND path_pattern must both match.
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
      # Extend the SAME rule (not a second rule) with the one extra path: an ALB
      # path_pattern ORs its values and this rule already carries the exact host
      # condition, so adding one value is the smaller diff and keeps a single
      # priority to reason about. Consequence: all three paths share priority 100
      # and forward to the same LiteLLM target group -- which is what we want,
      # there is no per-path differentiation to model.
      #
      # /mcp-rest/tools/list is opened for the demo agent's preflight (D6.22):
      # it checks the gateway actually offers the bouncer tools before asking the
      # model, so a silently-dropped tool set is caught up front (D6.21).
      #
      # It is matched EXACTLY, never /mcp-rest/* : ALB path_pattern is an
      # exact/wildcard literal, so the sibling /mcp-rest/tools/call and the rest
      # of the /mcp-rest prefix stay on the 404 default. tools/call must stay
      # closed because it would let any holder of the gateway key invoke tools
      # directly, bypassing the model-in-the-loop path entirely.
      values = ["/v1/chat/completions", "/v1/models", "/mcp-rest/tools/list"]
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
