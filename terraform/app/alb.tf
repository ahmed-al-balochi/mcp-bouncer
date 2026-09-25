# The internet-facing ALB (R36). HTTPS with the looked-up ACM certificate, HTTP
# 301-redirecting to HTTPS, and a target group that health-checks /health over
# HTTP on the container port. The ALB is the only public entry point; the tasks
# behind it have no public IP and no internet egress.

resource "aws_lb" "this" {
  name               = var.project_name
  load_balancer_type = "application"
  internal           = false
  subnets            = [for s in aws_subnet.public : s.id]
  security_groups    = [aws_security_group.alb.id]

  # Reject requests with malformed headers rather than forwarding them to the
  # gate. Cheap hardening for a public listener.
  drop_invalid_header_fields = true

  tags = { Name = "${var.project_name}-alb" }
}

resource "aws_lb_target_group" "this" {
  name        = var.project_name
  target_type = "ip" # Fargate awsvpc tasks register by IP, not instance.
  port        = local.container_port
  protocol    = "HTTP"
  vpc_id      = aws_vpc.this.id

  # Probe the unauthenticated /health route (R31, NOTES): GET, expect 200. MCP
  # traffic is on /mcp/, never health-checked.
  health_check {
    path                = "/health"
    protocol            = "HTTP"
    matcher             = "200"
    healthy_threshold   = 2
    unhealthy_threshold = 3
    timeout             = 5
    interval            = 15
  }

  # Short drain: the gate holds no long-lived server state worth waiting on, and
  # a fast deregister keeps deploys and destroys quick (R41).
  deregistration_delay = 10

  tags = { Name = "${var.project_name}-tg" }
}

# HTTPS listener with the certificate looked up (filtered to ISSUED) in main.tf.
# A TLS 1.3-capable policy: the -TLS13- policy negotiates 1.3 where the client
# supports it and falls back to 1.2, never below.
resource "aws_lb_listener" "https" {
  load_balancer_arn = aws_lb.this.arn
  port              = 443
  protocol          = "HTTPS"
  ssl_policy        = "ELBSecurityPolicy-TLS13-1-2-2021-06"
  certificate_arn   = data.aws_acm_certificate.this.arn

  default_action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.this.arn
  }
}

# HTTP listener that does nothing but 301 to HTTPS. No target, so plaintext MCP
# traffic is never forwarded to the gate (R36).
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
