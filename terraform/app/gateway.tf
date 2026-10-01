# The LiteLLM gateway: the only public path to models and to the gate, and the
# ECS Service Connect namespace both services share. The gate service (in ecs.tf)
# is the Service Connect server; this service is the client.

# --- Service Connect namespace ---------------------------------------------

# An HTTP namespace (Cloud Map) that Service Connect uses to wire the client
# (LiteLLM) to the server (gate). Service Connect resolves the `gate` alias in
# the mesh, so no Route53 private zone is needed.
resource "aws_service_discovery_http_namespace" "this" {
  name        = var.project_name
  description = "Service Connect namespace for ${var.project_name} (gate <- LiteLLM gateway)."

  tags = { Name = "${var.project_name}-namespace" }
}

# --- LiteLLM target group --------------------------------------------------

# The ALB forwards the two allowed paths to this group (alb.tf). Health check is
# LiteLLM's unauthenticated /health/liveliness route, which returns 200 when the
# worker is up; it is authless and reveals nothing, so it is safe as an ALB probe.
resource "aws_lb_target_group" "litellm" {
  name        = "${var.project_name}-litellm"
  target_type = "ip" # Fargate awsvpc tasks register by IP.
  port        = local.litellm_port
  protocol    = "HTTP"
  vpc_id      = aws_vpc.this.id

  health_check {
    path                = "/health/liveliness"
    protocol            = "HTTP"
    matcher             = "200"
    healthy_threshold   = 2
    unhealthy_threshold = 3
    timeout             = 5
    interval            = 15
  }

  deregistration_delay = 10

  tags = { Name = "${var.project_name}-litellm-tg" }
}

# --- LiteLLM task definition -----------------------------------------------

# 1024 CPU / 2048 MB: idle RSS measured ~365 MB and the Service Connect sidecar
# wants headroom. Same hardening as the gate: read-only root with a task-level
# /tmp volume, capabilities drop ALL, initProcessEnabled, no ECS Exec.
resource "aws_ecs_task_definition" "litellm" {
  family                   = "${var.project_name}-litellm"
  requires_compatibilities = ["FARGATE"]
  network_mode             = "awsvpc"
  cpu                      = "1024"
  memory                   = "2048"
  execution_role_arn       = aws_iam_role.litellm_execution.arn
  task_role_arn            = aws_iam_role.litellm_task.arn

  runtime_platform {
    operating_system_family = "LINUX"
    cpu_architecture        = var.cpu_architecture
  }

  # Writable /tmp under a read-only root, same rationale as the gate: Fargate
  # rejects tmpfs, so a task-level ephemeral volume is the supported route.
  # configure_at_launch is written out to avoid a drift replace.
  volume {
    name                = "tmp"
    configure_at_launch = false
  }

  container_definitions = jsonencode([
    {
      name      = "litellm"
      image     = local.litellm_image
      essential = true

      # No command override: the image's CMD already runs the proxy with
      # /etc/litellm/config.yaml on port 4000 (gateway/Dockerfile).

      # Container user: the base image runs as root, so gateway/Dockerfile sets
      # USER 10001:10001 and HOME=/tmp. Pinned here too, so a rebuilt image that
      # drops the USER line still cannot run as root (same uid as the gate).
      user = "10001"

      readonlyRootFilesystem = true

      mountPoints = [
        {
          sourceVolume  = "tmp"
          containerPath = "/tmp"
          readOnly      = false
        }
      ]

      portMappings = [
        {
          containerPort = local.litellm_port
          hostPort      = local.litellm_port
          protocol      = "tcp"
          # Named for Service Connect even though this service is a client only;
          # naming the port is harmless and keeps the mapping explicit.
          name        = "litellm"
          appProtocol = "http"
        }
      ]

      linuxParameters = {
        initProcessEnabled = true
        capabilities = {
          add  = []
          drop = ["ALL"]
        }
      }

      environment = [
        # Region for boto3/Bedrock, both variables: Fargate does not populate
        # AWS_REGION and boto3 falls through to the default chain, so both are
        # set (NOTES, same reasoning as the gate).
        { name = "AWS_REGION", value = var.aws_region },
        { name = "AWS_DEFAULT_REGION", value = var.aws_region },
        # Use LiteLLM's bundled cost map instead of fetching it over the
        # internet at boot (the VPC has no internet path). The local map is used
        # when this env var is "true", skipping the HTTP GET.
        { name = "LITELLM_LOCAL_MODEL_COST_MAP", value = "True" },
        # JSON logs to stdout. The config also sets litellm_settings.json_logs;
        # this env var is the same switch at import time.
        { name = "JSON_LOGS", value = "True" },
        # Disable the admin UI: the shared master key is the admin key, so the UI
        # is attack surface with no benefit here.
        { name = "DISABLE_ADMIN_UI", value = "True" },
        # Log level INFO, read by LiteLLM's logging setup.
        { name = "LITELLM_LOG", value = "INFO" },
        # Telemetry (phone-home) is disabled in the config, and there is no env
        # var for it in this LiteLLM version, so it is not set here. In the
        # no-internet VPC a telemetry call would fail anyway.
      ]

      # The master key is a credential, so it comes through the ECS `secrets`
      # block, not an environment literal. LiteLLM reads it from
      # os.environ/LITELLM_MASTER_KEY, so the env var name must be exactly this.
      secrets = [
        {
          name      = "LITELLM_MASTER_KEY"
          valueFrom = aws_secretsmanager_secret.litellm_master_key.arn
        }
      ]

      # Empty lists AWS adds, declared to avoid a drift-replace.
      systemControls = []
      volumesFrom    = []

      logConfiguration = {
        logDriver = "awslogs"
        options = {
          "awslogs-group"         = aws_cloudwatch_log_group.litellm.name
          "awslogs-region"        = var.aws_region
          "awslogs-stream-prefix" = "litellm"
        }
      }
    }
  ])

  tags = { Name = "${var.project_name}-litellm-task" }
}

# --- LiteLLM service -------------------------------------------------------
resource "aws_ecs_service" "litellm" {
  name            = "${var.project_name}-litellm"
  cluster         = aws_ecs_cluster.this.id
  task_definition = aws_ecs_task_definition.litellm.arn
  desired_count   = 1
  launch_type     = "FARGATE"

  platform_version = "LATEST"

  network_configuration {
    subnets          = [for s in aws_subnet.private : s.id]
    security_groups  = [aws_security_group.litellm.id]
    assign_public_ip = false
  }

  load_balancer {
    target_group_arn = aws_lb_target_group.litellm.arn
    container_name   = "litellm"
    container_port   = local.litellm_port
  }

  # Give the gateway time to pull its image, read the master key and warm up
  # before the ALB starts failing it.
  health_check_grace_period_seconds = 120

  deployment_circuit_breaker {
    enable   = true
    rollback = true
  }

  enable_execute_command = false

  # Service Connect client only: the gateway consumes the `gate` server in the
  # namespace; it exposes no Service Connect service of its own (the ALB reaches
  # it directly on 4000).
  service_connect_configuration {
    enabled   = true
    namespace = aws_service_discovery_http_namespace.this.arn

    log_configuration {
      log_driver = "awslogs"
      options = {
        "awslogs-group"         = aws_cloudwatch_log_group.serviceconnect.name
        "awslogs-region"        = var.aws_region
        "awslogs-stream-prefix" = "litellm-connect"
      }
    }
  }

  # Depends on the endpoints and the master-key secret value, not just the ARN,
  # or a task would boot with no master key. Also the listener rule, since ECS
  # refuses a service whose target group is not yet attached to a load balancer.
  depends_on = [
    aws_lb_listener_rule.gateway,
    aws_secretsmanager_secret_version.litellm_master_key,
    aws_vpc_endpoint.s3,
    aws_vpc_endpoint.ecr_api,
    aws_vpc_endpoint.ecr_dkr,
    aws_vpc_endpoint.logs,
    aws_vpc_endpoint.secretsmanager,
    aws_vpc_endpoint.bedrock_runtime,
  ]

  tags = { Name = "${var.project_name}-litellm-service" }
}
