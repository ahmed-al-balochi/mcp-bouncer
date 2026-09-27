# The LiteLLM gateway: the only public path to models and to the gate (R51), and
# the ECS Service Connect namespace both services share. The gate service (in
# ecs.tf) is a Service Connect SERVER; this service is a Service Connect CLIENT.

# --- Service Connect namespace (D6.8) --------------------------------------
#
# An HTTP namespace (Cloud Map) that Service Connect uses to wire the client
# (LiteLLM) to the server (gate). Not a DNS namespace: Service Connect resolves
# the `gate` alias inside the mesh, so no Route53 private zone is needed.
resource "aws_service_discovery_http_namespace" "this" {
  name        = var.project_name
  description = "Service Connect namespace for ${var.project_name} (gate <- LiteLLM gateway)."

  tags = { Name = "${var.project_name}-namespace" }
}

# --- LiteLLM target group --------------------------------------------------
#
# The ALB forwards the two allowed paths to this group (alb.tf). Health check is
# LiteLLM's unauthenticated /health/liveliness route, which returns 200 with
# "I'm alive!" when the worker is up (verified in litellm 1.103.0:
# proxy/health_endpoints/_health_endpoints.py:1954 returns "I'm alive!"; the
# route is in the public/no-auth set, proxy/_types.py:766). It is authless and
# reveals nothing, so it is safe as an ALB probe.
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

# --- LiteLLM task definition (R51, R55, R56, R57, D6.9, D6.10) --------------
#
# 1024 CPU / 2048 MB (D6.9): the spike measured ~365 MB RSS idle (D6.5), and the
# Service Connect sidecar wants headroom. readonlyRootFilesystem with a
# task-level /tmp volume, capabilities drop ALL, initProcessEnabled, no ECS Exec
# -- the same hardening as the gate (D4.11).
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

  # Writable /tmp under a read-only root, same rationale as the gate (D4.11):
  # Fargate rejects linuxParameters.tmpfs, so a task-level ephemeral volume is
  # the supported route. UNVERIFIED whether LiteLLM writes at boot and whether
  # the volume is writable by the base image's user; confirmed only at first
  # boot (G3). configure_at_launch written out to avoid the D4.14 drift replace.
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

      # Container user: the base image runs as ROOT (docker inspect, v1.103.0),
      # so gateway/Dockerfile sets USER 10001:10001 and HOME=/tmp. Pinned here
      # too, so a rebuilt image that drops the USER line still cannot run as
      # root (same uid as the gate, D6.12).
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
        # internet at boot (the VPC has no internet path, R57). Verified in
        # litellm 1.103.0: get_model_cost_map.py:365 and :626 return the local
        # map when os.getenv("LITELLM_LOCAL_MODEL_COST_MAP").lower()=="true",
        # skipping the HTTP GET. Proven in the spike (D6.5).
        { name = "LITELLM_LOCAL_MODEL_COST_MAP", value = "True" },
        # JSON logs to stdout. The config also sets litellm_settings.json_logs;
        # this env var is the same switch at import time. Verified in litellm
        # 1.103.0: _logging.py:500 json_logs = _parse_json_logs_env(os.getenv(
        # "JSON_LOGS")) (only "true", any case, enables it).
        { name = "JSON_LOGS", value = "True" },
        # Disable the admin UI (D6.10): the shared master key is the admin key,
        # so the UI is attack surface with no benefit here. Read in
        # litellm/proxy/discovery_endpoints/ui_discovery_endpoints.py:26
        # (DISABLE_ADMIN_UI) and proxy/management_endpoints/ui_sso.py:1026.
        { name = "DISABLE_ADMIN_UI", value = "True" },
        # Log level INFO. Read by LiteLLM's logging setup
        # (litellm/_logging.py:502: log_level = os.getenv("LITELLM_LOG", "DEBUG")).
        { name = "LITELLM_LOG", value = "INFO" },
        # Telemetry (phone-home) is disabled in the config via
        # litellm_settings.telemetry:false (gateway/litellm.yaml). There is NO
        # environment variable for it in litellm 1.103.0 -- verified: no getenv
        # for any *TELEMETRY* switch -- so it is not set here (env vars are not
        # invented). In the no-internet VPC a telemetry call would fail anyway.
      ]

      # The master key is a credential, so it comes through the ECS `secrets`
      # block (resolved by the execution role from Secrets Manager), NOT an
      # environment literal. LiteLLM reads general_settings.master_key =
      # os.environ/LITELLM_MASTER_KEY, so the env var name must be exactly this.
      secrets = [
        {
          name      = "LITELLM_MASTER_KEY"
          valueFrom = aws_secretsmanager_secret.litellm_master_key.arn
        }
      ]

      # Empty lists AWS adds, declared to avoid the D4.14 drift-replace.
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

# --- LiteLLM service (R51, R57) --------------------------------------------
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

  # Service Connect CLIENT only (D6.10): the gateway consumes the `gate` server
  # in the namespace; it exposes no Service Connect service of its own (the ALB
  # reaches it directly on 4000).
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

  # Depends on the endpoints (image pull, master key, Bedrock) and the master-key
  # secret VALUE, not just the secret ARN (D4.10): a task booting before the
  # value is written would have no master key.
  #
  # And the listener RULE: ECS refuses to create a service whose target group
  # is not yet attached to a load balancer, and nothing else orders the rule
  # before the service (the service references only the target group). On the
  # first G1 apply the service was created in parallel with a rule that never
  # ran, and CreateService failed; the provider's retry then reported "not
  # idempotent" and no service existed (D6.15). Hypothesis consistent with the
  # evidence, not confirmed from the original error text.
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
