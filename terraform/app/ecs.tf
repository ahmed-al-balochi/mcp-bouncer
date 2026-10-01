# ECS Fargate: one cluster, and the gate task definition and service. The gate is
# internal-only, reached only by the LiteLLM gateway over Service Connect (it is
# the server), never from the ALB. Task size is 0.5 vCPU / 1 GB to fit the sidecar.

resource "aws_ecs_cluster" "this" {
  name = var.project_name

  tags = { Name = "${var.project_name}-cluster" }
}

resource "aws_ecs_task_definition" "this" {
  family                   = var.project_name
  requires_compatibilities = ["FARGATE"]
  network_mode             = "awsvpc"
  cpu                      = "512"
  memory                   = "1024"
  execution_role_arn       = aws_iam_role.execution.arn
  task_role_arn            = aws_iam_role.task.arn

  runtime_platform {
    operating_system_family = "LINUX"
    cpu_architecture        = var.cpu_architecture
  }

  # Task-level ephemeral volume mounted at /tmp. The image runs with a read-only
  # root but needs a writable /tmp, and Fargate does not support tmpfs, so a
  # task-level volume is the only way; uid 10001 write access is confirmed at boot.
  volume {
    name = "tmp"
    # Written out because AWS stores it; omitting it made every plan replace the
    # task definition.
    configure_at_launch = false
  }

  container_definitions = jsonencode([
    {
      name      = var.project_name
      image     = local.container_image
      essential = true

      # Keep the image's own CMD: it already runs bouncer-server over http on
      # port 8000 (verified in Dockerfile), exactly what the deploy needs, so no
      # command override. --transport http means the bearer-token model is in force.

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
          containerPort = local.container_port
          # awsvpc requires hostPort == containerPort; AWS fills it in if
          # omitted, which Terraform then sees as drift.
          hostPort = local.container_port
          protocol = "tcp"
          # Named for ECS Service Connect: the service's server config references
          # this port by name. appProtocol http so the sidecar speaks HTTP to the
          # gate, enabling per-request timeouts and HTTP metrics.
          name        = "gate"
          appProtocol = "http"
        }
      ]

      linuxParameters = {
        # The gate spawns the demo upstream over stdio as a child process;
        # initProcessEnabled runs a tiny init (PID 1) that reaps the child so a
        # restarted upstream does not leave a zombie.
        initProcessEnabled = true
        # Drop all Linux capabilities: the process binds a high port and needs
        # none of them. Fargate accepts dropping ALL (it rejects ADDs of most
        # capabilities, but a drop is always honoured).
        capabilities = {
          add  = []
          drop = ["ALL"]
        }
      }

      # Container health check via Python, since the gate is no longer behind the
      # ALB: a one-line urllib GET of /health (the image has no curl or wget) that
      # exits non-zero unless HTTP 200. startPeriod 90 s covers the stdio warm-up.
      healthCheck = {
        command = [
          "CMD",
          "python",
          "-c",
          "import sys,urllib.request; sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:8000/health', timeout=3).status==200 else 1)",
        ]
        interval    = 30
        timeout     = 5
        retries     = 3
        startPeriod = 90
      }

      environment = [
        # Identity source MUST be secretsmanager: the default is "local", and
        # leaving it unset while setting the secret variable means the secret is
        # never consulted (NOTES).
        { name = "BOUNCER_IDENTITY", value = "secretsmanager" },
        # The secret's ARN; the app resolves it at boot via get_secret_value.
        # Passed as a plain env var (not an ECS `secrets` block) because the app
        # reads BOUNCER_TOKENS_SECRET itself; the ARN is an identifier, not a secret.
        { name = "BOUNCER_TOKENS_SECRET", value = aws_secretsmanager_secret.tokens.arn },
        { name = "BOUNCER_STORE", value = "dynamodb" },
        { name = "BOUNCER_DYNAMODB_TABLE", value = aws_dynamodb_table.approvals.name },
        { name = "BOUNCER_DYNAMODB_AUDIT_TABLE", value = aws_dynamodb_table.audit.name },
        # Both region variables: boto3 falls through to the default resolution
        # chain and Fargate does not populate AWS_REGION, so omitting these
        # yields a NoRegionError at boot (NOTES).
        { name = "AWS_REGION", value = var.aws_region },
        { name = "AWS_DEFAULT_REGION", value = var.aws_region },
        { name = "BOUNCER_LOG_LEVEL", value = "INFO" },
        # FORWARDED_ALLOW_IPS is deliberately removed: it let uvicorn trust the
        # ALB's X-Forwarded-Proto, but the gate is no longer behind the ALB, so
        # there is no proxy header to trust and no scheme downgrade to guard.

        # No BOUNCER_POLICY: WORKDIR is /app and policy.yaml is at /app/policy.yaml,
        # which the registry's default path already resolves.
      ]

      # Empty lists AWS adds on storage; declared so the plan shows no drift.
      systemControls = []
      volumesFrom    = []

      logConfiguration = {
        logDriver = "awslogs"
        options = {
          "awslogs-group"         = aws_cloudwatch_log_group.task.name
          "awslogs-region"        = var.aws_region
          "awslogs-stream-prefix" = "gate"
        }
      }
    }
  ])

  tags = { Name = "${var.project_name}-task" }
}

resource "aws_ecs_service" "this" {
  name            = var.project_name
  cluster         = aws_ecs_cluster.this.id
  task_definition = aws_ecs_task_definition.this.arn
  desired_count   = 1
  launch_type     = "FARGATE"

  # >= 1.4 is required for the VPC-endpoint-only model (the 1.4 platform pulls
  # image layers over the S3 gateway endpoint rather than needing internet).
  # LATEST tracks the newest, which is >= 1.4.
  platform_version = "LATEST"

  network_configuration {
    subnets          = [for s in aws_subnet.private : s.id]
    security_groups  = [aws_security_group.task.id]
    assign_public_ip = false
  }

  # No load_balancer block and no health_check_grace_period_seconds: the gate is
  # internal-only, reached over Service Connect. ECS rejects the grace period
  # without a load balancer; the container healthCheck covers the boot warm-up.

  # Register the gate as a Service Connect server so the gateway can reach it as
  # `gate` on port 8000. Timeouts are explicit (perRequest 120 s, idle 300 s) so
  # a slow model/tool round or SSE stream is not cut at the 15 s default.
  service_connect_configuration {
    enabled   = true
    namespace = aws_service_discovery_http_namespace.this.arn

    service {
      port_name = "gate"

      client_alias {
        dns_name = "gate"
        port     = local.container_port
      }

      timeout {
        per_request_timeout_seconds = 120
        idle_timeout_seconds        = 300
      }
    }

    log_configuration {
      log_driver = "awslogs"
      options = {
        "awslogs-group"         = aws_cloudwatch_log_group.serviceconnect.name
        "awslogs-region"        = var.aws_region
        "awslogs-stream-prefix" = "gate-connect"
      }
    }
  }

  # Roll back automatically if a new task definition fails to become healthy,
  # rather than leaving a wedged deployment.
  deployment_circuit_breaker {
    enable   = true
    rollback = true
  }

  # ECS Exec is off: it would require ssmmessages VPC endpoints this no-internet
  # network does not provision. Add those endpoints first if debugging is needed.
  enable_execute_command = false

  # The service depends on the endpoints, routes and the secret version existing,
  # or the first task cannot pull its image, reach DynamoDB, or find its token
  # map; some of these are not referenced by the service, so order them here.
  depends_on = [
    aws_secretsmanager_secret_version.tokens,
    aws_vpc_endpoint.s3,
    aws_vpc_endpoint.dynamodb,
    aws_vpc_endpoint.ecr_api,
    aws_vpc_endpoint.ecr_dkr,
    aws_vpc_endpoint.logs,
    aws_vpc_endpoint.secretsmanager,
  ]

  tags = { Name = "${var.project_name}-service" }
}
