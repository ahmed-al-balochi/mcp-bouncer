# ECS Fargate: one cluster, one task definition, one container, one service
# (R35). The container runs the gate over HTTP with the demo upstream spawned
# over stdio -- the same command the local demo runs, no deployed-only code path.
#
# Task size is fixed by the owner at the smallest Fargate size, 0.25 vCPU / 512
# MB (D4.3): cpu 256, memory 512.

resource "aws_ecs_cluster" "this" {
  name = var.project_name

  tags = { Name = "${var.project_name}-cluster" }
}

resource "aws_ecs_task_definition" "this" {
  family                   = var.project_name
  requires_compatibilities = ["FARGATE"]
  network_mode             = "awsvpc"
  cpu                      = "256"
  memory                   = "512"
  execution_role_arn       = aws_iam_role.execution.arn
  task_role_arn            = aws_iam_role.task.arn

  runtime_platform {
    operating_system_family = "LINUX"
    cpu_architecture        = var.cpu_architecture
  }

  # Task-level ephemeral volume mounted at /tmp. The image runs with
  # readonlyRootFilesystem = true, but the process needs a writable /tmp (Python
  # may write there, and BOUNCER_DB would land there if SQLite were ever used).
  # Fargate does NOT support linuxParameters.tmpfs, so a task-level volume is the
  # only way to get a writable path under a read-only root.
  #
  # UNVERIFIED: whether this volume is writable by uid 10001 specifically. A
  # Fargate ephemeral volume's ownership at mount time is not something this
  # file can prove; confirm at first boot in phase 5. If it mounts root-owned
  # and unwritable for 10001, the fix is a small entrypoint chown or an fsGroup
  # equivalent -- deferred, not solved here.
  volume {
    name = "tmp"
  }

  container_definitions = jsonencode([
    {
      name      = var.project_name
      image     = local.container_image
      essential = true

      # Keep the image's own CMD: it already runs `bouncer-server --upstream
      # demo/wiki_server.py --transport http --host 0.0.0.0 --port 8000`
      # (verified in Dockerfile), which is exactly what the deploy needs, so no
      # command override. --transport http is present, so the bearer-token model
      # is in force.

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
          protocol      = "tcp"
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
          drop = ["ALL"]
        }
      }

      # NO healthCheck: python:3.12-slim has neither curl nor wget, so a
      # container-level check that shelled out would always fail. The ALB target
      # group probes /health instead (NOTES, D3.1).

      environment = [
        # Identity source MUST be secretsmanager: the default is "local", and
        # leaving it unset while setting the secret variable means the secret is
        # never consulted (NOTES).
        { name = "BOUNCER_IDENTITY", value = "secretsmanager" },
        # The secret's ARN; the app resolves it at boot via get_secret_value.
        # Passed as a plain env var (not an ECS `secrets` block) because the app
        # itself reads BOUNCER_TOKENS_SECRET and calls Secrets Manager -- the ARN
        # is an identifier, not a credential.
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
        # No BOUNCER_POLICY: the image's WORKDIR is /app and policy.yaml is at
        # /app/policy.yaml, so the registry's default path (cwd/policy.yaml)
        # already resolves it (verified in gate/registry.py default_policy_path).
      ]

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

  load_balancer {
    target_group_arn = aws_lb_target_group.this.arn
    container_name   = var.project_name
    container_port   = local.container_port
  }

  # Give the task time to boot (resolve the secret, reach DynamoDB, start
  # uvicorn) before the ALB starts failing it. The boot does real network I/O to
  # the endpoints, so a too-short grace would kill a task that is merely still
  # starting.
  health_check_grace_period_seconds = 120

  # Roll back automatically if a new task definition fails to become healthy,
  # rather than leaving a wedged deployment.
  deployment_circuit_breaker {
    enable   = true
    rollback = true
  }

  # ECS Exec is off: it would require ssmmessages VPC endpoints, which this
  # no-internet network deliberately does not provision. Turning it on without
  # those endpoints would just fail; if interactive debugging is ever needed,
  # add the ssmmessages endpoints first.
  enable_execute_command = false

  # The service depends on the endpoints and routes existing, or the first task
  # cannot pull its image or reach DynamoDB. Terraform infers most of this from
  # references, but the gateway route associations are not referenced by the
  # service, so make the ordering explicit.
  #
  # The secret VERSION too: the task definition references only the secret's
  # ARN, which exists before any value is written. A task that booted in that
  # gap would find no token map and refuse to boot -- and on a first deployment
  # the circuit breaker can mark that as a failed rollout rather than retrying.
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
