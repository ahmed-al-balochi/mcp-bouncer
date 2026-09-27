# ECS Fargate: one cluster, and the GATE task definition + service (R35). The
# gate runs over HTTP with the demo upstream spawned over stdio -- the same
# command the local demo runs, no deployed-only code path. The LiteLLM gateway
# task/service live in gateway.tf.
#
# The gate is now INTERNAL-ONLY (R52): it is reached only by the LiteLLM gateway
# over ECS Service Connect, never from the ALB. It is registered as a Service
# Connect SERVER (the gateway is the client).
#
# Task size is set by the owner at 0.5 vCPU / 1 GB (D6.9): cpu 512, memory 1024.
# Raised from 0.25/512 (D4.3) because the Service Connect sidecar wants +256 CPU
# and >=64 MiB per task, and Fargate requires >=1024 MB once CPU is 512.

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
    # Written out because AWS stores it; omitting it made every plan replace the
    # task definition (DECISIONS D4.14).
    configure_at_launch = false
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
          # awsvpc requires hostPort == containerPort; AWS fills it in if
          # omitted, which Terraform then sees as drift (D4.14).
          hostPort = local.container_port
          protocol = "tcp"
          # Named for ECS Service Connect (D6.8): the service's server config
          # references this port by name. appProtocol http so the sidecar speaks
          # HTTP to the gate (enabling per-request timeouts and HTTP metrics).
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

      # Container health check via Python (D6.10). The gate is no longer behind
      # the ALB (R52), so the ALB target-group probe that used to replace a
      # wedged task is gone; without a container check a hung gate would never be
      # replaced. The image is python:3.12-slim (root Dockerfile FROM), which has
      # `python` on PATH but neither curl nor wget, so the check is a one-line
      # urllib GET of the unauthenticated /health route that exits non-zero
      # unless it returns HTTP 200.
      #
      # startPeriod is 90 s: the stdio upstream warm-up measured ~18 s at 0.25
      # vCPU (D5.10) and the gate turns healthy only after it; 90 s leaves ample
      # margin at 0.5 vCPU so a slow cold start is not counted as a failure.
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
        # FORWARDED_ALLOW_IPS is deliberately removed. It existed so uvicorn
        # would trust the ALB's X-Forwarded-Proto and not downgrade a `/mcp/`
        # redirect to http:// (D4.16). The gate is no longer behind the ALB
        # (R52): only the LiteLLM gateway reaches it, in-cluster over Service
        # Connect, addressed as http://gate:8000/mcp with no trailing slash and
        # no TLS-terminating proxy in front, so there is no X-Forwarded-Proto to
        # trust and no scheme-downgrade redirect to guard against. The Python
        # regression test in tests/test_health.py sets this variable itself and
        # pins uvicorn's behaviour at the app level; it does not read the
        # Terraform value, so it is unaffected by this removal.
        # No BOUNCER_POLICY: the image's WORKDIR is /app and policy.yaml is at
        # /app/policy.yaml, so the registry's default path (cwd/policy.yaml)
        # already resolves it (verified in gate/registry.py default_policy_path).
      ]

      # Empty lists AWS adds on storage; declared so the plan shows no drift
      # (D4.14).
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
  # internal-only now (R52), reached over Service Connect, not through the ALB.
  # ECS rejects healthCheckGracePeriodSeconds unless the service has a load
  # balancer, so it must go with the load_balancer block; the container-level
  # healthCheck (with its 90 s startPeriod) covers the boot warm-up instead.
  #
  # Register the gate as a Service Connect SERVER so the LiteLLM gateway can
  # reach it as `gate` (D6.8, D6.10). The server advertises the named port
  # "gate" under the DNS alias `gate` on port 8000. Timeouts are set explicitly
  # (perRequest 120 s, idle 300 s) so a slow model/tool round or an SSE stream is
  # not cut at the 15 s default (D6.8/D6.10). The Envoy sidecar logs to its own
  # log group.
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
