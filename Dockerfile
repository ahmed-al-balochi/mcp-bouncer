# mcp-bouncer container image (R35).
#
# What this image runs: the gate over HTTP, bound to 0.0.0.0 so the ALB can
# reach it, with the demo wiki server spawned as the upstream over stdio inside
# the same container -- exactly as the local demo does. There is deliberately no
# deployed-only code path: `bouncer-server --upstream demo/wiki_server.py
# --transport http` is the same command a developer runs locally, only with a
# non-loopback bind and the AWS-backed stores selected by environment (R35).
#
# Base image, pinned deliberately:
#   python:3.12-slim. 3.12 because that is the interpreter the code is written
#   and tested against (the runtime is pinned to 3.12 throughout the project);
#   -slim because it carries a real Debian userland (so boto3, cryptography and
#   their wheels resolve without musl surprises) while staying far smaller than
#   the full python image. A production build would additionally pin by digest
#   (python:3.12-slim@sha256:...) so the base cannot move under us; the tag is
#   left here so a reader without the digest can still build, and the owner can
#   substitute a digest when hardening.
FROM python:3.12-slim

# PYTHONDONTWRITEBYTECODE: never write .pyc files, so the root filesystem is not
#   modified at import time -- a prerequisite for running read-only (see below).
# PYTHONUNBUFFERED: flush stdout/stderr immediately so CloudWatch sees log lines
#   as they happen rather than when a buffer fills (R33).
# PIP_NO_CACHE_DIR: no wheel cache baked into a layer we will never reuse.
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1

WORKDIR /app

# --- dependency layer -----------------------------------------------------
# Copy ONLY the dependency manifest first, then install the third-party
# dependencies. Because this layer's inputs are just pyproject.toml, a change to
# application code below does not invalidate it, so fastmcp/boto3 are not
# reinstalled on every code edit. The `aws` extra is REQUIRED: without boto3 the
# DynamoDB store and the Secrets Manager token source raise at boot, so the
# deployed image must opt in explicitly (the extra is optional precisely so the
# local SQLite path stays slim).
#
# The dependency list is derived from pyproject.toml itself -- base dependencies
# plus the `aws` extra -- rather than duplicated here, so there is one source of
# truth for versions (R44). tomllib is in the 3.11+ standard library, so this
# needs nothing installed first.
COPY pyproject.toml ./
RUN python - <<'PY' > /tmp/requirements.txt
import tomllib
with open("pyproject.toml", "rb") as fh:
    project = tomllib.load(fh)["project"]
deps = list(project.get("dependencies", []))
deps += project.get("optional-dependencies", {}).get("aws", [])
print("\n".join(deps))
PY
RUN pip install --upgrade pip && pip install -r /tmp/requirements.txt

# --- application layer -----------------------------------------------------
# Now copy the source and install the package itself without re-resolving
# dependencies (they are already present from the layer above). A code change
# invalidates only from here down.
COPY gate/ ./gate/
COPY demo/ ./demo/
COPY policy.yaml ./policy.yaml
RUN pip install --no-deps .

# --- non-root user (R35) ---------------------------------------------------
# Run as an unprivileged user. Created after installs so the site-packages and
# /app are owned by root and NOT writable by the runtime user, which is what
# lets the container run with a read-only root filesystem.
RUN useradd --system --no-create-home --uid 10001 bouncer \
 && chown -R root:root /app
USER 10001

# The MCP endpoint listens here; the ALB target group forwards to it and probes
# GET /health (unauthenticated, see gate/server.py). Documentation only; ECS
# maps the port explicitly.
EXPOSE 8000

# The gate over HTTP, bound to 0.0.0.0, with the demo upstream over stdio. The
# upstream is spawned with sys.executable (fastmcp's PythonStdioTransport
# default), which is this image's interpreter, so no `python` shim on PATH is
# required. Store backend, identity source, table names, secret id and region
# arrive as environment variables from the ECS task definition; none is baked in
# here (R2, R19).
CMD ["bouncer-server", \
     "--upstream", "demo/wiki_server.py", \
     "--transport", "http", \
     "--host", "0.0.0.0", \
     "--port", "8000"]
