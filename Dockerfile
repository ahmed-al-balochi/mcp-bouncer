# The gate over HTTP, with the demo wiki spawned over stdio in the same
# container -- exactly as the local demo does, so there is no deployed-only path.
# python:3.12-slim is what the tests run on; a hardened build would pin a digest.
FROM python:3.12-slim

# PYTHONDONTWRITEBYTECODE: never write .pyc files -- a prerequisite for running
#   read-only. PYTHONUNBUFFERED: flush stdout/stderr immediately. PIP_NO_CACHE_DIR:
#   no wheel cache. FASTMCP_* : suppress banner and rich logging to keep JSON logs.
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    FASTMCP_SHOW_SERVER_BANNER=false \
    FASTMCP_ENABLE_RICH_LOGGING=false

WORKDIR /app

# Dependencies first, so a code change does not reinstall them. The list comes
# from pyproject.toml (base deps plus the `aws` extra, which the DynamoDB store
# and Secrets Manager token source need at boot).
COPY pyproject.toml ./
RUN python - <<'PY' > /tmp/requirements.txt
import tomllib
with open("pyproject.toml", "rb") as fh:
    project = tomllib.load(fh)["project"]
deps = list(project.get("dependencies", []))
deps += project.get("optional-dependencies", {}).get("aws", [])
print("\n".join(deps))
PY
# `--retries`/`--timeout` are deliberately short. pip's defaults retry five times
# with a long timeout, so a build with broken container DNS -- common behind a
# proxy -- stalls for minutes. Failing in seconds with a readable error is better.
RUN pip install --retries 1 --timeout 15 --upgrade pip \
 && pip install --retries 1 --timeout 15 -r /tmp/requirements.txt

# --- application layer -----------------------------------------------------
# Copy the source and install the package without re-resolving dependencies
# (already present above). A code change invalidates only from here down.
COPY gate/ ./gate/
COPY demo/ ./demo/
COPY policy.yaml ./policy.yaml
RUN pip install --retries 1 --timeout 15 --no-deps .

# Unprivileged runtime user, created after the installs so /app and
# site-packages stay root-owned and the root filesystem can be read-only.
RUN useradd --system --no-create-home --uid 10001 bouncer \
 && chown -R root:root /app
USER 10001

# The MCP endpoint. LiteLLM reaches it over Service Connect, and ECS health-checks
# GET /health (unauthenticated). Documentation only; ECS maps the port itself.
EXPOSE 8000

# The gate over HTTP, bound to 0.0.0.0, with the demo upstream over stdio. The
# upstream is spawned with sys.executable, this image's interpreter. Store
# backend, table names, secret id and region arrive as env vars; none baked in.
CMD ["bouncer-server", \
     "--upstream", "demo/wiki_server.py", \
     "--transport", "http", \
     "--host", "0.0.0.0", \
     "--port", "8000"]
