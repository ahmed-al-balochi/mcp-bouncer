# Thin LiteLLM gateway image for mcp-bouncer (R51, D6.10).
#
# This image is the mirrored official LiteLLM image plus one file: the committed
# litellm.yaml. Nothing environment-specific is baked in -- the master key and
# region arrive at runtime from the environment (R2, R3), and the gate is
# addressed by its Service Connect name in the config. The build context is this
# `gateway/` directory, NOT the repository root, so only litellm.yaml is in
# scope to COPY.
#
# The LiteLLM version is chosen at BUILD time, not hardcoded here (D6.10):
# LITELLM_BASE_IMAGE is an ARG with NO default, so a build must pass
# --build-arg LITELLM_BASE_IMAGE=<mirrored image ref>. That forces the builder
# to pin the exact image (ideally by digest) rather than inheriting a floating
# `latest` from this file. Spiked against LiteLLM 1.103.0 (D6.5).
ARG LITELLM_BASE_IMAGE
FROM ${LITELLM_BASE_IMAGE}

# The config lives at a fixed path and is passed explicitly on the command line
# below, so the image does not depend on LiteLLM's config-discovery defaults.
COPY litellm.yaml /etc/litellm/config.yaml

# Serve on 4000 (LiteLLM's conventional port; the task definition and target
# group key off this). Documentation only; ECS maps the port explicitly.
EXPOSE 4000

# UNVERIFIED ASSUMPTIONS about the base image (its ENTRYPOINT, CMD and USER
# cannot be inspected here -- Docker is unavailable in this environment):
#
#  1. The official LiteLLM image defines an ENTRYPOINT that runs the proxy and
#     forwards CMD as arguments. If that holds, the CMD below appends
#     `--config ... --port 4000` to it and the proxy starts with our config.
#     If instead the base image's ENTRYPOINT ignores CMD, or there is no proxy
#     ENTRYPOINT, this CMD will not take effect and the image will need an
#     explicit ENTRYPOINT here instead. The owner MUST run the `docker inspect`
#     command from the G1 report against the mirrored base image BEFORE
#     building, and convert this to an ENTRYPOINT override if the inspection
#     shows CMD is not forwarded to the proxy.
#  2. The base image already contains the proxy entrypoint and runs as a
#     non-root user by default (the upstream image is documented to). This
#     Dockerfile does NOT set USER, so it inherits whatever the base image
#     chose; if the inspection shows it runs as root, add a non-root USER here.
#     readonlyRootFilesystem is enforced at the task level with a writable /tmp
#     volume regardless (see terraform/app/gateway.tf).
#
#
# INSPECTED (litellm v1.103.0, docker inspect): ENTRYPOINT
# ["docker/prod_entrypoint.sh"], CMD ["--port","4000"], USER "root". So the
# proxy ENTRYPOINT exists and takes CMD as arguments (assumption 1 holds in
# shape; whether the script forwards "$@" verbatim is proven by the local boot
# test, not by reading), and the base image runs as ROOT (assumption 2 was
# wrong), hence the USER below.

# Run as an unprivileged uid, the same one the gate uses. A numeric uid needs no
# /etc/passwd entry. HOME points at the one writable path: the task runs with a
# read-only root and a writable /tmp volume, and a HOME of "/" would make any
# library that caches under ~ fail on the read-only root.
USER 10001:10001
ENV HOME=/tmp

# CMD (not ENTRYPOINT) so these become the base ENTRYPOINT's arguments; written
# as exec-form JSON so no shell is required.
CMD ["--config", "/etc/litellm/config.yaml", "--port", "4000"]
