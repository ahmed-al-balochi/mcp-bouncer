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

# INSPECTED against the base image (litellm v1.103.0, `docker inspect`):
# ENTRYPOINT ["docker/prod_entrypoint.sh"], CMD ["--port","4000"], USER "root".
# The script ends in `exec litellm "$@"`, so the CMD below reaches the proxy
# verbatim, and the base runs as ROOT -- hence the USER further down.

# --- patch the base image's OS packages -------------------------------------
#
# WHY this layer exists: the base is Wolfi, and the image's installed packages
# lag its own repositories. On v1.103.0 that left glibc, ld-linux, libcrypt1 and
# zlib on versions with known CVEs (a High container-remediation finding), with
# nowhere to move to: v1.103.0 is the newest stable LiteLLM and its digest has
# not been rebuilt. Patching here is the remediation that does not wait on the
# vendor.
#
# TWO traps, both found by measuring rather than reading, and both silent:
#
#  1. The image ships a STALE package index, so `apk` reports everything as
#     current until `apk update` runs. Without the refresh this layer would
#     report success and change nothing.
#  2. `/etc/apk/world` PINS exact versions (`glibc-2.44=2.44-r1`, `zlib=1.3.2-r5`
#     and so on -- the Chainguard build convention for reproducibility), and
#     `apk upgrade` honours those pins. With a fresh index but the pins left in
#     place, apk still reported "OK" and upgraded nothing. The pins have to be
#     removed for the packages being patched.
#
# WHY a named list rather than unpinning everything: a blanket unpin pulls in
# `openssl-4.0`, which fails the build with
# `trying to overwrite etc/ssl/openssl.cnf owned by openssl-3.6.4` -- a major
# openssl alongside a Python built against 3.6 is a bigger change than this
# finding warrants. The list below is exactly the packages the advisory named, so
# openssl stays where the vendor put it. The cost is maintenance: a future CVE in
# some other package needs this list extended, and the guard below is what turns
# a stale list into a loud build failure instead of a quiet no-op.
#
# Runs as root because apk writes under /usr and /lib; the USER directive below
# returns the runtime to an unprivileged uid, so nothing in the running container
# keeps the privilege this build step needed.
USER root
RUN set -eu; \
    apk update; \
    for p in glibc-2.44 glibc-2.44-locale-posix ld-linux-2.44 libcrypt1-2.44 zlib; do \
        grep -qE "^${p}(=|$)" /etc/apk/world || { \
            echo "ERROR: ${p} is no longer in /etc/apk/world -- the base image changed;" >&2; \
            echo "re-check this package list against the current advisory." >&2; \
            exit 1; \
        }; \
        sed -i "s/^${p}=.*$/${p}/" /etc/apk/world; \
    done; \
    apk upgrade --no-cache; \
    rm -rf /var/cache/apk/*

# Run as an unprivileged uid, the same one the gate uses. A numeric uid needs no
# /etc/passwd entry. HOME points at the one writable path: the task runs with a
# read-only root and a writable /tmp volume, and a HOME of "/" would make any
# library that caches under ~ fail on the read-only root.
USER 10001:10001
ENV HOME=/tmp

# CMD (not ENTRYPOINT) so these become the base ENTRYPOINT's arguments; written
# as exec-form JSON so no shell is required.
CMD ["--config", "/etc/litellm/config.yaml", "--port", "4000"]
