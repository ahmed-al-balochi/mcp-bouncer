# The official LiteLLM image plus the committed litellm.yaml. Nothing
# environment-specific is baked in -- the key and region arrive at runtime.
# LITELLM_BASE_IMAGE has no default, so every build names the exact image.
ARG LITELLM_BASE_IMAGE
FROM ${LITELLM_BASE_IMAGE}

# The config lives at a fixed path and is passed explicitly on the command line
# below, so the image does not depend on LiteLLM's config-discovery defaults.
COPY litellm.yaml /etc/litellm/config.yaml

# Serve on 4000 (LiteLLM's conventional port; the task definition and target
# group key off this). Documentation only; ECS maps the port explicitly.
EXPOSE 4000

# INSPECTED against the base image (`docker inspect`): ENTRYPOINT is the prod
# entrypoint and CMD is ["--port","4000"], and the base runs as ROOT -- hence the
# USER further down. The entrypoint ends in `exec litellm "$@"`, so CMD reaches it.

# Patch the base image's packages with known CVEs ourselves. Two silent traps:
# the package index is stale until `apk update`, and /etc/apk/world pins exact
# versions, so only the named packages are unpinned (a blanket unpin breaks openssl).
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
# /etc/passwd entry. HOME points at the one writable path, /tmp, since the task
# runs with a read-only root and a HOME of "/" would break caches under ~.
USER 10001:10001
ENV HOME=/tmp

# CMD (not ENTRYPOINT) so these become the base ENTRYPOINT's arguments; written
# as exec-form JSON so no shell is required.
CMD ["--config", "/etc/litellm/config.yaml", "--port", "4000"]
