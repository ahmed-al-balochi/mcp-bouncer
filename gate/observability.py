"""Structured operational logging to stdout, for CloudWatch Logs.

One module owns JSON formatting and enforces redaction at the boundary: no
prompt content, no arguments, no bearer token, boot config by knob name only.
"""

from __future__ import annotations

import json
import logging
import os
import sys
from typing import Any, Mapping

# Level knob, BOUNCER_-prefixed like the others. Accepts a standard level name;
# anything unrecognised falls back to INFO so a bad log level cannot stop the
# gate from booting.
LOG_LEVEL_ENV = "BOUNCER_LOG_LEVEL"
DEFAULT_LEVEL = "INFO"

# The single logger tree the gate logs under. Configuring the "bouncer" root
# here also formats gate.identity's "bouncer.identity" records, so auth
# rejections flow through this JSON formatter without that module knowing.
ROOT_LOGGER_NAME = "bouncer"

_logger = logging.getLogger(ROOT_LOGGER_NAME)

# Caller-supplied fields arrive in the record under `_extra`, kept separate so
# we never serialise Python's own reserved LogRecord attributes into the body.
_MESSAGE_KEY = "event"


class JsonLogFormatter(logging.Formatter):
    """Render a LogRecord as one compact JSON object on a single line.

    The only place JSON is produced, so redaction has one enforcement point. It
    reads fields only from a single `_extra` dict, never arbitrary attributes.
    """

    def format(self, record: logging.LogRecord) -> str:
        payload: dict[str, Any] = {
            "level": record.levelname,
            "logger": record.name,
            _MESSAGE_KEY: record.getMessage(),
        }
        extra = getattr(record, "_extra", None)
        if isinstance(extra, Mapping):
            # Caller fields are already redacted by construction. Coerce to
            # JSON-safe scalars so a stray value drops to its repr instead of
            # raising inside the logging stack.
            for key, value in extra.items():
                if key not in payload:
                    payload[key] = _json_safe(value)
        if record.exc_info:
            # A rendered traceback string, not the live exception. Tracebacks
            # here never contain a token (see gate.identity) and arguments never
            # reach an exception, since the middleware logs by hash.
            payload["exception"] = self.formatException(record.exc_info)
        return json.dumps(payload, separators=(",", ":"), sort_keys=False)


def configure_logging(*, stream: Any = None, level: str | None = None) -> None:
    """Install the JSON formatter on the bouncer logger tree, once, to stdout.

    Idempotent: it replaces the single handler rather than stacking duplicates.
    `stream` and `level` are injectable so a test can capture output and pin it.
    """
    target = stream if stream is not None else sys.stdout
    resolved = _resolve_level(level)

    handler = logging.StreamHandler(target)
    handler.setFormatter(JsonLogFormatter())

    # Replace, do not append: a second handler would double every line.
    _logger.handlers = [handler]
    _logger.setLevel(resolved)
    # Do not propagate to the root logger, or records would also hit whatever
    # default handler the root has and print twice, once unformatted.
    _logger.propagate = False


def _resolve_level(level: str | None) -> int:
    name = (level or os.environ.get(LOG_LEVEL_ENV) or DEFAULT_LEVEL).strip().upper()
    resolved = logging.getLevelName(name)
    # getLevelName returns an int for a known name and a str ("Level XYZ") for an
    # unknown one; only trust an int, else fall back rather than fail boot.
    return resolved if isinstance(resolved, int) else logging.INFO


def _json_safe(value: Any) -> Any:
    if value is None or isinstance(value, (str, int, float, bool)):
        return value
    return str(value)


def _emit(level: int, event: str, **fields: Any) -> None:
    """The one internal choke point. Never raises.

    Every public helper funnels through here, so the try/except that isolates a
    logging failure from a request's outcome lives in exactly one place.
    """
    try:
        _logger.log(level, event, extra={"_extra": fields})
    except Exception:
        # A broken logging stack must not change what the caller was going to do;
        # dropping the line is the only acceptable failure mode.
        pass


# --- public event helpers ------------------------------------------------
# Each helper names an event and takes only fields safe to log by construction.
# There is no generic "log this dict" entry point that could carry a secret.


def log_boot(config: Mapping[str, str]) -> None:
    """Record the effective, redacted boot configuration.

    `config` names which knobs are set, never a secret's contents. Table names
    and a secret ARN are identifiers an operator needs, not credentials.
    """
    _emit(logging.INFO, "boot", **dict(config))


def log_decision(
    *,
    caller: str,
    team: str | None,
    tool: str,
    classification: str,
    decision: str,
    args_hash: str,
) -> None:
    """Record one tool-call decision as it happens.

    Carries the argument hash, never the arguments, so no prompt content or
    payload reaches the log. It mirrors the audit trail's field set.
    """
    _emit(
        logging.INFO,
        "decision",
        caller=caller,
        team=team,
        tool=tool,
        classification=classification,
        decision=decision,
        args_hash=args_hash,
    )


def log_auth_rejected(*, reason: str, tool: str) -> None:
    """Record an authentication rejection.

    `reason` is the shape of the failure (missing header, unknown token), never
    the token itself; this helper has no parameter that could carry one.
    """
    _emit(logging.WARNING, "auth_rejected", reason=reason, tool=tool)


def log_upstream_ready(*, duration_ms: int, tool_count: int) -> None:
    """Record that the upstream was warmed up at boot before serving.

    `duration_ms` is the real cold-spawn time, the latency that triggers the era
    collision when it exceeds the discover timeout. tool_count leaks no names.
    """
    _emit(logging.INFO, "upstream_ready", duration_ms=duration_ms, tool_count=tool_count)


def log_fail_closed(*, caller: str, team: str | None, tool: str) -> None:
    """Record a fail-closed block: an internal error denied a call.

    No exception and no arguments, since an exception below may carry a secret;
    `team` groups the rate and is None when the caller was not identified.
    """
    _emit(logging.ERROR, "fail_closed", caller=caller, team=team, tool=tool)
