"""Structured operational logging to stdout, for CloudWatch Logs (R33).

One module owns log formatting and configuration so the rest of the gate never
builds a JSON line by hand (R42). Callers emit *events* -- a short name plus a
dict of already-safe fields -- and this module turns them into one JSON object
per line on stdout. CloudWatch's agent ingests stdout as-is, and JSON lines are
the format its Logs Insights queries parse without a custom pattern, which is
why JSON-per-line is the choice over a bespoke text format.

What this log is FOR, and how it differs from the audit trail:

    The audit log (gate.audit / gate.dynamodb_audit) is the durable, append-only
    RECORD of decisions: it answers "what did the gate decide about this call,
    and can I prove it later". It is queried by the operator CLI and retained.

    These logs are for OPERATING the running service: boot configuration, live
    decisions as they happen, authentication rejections, and fail-closed blocks.
    They are disposable stream data, not a system of record. They overlap the
    audit trail on the decision line on purpose -- an operator watching the log
    stream should not have to query DynamoDB to see traffic flowing -- but the
    audit trail, not this stream, is the thing we promise never loses a row. If
    the two ever disagree, the audit trail wins.

Hard redaction rules, enforced at the boundary so a caller cannot bypass them:

    * No prompt content and no tool-call arguments, ever. A decision event
      carries the argument HASH the audit trail already uses, never the
      arguments themselves (R33).
    * No bearer token, on any path including errors and exceptions. The
      identity layer already keeps tokens out of its own exceptions; this module
      additionally never accepts an argument named for a token and never logs an
      Authorization header.
    * Boot configuration is logged with values redacted: we record WHICH knobs
      are set, never their secret contents (a secret ARN is an identifier, not a
      credential, so it is safe; a token map is not).

Failure isolation:

    Logging must never change a call's outcome. A logging failure turning an
    allowed call into an error would be a reliability bug; turning a blocked
    call into an allowed one would be a security bug. Every public emit here is
    wrapped so that any exception from the logging stack is swallowed -- the
    worst a broken logger can do is drop a line.
"""

from __future__ import annotations

import json
import logging
import os
import sys
from typing import Any, Mapping

# Level knob, BOUNCER_-prefixed to match BOUNCER_STORE / BOUNCER_DB /
# BOUNCER_POLICY / BOUNCER_IDENTITY. Accepts a standard level name
# (DEBUG/INFO/WARNING/ERROR); anything unrecognised falls back to INFO rather
# than failing boot, because a bad log level must not be able to stop the gate.
LOG_LEVEL_ENV = "BOUNCER_LOG_LEVEL"
DEFAULT_LEVEL = "INFO"

# The single logger tree the gate logs under. gate.identity already logs under
# "bouncer.identity"; configuring the "bouncer" root here formats those records
# too, so authentication rejections flow through the same JSON formatter without
# the identity module knowing about this one.
ROOT_LOGGER_NAME = "bouncer"

_logger = logging.getLogger(ROOT_LOGGER_NAME)

# Reserved LogRecord attributes we must not copy into the JSON body: these are
# Python's own, not fields a caller passed. Everything a caller adds arrives in
# the record's __dict__ under `_extra`, kept separate so we never have to diff
# against this list at emit time.
_MESSAGE_KEY = "event"


class JsonLogFormatter(logging.Formatter):
    """Render a LogRecord as one compact JSON object on a single line.

    The formatter is the ONLY place JSON is produced, so the redaction contract
    has exactly one enforcement point. A record carries its structured fields in
    a single `_extra` dict (see `_emit`); the formatter never reaches into
    arbitrary record attributes, so it cannot accidentally serialise something
    Python or a library stashed on the record.
    """

    def format(self, record: logging.LogRecord) -> str:
        payload: dict[str, Any] = {
            "level": record.levelname,
            "logger": record.name,
            _MESSAGE_KEY: record.getMessage(),
        }
        extra = getattr(record, "_extra", None)
        if isinstance(extra, Mapping):
            # The caller's fields are already redacted by construction (see the
            # emit helpers). We still coerce to JSON-safe scalars with a string
            # fallback so a stray non-serialisable value drops to its repr
            # instead of raising inside the logging stack.
            for key, value in extra.items():
                if key not in payload:
                    payload[key] = _json_safe(value)
        if record.exc_info:
            # A rendered traceback string, not the live exception. Tracebacks in
            # this codebase are written to never contain a token (see
            # gate.identity), and the argument values that could contain prompt
            # content never reach an exception here because the middleware logs
            # by hash. We still keep the traceback as a plain string so nothing
            # structured leaks by accident.
            payload["exception"] = self.formatException(record.exc_info)
        return json.dumps(payload, separators=(",", ":"), sort_keys=False)


def configure_logging(*, stream: Any = None, level: str | None = None) -> None:
    """Install the JSON formatter on the bouncer logger tree, once, to stdout.

    Idempotent: repeated calls (a re-imported module, a test re-configuring)
    replace the single handler rather than stacking duplicates that would emit
    every line N times. stdout, not stderr, because CloudWatch's container agent
    captures both but operators expect application logs on stdout and only
    genuine process crashes on stderr.

    `stream` and `level` are injectable so a test can capture output and pin a
    level without touching global environment; production passes neither and
    gets stdout at the configured level.
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
        # A broken logging stack must not change what the caller was going to do.
        # Dropping the line is the only acceptable failure mode.
        pass


# --- public event helpers ------------------------------------------------
#
# Each helper names an operator-relevant event and takes only fields that are
# safe to log by construction. There is deliberately no generic "log this dict"
# entry point: a caller cannot pass arguments or a token through a named field
# that does not exist.


def log_boot(config: Mapping[str, str]) -> None:
    """Record the effective, redacted boot configuration.

    `config` names WHICH knobs are set (transport, store backend, identity
    source, host/port, table names), never a secret's contents. Table names and
    a secret ARN are identifiers an operator needs to correlate the task with
    its infrastructure; they are not credentials. The token map and any bearer
    token never appear here because no caller ever passes them in.
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

    Carries the argument HASH, never the arguments, so no prompt content or
    tool-call payload can reach the log (R33). This mirrors the field set the
    audit trail persists; see the module docstring for why the overlap is
    intentional and which of the two is the system of record.
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

    `reason` is the SHAPE of the failure (missing header, unknown token), never
    the token itself -- the identity layer already refuses to put a token in a
    message, and this helper has no parameter that could carry one.
    """
    _emit(logging.WARNING, "auth_rejected", reason=reason, tool=tool)


def log_upstream_ready(*, duration_ms: int, tool_count: int) -> None:
    """Record that the upstream was warmed up at boot before serving (bug D5.3).

    Emitted once per task start, after `build_gate` opens one connection to the
    upstream through the proxy's own client factory and lists its tools, so the
    kept-alive stdio child is already spawned before the first real request.
    `duration_ms` is how long that warm-up took: on 0.25 vCPU Fargate this is the
    operator's only measurement of the real cold-spawn time -- the very latency
    that, when it exceeds the client's 10 s discover timeout, produced the era
    collision. `tool_count` is a plain integer (how many tools the upstream
    advertised), never a tool name or argument, so no catalogue detail leaks
    (R33). No arguments and no secrets pass through this helper -- it has no
    parameter that could carry one.
    """
    _emit(logging.INFO, "upstream_ready", duration_ms=duration_ms, tool_count=tool_count)


def log_fail_closed(*, caller: str, tool: str) -> None:
    """Record a fail-closed block: an internal error denied a call (R13).

    No exception object and no arguments -- only that the gate denied a call for
    `caller` on `tool` because its own checks could not complete.

    That is deliberately a thin signal, and the trade is explicit: the middleware
    does NOT log the exception, because an exception raised anywhere below it may
    carry a tool argument or a credential in its message, and no amount of
    scrubbing at the log boundary is as reliable as never passing it in. The cost
    is that diagnosing a fail-closed block needs a reproduction rather than a
    stack trace. For a component whose job is to deny, losing a trace is the
    cheaper failure than leaking an argument into a log stream.
    """
    _emit(logging.ERROR, "fail_closed", caller=caller, tool=tool)
