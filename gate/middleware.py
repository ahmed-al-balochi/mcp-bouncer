"""The gate's single interception point for tool calls.

One hook, `on_call_tool`, authenticates the caller, asks the policy, then
forwards, blocks, or parks the call. Every failure inside the hook blocks it.
"""

from __future__ import annotations

from dataclasses import dataclass, replace
from typing import Any, Mapping

from fastmcp.server.dependencies import get_http_headers
from fastmcp.server.middleware import Middleware, MiddlewareContext
from fastmcp.tools import ToolResult

from gate import observability, policy
from gate.approvals import RATE_WINDOW_SECONDS, ApprovalStore, args_hash
from gate.audit import AuditLog
from gate.identity import AuthenticationError, Identity, IdentityResolver
from gate.registry import Registry, TeamView

ANONYMOUS_CALLER = "anonymous"
BLOCKED = "BLOCKED_BY_GATE"
APPROVAL_REQUIRED = "APPROVAL_REQUIRED"
UNREADABLE = "<unreadable>"

_FAIL_CLOSED = (
    f"{BLOCKED}: the gate could not complete its own checks, so the call was denied. "
    "The gate has no fail-open path, including for reads."
)


@dataclass(frozen=True)
class _Outcome:
    decision: str
    message: str


class GateMiddleware(Middleware):
    """Classifies each tool call and enforces the action policy around it."""

    def __init__(
        self,
        registry: Registry,
        approvals: ApprovalStore,
        audit: AuditLog,
        identity_resolver: IdentityResolver,
    ) -> None:
        self._registry = registry
        self._approvals = approvals
        self._audit = audit
        self._identity_resolver = identity_resolver

    async def on_call_tool(self, context: MiddlewareContext[Any], call_next: Any) -> Any:
        try:
            identity = self._resolve_identity()
        except AuthenticationError as error:
            # Rejected before classification: no authenticated identity to
            # attribute the call to. The audit line records a refused
            # unauthenticated call, never a token.
            tool = _peek_tool(context)
            self._audit_best_effort(tool, caller=UNREADABLE)
            # Log a fixed reason, not str(error), so no detail can ever leak.
            observability.log_auth_rejected(reason="authentication_failed", tool=tool)
            return _error(f"{BLOCKED}: {error}")
        except Exception:
            tool = _peek_tool(context)
            self._audit_best_effort(tool, caller=UNREADABLE)
            observability.log_fail_closed(caller=UNREADABLE, team=None, tool=tool)
            return _error(_FAIL_CLOSED)

        try:
            outcome = await self._evaluate(context, identity)
        except Exception:
            self._audit_best_effort(_peek_tool(context), caller=identity.caller)
            observability.log_fail_closed(
                caller=identity.caller, team=identity.team, tool=_peek_tool(context)
            )
            return _error(_FAIL_CLOSED)

        if outcome.decision == policy.PASS:
            return await call_next(context)
        return _error(outcome.message)

    async def _evaluate(
        self, context: MiddlewareContext[Any], identity: Identity
    ) -> _Outcome:
        tool: str = context.message.name
        arguments: Mapping[str, Any] = context.message.arguments or {}
        caller = identity.caller

        # The team's effective, already-tightened view. The engine cannot tell
        # it from the baseline; all the per-team reasoning happened at boot.
        view: TeamView = self._registry.for_team(identity.team)
        limits = view.limits

        classification = policy.classify(
            tool, await self._annotations(context, tool), view.patterns
        )
        self._approvals.expire()
        state = policy.ApprovalState(
            grant_available=False,
            approved_destructive_in_window=self._approvals.approved_in_window(
                caller, RATE_WINDOW_SECONDS
            ),
        )
        decision = policy.decide(classification, caller, state, limits)

        approval_id: str | None = None
        if decision == policy.APPROVE:
            # The grant is claimed before the call is released, so the claim and
            # the release cannot come apart: a claimed grant is spent whatever
            # happens next.
            if self._approvals.consume(caller, tool, arguments):
                decision = policy.decide(
                    classification, caller, replace(state, grant_available=True), limits
                )
            else:
                # Stamp the caller's effective TTL on the parked call. The gate
                # is the only component that knows the team at park time, so a
                # team that shortened the TTL gets a grant that lives that long.
                approval_id = self._approvals.create(
                    caller,
                    tool,
                    arguments,
                    ttl_seconds=limits.approval_ttl_minutes * 60.0,
                ).id

        self._audit.record(
            caller, tool, classification, decision, args_hash(caller, tool, arguments)
        )
        # The operational decision line mirrors the audit row but carries the
        # argument hash, never the arguments, so no prompt content reaches
        # the stream even on the allowed path.
        observability.log_decision(
            caller=caller,
            team=identity.team,
            tool=tool,
            classification=classification,
            decision=decision,
            args_hash=args_hash(caller, tool, arguments),
        )
        return _Outcome(
            decision=decision,
            message=self._message(
                decision, classification, tool, caller, approval_id, limits
            ),
        )

    def _resolve_identity(self) -> Identity:
        """Authenticate the caller. The identity seam.

        Hands the request headers to the configured `IdentityResolver` and takes
        back an `Identity`. Swapping the mechanism changes only gate.identity.
        """
        # FastMCP strips `authorization` from get_http_headers() by default so
        # it is not forwarded upstream. The gate is the component that consumes
        # it, so it opts the header back in here, and only here.
        return self._identity_resolver.resolve(get_http_headers(include={"authorization"}))

    async def _annotations(
        self, context: MiddlewareContext[Any], tool: str
    ) -> Mapping[str, Any]:
        server = getattr(context.fastmcp_context, "fastmcp", None)
        if server is None:
            return {}
        descriptor = await server.get_tool(tool)
        annotations = getattr(descriptor, "annotations", None)
        if annotations is None:
            return {}
        return {
            "readOnlyHint": annotations.read_only_hint,
            "destructiveHint": annotations.destructive_hint,
            "idempotentHint": annotations.idempotent_hint,
        }

    def _message(
        self,
        decision: str,
        classification: str,
        tool: str,
        caller: str,
        approval_id: str | None,
        limits: policy.Limits,
    ) -> str:
        if decision == policy.APPROVE and approval_id is not None:
            return (
                f"{APPROVAL_REQUIRED} id={approval_id} :: {tool} is classified"
                f" '{classification}' and needs human approval before it runs."
                f" Ask an approver to run: bouncer approve {approval_id}"
                " then retry this call unchanged. The approval covers these exact"
                f" arguments only, and expires in"
                f" {limits.approval_ttl_minutes} minutes."
            )
        if classification == policy.UNKNOWN:
            return (
                f"{BLOCKED}: '{tool}' matches no entry in"
                f" {self._registry.source.name}, so it is unclassified."
                " Unclassified tools are denied by default."
            )
        if classification == "destructive":
            return (
                f"{BLOCKED}: caller '{caller}' has used its allowance of"
                f" {limits.destructive_per_hour} approved destructive"
                " actions this hour. A human must run:"
                f" bouncer reset {caller}"
            )
        return (
            f"{BLOCKED}: {self._registry.source.name} maps '{classification}' tools"
            " to block."
        )

    def _audit_best_effort(self, tool: str, caller: str = UNREADABLE) -> None:
        try:
            self._audit.record(caller, tool, policy.UNKNOWN, policy.BLOCK, "")
        except Exception:
            # The call is already denied; losing the log line must not turn a
            # blocked call into a raised one.
            pass


def _peek_tool(context: MiddlewareContext[Any]) -> str:
    return getattr(getattr(context, "message", None), "name", UNREADABLE) or UNREADABLE


def _error(message: str) -> ToolResult:
    return ToolResult(content=message, is_error=True)
