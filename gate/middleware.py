"""The gate's single interception point for tool calls.

One hook, `on_call_tool`: authenticate the caller, ask the policy, then forward,
block, or park the call for a human. Every failure inside the hook blocks the
call -- see `_FAIL_CLOSED`.

Authentication lives entirely behind `IdentityResolver` (gate.identity): this
module receives an already-resolved `Identity` and never parses a token itself.
`_resolve_identity` is the one seam that changes when authentication changes
(R21). The resolved team selects the per-team policy view from the registry, so
the pure engine still does no lookups of its own (R23, R25).
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
            # Rejected before classification (R18): the caller is not
            # authenticated, so there is no identity to attribute the call to.
            # The audit line records that an unauthenticated call was refused,
            # never a token -- there is no token in scope here to leak.
            tool = _peek_tool(context)
            self._audit_best_effort(tool, caller=UNREADABLE)
            # The operational log records the SHAPE of the rejection, not the
            # oracle-safe caller message and never a token. str(error) is the
            # deliberately-uninformative "authentication failed" text, which is
            # safe by construction; we log a fixed reason rather than risk it
            # ever carrying detail.
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
                # Stamp the CALLER'S effective TTL on the parked call. `limits`
                # is the team's already-tightened view, so a team that shortened
                # approval_ttl_minutes (CustomerChat: 5) gets a grant that
                # actually lives 5 minutes, not the store's baseline 10 -- the
                # gate is the only component that authoritatively knows the team
                # at park time (R26, R23, bug D5.2). Seconds, because the store
                # works in seconds.
                approval_id = self._approvals.create(
                    caller,
                    tool,
                    arguments,
                    ttl_seconds=limits.approval_ttl_minutes * 60.0,
                ).id

        self._audit.record(
            caller, tool, classification, decision, args_hash(caller, tool, arguments)
        )
        # The operational decision line mirrors the audit row for a live operator
        # watching the stream, and carries the SAME argument hash -- never the
        # arguments (R33). The audit trail above is the system of record; this is
        # disposable stream data. Logging by hash is why no prompt content can
        # reach the stream even here, on the allowed path.
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
        """Authenticate the caller. THE identity seam (R21).

        This is the one method that knows a request has to be turned into an
        identity, and even it does not know how: it hands the request headers to
        the configured `IdentityResolver` and takes back an `Identity`. Over
        stdio the resolver trusts the spawning process's `--caller`; over HTTP it
        authenticates a bearer token. Swapping the mechanism is a change to
        gate.identity and to nothing here.
        """
        # FastMCP strips `authorization` from get_http_headers() by default,
        # because it normally must not be forwarded to an upstream. The gate is
        # exactly the component that consumes it, so it opts the header back in
        # here -- and only here -- for the resolver to authenticate.
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
                " -- then retry this call unchanged. The approval covers these exact"
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
