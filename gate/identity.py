"""The identity seam: who is calling, and how we know it (R18-R21).

This module is the single place that understands authentication. Everything
downstream -- middleware, policy, registry -- receives an already-resolved
`Identity` and never learns how it was established. Replacing bearer tokens with
mTLS or SigV4 later is an edit to this file and nothing else (R21).

Two transports, two honest answers to "who is this":

* Over **stdio** the client spawned this very process, so the operating system
  already bound the caller to us: there is no network in between and no header
  to forge. The spawning identity IS the identity, and it arrives as the
  `--caller` argument. Trusting it is not a weakness, it is the transport's own
  guarantee (R18).

* Over **HTTP** the gate is reachable across a network boundary, so nothing
  about the connection proves who is on the other end. Identity MUST be
  authenticated from an `Authorization: Bearer <token>` header, and there is no
  `--caller` fallback: a missing token, an unparsable header, or an unknown
  token is rejected before classification ever runs (R18). If HTTP is selected
  with no token source configured at all, every call is rejected -- the gate
  fails closed rather than waving traffic through (R13).

Security properties enforced here, and nowhere else:

* Tokens are compared with `hmac.compare_digest`, never `==`, so a comparison
  cannot leak a token's contents through timing.
* A token never reaches a log line, an error returned to a caller, or a
  traceback. `AuthenticationError` carries only an uninformative caller-facing
  message; server-side detail is logged separately and without the credential.
* Rejections do not distinguish "unknown token" from "malformed header" to the
  caller, so the gate cannot be used as an oracle to enumerate valid tokens.
* A token source that cannot load -- unreachable secret, malformed JSON, or a
  token mapped to a team that policy.yaml does not define -- makes the gate
  refuse to boot, exactly as the registry refuses a bad policy (R17). The gate
  never starts in a degraded, half-authenticated state.
"""

from __future__ import annotations

import hmac
import json
import logging
import os
from dataclasses import dataclass
from typing import Mapping, Protocol

from fastmcp.server.auth.auth import AccessToken, TokenVerifier

logger = logging.getLogger("bouncer.identity")

# Selection knob, BOUNCER_-prefixed to match BOUNCER_STORE / BOUNCER_DB /
# BOUNCER_POLICY. The default is the local source so offline development and the
# test suite need no AWS and no network (R20).
IDENTITY_ENV = "BOUNCER_IDENTITY"

# Local source inputs. Either or both may be set; the file is merged over the
# environment variable, and both are optional so a pure-env or pure-file
# deployment works.
LOCAL_TOKENS_ENV = "BOUNCER_TOKENS"
LOCAL_TOKENS_FILE_ENV = "BOUNCER_TOKENS_FILE"

# Secrets Manager source input: the secret's name or ARN. boto3 resolves it at
# boot. The container gets this by environment variable (R19).
SECRET_ID_ENV = "BOUNCER_TOKENS_SECRET"

SOURCE_LOCAL = "local"
SOURCE_SECRETS_MANAGER = "secretsmanager"
DEFAULT_SOURCE = SOURCE_LOCAL

# One caller-facing message for every authentication failure. Deliberately
# uninformative: it must not help an attacker tell a bad token from a malformed
# header from an unknown token.
_REJECTED_MESSAGE = "authentication failed: a valid bearer token is required"

_BEARER_PREFIX = "bearer "


class IdentityConfigError(RuntimeError):
    """A token source is unreachable, malformed, or maps a token to no team.

    Raised at boot only. Like `PolicyConfigError`, it means the gate must not
    start: there is no safe half-configured identity state.
    """


class AuthenticationError(Exception):
    """A call could not be authenticated. Its message is safe to return.

    The message is intentionally the same for every failure mode so it cannot be
    used to enumerate valid tokens. Any distinguishing detail belongs in a
    server-side log, never in this exception.
    """

    def __init__(self, message: str = _REJECTED_MESSAGE) -> None:
        super().__init__(message)


@dataclass(frozen=True)
class Identity:
    """The authenticated caller and the team it belongs to.

    Caller and team are distinct on purpose: the destructive rate cap is per
    caller, while policy overrides are per team, and several callers may share
    one team even though the POC ships one caller per team. Collapsing them
    would make it impossible to model that later without a schema change.
    """

    caller: str
    # None means "no team override": the baseline applies. Only the stdio path
    # with no --team produces this; every bearer token maps to a named team.
    team: str | None


@dataclass(frozen=True)
class _TokenRecord:
    """What a single token entry in a source maps to."""

    caller: str
    team: str


class IdentityResolver(Protocol):
    """Turn the transport-level request context into an `Identity`.

    `headers` is the request's HTTP headers (empty over stdio). Implementations
    either return an `Identity` or raise `AuthenticationError`; they never return
    an anonymous fallback on the HTTP path.
    """

    def resolve(self, headers: Mapping[str, str]) -> Identity: ...


class StdioIdentityResolver:
    """Trust the spawning process's declared identity (stdio transport only).

    There is no token here because there is no network here: the client started
    this process, so the OS boundary already authenticated the caller. The team
    is supplied alongside the caller so per-team policy still applies to a local
    run.
    """

    def __init__(self, caller: str, team: str | None) -> None:
        self._identity = Identity(caller=caller, team=team)

    def resolve(self, headers: Mapping[str, str]) -> Identity:
        # Headers are irrelevant over stdio; the identity was fixed at boot.
        return self._identity


class BearerTokenIdentityResolver:
    """Authenticate every HTTP call from an `Authorization: Bearer <token>` header.

    The token-to-identity table is resolved once at boot and held in memory; no
    lookup here touches the network. There is no `--caller` fallback: if the
    header is absent, unparsable, or names a token we do not hold, the call is
    rejected before classification (R18).
    """

    def __init__(self, tokens: Mapping[str, _TokenRecord]) -> None:
        # Copy into a plain dict we own, so a caller cannot mutate the table
        # after boot. The keys are the raw token strings.
        self._tokens: dict[str, _TokenRecord] = dict(tokens)

    def resolve(self, headers: Mapping[str, str]) -> Identity:
        token = _extract_bearer(headers)
        if token is None:
            # No header, or not a Bearer header. Uninformative to the caller;
            # the server-side log records the shape of the failure, never a
            # token value.
            logger.warning("authentication rejected: missing or malformed Authorization header")
            raise AuthenticationError()
        return self.authenticate(token)

    def authenticate(self, token: str) -> Identity:
        """Turn a raw bearer token into an `Identity`, or raise.

        Factored out of `resolve()` so the fastmcp session-level verifier
        (`BouncerTokenVerifier`) authenticates against the SAME token table and
        the SAME `hmac.compare_digest` matching this resolver uses, rather than
        keeping a second copy of either (R21). `resolve()` owns header parsing;
        this owns the token-to-identity decision. Both funnel through `_match`,
        so there is exactly one comparison and one table in the process.
        """
        record = self._match(token)
        if record is None:
            logger.warning("authentication rejected: unrecognised bearer token")
            raise AuthenticationError()

        return Identity(caller=record.caller, team=record.team)

    def _match(self, token: str) -> _TokenRecord | None:
        """Constant-time-per-candidate lookup.

        A plain dict `get(token)` would compare the token with `==` through the
        hash table and leak length and content through timing. Comparing every
        stored token with `hmac.compare_digest` keeps the comparison independent
        of how much of the token matched. The table is small (one entry per
        caller), so scanning it is cheap.
        """
        encoded = token.encode("utf-8")
        matched: _TokenRecord | None = None
        for candidate, record in self._tokens.items():
            if hmac.compare_digest(encoded, candidate.encode("utf-8")):
                matched = record
        return matched


def _extract_bearer(headers: Mapping[str, str]) -> str | None:
    """Pull the token out of an `Authorization: Bearer <token>` header.

    Returns None for any header we cannot parse into a non-empty token, so the
    caller treats "no header", "wrong scheme", and "empty token" identically.
    Header names are matched case-insensitively because HTTP header names are.
    """
    raw = _header(headers, "authorization")
    if raw is None:
        return None
    stripped = raw.strip()
    if len(stripped) <= len(_BEARER_PREFIX):
        return None
    if stripped[: len(_BEARER_PREFIX)].lower() != _BEARER_PREFIX:
        return None
    token = stripped[len(_BEARER_PREFIX) :].strip()
    return token or None


def _header(headers: Mapping[str, str], name: str) -> str | None:
    target = name.lower()
    for key, value in headers.items():
        if key.lower() == target:
            return value
    return None


def build_identity_resolver(
    *,
    transport: str,
    caller: str,
    known_teams: frozenset[str],
    team: str | None = None,
) -> IdentityResolver:
    """Construct the identity resolver, or raise `IdentityConfigError` at boot.

    `transport` decides the model, not a runtime sniff:

    * `stdio` (and the in-memory test transport) trusts `--caller`. `team` picks
      which team's policy applies; it defaults to the caller name so a local run
      with a matching team block just works, and it must name a team the policy
      defines.
    * `http` builds a `BearerTokenIdentityResolver` from the configured token
      source. If no token source is configured at all, that is a boot failure,
      not an open door (R13).

    `known_teams` is the set of team names policy.yaml defines. Every identity a
    resolver can ever produce must map to one of them, checked here at boot, so
    an unknown-team token can never reach the policy at request time.
    """
    if transport == "stdio":
        # Over stdio only an EXPLICIT team is validated against the policy. With
        # no --team the caller runs on the baseline (team=None), which is the
        # loosest the gate applies and exactly what the default local run and
        # the in-memory test transport expect. An explicit team, by contrast, is
        # a deliberate choice and must name a team the policy defines, so a typo
        # fails at boot rather than silently falling back to the baseline.
        if team is not None and team not in known_teams:
            raise IdentityConfigError(
                f"--team {team!r} is not defined in policy.yaml; known teams: "
                f"{sorted(known_teams)}"
            )
        return StdioIdentityResolver(caller=caller, team=team)

    if transport == "http":
        tokens = _load_tokens(known_teams)
        if not tokens:
            # HTTP with no usable token source is the fail-closed case: rather
            # than authenticate nobody and pass everybody, refuse to boot.
            #
            # The message names the SELECTED source, because the trap here is
            # setting the secret variable while leaving the selector at its
            # default: the secret is then never consulted, and an error listing
            # a variable the operator has already set reads as a lie.
            source = _selected_source()
            if source == SOURCE_SECRETS_MANAGER:
                remedy = f"set {SECRET_ID_ENV} to a secret holding the token map"
            else:
                remedy = (
                    f"set {LOCAL_TOKENS_ENV} or {LOCAL_TOKENS_FILE_ENV}, or select a"
                    f" different source with {IDENTITY_ENV}="
                    f"{SOURCE_SECRETS_MANAGER} and set {SECRET_ID_ENV}"
                )
            raise IdentityConfigError(
                "HTTP transport requires a token source, but the configured source"
                f" ({IDENTITY_ENV}={source}) yielded no tokens; {remedy}"
            )
        return BearerTokenIdentityResolver(tokens)

    raise IdentityConfigError(f"unknown transport {transport!r}")


def _selected_source() -> str:
    return os.environ.get(IDENTITY_ENV, DEFAULT_SOURCE).strip().lower() or DEFAULT_SOURCE


def _load_tokens(known_teams: frozenset[str]) -> Mapping[str, _TokenRecord]:
    """Load and validate the token table from the selected source.

    Every token must map to a team policy.yaml defines; a token pointing at an
    undefined team is a boot failure (R17), because honouring it at request time
    would mean applying no team's overrides -- silently loosening the baseline.
    """
    source = _selected_source()
    if source == SOURCE_LOCAL:
        raw = _load_local_tokens()
    elif source == SOURCE_SECRETS_MANAGER:
        raw = _load_secretsmanager_tokens()
    else:
        raise IdentityConfigError(
            f"{IDENTITY_ENV}={source!r} is not a known identity source; "
            f"use {SOURCE_LOCAL!r} or {SOURCE_SECRETS_MANAGER!r}"
        )
    return _validate_tokens(raw, known_teams, source)


def _load_local_tokens() -> Mapping[str, object]:
    """Read the token mapping from an env var and/or a JSON file, both optional.

    The file is layered over the environment variable so a deployment can ship a
    base set one way and override individual tokens the other; neither being set
    is not an error here (the HTTP path decides that), it just yields an empty
    table.
    """
    merged: dict[str, object] = {}

    inline = os.environ.get(LOCAL_TOKENS_ENV, "").strip()
    if inline:
        merged.update(_parse_json_object(inline, f"${LOCAL_TOKENS_ENV}"))

    path = os.environ.get(LOCAL_TOKENS_FILE_ENV, "").strip()
    if path:
        try:
            text = _read_file(path)
        except OSError as error:
            raise IdentityConfigError(
                f"cannot read token file {path}: {error}"
            ) from error
        merged.update(_parse_json_object(text, path))

    return merged


def _load_secretsmanager_tokens() -> Mapping[str, object]:
    """Resolve the token mapping from AWS Secrets Manager at boot.

    boto3 is imported LAZILY, right here, exactly as the DynamoDB store does it,
    so the local path and the test suite never need boto3 installed (R44). The
    secret's value is a JSON object of the same shape as the local source. The
    secret's contents are never logged.
    """
    secret_id = os.environ.get(SECRET_ID_ENV, "").strip()
    if not secret_id:
        # No secret configured under this source: an empty table, which the HTTP
        # path turns into a refuse-to-boot. Kept distinct from a load failure.
        return {}

    try:
        import boto3  # lazy: only the deployed Secrets Manager path needs it
    except ImportError as error:
        raise IdentityConfigError(
            f"{IDENTITY_ENV}={SOURCE_SECRETS_MANAGER!r} needs the 'aws' extra "
            "(which provides boto3); install it or use the local source"
        ) from error

    client = boto3.client("secretsmanager")
    try:
        response = client.get_secret_value(SecretId=secret_id)
    except Exception as error:
        # Any boto/network failure is a boot failure. The message names the
        # secret id (a name or ARN, not a credential) but never the response.
        raise IdentityConfigError(
            f"cannot resolve token secret {secret_id!r}: {type(error).__name__}"
        ) from error

    payload = response.get("SecretString")
    if not payload:
        raise IdentityConfigError(
            f"token secret {secret_id!r} has no SecretString payload"
        )
    return _parse_json_object(payload, f"secret {secret_id!r}")


def _validate_tokens(
    raw: Mapping[str, object],
    known_teams: frozenset[str],
    source: str,
) -> Mapping[str, _TokenRecord]:
    """Turn the raw {token: {caller, team}} mapping into validated records.

    Rejects, as a boot failure: a non-object entry, a missing caller or team, a
    team the policy does not define. Error messages never include a token value;
    tokens are identified by their caller/team, which are not secret.
    """
    validated: dict[str, _TokenRecord] = {}
    for token, entry in raw.items():
        if not isinstance(token, str) or not token:
            raise IdentityConfigError(
                f"token source {source!r} has a non-string or empty token key"
            )
        if not isinstance(entry, Mapping):
            raise IdentityConfigError(
                f"token source {source!r}: each token must map to an object with "
                "'caller' and 'team'"
            )
        caller = entry.get("caller")
        team = entry.get("team")
        if not isinstance(caller, str) or not caller:
            raise IdentityConfigError(
                f"token source {source!r}: a token entry is missing a string 'caller'"
            )
        if not isinstance(team, str) or not team:
            raise IdentityConfigError(
                f"token source {source!r}: caller {caller!r} is missing a string 'team'"
            )
        if team not in known_teams:
            raise IdentityConfigError(
                f"token source {source!r}: caller {caller!r} is mapped to team "
                f"{team!r}, which policy.yaml does not define; known teams: "
                f"{sorted(known_teams)}"
            )
        validated[token] = _TokenRecord(caller=caller, team=team)
    return validated


def _parse_json_object(text: str, where: str) -> Mapping[str, object]:
    try:
        parsed = json.loads(text)
    except json.JSONDecodeError as error:
        raise IdentityConfigError(f"{where} is not valid JSON: {error}") from error
    if not isinstance(parsed, dict):
        raise IdentityConfigError(f"{where} must be a JSON object of tokens")
    return parsed


def _read_file(path: str) -> str:
    with open(path, "r", encoding="utf-8") as handle:
        return handle.read()


class BouncerTokenVerifier(TokenVerifier):
    """Authenticate the whole MCP session, not just tool calls (R18 amended, A6).

    Why this exists at all: `GateMiddleware.on_call_tool` authenticates every
    tool call, but a `Middleware` hook only fires for tool calls. Over HTTP the
    session's `initialize` handshake and its `tools/list` catalogue listing are
    NOT tool calls, so nothing behind that hook can see them; without a
    session-level check an unauthenticated client could open a session and read
    the whole tool catalogue before it ever tried a call it could not make.
    fastmcp's native auth seam runs BEFORE the MCP session manager -- its
    `AuthenticationMiddleware`/`RequireAuthMiddleware` gate the streamable-HTTP
    route itself -- so wiring a verifier there is the only place that covers
    `initialize` and `tools/list` too. This is the single component that adapts
    fastmcp's token seam to ours.

    Why it delegates rather than re-implements: the token table and the
    `hmac.compare_digest` matching already live on `BearerTokenIdentityResolver`
    and must stay a single seam (R21). Duplicating either here would create a
    second place a token is compared and a second copy of the table to keep in
    sync -- exactly the drift R21 forbids. So the verifier holds the SAME
    resolver `GateMiddleware` holds and calls its `authenticate()`; there is one
    table and one comparison in the process.

    Why it returns `None` on failure instead of raising: that is fastmcp's
    contract (`TokenVerifier.verify_token`), and `BearerAuthBackend` turns a
    `None` into the 401 with a deliberately-uninformative body. Translating our
    `AuthenticationError` into `None` keeps the oracle-safe property at the HTTP
    layer too: a wrong token and a malformed header both become the same 401.
    The token is never logged here; the resolver's own rejection log records the
    shape of the failure, never the credential.
    """

    def __init__(self, resolver: BearerTokenIdentityResolver) -> None:
        # No base_url / resource_base_url on purpose: with neither set, fastmcp
        # registers NO `.well-known/oauth-protected-resource` route and the 401's
        # WWW-Authenticate advertises no resource-metadata URL, so adding auth
        # opens no new unauthenticated disclosure surface (verified in
        # fastmcp/server/http.py: resource_metadata_url is None when
        # _get_resource_url() returns None).
        super().__init__()
        self._resolver = resolver

    async def verify_token(self, token: str) -> AccessToken | None:
        """Verify a session-level bearer token via the shared resolver.

        `scopes=[]` because the gate does not model OAuth scopes: authorisation
        is the policy engine's job, keyed on the resolved caller/team, not on
        token scopes. `client_id` carries the authenticated caller so it is
        available to anything downstream that inspects the fastmcp auth context;
        the authoritative identity the gate acts on is still re-resolved by
        `GateMiddleware` from the same header (defence in depth).
        """
        try:
            identity = self._resolver.authenticate(token)
        except AuthenticationError:
            return None
        return AccessToken(token=token, client_id=identity.caller, scopes=[])
