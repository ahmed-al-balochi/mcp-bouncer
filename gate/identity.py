"""The single place that understands authentication.

Downstream code receives a resolved Identity and never learns how it was
established, so swapping the auth mechanism later touches only this file.
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

# Selection knob, BOUNCER_-prefixed to match the other BOUNCER_ settings. The
# default is the local source so offline development and tests need no AWS and
# no network.
IDENTITY_ENV = "BOUNCER_IDENTITY"

# Local source inputs. Either or both may be set; the file is merged over the
# environment variable, and both are optional.
LOCAL_TOKENS_ENV = "BOUNCER_TOKENS"
LOCAL_TOKENS_FILE_ENV = "BOUNCER_TOKENS_FILE"

# Secrets Manager source input: the secret's name or ARN, resolved by boto3 at
# boot.
SECRET_ID_ENV = "BOUNCER_TOKENS_SECRET"

SOURCE_LOCAL = "local"
SOURCE_SECRETS_MANAGER = "secretsmanager"
DEFAULT_SOURCE = SOURCE_LOCAL

# One caller-facing message for every authentication failure, deliberately
# uninformative so it cannot help tell a bad token from a malformed header from
# an unknown token.
_REJECTED_MESSAGE = "authentication failed: a valid bearer token is required"

_BEARER_PREFIX = "bearer "


class IdentityConfigError(RuntimeError):
    """A token source is unreachable, malformed, or maps a token to no team.

    Raised at boot only. Like PolicyConfigError, it means the gate must not
    start: there is no safe half-configured identity state.
    """


class AuthenticationError(Exception):
    """A call could not be authenticated. Its message is safe to return.

    The message is the same for every failure mode so it cannot be used to
    enumerate valid tokens; distinguishing detail belongs in a server-side log.
    """

    def __init__(self, message: str = _REJECTED_MESSAGE) -> None:
        super().__init__(message)


@dataclass(frozen=True)
class Identity:
    """The authenticated caller and the team it belongs to.

    Caller and team are kept distinct because the rate cap is per caller while
    policy overrides are per team, and several callers may share one team.
    """

    caller: str
    # None means no team override, so the baseline applies. Only the stdio path
    # with no --team produces this.
    team: str | None


@dataclass(frozen=True)
class _TokenRecord:
    """What a single token entry in a source maps to."""

    caller: str
    team: str


class IdentityResolver(Protocol):
    """Turn the transport-level request context into an Identity.

    `headers` is the request's HTTP headers (empty over stdio). Implementations
    return an Identity or raise AuthenticationError, never an anonymous fallback.
    """

    def resolve(self, headers: Mapping[str, str]) -> Identity: ...


class StdioIdentityResolver:
    """Trust the spawning process's declared identity (stdio only).

    There is no token because there is no network: the client started this
    process, so the OS boundary already authenticated the caller.
    """

    def __init__(self, caller: str, team: str | None) -> None:
        self._identity = Identity(caller=caller, team=team)

    def resolve(self, headers: Mapping[str, str]) -> Identity:
        # Headers are irrelevant over stdio; the identity was fixed at boot.
        return self._identity


class BearerTokenIdentityResolver:
    """Authenticate every HTTP call from an Authorization: Bearer header.

    The token table is resolved once at boot and held in memory. There is no
    --caller fallback; an absent, unparsable, or unknown token is rejected.
    """

    def __init__(self, tokens: Mapping[str, _TokenRecord]) -> None:
        # Copy into a dict we own so a caller cannot mutate the table after boot.
        # Keys are the raw token strings.
        self._tokens: dict[str, _TokenRecord] = dict(tokens)

    def resolve(self, headers: Mapping[str, str]) -> Identity:
        token = _extract_bearer(headers)
        if token is None:
            # No header, or not a Bearer header. The log records the shape of
            # the failure, never a token value.
            logger.warning("authentication rejected: missing or malformed Authorization header")
            raise AuthenticationError()
        return self.authenticate(token)

    def authenticate(self, token: str) -> Identity:
        """Turn a raw bearer token into an Identity, or raise.

        Shared with the fastmcp session verifier so both authenticate against the
        same table and the same hmac.compare_digest, with no second copy.
        """
        record = self._match(token)
        if record is None:
            logger.warning("authentication rejected: unrecognised bearer token")
            raise AuthenticationError()

        return Identity(caller=record.caller, team=record.team)

    def _match(self, token: str) -> _TokenRecord | None:
        """Constant-time-per-candidate lookup.

        A dict get() compares with == and leaks length and content through
        timing; comparing every token with hmac.compare_digest does not.
        """
        encoded = token.encode("utf-8")
        matched: _TokenRecord | None = None
        for candidate, record in self._tokens.items():
            if hmac.compare_digest(encoded, candidate.encode("utf-8")):
                matched = record
        return matched


def _extract_bearer(headers: Mapping[str, str]) -> str | None:
    """Pull the token out of an Authorization: Bearer header.

    Returns None for anything that is not a non-empty token, so the caller
    treats "no header", "wrong scheme", and "empty token" identically.
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
    """Construct the identity resolver, or raise IdentityConfigError at boot.

    stdio trusts --caller and validates an explicit --team; http builds a
    bearer-token resolver and refuses to boot with no token source.
    """
    if transport == "stdio":
        # With no --team the caller runs on the baseline (team=None), the
        # loosest the gate applies. An explicit --team is a deliberate choice and
        # must name a team the policy defines, so a typo fails at boot.
        if team is not None and team not in known_teams:
            raise IdentityConfigError(
                f"--team {team!r} is not defined in policy.yaml; known teams: "
                f"{sorted(known_teams)}"
            )
        return StdioIdentityResolver(caller=caller, team=team)

    if transport == "http":
        tokens = _load_tokens(known_teams)
        if not tokens:
            # HTTP with no usable token source fails closed: refuse to boot. The
            # message names the SELECTED source, so it does not point at a
            # variable the operator set under a different, unselected source.
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

    Every token must map to a team policy.yaml defines; a token for an undefined
    team is a boot failure, since it would silently loosen the baseline.
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

    The file is layered over the environment variable. Neither being set yields
    an empty table, which the HTTP path decides whether to treat as an error.
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

    boto3 is imported lazily so the local path and tests never need it. The
    secret is JSON of the same shape as the local source and is never logged.
    """
    secret_id = os.environ.get(SECRET_ID_ENV, "").strip()
    if not secret_id:
        # No secret under this source: an empty table, which the HTTP path turns
        # into a refuse-to-boot. Kept distinct from a load failure.
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

    Rejects a non-object entry, a missing caller or team, or an undefined team.
    Error messages identify a token by its caller/team, never by its value.
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
    """Authenticate the whole MCP session, not just tool calls.

    A Middleware hook misses initialize and tools/list, so this gates them via
    fastmcp's auth seam, delegating to the resolver GateMiddleware holds.
    """

    def __init__(self, resolver: BearerTokenIdentityResolver) -> None:
        # No base_url / resource_base_url on purpose: with neither set, fastmcp
        # registers no oauth-protected-resource route and the 401 advertises no
        # metadata URL, so adding auth opens no new disclosure surface.
        super().__init__()
        self._resolver = resolver

    async def verify_token(self, token: str) -> AccessToken | None:
        """Verify a session-level bearer token via the shared resolver.

        scopes=[] because the gate authorises in the policy engine, not via token
        scopes; GateMiddleware still re-resolves the authoritative identity.
        """
        try:
            identity = self._resolver.authenticate(token)
        except AuthenticationError:
            return None
        return AccessToken(token=token, client_id=identity.caller, scopes=[])
