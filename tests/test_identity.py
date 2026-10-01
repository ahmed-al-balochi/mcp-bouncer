"""Unit tests for the identity seam: token sources, validation, and rejection.
They exercise gate.identity in isolation; the HTTP path is in
test_identity_lifecycle.py. The Secrets Manager source is faked with moto.
"""

from __future__ import annotations

import json
import os
import uuid
from pathlib import Path
from typing import Iterator

import pytest

from gate.identity import (
    IDENTITY_ENV,
    LOCAL_TOKENS_ENV,
    LOCAL_TOKENS_FILE_ENV,
    SECRET_ID_ENV,
    AuthenticationError,
    BearerTokenIdentityResolver,
    Identity,
    IdentityConfigError,
    build_identity_resolver,
)

TEAMS = frozenset({"CustomerChat", "DevChat"})

# A token value used throughout. It is a test fixture, not a real credential.
TOKEN = "tok-customer-000000000000"
TABLE = {TOKEN: {"caller": "customer-agent", "team": "CustomerChat"}}


@pytest.fixture(autouse=True)
def _clean_identity_env(monkeypatch: pytest.MonkeyPatch) -> None:
    """Every test starts from no identity configuration, so one cannot leak in."""
    for name in (IDENTITY_ENV, LOCAL_TOKENS_ENV, LOCAL_TOKENS_FILE_ENV, SECRET_ID_ENV):
        monkeypatch.delenv(name, raising=False)


def _bearer(token: str) -> dict[str, str]:
    return {"authorization": f"Bearer {token}"}


# --- stdio transport ------------------------------------------------------


def test_stdio_trusts_the_caller_argument():
    resolver = build_identity_resolver(
        transport="stdio", caller="agent-1", known_teams=TEAMS
    )
    assert resolver.resolve({}) == Identity(caller="agent-1", team=None)


def test_stdio_with_no_team_runs_on_the_baseline_even_for_an_unknown_caller():
    # The default local run passes a caller that is not a team; that must NOT be
    # a boot failure, or every offline run and the whole in-memory test suite
    # would refuse to start.
    resolver = build_identity_resolver(
        transport="stdio", caller="anonymous", known_teams=frozenset()
    )
    assert resolver.resolve({}).team is None


def test_stdio_with_an_explicit_known_team_applies_it():
    resolver = build_identity_resolver(
        transport="stdio", caller="agent-1", known_teams=TEAMS, team="DevChat"
    )
    assert resolver.resolve({}) == Identity(caller="agent-1", team="DevChat")


def test_stdio_with_an_explicit_unknown_team_refuses_to_boot():
    with pytest.raises(IdentityConfigError) as error:
        build_identity_resolver(
            transport="stdio", caller="agent-1", known_teams=TEAMS, team="Ghost"
        )
    assert "Ghost" in str(error.value)


# --- HTTP transport: rejection paths ---------------------------------


def test_http_with_no_token_source_refuses_to_boot():
    """HTTP with nothing configured must fail closed at boot, not pass all."""
    with pytest.raises(IdentityConfigError):
        build_identity_resolver(transport="http", caller="ignored", known_teams=TEAMS)


def test_a_known_token_resolves_to_its_caller_and_team(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setenv(LOCAL_TOKENS_ENV, json.dumps(TABLE))
    resolver = build_identity_resolver(
        transport="http", caller="ignored", known_teams=TEAMS
    )
    assert resolver.resolve(_bearer(TOKEN)) == Identity(
        caller="customer-agent", team="CustomerChat"
    )


def test_an_unknown_token_is_rejected(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setenv(LOCAL_TOKENS_ENV, json.dumps(TABLE))
    resolver = build_identity_resolver(
        transport="http", caller="ignored", known_teams=TEAMS
    )
    with pytest.raises(AuthenticationError):
        resolver.resolve(_bearer("tok-not-a-real-token"))


@pytest.mark.parametrize(
    "headers",
    [
        pytest.param({}, id="no-header"),
        pytest.param({"authorization": ""}, id="empty"),
        pytest.param({"authorization": "Bearer"}, id="scheme-only"),
        pytest.param({"authorization": "Bearer "}, id="scheme-no-token"),
        pytest.param({"authorization": "Basic abc123"}, id="wrong-scheme"),
        pytest.param({"authorization": TOKEN}, id="token-without-scheme"),
    ],
)
def test_a_missing_or_malformed_header_is_rejected(
    monkeypatch: pytest.MonkeyPatch, headers: dict[str, str]
):
    monkeypatch.setenv(LOCAL_TOKENS_ENV, json.dumps(TABLE))
    resolver = build_identity_resolver(
        transport="http", caller="ignored", known_teams=TEAMS
    )
    with pytest.raises(AuthenticationError):
        resolver.resolve(headers)


def test_every_rejection_gives_the_same_uninformative_message(
    monkeypatch: pytest.MonkeyPatch,
):
    """Anti-enumeration: unknown token and malformed header look identical."""
    monkeypatch.setenv(LOCAL_TOKENS_ENV, json.dumps(TABLE))
    resolver = build_identity_resolver(
        transport="http", caller="ignored", known_teams=TEAMS
    )

    messages = set()
    for headers in ({}, _bearer("wrong"), {"authorization": "Basic x"}):
        try:
            resolver.resolve(headers)
        except AuthenticationError as error:
            messages.add(str(error))
    assert len(messages) == 1


def test_the_rejection_message_never_contains_a_token(
    monkeypatch: pytest.MonkeyPatch,
):
    monkeypatch.setenv(LOCAL_TOKENS_ENV, json.dumps(TABLE))
    resolver = build_identity_resolver(
        transport="http", caller="ignored", known_teams=TEAMS
    )
    try:
        resolver.resolve(_bearer(TOKEN + "-tampered"))
    except AuthenticationError as error:
        assert TOKEN not in str(error)
        assert "tampered" not in str(error)


def test_the_header_name_is_matched_case_insensitively(
    monkeypatch: pytest.MonkeyPatch,
):
    monkeypatch.setenv(LOCAL_TOKENS_ENV, json.dumps(TABLE))
    resolver = build_identity_resolver(
        transport="http", caller="ignored", known_teams=TEAMS
    )
    assert resolver.resolve({"Authorization": f"bearer {TOKEN}"}).caller == "customer-agent"


# --- two tokens, two callers -----------------------------------------


def test_two_tokens_map_to_two_distinct_callers(monkeypatch: pytest.MonkeyPatch):
    table = {
        "tok-a-0000000000000000": {"caller": "customer-agent", "team": "CustomerChat"},
        "tok-b-0000000000000000": {"caller": "dev-agent", "team": "DevChat"},
    }
    monkeypatch.setenv(LOCAL_TOKENS_ENV, json.dumps(table))
    resolver = build_identity_resolver(
        transport="http", caller="ignored", known_teams=TEAMS
    )
    assert resolver.resolve(_bearer("tok-a-0000000000000000")) == Identity(
        "customer-agent", "CustomerChat"
    )
    assert resolver.resolve(_bearer("tok-b-0000000000000000")) == Identity(
        "dev-agent", "DevChat"
    )


# --- local source loading and merging -------------------------------------


def test_a_file_source_is_read(monkeypatch: pytest.MonkeyPatch, tmp_path: Path):
    path = tmp_path / "tokens.json"
    path.write_text(json.dumps(TABLE), encoding="utf-8")
    monkeypatch.setenv(LOCAL_TOKENS_FILE_ENV, str(path))
    resolver = build_identity_resolver(
        transport="http", caller="ignored", known_teams=TEAMS
    )
    assert resolver.resolve(_bearer(TOKEN)).caller == "customer-agent"


def test_the_file_is_layered_over_the_env_var(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
):
    monkeypatch.setenv(
        LOCAL_TOKENS_ENV,
        json.dumps({"tok-env-000000000000": {"caller": "dev-agent", "team": "DevChat"}}),
    )
    path = tmp_path / "tokens.json"
    path.write_text(json.dumps(TABLE), encoding="utf-8")
    monkeypatch.setenv(LOCAL_TOKENS_FILE_ENV, str(path))

    resolver = build_identity_resolver(
        transport="http", caller="ignored", known_teams=TEAMS
    )
    # Both survive the merge.
    assert resolver.resolve(_bearer("tok-env-000000000000")).caller == "dev-agent"
    assert resolver.resolve(_bearer(TOKEN)).caller == "customer-agent"


# --- boot failures: a bad source refuses to start -------------------


def test_malformed_json_refuses_to_boot(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setenv(LOCAL_TOKENS_ENV, "{not valid json")
    with pytest.raises(IdentityConfigError):
        build_identity_resolver(transport="http", caller="ignored", known_teams=TEAMS)


def test_a_token_mapped_to_an_undefined_team_refuses_to_boot(
    monkeypatch: pytest.MonkeyPatch,
):
    """The subtle one: a token for a team policy.yaml does not define is a boot
    failure, because honouring it would apply no team's overrides at all."""
    monkeypatch.setenv(
        LOCAL_TOKENS_ENV,
        json.dumps({TOKEN: {"caller": "customer-agent", "team": "Ghost"}}),
    )
    with pytest.raises(IdentityConfigError) as error:
        build_identity_resolver(transport="http", caller="ignored", known_teams=TEAMS)
    assert "Ghost" in str(error.value)


@pytest.mark.parametrize(
    "entry",
    [
        pytest.param({"team": "DevChat"}, id="missing-caller"),
        pytest.param({"caller": "dev-agent"}, id="missing-team"),
        pytest.param({"caller": "", "team": "DevChat"}, id="empty-caller"),
        pytest.param("just-a-string", id="not-an-object"),
    ],
)
def test_a_malformed_token_entry_refuses_to_boot(
    monkeypatch: pytest.MonkeyPatch, entry: object
):
    monkeypatch.setenv(LOCAL_TOKENS_ENV, json.dumps({TOKEN: entry}))
    with pytest.raises(IdentityConfigError):
        build_identity_resolver(transport="http", caller="ignored", known_teams=TEAMS)


def test_an_unknown_identity_source_refuses_to_boot(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setenv(IDENTITY_ENV, "carrier-pigeon")
    monkeypatch.setenv(LOCAL_TOKENS_ENV, json.dumps(TABLE))
    with pytest.raises(IdentityConfigError):
        build_identity_resolver(transport="http", caller="ignored", known_teams=TEAMS)


# --- Secrets Manager source, faked with moto ------------------------


@pytest.fixture
def _secretsmanager(monkeypatch: pytest.MonkeyPatch) -> Iterator[object]:
    """A moto-faked Secrets Manager client, entirely in-process."""
    region = "us-east-1"
    saved = {
        name: os.environ.get(name)
        for name in (
            "AWS_ACCESS_KEY_ID",
            "AWS_SECRET_ACCESS_KEY",
            "AWS_SESSION_TOKEN",
            "AWS_REGION",
            "AWS_DEFAULT_REGION",
        )
    }
    for name in saved:
        os.environ[name] = "testing"
    os.environ["AWS_REGION"] = region
    os.environ["AWS_DEFAULT_REGION"] = region

    from moto import mock_aws
    import boto3

    try:
        with mock_aws():
            yield boto3.client("secretsmanager", region_name=region)
    finally:
        for name, value in saved.items():
            if value is None:
                os.environ.pop(name, None)
            else:
                os.environ[name] = value


def test_secretsmanager_source_resolves_the_token_table(
    monkeypatch: pytest.MonkeyPatch, _secretsmanager: object
):
    secret_name = f"bouncer/tokens-{uuid.uuid4().hex[:8]}"
    _secretsmanager.create_secret(  # type: ignore[attr-defined]
        Name=secret_name, SecretString=json.dumps(TABLE)
    )
    monkeypatch.setenv(IDENTITY_ENV, "secretsmanager")
    monkeypatch.setenv(SECRET_ID_ENV, secret_name)

    resolver = build_identity_resolver(
        transport="http", caller="ignored", known_teams=TEAMS
    )
    assert resolver.resolve(_bearer(TOKEN)) == Identity(
        caller="customer-agent", team="CustomerChat"
    )


def test_secretsmanager_source_with_a_missing_secret_refuses_to_boot(
    monkeypatch: pytest.MonkeyPatch, _secretsmanager: object
):
    monkeypatch.setenv(IDENTITY_ENV, "secretsmanager")
    monkeypatch.setenv(SECRET_ID_ENV, "bouncer/does-not-exist")
    with pytest.raises(IdentityConfigError):
        build_identity_resolver(transport="http", caller="ignored", known_teams=TEAMS)


def test_secretsmanager_source_with_malformed_json_refuses_to_boot(
    monkeypatch: pytest.MonkeyPatch, _secretsmanager: object
):
    secret_name = f"bouncer/tokens-{uuid.uuid4().hex[:8]}"
    _secretsmanager.create_secret(  # type: ignore[attr-defined]
        Name=secret_name, SecretString="{not json"
    )
    monkeypatch.setenv(IDENTITY_ENV, "secretsmanager")
    monkeypatch.setenv(SECRET_ID_ENV, secret_name)
    with pytest.raises(IdentityConfigError):
        build_identity_resolver(transport="http", caller="ignored", known_teams=TEAMS)


# --- timing-safe comparison (structural check) ----------------------------


def test_resolver_does_not_use_plain_equality_for_tokens():
    """The comparison must be hmac.compare_digest, never ==.
    A timing leak is invisible to a behavioural test, so this reads the match
    method's source and asserts it calls compare_digest and never compares with ==.
    """
    import ast
    import inspect
    import textwrap

    source = textwrap.dedent(inspect.getsource(BearerTokenIdentityResolver._match))
    tree = ast.parse(source)
    func = tree.body[0]
    assert isinstance(func, ast.FunctionDef)
    # Drop the docstring so its prose (which mentions `==` to explain why it is
    # avoided) does not defeat the check; inspect the real statements only.
    if (
        func.body
        and isinstance(func.body[0], ast.Expr)
        and isinstance(func.body[0].value, ast.Constant)
    ):
        func.body = func.body[1:]
    code = ast.unparse(func)
    assert "compare_digest" in code
    assert "==" not in code
    assert "!=" not in code
