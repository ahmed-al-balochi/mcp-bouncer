"""Offline tests for the real-LLM demo agent (demo/llm_agent.py).

They point the real openai SDK at a stdlib fake server on loopback and assert on
what the SDK actually sent, proving its real pass-through behaviour. Fully offline.
"""

from __future__ import annotations

import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any, Iterator

import pytest

from demo import llm_agent

# A key and token with recognisable, unique substrings so a leak is unmistakable
# in any captured output.
FAKE_KEY = "sk-fake-master-key-DO-NOT-LEAK-abc123"
FAKE_TOKEN = "gate-token-DO-NOT-LEAK-xyz789"


class _Recorder:
    """Shared state between the test and the fake server thread.

    Records every request the server saw and holds the scripted response(s). The
    tests read it only after the client call returns.
    """

    def __init__(self) -> None:
        self.requests: list[dict[str, Any]] = []
        # Default response: a minimal but valid chat.completion the SDK can parse.
        self.status_sequence: list[int] = [200]
        self.body: dict[str, Any] = _completion("done")
        # For the redaction test: an error body that echoes the secrets back.
        self.error_body: dict[str, Any] = {"error": {"message": "boom"}}
        # Preflight (GET /mcp-rest/tools/list) scripting. By default one bouncer
        # tool is reported, so the preflight passes and completion proceeds. A
        # test sets preflight_status to a 4xx/5xx or preflight_tools to [].
        self.preflight_status: int = 200
        self.preflight_tools: list[dict[str, Any]] = [
            {"name": "wiki.read_page", "mcp_info": {"server_name": "bouncer"}}
        ]


def _completion(content: str) -> dict[str, Any]:
    """A minimal OpenAI chat.completion object the SDK will parse without error."""
    return {
        "id": "chatcmpl-test",
        "object": "chat.completion",
        "created": 0,
        "model": "claude-sonnet-5-eu",
        "choices": [
            {
                "index": 0,
                "message": {"role": "assistant", "content": content},
                "finish_reason": "stop",
            }
        ],
    }


def _make_handler(recorder: _Recorder):
    class Handler(BaseHTTPRequestHandler):
        # Silence the default stderr access log so test output stays clean.
        def log_message(self, *args: Any) -> None:  # noqa: D401
            return

        def do_GET(self) -> None:  # noqa: N802 (http.server API)
            # The only GET the agent makes is the preflight to
            # /mcp-rest/tools/list. Record it, then answer per the recorder.
            recorder.requests.append(
                {
                    "method": "GET",
                    "path": self.path,
                    "headers": {k.lower(): v for k, v in self.headers.items()},
                    "body": None,
                }
            )
            status = recorder.preflight_status
            if status == 200:
                payload: dict[str, Any] = {
                    "tools": recorder.preflight_tools,
                    "error": None,
                    "message": "Successfully retrieved tools",
                }
            else:
                payload = {"error": {"message": "preflight error"}}
            data = json.dumps(payload).encode()
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)

        def do_POST(self) -> None:  # noqa: N802 (http.server API)
            length = int(self.headers.get("Content-Length", "0"))
            raw = self.rfile.read(length) if length else b""
            recorder.requests.append(
                {
                    "method": "POST",
                    "path": self.path,
                    "headers": {k.lower(): v for k, v in self.headers.items()},
                    "body": json.loads(raw) if raw else None,
                }
            )
            # Pop the next scripted status; keep the last one once exhausted so a
            # single-500 script becomes 500 then 200 on any (disallowed) retry.
            if len(recorder.status_sequence) > 1:
                status = recorder.status_sequence.pop(0)
            else:
                status = recorder.status_sequence[0]

            if status == 200:
                payload = recorder.body
            else:
                payload = recorder.error_body
            data = json.dumps(payload).encode()
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)

    return Handler


@pytest.fixture
def server() -> Iterator[tuple[str, _Recorder]]:
    """Run the fake OpenAI server on a free loopback port; yield its base URL.

    The base URL ends in /v1, matching gateway_openai_base_url, so the SDK POSTs
    to /v1/chat/completions.
    """
    recorder = _Recorder()
    httpd = ThreadingHTTPServer(("127.0.0.1", 0), _make_handler(recorder))
    thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    thread.start()
    host, port = httpd.server_address[0], httpd.server_address[1]
    try:
        yield f"http://{host}:{port}/v1", recorder
    finally:
        httpd.shutdown()
        httpd.server_close()
        thread.join(timeout=5)


def _env(url: str, *, token: str | None = FAKE_TOKEN) -> dict[str, str]:
    env = {
        llm_agent.GATEWAY_URL_ENV: url,
        llm_agent.GATEWAY_KEY_ENV: FAKE_KEY,
    }
    if token is not None:
        env[llm_agent.TOKEN_ENV] = token
    return env


def _posts(recorder: _Recorder) -> list[dict[str, Any]]:
    """The completion requests (POST /v1/chat/completions) the server recorded.

    Filtering by method keeps the completion assertions independent of the
    preflight GET that now precedes every completion by default.
    """
    return [r for r in recorder.requests if r["method"] == "POST"]


def _gets(recorder: _Recorder) -> list[dict[str, Any]]:
    """The preflight requests (GET /mcp-rest/tools/list) the server recorded."""
    return [r for r in recorder.requests if r["method"] == "GET"]


# --- what the SDK actually sends -------------------------------------------


def test_request_shape_on_the_wire(server, capsys):
    """The SDK POSTs the exact request the gateway expects."""
    url, recorder = server
    config = llm_agent.load_config(_env(url), require_gate_token=True)

    rc = llm_agent.run(
        config, model="claude-sonnet-5-eu", prompt="Read the home page.", with_gate_token=True
    )
    assert rc == 0

    # Exactly one completion request (the preflight GET precedes it, asserted in
    # its own test). Filter by method so this stays about the completion shape.
    posts = _posts(recorder)
    assert len(posts) == 1
    req = posts[0]

    # Path: the SDK appends /chat/completions to the /v1 base_url.
    assert req["path"] == "/v1/chat/completions"

    # Auth header carries the master key, not the gate token.
    assert req["headers"]["authorization"] == f"Bearer {FAKE_KEY}"

    body = req["body"]
    assert body["model"] == "claude-sonnet-5-eu"
    assert body["messages"] == [
        {"role": "system", "content": llm_agent.SYSTEM_PROMPT},
        {"role": "user", "content": "Read the home page."},
    ]

    # The MCP tool block survives the SDK unchanged: the pass-through of a LiteLLM
    # extension the SDK does not type, proven on the real wire.
    assert body["tools"] == [
        {
            "type": "mcp",
            "server_label": "bouncer",
            "server_url": "litellm_proxy/mcp/bouncer",
            "require_approval": "never",
            "headers": {llm_agent.GATE_TOKEN_HEADER: f"Bearer {FAKE_TOKEN}"},
        }
    ]

    # No temperature: Sonnet 5 rejects it, so the agent must not send one.
    assert "temperature" not in body

    # The model's answer reached stdout.
    assert capsys.readouterr().out.strip() == "done"


def test_model_flag_passes_through(server, capsys):
    """--model reaches the request body verbatim (a demonstration lever)."""
    url, recorder = server
    config = llm_agent.load_config(_env(url), require_gate_token=True)
    rc = llm_agent.run(
        config, model="some-other-model", prompt="hi", with_gate_token=True
    )
    assert rc == 0
    assert _posts(recorder)[0]["body"]["model"] == "some-other-model"


# --- config errors ---------------------------------------------------------


@pytest.mark.parametrize(
    "missing_var",
    [llm_agent.GATEWAY_URL_ENV, llm_agent.GATEWAY_KEY_ENV, llm_agent.TOKEN_ENV],
)
def test_missing_env_var_refuses_and_names_it(server, missing_var):
    """Each missing variable raises ConfigError naming it, never printing a value."""
    url, _ = server
    env = _env(url)
    del env[missing_var]

    with pytest.raises(llm_agent.ConfigError) as excinfo:
        llm_agent.load_config(env, require_gate_token=True)

    message = str(excinfo.value)
    assert missing_var in message
    # The values themselves must never appear in the message.
    assert FAKE_KEY not in message
    assert FAKE_TOKEN not in message


def test_main_missing_var_exits_nonzero_without_value(server, monkeypatch, capsys):
    """Through main(): a missing var exits non-zero; the key never prints."""
    url, _ = server
    monkeypatch.setattr(
        llm_agent.os, "environ", {llm_agent.GATEWAY_URL_ENV: url}
    )  # key and token absent
    rc = llm_agent.main(["a prompt"])
    assert rc == 2
    captured = capsys.readouterr()
    assert llm_agent.GATEWAY_KEY_ENV in captured.err
    assert FAKE_KEY not in captured.err


# --- the gate token requirement ------------------------------------


def test_missing_gate_token_refuses_by_default(server):
    """Gate token is required by default: its absence refuses to run."""
    url, _ = server
    env = _env(url, token=None)
    with pytest.raises(llm_agent.ConfigError) as excinfo:
        llm_agent.load_config(env, require_gate_token=True)
    assert llm_agent.TOKEN_ENV in str(excinfo.value)
    assert "--without-gate-token" in str(excinfo.value)


def test_without_gate_token_sends_no_gate_header_anywhere(server, capsys):
    """--without-gate-token: NO preflight, and the request carries NO gate header.
    Mirrors main()'s wiring: the flag skips the preflight (expecting zero tools)
    and sends no gate-token header anywhere, so that path stays intact.
    """
    url, recorder = server
    # No token in env, and the flag lets config load anyway.
    config = llm_agent.load_config(_env(url, token=None), require_gate_token=False)
    rc = llm_agent.run(
        config,
        model="claude-sonnet-5-eu",
        prompt="hi",
        with_gate_token=False,
        preflight=False,
    )
    assert rc == 0

    # No preflight GET was made (the whole point under --without-gate-token).
    assert _gets(recorder) == []

    # The completion still went out.
    posts = _posts(recorder)
    assert len(posts) == 1
    req = posts[0]
    # The tool block exists but has no headers key.
    tool = req["body"]["tools"][0]
    assert tool["type"] == "mcp"
    assert "headers" not in tool

    # And the gate-token header appears nowhere in the HTTP headers either.
    for name in req["headers"]:
        assert llm_agent.GATE_TOKEN_HEADER not in name.lower()


# --- error handling and redaction ------------------------------------------


def test_bad_request_unknown_model_is_a_clean_stderr_line(server, capsys):
    """A 400 (e.g. 'Invalid model name') gives one clear stderr line, non-zero."""
    url, recorder = server
    recorder.status_sequence = [400]
    recorder.error_body = {"error": {"message": "Invalid model name: bogus"}}

    config = llm_agent.load_config(_env(url), require_gate_token=True)
    rc = llm_agent.run(
        config, model="bogus", prompt="hi", with_gate_token=True
    )
    assert rc == 1
    captured = capsys.readouterr()
    assert "400" in captured.err
    assert "Invalid model name" in captured.err
    assert captured.out == ""


def test_401_message_and_secrets_never_leak_even_when_echoed(server, capsys):
    """A 401 whose body echoes the key and token gives a clear line, secrets redacted."""
    url, recorder = server
    recorder.status_sequence = [401]
    # The server echoes both secrets back in its error body, as a hostile or
    # careless gateway might.
    recorder.error_body = {
        "error": {
            "message": (
                f"auth failed for Authorization: Bearer {FAKE_KEY} and header "
                f"Bearer {FAKE_TOKEN}"
            )
        }
    }

    config = llm_agent.load_config(_env(url), require_gate_token=True)
    rc = llm_agent.run(
        config, model="claude-sonnet-5-eu", prompt="hi", with_gate_token=True
    )
    assert rc == 1
    captured = capsys.readouterr()
    assert "401" in captured.err
    # Neither secret survives anywhere in stdout or stderr.
    assert FAKE_KEY not in captured.err
    assert FAKE_KEY not in captured.out
    assert FAKE_TOKEN not in captured.err
    assert FAKE_TOKEN not in captured.out


def test_max_retries_zero_means_exactly_one_request(server, capsys):
    """A single 500 means exactly ONE request received, no auto-retry.

    If max_retries were left at the SDK default of 2, the SDK would resend on the
    5xx and the server would record more than one request, failing this.
    """
    url, recorder = server
    recorder.status_sequence = [500]
    recorder.error_body = {"error": {"message": "internal"}}

    config = llm_agent.load_config(_env(url), require_gate_token=True)
    rc = llm_agent.run(
        config, model="claude-sonnet-5-eu", prompt="hi", with_gate_token=True
    )
    assert rc == 1
    assert len(_posts(recorder)) == 1


# --- the preflight ---------------------------------------------------------


def test_preflight_carries_master_key_and_gate_token(server, capsys):
    """The preflight GET sends the gateway key as bearer AND the gate-token header.

    This makes the preflight test the same credentials the tool call uses. Not
    vacuous: dropping either header fails the matching assertion below.
    """
    url, recorder = server
    config = llm_agent.load_config(_env(url), require_gate_token=True)

    rc = llm_agent.run(
        config, model="claude-sonnet-5-eu", prompt="hi", with_gate_token=True
    )
    assert rc == 0

    gets = _gets(recorder)
    assert len(gets) == 1
    pf = gets[0]

    # Exact path and query the LiteLLM REST route expects.
    assert pf["path"] == "/mcp-rest/tools/list?mcp_server_name=bouncer"
    # Master key as the request bearer (the route's auth dependency).
    assert pf["headers"]["authorization"] == f"Bearer {FAKE_KEY}"
    # Gate token in the per-server MCP auth header (parsed off request.headers).
    assert pf["headers"][llm_agent.GATE_TOKEN_HEADER] == f"Bearer {FAKE_TOKEN}"

    # The completion still went out after a satisfied preflight.
    assert len(_posts(recorder)) == 1


def test_preflight_zero_tools_refuses_before_any_completion(server, capsys):
    """Zero bouncer tools means exit non-zero and NO completion request at all.

    The core fix: the model is never asked when it would have no tools. Not
    vacuous: empty _posts fails on fall-through, rc==1 fails if it did not refuse.
    """
    url, recorder = server
    recorder.preflight_tools = []  # gateway reports no bouncer tools

    config = llm_agent.load_config(_env(url), require_gate_token=True)
    rc = llm_agent.run(
        config, model="claude-sonnet-5-eu", prompt="hi", with_gate_token=True
    )
    assert rc == 1

    # A preflight GET happened, but NO completion POST.
    assert len(_gets(recorder)) == 1
    assert _posts(recorder) == []

    captured = capsys.readouterr()
    # The message names neither the key nor the token.
    assert FAKE_KEY not in captured.err
    assert FAKE_TOKEN not in captured.err
    # It is actionable and does not guess the cause: it names both likely causes.
    assert "no tools" in captured.err.lower()
    assert "rotated" in captured.err.lower()
    assert "unreachable" in captured.err.lower()
    assert captured.out == ""


def test_preflight_401_refuses_with_distinct_message(server, capsys):
    """A preflight 401 gives non-zero, a credential-rejection message, no completion.

    Not vacuous: rc==1 fails if the agent proceeded, and the 'credential' wording
    and empty _posts assertion fail if the wrong branch ran or the model was asked.
    """
    url, recorder = server
    recorder.preflight_status = 401

    config = llm_agent.load_config(_env(url), require_gate_token=True)
    rc = llm_agent.run(
        config, model="claude-sonnet-5-eu", prompt="hi", with_gate_token=True
    )
    assert rc == 1
    assert _posts(recorder) == []

    captured = capsys.readouterr()
    assert "401" in captured.err
    assert "credential" in captured.err.lower()
    # Distinct from the 404 message: it must NOT talk about a version skew.
    assert "version skew" not in captured.err.lower()
    # It must name BOTH candidate credentials, not just the gateway key: a gate
    # token the gate rejects surfaces as 401 here too, so blaming only the gateway
    # key would misdirect the rotation case. The two are indistinguishable here.
    assert "gate token" in captured.err.lower()
    assert "gateway key" in captured.err.lower()
    assert FAKE_KEY not in captured.err
    assert FAKE_TOKEN not in captured.err
    assert captured.out == ""


def test_preflight_404_says_route_may_be_absent(server, capsys):
    """A preflight 404 gives non-zero, a version-skew message, no completion.

    A 404 should say the gateway may not expose this experimental route, distinct
    from the 401 message, and the empty _posts assertion proves the model is spared.
    """
    url, recorder = server
    recorder.preflight_status = 404

    config = llm_agent.load_config(_env(url), require_gate_token=True)
    rc = llm_agent.run(
        config, model="claude-sonnet-5-eu", prompt="hi", with_gate_token=True
    )
    assert rc == 1
    assert _posts(recorder) == []

    captured = capsys.readouterr()
    assert "404" in captured.err
    assert "version skew" in captured.err.lower()
    assert captured.out == ""


def test_preflight_connection_error_refuses(capsys):
    """A preflight that cannot connect gives non-zero and a connection message.

    Pointing at a closed port makes the GET raise a ConnectError. The message must
    be the connection-failure wording, not the zero-tools wording, pinning that branch.
    """
    # 127.0.0.1:1 has nothing listening; the SDK's short connect timeout applies.
    config = llm_agent.load_config(
        _env("http://127.0.0.1:1/v1"), require_gate_token=True
    )
    rc = llm_agent.run(
        config, model="claude-sonnet-5-eu", prompt="hi", with_gate_token=True
    )
    assert rc == 1
    captured = capsys.readouterr()
    # Connection-specific wording, distinct from the zero-tools message.
    assert "could not reach" in captured.err.lower()
    assert "no tools" not in captured.err.lower()
    assert FAKE_KEY not in captured.err
    assert FAKE_TOKEN not in captured.err
    assert captured.out == ""


def test_no_preflight_flag_skips_the_preflight(server, capsys):
    """--no-preflight (preflight=False) sends the completion with NO preflight GET.

    Even with zero tools reported, it proceeds to the model, the documented escape
    hatch. Not vacuous: empty _gets fails if the preflight ran.
    """
    url, recorder = server
    recorder.preflight_tools = []  # would refuse if the preflight ran

    config = llm_agent.load_config(_env(url), require_gate_token=True)
    rc = llm_agent.run(
        config,
        model="claude-sonnet-5-eu",
        prompt="hi",
        with_gate_token=True,
        preflight=False,
    )
    assert rc == 0
    assert _gets(recorder) == []
    assert len(_posts(recorder)) == 1


def test_preflight_url_derivation():
    """preflight_url strips a trailing /v1 and targets the origin sibling path.

    Not vacuous: each assertion pins a specific derivation, so a regression that
    kept /v1 or hardcoded a host changes the output and fails here.
    """
    assert (
        llm_agent.preflight_url("https://llm.example.com/v1")
        == "https://llm.example.com/mcp-rest/tools/list"
    )
    assert (
        llm_agent.preflight_url("https://llm.example.com/v1/")
        == "https://llm.example.com/mcp-rest/tools/list"
    )
    # Host is never hardcoded: a different host flows straight through.
    assert (
        llm_agent.preflight_url("http://127.0.0.1:4000/v1")
        == "http://127.0.0.1:4000/mcp-rest/tools/list"
    )


def test_main_skips_the_preflight_only_for_without_gate_token(server, monkeypatch, capsys):
    """main() wires --without-gate-token to preflight=False, and nothing else to it.

    The other tests call run() directly, so this drives the real entry point and
    pins both branches, which a dropped wiring term would silently break.
    """
    url, recorder = server  # the fixture default advertises a bouncer tool
    for key, value in _env(url, token=FAKE_TOKEN).items():
        monkeypatch.setenv(key, value)

    # Without-gate-token path: no preflight GET, but the completion is still sent.
    assert llm_agent.main(["--without-gate-token", "hi"]) == 0
    assert _gets(recorder) == []
    assert len(_posts(recorder)) == 1

    # Default path: the preflight DOES run (the same wiring, the other branch).
    recorder.requests.clear()
    assert llm_agent.main(["hi"]) == 0
    assert len(_gets(recorder)) == 1
    assert len(_posts(recorder)) == 1
