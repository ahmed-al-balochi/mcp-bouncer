"""Offline tests for the real-LLM demo agent (demo/llm_agent.py).

The agent's whole job is to put the right bytes on the wire: the OpenAI
chat-completions request the LiteLLM gateway expects, with the bouncer MCP tool
block unchanged and the agent's gate token forwarded, and to keep secrets out of
every output. None of that needs a real gateway to verify -- it needs to observe
what the SDK actually sends.

So these tests stand up a fake OpenAI-compatible server on 127.0.0.1 with the
standard library's `http.server` in a thread (no new test dependency, R44) and
point the *real* openai SDK at it via `base_url`. Every assertion is on what the
SDK sent or how the agent behaved -- never on a mock of the SDK -- so the tests
prove the SDK's real pass-through behaviour, which is the part that is otherwise
UNVERIFIED until the live G3 run.

Fully offline: the server binds loopback, nothing leaves the host, and the
agent's config comes from an explicit env dict, never the ambient environment.
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

    Records every request the server saw and holds the scripted response(s). A
    plain object guarded by the server's single-request-at-a-time handling; the
    tests read it only after the client call returns.
    """

    def __init__(self) -> None:
        self.requests: list[dict[str, Any]] = []
        # Default response: a minimal but valid chat.completion the SDK can parse.
        self.status_sequence: list[int] = [200]
        self.body: dict[str, Any] = _completion("done")
        # For the redaction test: an error body that echoes the secrets back.
        self.error_body: dict[str, Any] = {"error": {"message": "boom"}}
        # Preflight (GET /mcp-rest/tools/list) scripting. By default the gateway
        # reports one bouncer tool, so the preflight is satisfied and completion
        # proceeds -- this keeps the pre-existing completion tests passing (D6.22).
        # A test sets preflight_status to a 4xx/5xx to exercise the error paths,
        # or preflight_tools to [] to exercise the zero-tools refusal.
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
            # /mcp-rest/tools/list (D6.22). Record it (path + headers) so tests
            # can assert the credentials it carried, then answer per the recorder.
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

    The base URL ends in /v1, matching what terraform's gateway_openai_base_url
    emits and what the agent expects, so the SDK POSTs to /v1/chat/completions.
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
    preflight GET, which now precedes every completion by default (D6.22).
    """
    return [r for r in recorder.requests if r["method"] == "POST"]


def _gets(recorder: _Recorder) -> list[dict[str, Any]]:
    """The preflight requests (GET /mcp-rest/tools/list) the server recorded."""
    return [r for r in recorder.requests if r["method"] == "GET"]


# --- what the SDK actually sends -------------------------------------------


def test_request_shape_on_the_wire(server, capsys):
    """The SDK POSTs the exact request the gateway expects (D6.17 shape)."""
    url, recorder = server
    config = llm_agent.load_config(_env(url), require_gate_token=True)

    rc = llm_agent.run(
        config, model="claude-sonnet-5-eu", prompt="Read the home page.", with_gate_token=True
    )
    assert rc == 0

    # Exactly one completion request (the preflight GET precedes it; asserted in
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

    # The MCP tool block survives the SDK unchanged -- this is the pass-through
    # of a LiteLLM extension the SDK does not type, proven on the real wire.
    assert body["tools"] == [
        {
            "type": "mcp",
            "server_label": "bouncer",
            "server_url": "litellm_proxy/mcp/bouncer",
            "require_approval": "never",
            "headers": {llm_agent.GATE_TOKEN_HEADER: f"Bearer {FAKE_TOKEN}"},
        }
    ]

    # No temperature: Sonnet 5 rejects it (D6.5); the agent must not send one.
    assert "temperature" not in body

    # The model's answer reached stdout.
    assert capsys.readouterr().out.strip() == "done"


def test_model_flag_passes_through(server, capsys):
    """--model reaches the request body verbatim (A14 demonstration lever)."""
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
    """Each missing variable -> ConfigError naming it, never printing a value."""
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


# --- the gate token requirement and A16 ------------------------------------


def test_missing_gate_token_refuses_by_default(server):
    """Gate token is required by default: its absence refuses to run (A16)."""
    url, _ = server
    env = _env(url, token=None)
    with pytest.raises(llm_agent.ConfigError) as excinfo:
        llm_agent.load_config(env, require_gate_token=True)
    assert llm_agent.TOKEN_ENV in str(excinfo.value)
    assert "--without-gate-token" in str(excinfo.value)


def test_without_gate_token_sends_no_gate_header_anywhere(server, capsys):
    """--without-gate-token: NO preflight, and the request carries NO gate header.

    Mirrors main()'s wiring: --without-gate-token skips the preflight (A16 expects
    zero tools, so a preflight would correctly refuse and defeat the demo, D6.22)
    and sends no gate-token header anywhere. Proves the A16 path stays intact.
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
    """A 400 (e.g. 'Invalid model name') -> one clear stderr line, non-zero."""
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
    """A 401 whose body echoes the key and token -> clear line, secrets redacted."""
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
    """A single 500 -> exactly ONE request received (no auto-retry). D6.17.

    Mutation-sensitive by construction: if max_retries were left at the SDK
    default of 2, the SDK would resend on the 5xx and the server would record
    more than one request, failing this assertion.
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


# --- the preflight (D6.22) -------------------------------------------------


def test_preflight_carries_master_key_and_gate_token(server, capsys):
    """The preflight GET sends the gateway key as bearer AND the gate-token header.

    This is the property that makes the preflight test the SAME credential the
    tool call uses (D6.22): the LiteLLM master key as the request Authorization
    bearer (the REST route's user_api_key_auth), and the gate token in the
    x-mcp-bouncer-authorization header the REST handler parses off request.headers.

    Not vacuous: if the preflight omitted either header, the corresponding
    assertion below would fail. Verified by temporarily dropping each header from
    preflight_tool_names -> this test failed on that header.
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

    # Exact path and query the LiteLLM REST route expects (rest_endpoints.py:858).
    assert pf["path"] == "/mcp-rest/tools/list?mcp_server_name=bouncer"
    # Master key as the request bearer (the route's Depends(user_api_key_auth)).
    assert pf["headers"]["authorization"] == f"Bearer {FAKE_KEY}"
    # Gate token in the per-server MCP auth header (parsed off request.headers).
    assert pf["headers"][llm_agent.GATE_TOKEN_HEADER] == f"Bearer {FAKE_TOKEN}"

    # The completion still went out after a satisfied preflight.
    assert len(_posts(recorder)) == 1


def test_preflight_zero_tools_refuses_before_any_completion(server, capsys):
    """Zero bouncer tools -> exit non-zero, NO completion request at all (D6.22).

    The core D6.21 fix: the model is never asked when it would have no tools.

    Not vacuous: the assertion that _posts(recorder) is empty fails if the agent
    fell through to the model; the rc==1 assertion fails if it did not refuse.
    Verified by temporarily making preflight_or_raise return on empty -> this
    test failed (a completion POST appeared and rc was 0).
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
    """A preflight 401 -> non-zero, a credential-rejection message, no completion.

    Not vacuous: rc==1 fails if the agent proceeded; the 'credential' wording and
    the empty _posts assertion fail if the wrong branch ran or the model was
    asked. Verified by pointing preflight_status at 200 -> this test failed.
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
    # It must name BOTH candidate credentials, not just the gateway key: measured
    # live, a gate token the gate rejects surfaces as 401 on this route, so a
    # message blaming only the gateway key would misdirect the rotation case
    # (D6.23). The two are indistinguishable from here.
    assert "gate token" in captured.err.lower()
    assert "gateway key" in captured.err.lower()
    assert FAKE_KEY not in captured.err
    assert FAKE_TOKEN not in captured.err
    assert captured.out == ""


def test_preflight_404_says_route_may_be_absent(server, capsys):
    """A preflight 404 -> non-zero, a version-skew message, no completion (D6.22).

    A 404 specifically should say the gateway may not expose this experimental
    route (a plausible upstream change), distinct from the 401 message.

    Not vacuous: the 'version skew' wording fails if the 404 branch did not run;
    the empty _posts assertion fails if the model was asked. Verified by pointing
    preflight_status at 200 -> this test failed.
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
    """A preflight that cannot connect -> non-zero, connection-specific message.

    Points the agent at a closed port (nothing listening) so the httpx2 GET
    raises a ConnectError, which preflight_tool_names must turn into a
    PreflightError rather than letting the run proceed to the model.

    Not vacuous, and distinct from the zero-tools path: the message must be the
    connection-failure wording ("could not reach"), NOT the zero-tools wording.
    Verified by replacing the httpx2.HTTPError branch's `raise` with `return []`
    -- that made preflight_or_raise raise the ZERO-TOOLS message instead, so the
    "could not reach" assertion below failed. So this test pins the connection
    branch specifically, not merely a non-zero exit.
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

    Even when the gateway would report zero tools, --no-preflight proceeds to the
    model -- the documented escape hatch (D6.22).

    Not vacuous: the empty _gets assertion fails if the preflight ran anyway; the
    single-POST assertion fails if the completion did not go out. Verified by
    flipping preflight back to True here -> this test failed (a GET appeared and,
    with zero tools, no POST did).
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

    Not vacuous: each assertion pins a specific derivation; a regression that
    kept /v1 in the path, or hardcoded a host, changes the output and fails here.
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
    """main() must wire --without-gate-token to preflight=False, and nothing else to it.

    The other tests call run() directly, so a regression that dropped the
    `and not args.without_gate_token` term would leave them all green while
    silently breaking A16's demonstration: the preflight would refuse (zero tools
    is the expected state there) and the model would never be asked. This drives
    the real entry point instead, and pins the default the other way round too.
    """
    url, recorder = server  # the fixture default advertises a bouncer tool
    for key, value in _env(url, token=FAKE_TOKEN).items():
        monkeypatch.setenv(key, value)

    # A16 path: no preflight GET, but the completion is still sent.
    assert llm_agent.main(["--without-gate-token", "hi"]) == 0
    assert _gets(recorder) == []
    assert len(_posts(recorder)) == 1

    # Default path: the preflight DOES run (the same wiring, the other branch).
    recorder.requests.clear()
    assert llm_agent.main(["hi"]) == 0
    assert len(_gets(recorder)) == 1
    assert len(_posts(recorder)) == 1
