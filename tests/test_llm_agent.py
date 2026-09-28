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

        def do_POST(self) -> None:  # noqa: N802 (http.server API)
            length = int(self.headers.get("Content-Length", "0"))
            raw = self.rfile.read(length) if length else b""
            recorder.requests.append(
                {
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


# --- what the SDK actually sends -------------------------------------------


def test_request_shape_on_the_wire(server, capsys):
    """The SDK POSTs the exact request the gateway expects (D6.17 shape)."""
    url, recorder = server
    config = llm_agent.load_config(_env(url), require_gate_token=True)

    rc = llm_agent.run(
        config, model="claude-sonnet-5-eu", prompt="Read the home page.", with_gate_token=True
    )
    assert rc == 0

    assert len(recorder.requests) == 1
    req = recorder.requests[0]

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
    assert recorder.requests[0]["body"]["model"] == "some-other-model"


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
    """--without-gate-token: the request carries NO gate-token header at all."""
    url, recorder = server
    # No token in env, and the flag lets config load anyway.
    config = llm_agent.load_config(_env(url, token=None), require_gate_token=False)
    rc = llm_agent.run(
        config, model="claude-sonnet-5-eu", prompt="hi", with_gate_token=False
    )
    assert rc == 0

    req = recorder.requests[0]
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
    assert len(recorder.requests) == 1
