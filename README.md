# mcp-bouncer

A governance proxy for [Model Context Protocol](https://modelcontextprotocol.io/)
tool calls. It sits transparently in front of any upstream MCP server, so an agent
talks to the bouncer exactly as it would to the real server — and only calls the
policy allows ever reach it.

Every tool call is classified:

| Class | What happens |
|---|---|
| `read` | passes through |
| `write` | passes through |
| `destructive` | **parked** until a human approves it |
| `unknown` | **denied** — a tool the policy does not recognise |

An approval is one-shot and bound to the exact arguments it was granted for.
Approving `delete_page(title="home")` does nothing for `title="runbook"`, and it
releases exactly one call.

## Why classification follows reversibility

The class boundary is not "does this change something" but **"can this be
undone"**. `wiki.write_page` ships as `write` on the assumption that the store
behind it keeps revision history, so an overwrite is one revert away from
harmless. Point it at a store with no history and the same tool destroys the
previous content — it belongs in `destructive`. That is a one-line change in
`policy.yaml`, never a code change.

## Quickstart

Requires Python 3.10+.

```bash
python3 -m venv .venv && . .venv/bin/activate
pip install -e '.[test]'
pytest
```

The tests are the fastest way to see what the component actually guarantees: a
read passes, an unknown tool is denied, a destructive call parks, an approval
releases exactly one call, a replay is refused, and a poisoned policy engine
blocks everything including reads.

## The demo: park, notify, retry

The point of the bouncer is that a destructive call cannot run until a human says
so. MCP has no "pending" state to model that in, so the gate returns an error
carrying an approval id, a human approves out of band, and the agent retries the
identical call.

**Terminal 1** — run the gate in front of the bundled demo wiki. Over HTTP the
gate needs to know which tokens map to which callers, so hand it one:

```bash
export BOUNCER_TOKENS='{"demo-token":{"caller":"agent-1","team":"DevChat"}}'
bouncer-server --upstream demo/wiki_server.py --transport http --port 8000
```

**Terminal 2** — play the agent, then the operator. Run these from the same
directory, so the `bouncer` CLI reads the same local database the server writes:

```bash
export BOUNCER_DEMO_TOKEN=demo-token

python demo/agent.py wiki.read_page '{"title": "home"}'      # passes
python demo/agent.py wiki.rename_page '{"title": "home", "new_title": "index"}'  # unknown: denied
python demo/agent.py wiki.delete_page '{"title": "home"}'    # parks, prints an id
```

The delete deletes nothing. The gate writes a pending record and returns:

```
APPROVAL_REQUIRED id=ab12cd34ef56 :: wiki.delete_page is classified 'destructive'
and needs human approval before it runs. Ask an approver to run:
bouncer approve ab12cd34ef56 -- then retry this call unchanged.
```

The operator inspects and releases it:

```bash
bouncer list
bouncer approve ab12cd34ef56
```

The agent retries the identical call, it runs once, and the grant is spent. A
second identical call parks again. Try `wiki.delete_page '{"title": "runbook"}'`
with the same approval to see that a grant does not cover different arguments.
`bouncer log` shows the decision trail.

Pass a token the gate does not know and the call is refused before it is ever
classified:

```
BLOCKED_BY_GATE: authentication failed: a valid bearer token is required
```

That message is deliberately uninformative — it does not distinguish an unknown
token from a malformed header, because an attacker should not be able to use the
error text to tell the difference. The token itself never reaches a log line, an
audit record, or an error returned to the caller.

## Teams

A team may override the baseline policy, but **only to tighten it**: raise a
classification, lower its own destructive rate cap, shorten its approval window.
Any attempt to loosen — a softer classification, a higher cap, a longer TTL, or
naming a tool the baseline does not classify — makes the gate refuse to boot.

Two teams ship in `policy.yaml`. `CustomerChat` promotes wiki writes to
`destructive`, because an edit is visible to a customer the moment it lands and
revision history does not undo what someone already saw. `DevChat` keeps writes
passing and only lowers its destructive cap.

Adding a team is one block in `policy.yaml` plus one token. No code change.

## Identity depends on transport

Over **stdio** the client spawned the gate process, so the spawning process's
identity *is* the identity and `--caller` is trusted. Over **HTTP** there is a
network boundary, so an `Authorization: Bearer` token is mandatory for the
**whole MCP session** — a request without a valid token cannot even open a
session, so it can neither `initialize` nor list the tool catalogue, let alone
call a tool. The one exception is the unauthenticated health endpoint (below).
There is no fallback, and if no token source is configured at all, the gate
refuses to boot rather than authenticating nobody and passing everybody.

Two layers enforce this on HTTP, on purpose: the session-level bearer check runs
before the MCP session manager (so `initialize` and `tools/list` are covered),
and the gate's own per-call check re-resolves the same token as defence in
depth. The health endpoint (`/health`) is the sole unauthenticated route; it
returns a fixed `ok` and reveals nothing.

## Optional dependencies

Two optional extras keep the gate's own runtime slim (R44):

- `aws` (`boto3`) — the DynamoDB store and Secrets Manager token source, needed
  only when the gate is deployed. The local SQLite path never installs it.
- `llm-demo` (`openai`, pinned `==3.19.2`) — the `openai` SDK, used only by the
  real-LLM demo agent (`demo/llm_agent.py`), which calls the deployed LiteLLM
  gateway's OpenAI-compatible API. It needs a live Bedrock-backed gateway, so it
  is not part of the gate's runtime and the gate image never installs it. Pinned
  to the newest release that installs cleanly alongside `fastmcp==4.0.1` without
  changing any other dependency (it shares fastmcp's httpx/pydantic stack).

## Layout

```
gate/
  policy.py         pure classify()/decide() — no I/O, unit-testable without mocks
  registry.py       loads and validates policy.yaml; per-team views; refuses bad config
  identity.py       bearer-token authentication and token sources
  storage.py        the store interfaces and the backend factory
  approvals.py      SQLite approvals: one-shot, argument-bound grants
  audit.py          SQLite append-only decision log
  dynamodb_*.py     the same contracts on DynamoDB, for a gate scaled across hosts
  middleware.py     the single on_call_tool hook
  server.py         the FastMCP proxy and the health endpoint
  cli.py            bouncer list | approve | deny | reset | log
demo/               a toy upstream MCP server and a minimal client
terraform/          infrastructure, split into a bootstrap stack and an app stack
policy.yaml         the rules
```

`REQUIREMENTS.md` is the contract this is built against.

## Design notes

- **Unknown tools are denied.** A gate that allows what it cannot classify is not
  a gate.
- **MCP tool annotations escalate only.** `readOnlyHint` and friends come from the
  upstream server, which the gate does not control, and the spec treats them as
  untrusted hints. So a hint may *raise* a classification and never lower one, and
  no hint can rescue an unlisted tool into a permitted class.
- **Fail closed, everywhere.** Any internal error blocks the call, including on
  reads. A classification engine that has thrown cannot trust its own verdict.
- **One-shot grants are claimed, not checked.** The claim is a single atomic
  delete, so of any number of concurrent callers exactly one wins. On DynamoDB
  that is a conditional delete with the expiry check inside the same condition,
  so the guarantee holds across hosts rather than across processes on one file.
- **Storage sits behind a narrow interface.** SQLite is the default so local runs
  and tests stay offline; DynamoDB is selected by one environment variable and the
  middleware never learns which it holds.

## Status

The component, its test suite and the DNS and image infrastructure are done. The
application infrastructure — load balancer, container service, tables, secrets —
and the deployment walkthrough are in progress, as is a fuller design document.

## Not built, on purpose

- **Approver authorisation.** Anyone who can reach the store can approve.
- **Masking.** The gate blocks or parks; it does not redact tool results.
- **Prompt-injection detection** in tool output fed back to a model.
- A UI. The operator surface is a CLI.

## Licence

MIT. See `LICENSE`.
