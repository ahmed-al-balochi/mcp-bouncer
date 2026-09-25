# mcp-bouncer — Requirements

The contract for this project. Implementer agents build against it; the reviewer
agent checks work against it. If a requirement here is wrong, fix it here first
rather than deviating in code.

Status: DRAFT — awaiting owner sign-off.

---

## 1. What this is

An MCP (Model Context Protocol) governance proxy, deployed as a working proof of
concept on AWS. Every tool call an agent makes is classified as `read`, `write`,
or `destructive`. Reads and writes pass. Tools the policy does not recognise are
`unknown` and denied. Destructive calls are parked until a human approves them.

It is a **POC**, not a product. Small and complete beats large and half done.
A reviewer must be able to clone the repo, read one README, and either run it
locally in two minutes or deploy it with two `terraform apply` commands.

## 2. Non-negotiables

- **R1** No reference anywhere — code, docs, comments, commit messages, git
  history — to the case study this originated from, its author's employer, or
  any company name. The repo starts with fresh git history.
- **R2** No secrets in the repository. No bearer tokens, no account IDs, no
  domain names, no IP addresses committed. All of it is configuration.
- **R3** No hardcoded domain. The domain and subdomain are Terraform variables
  and runtime environment variables. A reader supplies their own.
- **R4** MIT licence.
- **R5** Inclusive language throughout. `allowlist`, never the other word.
- **R6** The existing 68 tests keep passing. Behaviour changes require the test
  that proves them.

## 3. Behaviour that must be preserved

These are the semantics the component already has and its whole value rests on.
None may regress.

- **R7** Classification follows **reversibility**, not mutation. A write to a
  versioned store is `write`; the same write to a store with no history is
  `destructive`. This is a policy decision, expressed in configuration, never in
  code.
- **R8** Unknown tools are **denied by default**. A tool matching no policy entry
  is `unknown` and blocked. A gate that allows what it cannot classify is not a
  gate.
- **R9** MCP tool annotations (`readOnlyHint`, `destructiveHint`,
  `idempotentHint`) come from the upstream server and are **untrusted**. They may
  only **raise** a classification, never lower one. No annotation can promote an
  unlisted tool into a permitted class.
- **R10** **Park, notify, retry.** MCP has no pending state, so a destructive
  call returns an error carrying an approval id and the exact command a human
  runs to release it. The agent retries the identical call.
- **R11** Grants are **one-shot and argument-bound**: keyed to
  `sha256(caller + tool + canonical-JSON arguments)`, claimed atomically, so a
  grant releases exactly one call and never twice, even under concurrency.
  Approving `delete(page=7)` does nothing for `delete(page=8)`.
- **R12** Grants **expire** after a TTL set in policy.
- **R13** **Fail closed, everywhere.** Any internal exception, for any
  classification including reads, blocks the call. There is no fail-open path.
- **R14** A per-caller **destructive rate cap** over a rolling hour. Beyond it,
  destructive calls are blocked until a human explicitly resets that caller.
- **R15** An **append-only** decision log. Every decision is recorded with
  caller, tool, classification, decision, and argument hash. No update or delete
  path exists.
- **R16** The policy engine stays **pure**: no I/O, no third-party imports, no
  global mutable state, unit-testable without mocks.
- **R17** The gate **refuses to boot** on a policy it cannot fully validate.
  There is no partially-applied policy.

## 4. New functional requirements

### 4.1 Identity

- **R18** Callers authenticate with a bearer token. The token maps to a caller
  identity; an unknown or missing token is rejected before classification.
  Over HTTP this covers the whole MCP session, including `initialize` and
  catalogue listing, not only tool calls; the health endpoint (R31) is the sole
  unauthenticated route.
- **R19** Tokens are never in the repo, never in the image, and never in
  Terraform state as plaintext input. They are generated at provision time and
  stored in AWS Secrets Manager. The container receives the secret's ARN or name
  by environment variable and resolves it at boot.
- **R20** The local development path must still work without AWS. A file or
  environment-variable token source is acceptable for local use, selected by
  configuration.
- **R21** Replacing the identity mechanism must remain a single seam. The
  authenticated identity flows into the policy decision; no other module learns
  how authentication works.

### 4.2 Per-team policy

- **R22** `policy.yaml` gains a `teams:` section. A team may override tool
  classifications and limits.
- **R23** Overrides may only **tighten**, never loosen. A team may raise
  `write` to `destructive` or lower its own destructive cap; it may not lower a
  classification or raise its cap above the baseline. Attempting to loosen is a
  policy validation failure and the gate refuses to boot.
- **R24** Two teams ship in the default policy: **CustomerChat** (customer
  facing, tightest posture) and **DevChat** (internal tooling, more latitude).
- **R25** Adding a team is a documented two-step operation: one block in
  `policy.yaml` and one token. No code change, no redeploy of anything but
  configuration.

### 4.3 Storage

- **R26** A DynamoDB-backed approval store, selected by environment variable,
  behind the **existing** `ApprovalStore` interface. If the interface needs to
  change to accommodate it, that is a finding worth reporting, not a silent
  edit.
- **R27** The one-shot guarantee on DynamoDB is a **conditional delete**, so it
  holds across many concurrent tasks, not just many processes on one file.
- **R28** Grant expiry uses DynamoDB's native TTL attribute, with the
  application still refusing to honour an expired grant it happens to read
  before TTL removes it.
- **R29** The audit log is likewise DynamoDB-backed, append-only, and IAM
  permissions grant no update or delete on it.
- **R30** SQLite remains the default for local runs and the test suite, so tests
  stay fast and offline.

### 4.4 Operability

- **R31** An HTTP health endpoint suitable for an ALB target group, separate
  from the MCP endpoint, requiring no authentication and revealing nothing.
- **R32** The operator CLI works against the deployed store, so approvals can be
  granted from a laptop.
- **R33** Structured logs to stdout, captured by CloudWatch Logs. No prompt or
  tool-argument content in logs — argument hashes only.

## 5. Infrastructure requirements

- **R34** Terraform, split into two stacks:
  - `bootstrap/` — Route53 hosted zone and ECR repository. Applied once, never
    destroyed, so the DNS delegation stays valid and the image survives.
  - `app/` — everything else. Applied and destroyed freely.
- **R35** ECS Fargate, one task definition, one container. The gate spawns the
  demo upstream MCP server over stdio exactly as the local demo does, so there
  is no deployed-only code path.
- **R36** ALB with an HTTPS listener, an ACM certificate validated by DNS, and
  HTTP redirecting to HTTPS.
- **R37** The ALB security group allows only an operator-supplied list of source
  IP addresses. Default behaviour discovers the applier's own public IP; a
  variable overrides it.
- **R38** IAM roles are least privilege. The task role gets exactly the
  DynamoDB actions it uses on exactly its own table, and read on exactly its own
  secret. No wildcards on resources.
- **R39** Every environment-specific value is a Terraform variable with no
  default that leaks the owner's setup. A committed
  `terraform.tfvars.example` shows placeholders; the real `terraform.tfvars` is
  gitignored.
- **R40** Terraform state is local and gitignored.
- **R41** `terraform destroy` on `app/` leaves nothing running that costs money.

## 6. Engineering standards

- **R42** Modular. One responsibility per module. The existing separation —
  pure policy, validated registry, storage, audit, one middleware hook, thin
  server, CLI — is the pattern to extend, not to blur.
- **R43** Every new module gets tests. New behaviour is proven by a test that
  fails without it.
- **R44** Type hints on all new code. No new runtime dependency without a
  reason recorded in the README.
- **R45** DynamoDB tests must not require AWS credentials or network. Use a fake
  or a local stand-in.
- **R46** Comments explain *why*, not *what*. The existing code's docstring
  style — stating the reasoning behind a decision — is the standard.
- **R47** Errors returned to an agent are actionable: what was refused, why, and
  the exact command that resolves it.

## 7. Deliverables

```
mcp-bouncer/
  gate/                     Python package
  demo/                     toy upstream MCP server + minimal client
  tests/                    unit + end-to-end
  terraform/bootstrap/
  terraform/app/
  policy.yaml
  Dockerfile
  pyproject.toml
  README.md                 what it is, run it locally, deploy it, tear it down
  DESIGN.md                 the decisions and why
  REQUIREMENTS.md           this file
  LICENSE                   MIT
```

- **R48** `README.md` gets a reader from clone to a working local demo without
  AWS, and separately from clone to a deployed stack. It states the known
  limitations plainly, including anything left as a stub.
- **R49** `DESIGN.md` covers the **whole solution** — the component and the
  deployment — and records the reasoning, not just the outcome:
  - *Gate design:* why classify by reversibility, why unknown is denied, why
    annotations escalate only, why park-notify-retry, why one-shot
    argument-bound grants, why fail closed including on reads, why the policy
    engine is pure, why the gate refuses to boot on bad policy.
  - *Identity and teams:* why identity is a single seam, why overrides tighten
    only, what a team is and how you add one.
  - *Storage:* what the SQLite-to-DynamoDB port proved about the interface, why
    the one-shot claim is a conditional delete, why TTL is enforced twice.
  - *Deployment:* why two Terraform stacks, why the container spawns its
    upstream over stdio rather than having a deployed-only code path, why
    network allowlist and bearer token are both present and what each one
    actually buys, where least privilege lands in IAM, what the operator's
    approval path looks like against a remote store.
  - *Absences:* what is deliberately not built, and what would change first if
    this had to become real.
- **R50** Evidence of the deployed system working — the park, approve, retry
  loop executed against the real endpoint — captured in the repo as text.

## 8. Out of scope

Stated plainly in the README rather than left to be discovered:

- Approver authorisation. Anyone who can reach the store can approve.
- Masking or redaction of tool results.
- A UI. The operator surface is a CLI.
- Multi-region, autoscaling, disaster recovery.
- Prompt-injection detection in tool output.

## 9. Acceptance criteria

Verifiable, in order:

- **A1** `pytest` passes, including the original 68 tests.
- **A2** A read passes; an unclassified tool is denied; a destructive call parks
  and returns an approval id — all through the real proxy.
- **A3** An approval releases exactly one call. A replay of the identical call
  parks again. Concurrent consumers of one grant produce exactly one winner.
- **A4** A grant for one set of arguments does not release a different set.
- **A5** A poisoned policy engine blocks reads, writes and destructive calls
  alike.
- **A6** An unknown bearer token is rejected. Over HTTP, a request without a
  valid token cannot initialise a session or list tools. Two tokens map to two
  distinct callers, and their destructive counters are independent.
- **A7** A team override that loosens the baseline prevents boot.
- **A8** The DynamoDB store passes the same store test suite as SQLite.
- **A9** `terraform apply` in `bootstrap/` then `app/` produces a reachable
  HTTPS endpoint on the operator's own domain, and the ALB refuses a source IP
  outside the allowlist.
- **A10** The park, approve, retry loop completes against the deployed endpoint
  with approvals granted from the CLI against DynamoDB.
- **A11** `terraform destroy` in `app/` succeeds and leaves no billable
  resources.
- **A12** `git grep` finds no company name, no domain, no token, no account id.
