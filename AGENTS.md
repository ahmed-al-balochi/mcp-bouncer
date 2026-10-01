# House rules for AI agents

This is a bouncer, so it has house rules. You are helping a person run or
deploy this repo. The commands are in `README.md` (the local demo, then
"Deploy it", steps 1 to 8); follow them in order. This file adds what an agent
needs on top: where to stop, what never to do, and how to check your work.

## Run it locally first

No AWS needed. From the repo root:

```bash
python3 -m venv .venv && . .venv/bin/activate
pip install -e '.[test]'
pytest
```

All tests should pass before you touch any cloud resource.

## Ask for these up front

Only the human can give you these, so ask for all of them in one message
before you start:

- a domain (or subdomain) they control, for `dns_zone_name`;
- an email address for the fail-closed alarm;
- their own public IP, for `allowed_cidrs` (see Traps);
- which LiteLLM base image to build the gateway from (README step 3).

## Stop and hand over to the human

Do not try to do these yourself. Say what is needed and wait.

- **Every `terraform apply` and `terraform destroy`.** Run `terraform plan`
  first, show the human the summary line, and apply only after they agree. The
  app stack is billed by the hour, and the bootstrap stack creates resources
  that are protected from `terraform destroy` on purpose.
- **The DNS delegation** (README step 2). The human adds four NS records at
  their registrar. Nothing works until that resolves.
- **Bedrock model access** to the EU Claude inference profile, enabled in the
  account by the human.
- **The alert email.** AWS sends a confirmation link that the human must click.
- **Approving a parked call.** See the next section.

## Never approve your own parked calls

The gate exists so a human decides on destructive actions. When the demo agent
parks a call, show the human the approval id from `bouncer list` and let them
run `bouncer approve`. Do not run it yourself, even if you have the
credentials. An approval id is real only if `bouncer list` or the audit log
shows it: a model with no tools can print a convincing fake one.

## Rules

- Never commit `terraform.tfvars`, tokens, the gateway key, account ids, your
  domain or IP addresses. They belong in the gitignored `terraform.tfvars`.
- Get secrets only through `terraform output -raw tokens_get_command` and
  `terraform output -raw litellm_master_key_get_command`, and never print them.
- Never destroy or edit `terraform/bootstrap`. It holds the DNS zone, the
  certificate and the image repositories, and is protected on purpose.
- When the human is done, offer `terraform destroy` in `terraform/app`.

## Traps

- **The IP allowlist** defaults to the public IP of the machine running
  Terraform. If you run on a cloud VM or behind a VPN, that is not the
  human's address and they will be locked out. Ask for their IP and set
  `allowed_cidrs` in `terraform.tfvars`.
- **Build images** with `--provenance=false --sbom=false` and the platform that
  matches `cpu_architecture` (README step 3).
- **Pushing a new `:latest` image does not restart the service.** Run
  `aws ecs update-service --force-new-deployment` for it, after asking.
- **The first start is slow.** The gate takes about 15 seconds to warm up
  before its health check passes.

## Check your work

- `pytest` passes, and `terraform fmt -check` and `terraform validate` are clean.
- `terraform plan` right after an apply reports no changes.
- Without a key, `GET <gateway_url>/v1/models` returns 401 and `<gateway_url>/mcp`
  returns 404. The gate itself is never reachable from outside.
- `terraform output -raw dashboard_url` opens a dashboard that shows data after
  one demo run.
