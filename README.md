# ftpctl

Data-plane CLI for a profile-backed API; agent-first (clean stdout, JSON envelopes, exit codes).

## Install

```bash
./install.sh     # uv tool install --editable . + shell completions + cli-hub register (idempotent)
```

Dev: `uv sync` (venv + deps), then `make check` — ruff + pytest + `scripts/verify-cli`.
Tests are offline; HTTP is mocked with httpx.MockTransport.

## Quick start

```bash
ftpctl list widgets --output json | jq '.[0]'   # demo rows — wire client.Client for your API
ftpctl list widgets --fields id,name --limit 2
ftpctl profile create prod --url https://prod.example --default   # token via FTPCTL_TOKEN or hidden prompt
ftpctl profile list                               # token never printed
ftpctl profile remove prod --dry-run              # preview the plan; add --yes to execute
ftpctl doctor                                     # status: ok|missing
ftpctl schema                                     # machine-readable commands + profile JSON Schemaftpctl completion bash                            # also dropped by install.sh (bash/zsh/fish)
```

`--output table|json|csv|tsv` (+ `--json` alias) on list-style output; agent default csv.

## Contract

- stdout carries data only; logs, prompts, errors → stderr. Errors: agents (non-TTY, or JSON
  output requested: `--json` / `--output json` / `FTPCTL_OUTPUT=json`)
  get `{"error":{"code","message","hint"}}` with a matching exit code; humans get a plain line + hint.
- Exit codes: 0 success · 1 error · 2 usage · 3 network · 4 partial. `-v` adds a traceback,
  `-q` drops hints, `--no-input`/`CI`/non-TTY never prompt.
- Secrets live only in 0600 profile files or env (`FTPCTL_TOKEN`) — never in flags, logs, or code.
  Precedence: `FTPCTL_PROFILE` env > ephemeral `FTPCTL_URL`/`FTPCTL_TOKEN` > stored default profile.
- `NO_COLOR`, `TERM=dumb`, and `--no-color` suppress all styling.

## Wiring your API

Replace the `DEMO_ROWS` stub in `cli.list_cmd` with
`Client(resolve_profile()).request("GET", f"/{resource}")` — retry, Bearer auth, socks-proxy
normalization, and network exit code 3 are already handled by `client.py`.
