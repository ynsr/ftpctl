# Commands, architecture, and module map for AI agents working on ftpctl.

## Build / test / run

```bash
uv sync        # .venv with locked deps
make check     # ruff + pytest + scripts/verify-cli (probe: "list widgets"; destructive probe: "profile remove demo")
uv run pytest -q
```

All tests pass offline — HTTP is mocked with httpx.MockTransport; never write tests that hit a real server.

## Architecture

1. `cli.py` — typer app; `main()` (the console entry) catches errors into the
   `{"error":{"code","message","hint"}}` stderr envelope; exit 0/1/2/3/4 documented in `--help`.
   The demo `list` is offline on purpose (verify-cli must pass without network/profiles).
2. `output.py` — `emit()` prints rows as table/csv/tsv/json (plain text, box-free); `fail()`
   prints the envelope for agents (non-TTY or `--json`), a plain line + hint for humans.
3. `config.py` — pydantic v2 Profile; 0600 JSON files under platformdirs dir (`FTPCTL_CONFIG_DIR`
   overrides); `config.toml` default; `resolve_profile()` precedence flag > env > default.
4. `client.py` — httpx factory (+socks), Bearer auth, tenacity retry on 429/502/503/504 and
   transport errors; `APIError` code "network" maps to exit 3.
5. `doctor.py` — status-only: first line `status: ok|missing`, `--json` single line; never "stale".

## Conventions

- stdout data only; delete superseded code instead of deprecating; keep every command within the
  documented exit codes and the secrets-never-in-flags rule.
