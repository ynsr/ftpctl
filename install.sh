#!/usr/bin/env bash
# Install ftpctl: uv-managed editable tool + completion file-drop + cli-hub register. Idempotent.
set -euo pipefail

REPO_DIR="$(cd "$(dirname "$0")" && pwd)"
TOOL="ftpctl"
command -v uv >/dev/null || { echo "uv is required: https://docs.astral.sh/uv/" >&2; exit 1; }

echo "==> Installing $TOOL (editable; re-run to refresh)…"
uv tool install --force --editable "$REPO_DIR"

# Completion file-drop: skipped — ftpctl is argparse-based and has no `completion`
# subcommand yet. Revisit when a completion generator lands (verify-cli check 8 skips).

# ── Register with cli-hub (best-effort; never fails the install) ─────────────
if command -v cli-hub &>/dev/null; then
    cli-hub register "$TOOL" \
        --version "$("$TOOL" --version 2>/dev/null | grep -m1 -oE '[0-9]+(\.[0-9]+)+')" \
        --description "Safe FTP/FTPS/SFTP wrapper for AI agents (JSON output, profiles, exit codes)." \
        --group "net" \
        --source-path "$REPO_DIR" \
        --config-path "$HOME/.config/ftpctl/profiles.toml" \
        --uninstall "uv tool uninstall $TOOL" \
        --reinstall "uv tool install --editable $REPO_DIR" \
        --yes || true
fi

echo "==> Done. Try: $TOOL --help"
