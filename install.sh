#!/usr/bin/env bash
# Install ftpctl: uv-managed editable tool + completion file-drop + cli-hub register. Idempotent.
set -euo pipefail

REPO_DIR="$(cd "$(dirname "$0")" && pwd)"
TOOL="ftpctl"
command -v uv >/dev/null || { echo "uv is required: https://docs.astral.sh/uv/" >&2; exit 1; }

echo "==> Installing $TOOL (editable; re-run to refresh)…"
uv tool install --force --editable "$REPO_DIR"

# Completion file-drop (typer-generated scripts; dynamic values read local state only).
mkdir -p "$HOME/.local/share/bash-completion/completions" "$HOME/.config/fish/completions" "$HOME/.local/share/zsh/site-functions"
"$TOOL" completion bash > "$HOME/.local/share/bash-completion/completions/$TOOL"
"$TOOL" completion fish > "$HOME/.config/fish/completions/$TOOL.fish"
"$TOOL" completion zsh  > "$HOME/.local/share/zsh/site-functions/_$TOOL"
echo "zsh: add  fpath=(\"$HOME/.local/share/zsh/site-functions\" \$fpath)  BEFORE compinit in ~/.zshrc"

# ── Register with cli-hub (best-effort; never fails the install) ─────────────
if command -v cli-hub &>/dev/null; then
    cli-hub register "$TOOL" \
        --version "$("$TOOL" --version 2>/dev/null | grep -m1 -oE '[0-9]+(\.[0-9]+)+')" \
        --description "<one-line description>" \
        --group "misc" \
        --source-path "$REPO_DIR" \
        --uninstall "uv tool uninstall $TOOL" \
        --reinstall "uv tool install --editable $REPO_DIR" \
        --yes || true
fi

echo "==> Done. Try: $TOOL --help"
