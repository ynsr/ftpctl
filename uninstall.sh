#!/usr/bin/env bash
# Uninstall ftpctl — reverses install.sh. Idempotent: safe to re-run.
set -euo pipefail

TOOL="ftpctl"
uv tool uninstall "$TOOL" 2>/dev/null || echo "  (not installed: $TOOL)"
rm -f "$HOME/.local/share/bash-completion/completions/$TOOL" \
      "$HOME/.config/fish/completions/$TOOL.fish" \
      "$HOME/.local/share/zsh/site-functions/_$TOOL"
command -v cli-hub &>/dev/null && cli-hub unregister "$TOOL" --yes 2>/dev/null || true
echo "  ✔ $TOOL uninstalled."
