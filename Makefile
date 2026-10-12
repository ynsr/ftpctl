CMD ?= .venv/bin/ftpctl

.PHONY: check
check:
	uv sync -q
	uv run ruff check .
	uv run -- mypy --strict src/
	uv run -- pytest -q tests
	@tmp=$$(mktemp --suffix=.toml) && printf '[defaults]\n' > $$tmp && chmod 600 $$tmp && \
		FTPCTL_CONFIG=$$tmp ./scripts/verify-cli $(CMD) "profiles"; rc=$$?; rm -f $$tmp; exit $$rc