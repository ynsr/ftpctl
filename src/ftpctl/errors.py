"""ftpctl exit codes and the secret-scrubbing error kernel.

Exit map (spec §Output): 0 ok, 2 usage/config, 3 missing env var,
4 auth failure, 5 host key/cert failure, 6 network/timeout,
7 policy violation, 1 other.
"""

from __future__ import annotations


class FtpctlError(Exception):
    """Command-level failure with a fixed exit status."""

    def __init__(self, message: str, exit_code: int) -> None:
        super().__init__(message)
        self.exit_code = exit_code


# Secrets resolved during this process; scrubbed from every outward message.
_secrets: list[str] = []


def register_secret(value: str) -> None:
    if value and value not in _secrets:
        _secrets.append(value)


def scrub(message: str) -> str:
    for secret in sorted(_secrets, key=len, reverse=True):
        if secret:
            message = message.replace(secret, "[redacted]")
    return message


def wrap(exc: Exception, exit_code: int, hint: str = "") -> FtpctlError:
    """Convert any exception into an FtpctlError with secrets scrubbed."""
    text = scrub(f"{type(exc).__name__}: {exc}")
    if hint:
        text = f"{text} (hint: {hint})"
    return FtpctlError(text, exit_code)
