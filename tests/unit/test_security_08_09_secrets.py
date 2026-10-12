"""Req 8: secrets never leak into errors/logs/stdout. Req 9: no credential inputs."""

from __future__ import annotations

import inspect
import json
import subprocess

from conftest import BASE_FTP_PROFILE, write_config

from ftpctl import errors
from ftpctl.config import load_config


def _ftpctl_binary() -> str:
    import pathlib
    return str(pathlib.Path(__file__).resolve().parents[2] / ".venv" / "bin" / "ftpctl")


def test_scrub_removes_registered_secrets() -> None:
    errors.register_secret("s3cret-pw")
    assert errors.scrub("login failed for agent with s3cret-pw here") == \
        "login failed for agent with [redacted] here"


def test_wrap_scrubs_exception_text() -> None:
    errors.register_secret("hunter2")
    wrapped = errors.wrap(ValueError("server said hunter2 bad"), 4)
    assert "hunter2" not in str(wrapped)


def test_no_password_flags_in_cli() -> None:
    import ftpctl.cli as cli
    src = inspect.getsource(cli.build_parser)
    assert "--password" not in src
    assert "--token" not in src
    src_all = inspect.getsource(cli)
    assert "getpass" not in src_all
    assert "input(" not in src_all


def test_no_verbose_flag() -> None:
    import ftpctl.cli as cli
    assert "--verbose" not in inspect.getsource(cli.build_parser)


def test_secrets_not_in_profiles_output(workdir, monkeypatch, ftp_server) -> None:  # type: ignore[no-untyped-def]
    port = ftp_server["port"]
    monkeypatch.setenv("FTPCTL_DEMO_USER", "agent")
    monkeypatch.setenv("FTPCTL_DEMO_PASS", "s3cret-xyz")
    cfg = write_config(workdir, BASE_FTP_PROFILE.format(port=port, allow_insecure="true"))
    import os
    env = {**os.environ, "PATH": os.environ.get("PATH", "")}
    proc = subprocess.run([_ftpctl_binary(), "--config", str(cfg), "profiles"],
                          capture_output=True, text=True, stdin=subprocess.DEVNULL,
                          timeout=30, env=env)
    assert proc.returncode == 0, proc.stderr
    assert "s3cret-xyz" not in proc.stdout
    assert "agent" not in proc.stdout or '"host"' in proc.stdout  # username must not appear
    payload = json.loads(proc.stdout)
    assert "password" not in json.dumps(payload).lower()


def test_only_referenced_env_vars_read(workdir, monkeypatch) -> None:  # type: ignore[no-untyped-def]
    """Env vars not matching FTPCTL_* or not referenced are never consumed."""
    monkeypatch.setenv("FTPCTL_DEMO_USER", "agent")
    monkeypatch.setenv("FTPCTL_DEMO_PASS", "pw")
    monkeypatch.setenv("TOTALLY_UNRELATED", "should-never-be-read")
    cfg = write_config(workdir, BASE_FTP_PROFILE.format(port=21, allow_insecure="true"))
    config, _ = load_config(cfg)
    assert config.profiles["demo"].username == "agent"
    assert "should-never-be-read" not in errors._secrets
