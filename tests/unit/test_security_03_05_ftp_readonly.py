"""Req 3: plain FTP refused unless allow_insecure=true (+ JSON warning). Req 5: readonly default."""

from __future__ import annotations

import json
import os
import subprocess

import pytest
from conftest import BASE_FTP_PROFILE, make_profile, write_config

from ftpctl import errors
from ftpctl.backends import FtpBackend


def _ftpctl_binary() -> str:
    import pathlib
    return str(pathlib.Path(__file__).resolve().parents[2] / ".venv" / "bin" / "ftpctl")


def test_plain_ftp_refused_by_default() -> None:
    backend = FtpBackend(make_profile(protocol="ftp", allow_insecure=False))
    with pytest.raises(errors.FtpctlError) as excinfo:
        backend.connect()
    assert excinfo.value.exit_code == 7
    assert "allow_insecure" in str(excinfo.value)


def test_plain_ftp_allowed_with_warning(ftp_server: dict[str, object], workdir, monkeypatch) -> None:  # type: ignore[no-untyped-def]
    port = ftp_server["port"]
    monkeypatch.setenv("FTPCTL_DEMO_USER", "agent")
    monkeypatch.setenv("FTPCTL_DEMO_PASS", "s3cret")
    cfg = write_config(workdir, BASE_FTP_PROFILE.format(port=port, allow_insecure="true"))
    proc = subprocess.run(
        ["ftpctl", "--config", str(cfg), "ls", "--profile", "demo", "/"],
        capture_output=True, text=True, stdin=subprocess.DEVNULL, timeout=30,
        env={**os.environ, "PATH": os.environ.get("PATH", "")},
    )
    assert proc.returncode == 0, proc.stderr
    payload = json.loads(proc.stdout)
    assert payload.get("warning", "").startswith("plain FTP")
    assert any(e["name"] == "hello.txt" for e in payload["entries"])


def test_readonly_default_true() -> None:
    profile = make_profile()
    assert profile.readonly is True


def test_put_refused_when_readonly(workdir, ftp_server) -> None:  # type: ignore[no-untyped-def]
    from ftpctl.transfer import cmd_put
    backend = FtpBackend(make_profile(protocol="ftp", allow_insecure=True, readonly=True))
    local = workdir / "up.txt"
    local.write_bytes(b"data")
    with pytest.raises(errors.FtpctlError) as excinfo:
        cmd_put(backend, make_profile(readonly=True), str(local), "/up.txt", False)
    assert excinfo.value.exit_code == 7
    assert "readonly" in str(excinfo.value).lower()
