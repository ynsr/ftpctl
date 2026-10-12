"""`profiles add` tests: all offline (pyftpdlib FTP fixture, paramiko SFTP stubs).

- derive_env_var naming + validate_name
- render/upsert surgical TOML (comments preserved, replace vs append)
- full add against local FTP: probe ok -> written with ${VAR} ref, no secret on disk
- probe failure with --yes still writes (insist path); without --yes refuses
- existing name refused without --overwrite; replaced with it
"""

from __future__ import annotations

import json
import os
import subprocess
import tomllib
from pathlib import Path

import pytest
from conftest import write_config

from ftpctl.profiles_add import (
    derive_env_var,
    render_profile_block,
    upsert_profile_block,
    validate_name,
)


def run_add(
    cfg_path: object, *args: str, env_extra: dict[str, str] | None = None
) -> subprocess.CompletedProcess[str]:
    env = {**os.environ, "PATH": os.environ.get("PATH", "")}
    env.update(env_extra or {})
    binary = str(Path(__file__).resolve().parents[2] / ".venv" / "bin" / "ftpctl")
    return subprocess.run([binary, "--config", str(cfg_path), *args],
                          capture_output=True, text=True, stdin=subprocess.DEVNULL,
                          timeout=30, env=env)


def test_derive_env_var() -> None:
    assert derive_env_var("saman-pmr") == "FTPCTL_SAMAN_PMR_PASSWORD"
    assert derive_env_var("sepehr") == "FTPCTL_SEPEHR_PASSWORD"
    assert derive_env_var("my profile!") == "FTPCTL_MY_PROFILE_PASSWORD"


def test_validate_name_rejects_bad() -> None:
    from ftpctl.errors import FtpctlError
    validate_name("saman-pmr")
    for bad in ("", "../evil", "has space", "semi;colon"):
        with pytest.raises(FtpctlError):
            validate_name(bad)


def test_upsert_preserves_comments_and_replaces() -> None:
    original = "# header comment\n[profiles]\n\n# note about a\n[profiles.a]\nprotocol = \"ftp\"\nhost = \"h\"\n"
    block = render_profile_block("a", "ftp", "new", 21, "u", "FTPCTL_A_PASSWORD")
    new_text, replaced = upsert_profile_block(original, "a", block)
    assert replaced is True
    assert "# header comment" in new_text  # file-level comment untouched
    assert new_text.count("[profiles.a]") == 1  # old block replaced, not duplicated
    assert 'host = "new"' in new_text
    assert tomllib.loads(new_text)["profiles"]["a"]["host"] == "new"


def test_upsert_appends_new_profile() -> None:
    original = "# keep me\n[profiles.a]\nprotocol = \"ftp\"\nhost = \"h\"\n"
    block = render_profile_block("b", "sftp", "sftp.example.com", 22, "u", "FTPCTL_B_PASSWORD",
                                 known_hosts="~/.config/ftpctl/known_hosts")
    new_text, replaced = upsert_profile_block(original, "b", block)
    assert replaced is False
    assert "# keep me" in new_text
    raw = tomllib.loads(new_text)
    assert set(raw["profiles"]) == {"a", "b"}
    assert raw["profiles"]["b"]["password"] == "${FTPCTL_B_PASSWORD}"


def test_add_ftp_probe_ok_writes_ref(workdir, ftp_server, monkeypatch) -> None:  # type: ignore[no-untyped-def]
    port = ftp_server["port"]
    cfg = workdir / "profiles.toml"
    monkeypatch.setenv("FTPCTL_DEMO_ADD_PASSWORD", "s3cret")
    proc = run_add(
        cfg, "profiles", "add", "--name", "demo-add", "--protocol", "ftp",
        "--host", "127.0.0.1", "--port", str(port), "--username", "agent",
        "--root", "/", "--allow-insecure", "--no-input",
        env_extra={"FTPCTL_DEMO_ADD_PASSWORD": "s3cret"},
    )
    assert proc.returncode == 0, proc.stderr
    payload = json.loads(proc.stdout)
    assert payload == {
        "profile": "demo-add", "added": True, "replaced": False,
        "probe": {"connect": "ok", "auth": "ok", "list_root": "ok", "ok": True},
        "env_var": "FTPCTL_DEMO_ADD_PASSWORD", "pinned_host_key": False,
        "config": str(cfg), "ok": True,
    }
    body = cfg.read_text()
    assert "s3cret" not in body  # secret never lands on disk
    assert "${FTPCTL_DEMO_ADD_PASSWORD}" in body
    assert (cfg.stat().st_mode & 0o777) == 0o600

def test_add_probe_failure_insist_vs_refuse(workdir, monkeypatch) -> None:  # type: ignore[no-untyped-def]
    from conftest import free_port
    port = free_port()  # nothing listening -> connect fails
    cfg = workdir / "profiles.toml"
    env = {"FTPCTL_DEMO_BAD_PASSWORD": "nope"}
    # Refuse path: --no-input, no --yes -> not added, probe exit code returned.
    # --timeout 3 bounds the retry loop (connect retries until the deadline).
    proc = run_add(
        cfg, "profiles", "add", "--name", "demo-bad", "--protocol", "ftp",
        "--host", "127.0.0.1", "--port", str(port), "--username", "agent",
        "--allow-insecure", "--no-input", "--timeout", "3", env_extra=env,
    )
    assert proc.returncode != 0
    payload = json.loads(proc.stdout)
    assert payload["added"] is False and payload["ok"] is False
    assert not cfg.exists()
    # Insist path: --yes writes despite the failed probe.
    proc2 = run_add(
        cfg, "profiles", "add", "--name", "demo-bad", "--protocol", "ftp",
        "--host", "127.0.0.1", "--port", str(port), "--username", "agent",
        "--allow-insecure", "--no-input", "--timeout", "3", "--yes", env_extra=env,
    )
    assert proc2.returncode == 0, proc2.stderr
    payload2 = json.loads(proc2.stdout)
    assert payload2["added"] is True and payload2["probe"]["ok"] is False
    assert "demo-bad" in tomllib.loads(cfg.read_text())["profiles"]


def test_add_existing_name_needs_overwrite(workdir, ftp_server, monkeypatch) -> None:  # type: ignore[no-untyped-def]
    port = ftp_server["port"]
    cfg = write_config(workdir, '[profiles.demo]\nprotocol="ftp"\nhost="h"\nusername="u"\npassword="p"\n')
    env = {"FTPCTL_DEMO_PASSWORD": "s3cret"}
    proc = run_add(
        cfg, "profiles", "add", "--name", "demo", "--protocol", "ftp",
        "--host", "127.0.0.1", "--port", str(port), "--username", "agent",
        "--allow-insecure", "--no-input", env_extra=env,
    )
    assert proc.returncode == 2
    assert "already exists" in proc.stderr
    proc2 = run_add(
        cfg, "profiles", "add", "--name", "demo", "--protocol", "ftp",
        "--host", "127.0.0.1", "--port", str(port), "--username", "agent",
        "--allow-insecure", "--no-input", "--overwrite", env_extra=env,
    )
    assert proc2.returncode == 0, proc2.stderr
    assert json.loads(proc2.stdout)["replaced"] is True
    assert tomllib.loads(cfg.read_text())["profiles"]["demo"]["host"] == "127.0.0.1"
