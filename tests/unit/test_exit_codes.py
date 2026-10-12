"""Exit-code contract: 0/2/3/4/5/6/7/1 across the CLI surface."""

from __future__ import annotations

import json
import os
import subprocess

from conftest import BASE_FTP_PROFILE, write_config


def run_ftpctl(
    cfg_path: object, *args: str, env_extra: dict[str, str] | None = None
) -> subprocess.CompletedProcess[str]:
    env = {**os.environ, "PATH": os.environ.get("PATH", "")}
    env.update(env_extra or {})
    import pathlib
    binary = str(pathlib.Path(__file__).resolve().parents[2] / ".venv" / "bin" / "ftpctl")
    return subprocess.run([binary, "--config", str(cfg_path), *args],
                          capture_output=True, text=True, stdin=subprocess.DEVNULL,
                          timeout=30, env=env)


def test_exit_2_unknown_profile(workdir) -> None:  # type: ignore[no-untyped-def]
    cfg = write_config(workdir, "[defaults]\n[profiles.a]\nprotocol='ftp'\nhost='h'\n")
    proc = run_ftpctl(cfg, "ls", "--profile", "ghost", "/")
    assert proc.returncode == 2
    assert proc.stdout == ""  # stdout carries data only


def test_exit_3_missing_env_var(workdir) -> None:  # type: ignore[no-untyped-def]
    cfg = write_config(workdir, BASE_FTP_PROFILE.format(port=21, allow_insecure="true"))
    proc = run_ftpctl(cfg, "ls", "--profile", "demo", "/")
    assert proc.returncode == 3
    assert "FTPCTL_DEMO_USER" in proc.stderr


def test_exit_2_bad_config(workdir) -> None:  # type: ignore[no-untyped-def]
    cfg = write_config(workdir, "not = [valid toml")
    proc = run_ftpctl(cfg, "profiles")
    assert proc.returncode == 2


def test_exit_4_auth_failure(workdir, ftp_server, monkeypatch) -> None:  # type: ignore[no-untyped-def]
    port = ftp_server["port"]
    monkeypatch.setenv("FTPCTL_DEMO_USER", "agent")
    monkeypatch.setenv("FTPCTL_DEMO_PASS", "wrong-pass")
    cfg = write_config(workdir, BASE_FTP_PROFILE.format(port=port, allow_insecure="true"))
    proc = run_ftpctl(cfg, "check", "--profile", "demo")
    assert proc.returncode == 4, proc.stderr
    payload = json.loads(proc.stdout)
    assert payload["ok"] is False
    assert payload["steps"]["auth"] == "failed"


def test_exit_6_network_failure(workdir, monkeypatch) -> None:  # type: ignore[no-untyped-def]
    from conftest import free_port
    port = free_port()  # nothing listening
    monkeypatch.setenv("FTPCTL_DEMO_USER", "agent")
    monkeypatch.setenv("FTPCTL_DEMO_PASS", "pw")
    cfg = write_config(workdir, BASE_FTP_PROFILE.format(port=port, allow_insecure="true"))
    proc = run_ftpctl(cfg, "check", "--profile", "demo")
    assert proc.returncode == 6, proc.stderr


def test_exit_7_path_escape(workdir, ftp_server, monkeypatch) -> None:  # type: ignore[no-untyped-def]
    port = ftp_server["port"]
    monkeypatch.setenv("FTPCTL_DEMO_USER", "agent")
    monkeypatch.setenv("FTPCTL_DEMO_PASS", "s3cret")
    cfg = write_config(workdir, BASE_FTP_PROFILE.format(port=port, allow_insecure="true"))
    proc = run_ftpctl(cfg, "ls", "--profile", "demo", "/../etc")
    assert proc.returncode == 7


def test_exit_0_check_ok(workdir, ftp_server, monkeypatch) -> None:  # type: ignore[no-untyped-def]
    port = ftp_server["port"]
    monkeypatch.setenv("FTPCTL_DEMO_USER", "agent")
    monkeypatch.setenv("FTPCTL_DEMO_PASS", "s3cret")
    cfg = write_config(workdir, BASE_FTP_PROFILE.format(port=port, allow_insecure="true"))
    proc = run_ftpctl(cfg, "check", "--profile", "demo")
    assert proc.returncode == 0, proc.stderr
    payload = json.loads(proc.stdout)
    assert payload == {"profile": "demo",
                       "steps": {"connect": "ok", "auth": "ok", "list_root": "ok"},
                       "ok": True}


def test_exit_0_ls_stat_get_roundtrip(workdir, ftp_server, monkeypatch) -> None:  # type: ignore[no-untyped-def]
    port = ftp_server["port"]
    monkeypatch.setenv("FTPCTL_DEMO_USER", "agent")
    monkeypatch.setenv("FTPCTL_DEMO_PASS", "s3cret")
    cfg = write_config(workdir, BASE_FTP_PROFILE.format(port=port, allow_insecure="true"))
    ls = run_ftpctl(cfg, "ls", "--profile", "demo", "/")
    assert ls.returncode == 0, ls.stderr
    assert any(e["name"] == "hello.txt" for e in json.loads(ls.stdout)["entries"])
    st = run_ftpctl(cfg, "stat", "--profile", "demo", "/hello.txt")
    assert st.returncode == 0, st.stderr
    item = json.loads(st.stdout)
    assert item["type"] == "file" and item["size"] == 10
    get = run_ftpctl(cfg, "get", "--profile", "demo", "/hello.txt", "hello.txt")
    assert get.returncode == 0, get.stderr
    result = json.loads(get.stdout)
    assert result["bytes"] == 10 and len(result["sha256"]) == 64
    assert (workdir / "hello.txt").read_bytes() == b"hello ftp\n"
