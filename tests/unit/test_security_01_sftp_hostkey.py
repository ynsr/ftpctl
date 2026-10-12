"""Req 1: SFTP uses RejectPolicy only; unknown host -> exit 5 with instructions.

- No AutoAddPolicy/WarningPolicy anywhere in the source.
- connect() against a server whose key is not in known_hosts fails exit 5.
"""

from __future__ import annotations

import inspect
from pathlib import Path

import pytest

from ftpctl import errors
from ftpctl.backends import SftpBackend
from ftpctl.config import Profile


def test_no_auto_add_policy_in_source() -> None:
    src = Path("src/ftpctl/backends.py").read_text()
    assert "RejectPolicy()" in src
    assert "AutoAddPolicy(" not in src
    assert "WarningPolicy(" not in src


def test_agent_and_key_lookup_disabled() -> None:
    src = inspect.getsource(SftpBackend.connect)
    assert "allow_agent=False" in src
    assert "look_for_keys=False" in src


def test_paramiko_logger_critical() -> None:
    import logging

    import ftpctl.backends  # noqa: F401  (import applies the level)
    assert logging.getLogger("paramiko").level == logging.CRITICAL


def test_unknown_host_key_fails_exit_5(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """A server key absent from known_hosts -> exit 5, never silent trust."""
    import socket
    import threading

    import paramiko

    host_key = paramiko.RSAKey.generate(1024)
    wrong_key = paramiko.RSAKey.generate(1024)  # what known_hosts claims
    listener = socket.socket()
    listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    listener.bind(("127.0.0.1", 0))
    listener.listen(1)
    port = int(listener.getsockname()[1])
    ready = threading.Event()

    class Stub(paramiko.ServerInterface):
        def check_auth_password(self, username: str, password: str) -> int:
            return paramiko.AUTH_FAILED

        def check_channel_request(self, kind: str, chanid: int) -> int:
            if kind == "session":
                return paramiko.OPEN_SUCCEEDED
            return paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED

        def get_allowed_auths(self, username: str) -> str:
            return "password"

    def serve_once() -> None:
        from paramiko.transport import Transport as ServerTransport
        ready.set()
        try:
            conn, _ = listener.accept()
            conn.settimeout(10)
            transport = ServerTransport(conn)
            transport.add_server_key(host_key)  # server presents host_key ...
            transport.start_server(server=Stub())
            channel = transport.accept(timeout=5)
            if channel is not None:
                channel.close()
            transport.close()
        except Exception:
            pass

    thread = threading.Thread(target=serve_once, daemon=True)
    thread.start()
    ready.wait(timeout=5)
    kh = tmp_path / "known_hosts"
    # ... but known_hosts pins a DIFFERENT key -> BadHostKeyException -> exit 5.
    kh.write_text(f"[127.0.0.1]:{port} ssh-rsa {wrong_key.get_base64()}\n")
    profile = Profile(name="t", protocol="sftp", host="127.0.0.1", port=port,
                      username="u", password="p", known_hosts=str(kh),
                      timeout_seconds=10)
    backend = SftpBackend(profile)
    try:
        with pytest.raises(errors.FtpctlError) as excinfo:
            backend.connect()
    finally:
        backend.close()
        listener.close()
    assert excinfo.value.exit_code == 5
