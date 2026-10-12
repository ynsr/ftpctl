"""Req 1 follow-up: host-key pinning round-trip (lesson from real SFTP onboarding).

- Correct pin in a dedicated known_hosts file -> auth proceeds (exit 4 here:
  the stub server rejects the password, proving the key was accepted).
- Wrong pin -> exit 5 (BadHostKeyException), never silent trust.
- Missing pin -> exit 5 with remediation instructions.

Offline: in-process paramiko SSH server stubs on 127.0.0.1, no real servers.
"""

from __future__ import annotations

import socket
import threading
from pathlib import Path

import pytest

from ftpctl import errors
from ftpctl.backends import SftpBackend
from ftpctl.config import Profile


def _serve_once(listener: socket.socket, host_key: object, ready: threading.Event) -> None:
    import paramiko
    from paramiko.transport import Transport as ServerTransport

    class Stub(paramiko.ServerInterface):
        def check_auth_password(self, username: str, password: str) -> int:
            return paramiko.AUTH_FAILED

        def check_channel_request(self, kind: str, chanid: int) -> int:
            if kind == "session":
                return paramiko.OPEN_SUCCEEDED
            return paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED

        def get_allowed_auths(self, username: str) -> str:
            return "password"

    ready.set()
    try:
        conn, _ = listener.accept()
        conn.settimeout(10)
        transport = ServerTransport(conn)
        transport.add_server_key(host_key)  # type: ignore[arg-type]
        transport.start_server(server=Stub())
        channel = transport.accept(timeout=5)
        if channel is not None:
            channel.close()
        transport.close()
    except Exception:
        pass


def _start_server(host_key: object) -> tuple[socket.socket, int, threading.Thread]:
    listener = socket.socket()
    listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    listener.bind(("127.0.0.1", 0))
    listener.listen(1)
    port = int(listener.getsockname()[1])
    ready = threading.Event()
    thread = threading.Thread(target=_serve_once, args=(listener, host_key, ready), daemon=True)
    thread.start()
    ready.wait(timeout=5)
    return listener, port, thread


def test_correct_pin_passes_host_key_stage(tmp_path: Path) -> None:
    """Correct pin -> key accepted; stub rejects password -> exit 4 (auth), not 5."""
    import paramiko

    host_key = paramiko.RSAKey.generate(1024)
    listener, port, _ = _start_server(host_key)
    kh = tmp_path / "known_hosts"
    kh.write_text(f"[127.0.0.1]:{port} ssh-rsa {host_key.get_base64()}\n")
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
    assert excinfo.value.exit_code == 4


def test_wrong_pin_fails_exit_5(tmp_path: Path) -> None:
    """Wrong pin -> BadHostKeyException -> exit 5 (possible MITM)."""
    import paramiko

    host_key = paramiko.RSAKey.generate(1024)
    other_key = paramiko.RSAKey.generate(1024)
    listener, port, _ = _start_server(host_key)
    kh = tmp_path / "known_hosts"
    kh.write_text(f"[127.0.0.1]:{port} ssh-rsa {other_key.get_base64()}\n")
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


def test_missing_pin_names_keyscan_remediation(tmp_path: Path) -> None:
    """Absent pin -> exit 5 with out-of-band ssh-keyscan instructions, never trust."""
    import paramiko

    host_key = paramiko.RSAKey.generate(1024)
    listener, port, _ = _start_server(host_key)
    kh = tmp_path / "known_hosts"  # never created
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
    assert "ssh-keyscan" in str(excinfo.value)
