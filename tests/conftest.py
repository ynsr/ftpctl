"""Shared fixtures: temp config, env isolation, in-process FTP server, fake backends."""

from __future__ import annotations

import ipaddress
import os
import socket
import threading
from pathlib import Path
from typing import Any

import pytest

from ftpctl import errors
from ftpctl.backends import Backend, Entry


@pytest.fixture(autouse=True)
def _clean_secrets():
    errors._secrets.clear()
    yield
    errors._secrets.clear()


@pytest.fixture()
def workdir(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    """Isolated cwd + state dir; FTPCTL_* env wiped except test-set ones."""
    monkeypatch.chdir(tmp_path)
    for var in list(os.environ):
        if var.startswith("FTPCTL_"):
            monkeypatch.delenv(var, raising=False)
    monkeypatch.setenv("FTPCTL_STATE_DIR", str(tmp_path / "state"))
    return tmp_path


def write_config(workdir: Path, body: str, mode: int = 0o600) -> Path:
    path = workdir / "profiles.toml"
    path.write_text(body)
    path.chmod(mode)
    return path


BASE_FTP_PROFILE = """\
[defaults]
timeout_seconds = 5
max_download_bytes = 1048576
max_list_entries = 100

[profiles.demo]
protocol = "ftp"
host = "127.0.0.1"
port = {port}
username = "${{FTPCTL_DEMO_USER}}"
password = "${{FTPCTL_DEMO_PASS}}"
root = "/"
readonly = true
allow_insecure = {allow_insecure}
"""

def free_port() -> int:
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


class FakeBackend(Backend):
    """In-memory backend for policy/transfer tests (no network)."""

    protocol = "fake"

    def __init__(self, files: dict[str, bytes] | None = None, dirs: list[str] | None = None) -> None:
        self.files: dict[str, bytes] = dict(files or {"/hello.txt": b"hello\n"})
        self.dirs = set(dirs or ["/", "/sub"])
        self.renamed: list[tuple[str, str]] = []

    def connect(self) -> None:
        return None

    def close(self) -> None:
        return None

    def list(self, path: str) -> list[Entry]:
        from ftpctl.errors import FtpctlError
        if path not in self.dirs:
            if path in self.files:
                raise FtpctlError("not a directory", 1)
            raise FtpctlError("no such directory", 1)
        out: list[Entry] = []
        prefix = path.rstrip("/") + "/"
        seen: set[str] = set()
        for fpath,chang in sorted(self.files.items()):
            if fpath.startswith(prefix):
                rest = fpath[len(prefix):]
                if "/" not in rest and rest not in seen:
                    seen.add(rest)
                    out.append(Entry(rest, fpath, "file", len(chang), "2026-01-01T00:00:00Z", "0o644"))
        for d in sorted(self.dirs):
            if d != path and d.startswith(prefix) and "/" not in d[len(prefix):]:
                name = d[len(prefix):]
                out.append(Entry(name, d, "dir", None, "2026-01-01T00:00:00Z", "0o755"))
        return out

    def stat(self, path: str) -> Entry:
        from ftpctl.errors import FtpctlError
        if path in self.files:
            data = self.files[path]
            return Entry(path.rsplit("/", 1)[-1], path, "file", len(data), "2026-01-01T00:00:00Z", "0o644")
        if path in self.dirs:
            return Entry(path.rsplit("/", 1)[-1] or "/", path, "dir", None, "2026-01-01T00:00:00Z", "0o755")
        raise FtpctlError("no such file or directory", 1)

    def download(self, remote: str, local_tmp: Path, limit_bytes: int) -> int:
        from ftpctl.errors import FtpctlError
        data = self.files[remote]
        if len(data) > limit_bytes:
            raise FtpctlError("download exceeds max_download_bytes", 7)
        local_tmp.write_bytes(data)
        return len(data)

    def upload(self, local: Path, remote_tmp: str) -> int:
        data = local.read_bytes()
        self.files[remote_tmp] = data
        return len(data)

    def rename(self, src: str, dst: str) -> None:
        self.files[dst] = self.files.pop(src)
        self.renamed.append((src, dst))

    def size(self, path: str) -> int | None:
        return len(self.files[path]) if path in self.files else None


@pytest.fixture()
def ftp_server(tmp_path: Path):
    """In-process plain-FTP server (pyftpdlib) rooted at tmp_path/srv."""
    from pyftpdlib.authorizers import DummyAuthorizer
    from pyftpdlib.handlers import FTPHandler
    from pyftpdlib.servers import FTPServer

    root = tmp_path / "srv"
    root.mkdir(exist_ok=True)
    (root / "hello.txt").write_bytes(b"hello ftp\n")
    (root / "sub").mkdir(exist_ok=True)
    (root / "sub" / "nested.txt").write_bytes(b"nested\n")

    auth = DummyAuthorizer()
    auth.add_user("agent", "s3cret", str(root), perm="elradfmw")
    handler = FTPHandler
    handler.authorizer = auth
    port = free_port()
    server = FTPServer(("127.0.0.1", port), handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield {"port": port, "root": root}
    finally:
        server.close_all()


@pytest.fixture()
def ftps_server(tmp_path: Path):
    """In-process explicit-FTPS server (pyftpdlib TLS_FTPHandler) with a self-signed cert."""
    import datetime

    from pyftpdlib.authorizers import DummyAuthorizer
    from pyftpdlib.handlers import TLS_FTPHandler
    from pyftpdlib.servers import FTPServer

    try:
        from cryptography import x509
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import rsa
        from cryptography.x509.oid import NameOID
    except ImportError:
        pytest.skip("cryptography package required for FTPS fixture")

    root = tmp_path / "srv"
    root.mkdir(exist_ok=True)
    (root / "hello.txt").write_bytes(b"hello ftps\n")

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "127.0.0.1")])
    now = datetime.datetime.now(datetime.UTC)
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject).issuer_name(subject)
        .public_key(key.public_key()).serial_number(x509.random_serial_number())
        .not_valid_before(now).not_valid_after(now + datetime.timedelta(days=1))
        .add_extension(
            x509.SubjectAlternativeName([x509.IPAddress(ipaddress.IPv4Address("127.0.0.1"))]),
            critical=False,
        )
        .sign(key, hashes.SHA256())
    )
    cert_path = tmp_path / "cert.pem"
    key_path = tmp_path / "key.pem"
    cert_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    key_path.write_bytes(key.private_bytes(serialization.Encoding.PEM,
        serialization.PrivateFormat.TraditionalOpenSSL, serialization.NoEncryption()))

    auth = DummyAuthorizer()
    auth.add_user("agent", "s3cret", str(root), perm="elradfmw")
    handler = TLS_FTPHandler
    handler.authorizer = auth
    handler.certfile = str(cert_path)
    handler.keyfile = str(key_path)
    handler.tls_control_required = True
    handler.tls_data_required = True
    port = free_port()
    server = FTPServer(("127.0.0.1", port), handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield {"port": port, "root": root, "cert": cert_path}
    finally:
        server.close_all()


def make_profile(**kwargs: Any) -> Any:
    from ftpctl.config import Profile
    base: dict[str, Any] = {
        "name": "demo", "protocol": "ftp", "host": "127.0.0.1", "port": 21,
        "username": "agent", "password": "s3cret", "root": "/",
        "readonly": True, "timeout_seconds": 5,
        "max_download_bytes": 1_048_576, "max_list_entries": 100,
    }
    base.update(kwargs)
    return Profile(**base)
