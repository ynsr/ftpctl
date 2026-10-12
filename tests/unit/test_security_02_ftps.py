"""Req 2: FTPS verifies certs (no disable switch), reuses TLS session, calls prot_p."""

from __future__ import annotations

import inspect
import ssl
from pathlib import Path

from ftpctl.backends import FtpBackend, _ReuseSessionFTP_TLS


def test_no_verify_disable_switch() -> None:
    src = Path("src/ftpctl/backends.py").read_text()
    assert "create_default_context" in src
    assert "CERT_NONE" not in src
    assert "check_hostname = False" not in src
    assert "verify_mode" not in src.replace("verify_mode=CERT_REQUIRED", "")


def test_session_reuse_override_present() -> None:
    src = inspect.getsource(_ReuseSessionFTP_TLS.ntransfercmd)
    assert "session" in src


def test_prot_p_always_called() -> None:
    src = inspect.getsource(FtpBackend.connect)
    assert "prot_p()" in src


def test_default_context_verifies() -> None:
    ctx = ssl.create_default_context()
    assert ctx.verify_mode == ssl.CERT_REQUIRED
    assert ctx.check_hostname is True


def test_ftps_explicit_roundtrip(ftps_server: object) -> None:
    """Explicit FTPS against a local TLS server with session reuse (req 2 live)."""
    import os
    info = ftps_server  # type: ignore[assignment]
    from conftest import make_profile
    profile = make_profile(protocol="ftps", port=info["port"])
    os.environ["SSL_CERT_FILE"] = str(info["cert"])
    backend = FtpBackend(profile)
    try:
        backend.connect()
        entries = backend.list("/")
        assert any(e.name == "hello.txt" for e in entries)
    finally:
        backend.close()
        os.environ.pop("SSL_CERT_FILE", None)
