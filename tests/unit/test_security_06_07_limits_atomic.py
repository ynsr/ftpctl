"""Req 6: size/list/timeout limits. Req 7: atomic get, overwrite rules, tmp+rename put."""

from __future__ import annotations

import hashlib
import json

import pytest
from conftest import FakeBackend, make_profile

from ftpctl import errors
from ftpctl.transfer import cmd_get, cmd_put


def test_get_atomic_and_verified(workdir) -> None:  # type: ignore[no-untyped-def]
    profile = make_profile(readonly=True)
    payload = cmd_get(FakeBackend(), profile, "/hello.txt", "got.txt", False)
    assert payload["bytes"] == 6
    assert payload["sha256"] == hashlib.sha256(b"hello\n").hexdigest()
    assert (workdir / "got.txt").read_bytes() == b"hello\n"
    assert not (workdir / "got.txt.part").exists()


def test_get_refuses_existing_without_overwrite(workdir) -> None:  # type: ignore[no-untyped-def]
    (workdir / "got.txt").write_bytes(b"old")
    with pytest.raises(errors.FtpctlError) as excinfo:
        cmd_get(FakeBackend(), make_profile(), "/hello.txt", "got.txt", False)
    assert excinfo.value.exit_code == 7
    assert (workdir / "got.txt").read_bytes() == b"old"  # untouched


def test_get_size_cap_aborts_and_cleans(workdir) -> None:  # type: ignore[no-untyped-def]
    big = FakeBackend(files={"/big.bin": b"x" * 100})
    profile = make_profile(max_download_bytes=10)
    with pytest.raises(errors.FtpctlError) as excinfo:
        cmd_get(big, profile, "/big.bin", "big.bin", False)
    assert excinfo.value.exit_code == 7
    assert not (workdir / "big.bin").exists()
    assert not (workdir / "big.bin.part").exists()


def test_list_truncation_flag() -> None:
    from ftpctl.cli import cmd_ls
    files = {f"/f{i:03d}.txt": b"x" for i in range(10)}
    backend = FakeBackend(files=files)
    profile = make_profile(max_list_entries=4)
    import ftpctl.cli as cli
    real_open = cli._open
    cli._open = lambda _p: backend  # type: ignore[assignment]
    try:
        import io
        from contextlib import redirect_stdout
        buf = io.StringIO()
        with redirect_stdout(buf):
            assert cmd_ls(profile, "/", False, None) == 0
        payload = json.loads(buf.getvalue())
        assert payload["truncated"] is True
        assert len(payload["entries"]) == 4
    finally:
        cli._open = real_open


def test_put_tmp_and_rename(workdir) -> None:  # type: ignore[no-untyped-def]
    backend = FakeBackend()
    profile = make_profile(readonly=False)
    local = workdir / "up.txt"
    local.write_bytes(b"upload me")
    payload = cmd_put(backend, profile, str(local), "/up.txt", False)
    assert payload["bytes"] == 9
    assert backend.files["/up.txt"] == b"upload me"
    assert ("/up.txt.ftpctl.tmp", "/up.txt") in backend.renamed


def test_put_refuses_existing_without_overwrite(workdir) -> None:  # type: ignore[no-untyped-def]
    backend = FakeBackend(files={"/up.txt": b"old"})
    profile = make_profile(readonly=False)
    local = workdir / "up.txt"
    local.write_bytes(b"new")
    with pytest.raises(errors.FtpctlError) as excinfo:
        cmd_put(backend, profile, str(local), "/up.txt", False)
    assert excinfo.value.exit_code == 7


def test_put_size_cap(workdir) -> None:  # type: ignore[no-untyped-def]
    profile = make_profile(readonly=False, max_download_bytes=4)
    local = workdir / "up.txt"
    local.write_bytes(b"too big for cap")
    with pytest.raises(errors.FtpctlError) as excinfo:
        cmd_put(FakeBackend(), profile, str(local), "/up.txt", True)
    assert excinfo.value.exit_code == 7


def test_connect_timeout_exit_6() -> None:

    from ftpctl.backends import connect_with_retries
    backend = FakeBackend()
    def boom() -> None:
        raise OSError("timed out")
    backend.connect = boom  # type: ignore[method-assign]
    class TimeoutBackend(FakeBackend):
        def connect(self) -> None:
            raise errors.FtpctlError("connection timed out", 6)
    with pytest.raises(errors.FtpctlError) as excinfo:
        connect_with_retries(TimeoutBackend(), timeout_s=0.01)
    assert excinfo.value.exit_code == 6
