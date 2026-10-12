"""Req 4: remote path confinement. Req 10: control-char sanitizing."""

from __future__ import annotations

import pytest

from ftpctl import errors
from ftpctl.paths import confine_local, confine_remote, sanitize_name


@pytest.mark.parametrize(("root", "path", "expected"), [
    ("/outbound", "a/b.txt", "/outbound/a/b.txt"),
    ("/outbound", "/outbound/a.txt", "/outbound/a.txt"),
    ("/outbound", ".", "/outbound"),
    ("/outbound", "sub/../a.txt", "/outbound/a.txt"),
    ("/", "a.txt", "/a.txt"),
])
def test_confinement_allows(root: str, path: str, expected: str) -> None:
    assert confine_remote(root, path) == expected


@pytest.mark.parametrize("path", [
    "..", "../secret", "a/../../etc", "/etc/passwd", "/other/root",
    "/outbound/../escape", "a/\x00b", "a\x01b.txt",
])
def test_confinement_rejects(path: str) -> None:
    with pytest.raises(errors.FtpctlError) as excinfo:
        confine_remote("/outbound", path)
    assert excinfo.value.exit_code == 7


def test_absolute_under_root_ok() -> None:
    assert confine_remote("/outbound", "/outbound/sub/f.txt") == "/outbound/sub/f.txt"


def test_sanitize_control_chars() -> None:
    assert "\x01" not in sanitize_name("a\x01b\x7fc")
    assert sanitize_name("plain.txt") == "plain.txt"


def test_local_confined_to_cwd(workdir) -> None:  # type: ignore[no-untyped-def]
    target = confine_local("downloads/f.txt")
    assert str(target).startswith(str(workdir.resolve()))


def test_local_escape_rejected(workdir) -> None:  # type: ignore[no-untyped-def]
    with pytest.raises(errors.FtpctlError) as excinfo:
        confine_local("/etc/passwd")
    assert excinfo.value.exit_code == 7


def test_local_symlink_escape_rejected(workdir) -> None:  # type: ignore[no-untyped-def]
    outside = workdir / "outside.txt"
    outside.write_bytes(b"x")
    link = workdir / "link.txt"
    link.symlink_to(outside)
    # link itself is under cwd so allowed; a link pointing outside cwd is caught
    # when it resolves outside: craft via subdir + ..
    sub = workdir / "sub"
    sub.mkdir()
    evil = sub / "evil"
    evil.symlink_to(workdir / ".." / "elsewhere.txt")
    with pytest.raises(errors.FtpctlError):
        confine_local(str(evil))


def test_download_dir_allows_configured(workdir, tmp_path) -> None:  # type: ignore[no-untyped-def]
    dl = tmp_path / "dl"
    dl.mkdir()
    target = confine_local(str(dl / "f.txt"), download_dir=str(dl))
    assert target.parent == dl.resolve()
