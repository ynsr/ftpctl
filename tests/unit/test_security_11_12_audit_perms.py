"""Req 11: append-only audit log (JSON lines, 0600, no secrets). Req 12: config perms."""

from __future__ import annotations

import json
import stat

import pytest
from conftest import write_config

from ftpctl import errors
from ftpctl.transfer import audit


def test_audit_appends_json_line(workdir) -> None:  # type: ignore[no-untyped-def]
    audit("get", "demo", "/hello.txt", 6, "abc123", 0)
    audit("put", "demo", "/up.txt", 9, "def456", 7)
    lines = (workdir / "state" / "audit.log").read_text().splitlines()
    assert len(lines) == 2
    first = json.loads(lines[0])
    assert first == {"ts": first["ts"], "profile": "demo", "op": "get",
                     "remote": "/hello.txt", "bytes": 6, "sha256": "abc123", "exit": 0}
    assert first["ts"].endswith("Z")


def test_audit_mode_600(workdir) -> None:  # type: ignore[no-untyped-def]
    audit("check", "demo", "/", 0, "", 0)
    mode = (workdir / "state" / "audit.log").stat().st_mode
    assert stat.S_IMODE(mode) == 0o600


def test_audit_never_contains_secrets(workdir) -> None:  # type: ignore[no-untyped-def]
    errors.register_secret("s3cret-xyz")
    audit("get", "demo", "/hello.txt", 6, "abc", 0)
    body = (workdir / "state" / "audit.log").read_text()
    assert "s3cret-xyz" not in body


def test_config_group_writable_refused(workdir) -> None:  # type: ignore[no-untyped-def]
    cfg = write_config(workdir, "[defaults]\n", mode=0o664)
    from ftpctl.config import load_config
    with pytest.raises(errors.FtpctlError) as excinfo:
        load_config(cfg)
    assert excinfo.value.exit_code == 2
    assert "writable" in str(excinfo.value)


def test_config_group_readable_warns(workdir, capsys) -> None:  # type: ignore[no-untyped-def]
    cfg = write_config(workdir, "[defaults]\n", mode=0o644)
    from ftpctl.config import check_config_perms
    warnings = check_config_perms(cfg)
    assert len(warnings) == 1 and "readable" in warnings[0]


def test_env_interpolation_rules(workdir, monkeypatch) -> None:  # type: ignore[no-untyped-def]
    from ftpctl.config import load_config
    # Disallowed name:
    cfg = write_config(workdir, '[profiles.a]\nprotocol="ftp"\nhost="h"\nusername="${HOME}"\n')
    with pytest.raises(errors.FtpctlError, match="disallowed env var reference"):
        load_config(cfg)
    # Missing var names the VARIABLE, exit 3:
    cfg = write_config(workdir, '[profiles.a]\nprotocol="ftp"\nhost="h"\nusername="${FTPCTL_NOPE_X}"\n')
    with pytest.raises(errors.FtpctlError) as excinfo:
        load_config(cfg)
    assert excinfo.value.exit_code == 3
    assert "FTPCTL_NOPE_X" in str(excinfo.value)
    # Interpolation outside username/password/host refused:
    cfg = write_config(workdir, '[profiles.a]\nprotocol="ftp"\nhost="h"\nroot="${FTPCTL_X_ROOT}"\n')
    with pytest.raises(errors.FtpctlError) as excinfo2:
        load_config(cfg)
    assert excinfo2.value.exit_code == 2


def test_ftp_prefix_var_rejected(workdir, monkeypatch) -> None:  # type: ignore[no-untyped-def]
    """Lesson from real onboarding: only ${FTPCTL_*} interpolates; ${FTP_*} is refused.

    A user exporting FTP_SAMAN_* / FTP_SEPEHR_* and referencing ${FTP_...} in
    profiles.toml gets "disallowed env var reference" (exit 2) — the fix is to
    rename the env vars to the FTPCTL_ prefix, not to relax the pattern.
    """
    from ftpctl.config import load_config
    monkeypatch.setenv("FTP_SAMAN_PMR_PASSWORD", "s3cret")
    cfg = write_config(workdir, '[profiles.a]\nprotocol="sftp"\nhost="h"\n'
                                'username="u"\npassword="${FTP_SAMAN_PMR_PASSWORD}"\n')
    with pytest.raises(errors.FtpctlError, match="disallowed env var reference") as excinfo:
        load_config(cfg)
    assert excinfo.value.exit_code == 2
