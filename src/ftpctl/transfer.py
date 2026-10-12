"""Atomic transfers + append-only audit log (req 7, req 11).

get: stream to LOCAL_PATH + ".part", enforce the size cap mid-stream (abort and
delete the partial file), os.replace on success.
put: upload to REMOTE_PATH + ".ftpctl.tmp", verify size, then rename.
Audit: JSON lines at ~/.local/state/ftpctl/audit.log (FTPCTL_STATE_DIR override
for tests), mode 600, no secrets ever.
"""

from __future__ import annotations

import hashlib
import json
import os
import time
from datetime import UTC, datetime
from pathlib import Path

from platformdirs import user_state_dir

from .backends import Backend
from .config import Profile
from .errors import FtpctlError
from .paths import confine_local


def audit_path() -> Path:
    override = os.environ.get("FTPCTL_STATE_DIR")
    base = Path(override) if override else Path(user_state_dir("ftpctl"))
    return base / "audit.log"


def audit(op: str, profile: str, remote: str, size_bytes: int, sha256: str, exit_code: int) -> None:
    """Req 11: best-effort append; a logging failure never fails the command."""
    import sys
    path = audit_path()
    record = {
        "ts": datetime.now(UTC).isoformat().replace("+00:00", "Z"),
        "profile": profile,
        "op": op,
        "remote": remote,
        "bytes": size_bytes,
        "sha256": sha256,
        "exit": exit_code,
    }
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        try:
            path.parent.chmod(0o700)
        except OSError:
            pass
        with open(path, "a", encoding="utf-8") as fh:
            fh.write(json.dumps(record) + "\n")
        try:
            path.chmod(0o600)
        except OSError:
            pass
    except OSError as exc:
        print(f"warning: audit log append failed: {exc}", file=sys.stderr)


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(65536), b""):
            digest.update(chunk)
    return digest.hexdigest()


def cmd_get(backend: Backend, profile: Profile, remote: str, local_str: str, overwrite: bool) -> dict[str, object]:
    """Download remote -> local atomically. Returns the result payload."""
    started = time.monotonic()
    local = confine_local(local_str, profile.download_dir)
    if local.exists() and not overwrite:
        raise FtpctlError(f"local file exists (use --overwrite): {local}", 7)
    if local.is_dir():
        raise FtpctlError(f"local path is a directory: {local}", 2)
    tmp = local.with_name(local.name + ".part")
    try:
        size_bytes = backend.download(remote, tmp, profile.max_download_bytes)
    except BaseException:
        try:
            if tmp.exists():
                tmp.unlink()
        except OSError:
            pass
        raise
    digest = sha256_file(tmp)
    try:
        os.replace(tmp, local)
    except OSError as exc:
        try:
            tmp.unlink()
        except OSError:
            pass
        raise FtpctlError(f"cannot move download into place: {exc}", 1) from None
    duration_ms = int((time.monotonic() - started) * 1000)
    payload = {"path": str(local), "bytes": size_bytes, "sha256": digest, "duration_ms": duration_ms}
    audit("get", profile.name, remote, size_bytes, digest, 0)
    return payload


def cmd_put(backend: Backend, profile: Profile, local_str: str, remote: str, overwrite: bool) -> dict[str, object]:
    """Upload local -> remote via tmp + size verify + rename."""
    if profile.readonly:
        raise FtpctlError(f"profile '{profile.name}' is readonly: upload refused", 7)
    started = time.monotonic()
    local = confine_local(local_str, profile.download_dir)
    if not local.is_file():
        raise FtpctlError(f"local file not found: {local}", 2)
    if local.stat().st_size > profile.max_download_bytes:
        raise FtpctlError(f"upload exceeds max_download_bytes ({profile.max_download_bytes})", 7)
    if not overwrite:
        try:
            backend.stat(remote)
        except FtpctlError as exc:
            if exc.exit_code != 1:
                raise
        else:
            raise FtpctlError("remote file exists (use --overwrite)", 7)
    remote_tmp = remote + ".ftpctl.tmp"
    sent = backend.upload(local, remote_tmp)
    remote_size = backend.size(remote_tmp)
    if remote_size is not None and remote_size != sent:
        raise FtpctlError(f"upload size mismatch: sent {sent}, remote has {remote_size}", 6)
    backend.rename(remote_tmp, remote)
    digest = sha256_file(local)
    duration_ms = int((time.monotonic() - started) * 1000)
    payload = {"path": remote, "bytes": sent, "sha256": digest, "duration_ms": duration_ms}
    audit("put", profile.name, remote, sent, digest, 0)
    return payload
