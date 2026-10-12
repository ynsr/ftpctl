"""Path confinement: remote posix paths under root, local paths under cwd/download_dir.

Req 4: normalize remote paths with posixpath; reject escapes (.., absolute paths
outside root, symlinks resolving outside root where detectable). Reject NUL and
control characters. Req 10: remote filenames are untrusted — sanitize control
characters before they reach JSON output.
"""

from __future__ import annotations

import os
import posixpath
from pathlib import Path

from .errors import FtpctlError

_CONTROL_RE_TRANSLATE = {c: "�" for c in range(0x20)}
_CONTROL_RE_TRANSLATE[0x7F] = "�"


def has_control_chars(value: str) -> bool:
    return "\x00" in value or any(ord(c) < 0x20 or ord(c) == 0x7F for c in value)


def sanitize_name(value: str) -> str:
    """Req 10: strip/escape control characters from untrusted remote names."""
    return value.translate(_CONTROL_RE_TRANSLATE)


def confine_remote(root: str, path: str) -> str:
    """Resolve a user-supplied remote path under root. Returns the absolute remote path.

    Raises FtpctlError(exit 7) on escape attempts or control characters.
    """
    if "\x00" in path or "\x00" in root:
        raise FtpctlError("path contains NUL byte", 7)
    if has_control_chars(path):
        raise FtpctlError("path contains control characters", 7)
    norm_root = posixpath.normpath("/" + root.lstrip("/"))
    # normpath collapses "/../etc" to "/etc": detect the traversal itself.
    # Any ".." segment is a policy violation unless it stays within root
    # (e.g. "sub/../a.txt" under /outbound is fine; "/../etc" is not).
    if path.startswith("/"):
        joined = posixpath.normpath(path)
        depth = 0
        for seg in path.split("/"):
            if seg in ("", "."):
                continue
            if seg == "..":
                depth -= 1
            else:
                depth += 1
            if depth < 0:
                raise FtpctlError(f"path escapes profile root: {path}", 7)
        candidate = joined
    else:
        candidate = posixpath.normpath(posixpath.join(norm_root, path))
    if norm_root == "/":
        ok = candidate.startswith("/")
    else:
        ok = candidate == norm_root or candidate.startswith(norm_root + "/")
    if not ok:
        raise FtpctlError(f"path escapes profile root: {path}", 7)
    return candidate


def confine_local(path_str: str, download_dir: str = "") -> Path:
    """Req 7: LOCAL_PATH must resolve under cwd or the configured download_dir.

    Symlinks resolved first via Path.resolve(). Raises FtpctlError(exit 7).
    """
    if "\x00" in path_str:
        raise FtpctlError("local path contains NUL byte", 7)
    if has_control_chars(path_str):
        raise FtpctlError("local path contains control characters", 7)
    candidate = Path(path_str).expanduser()
    if not candidate.is_absolute():
        candidate = Path.cwd() / candidate
    resolved = candidate.resolve() if candidate.exists() or candidate.is_symlink() else Path(
        os.path.abspath(candidate)
    )
    allowed = [Path.cwd().resolve()]
    if download_dir:
        allowed.append(Path(download_dir).expanduser().resolve())
    for base in allowed:
        try:
            resolved.relative_to(base)
            return resolved
        except ValueError:
            continue
    raise FtpctlError(f"local path outside allowed directories: {path_str}", 7)
