"""TOML profile loading + strict ${FTPCTL_*} interpolation (security critical).

Rules (spec §Env-var interpolation):
- Only the literal form ${NAME} inside a string value. No defaults, no nesting.
- NAME must match ^FTPCTL_[A-Z0-9_]+$; anything else -> "disallowed env var reference".
- Missing or empty var -> error naming the VARIABLE NAME only, exit code 3.
- Interpolation allowed only in: username, password, host. Other fields are literals.
- Resolved values held in memory only; registered with errors.register_secret
  so the error kernel can scrub them from every outward message.
"""

from __future__ import annotations

import os
import re
import stat
import sys
import tomllib
from dataclasses import dataclass, field
from pathlib import Path

from platformdirs import user_config_dir

from .errors import FtpctlError, register_secret

_NAME_RE = re.compile(r"FTPCTL_[A-Z0-9_]+$")
_REF_RE = re.compile(r"\$\{([^}]*)\}")
_INTERPOLATED_FIELDS = frozenset({"username", "password", "host"})

DEFAULT_TIMEOUT = 30
DEFAULT_MAX_DOWNLOAD_BYTES = 104_857_600
DEFAULT_MAX_LIST_ENTRIES = 1_000


def _to_int(value: object, default: int) -> int:
    """Coerce a TOML scalar to int; None means unset -> default."""
    if value is None:
        return default
    if isinstance(value, (int, float, str)):
        return int(value)
    return int(str(value))


@dataclass
class Profile:
    name: str
    protocol: str  # sftp | ftps | ftp
    host: str
    port: int
    username: str
    password: str
    root: str = "/"
    readonly: bool = True
    known_hosts: str = ""
    ftps_mode: str = "explicit"  # explicit | implicit (ftps only)
    ftp_passive: bool = True
    allow_insecure: bool = False
    timeout_seconds: int = DEFAULT_TIMEOUT
    max_download_bytes: int = DEFAULT_MAX_DOWNLOAD_BYTES
    max_list_entries: int = DEFAULT_MAX_LIST_ENTRIES
    download_dir: str = ""
    # Resolved secrets, memory-only, never serialized:
    _secrets: tuple[str, ...] = field(default=(), repr=False)


@dataclass
class Config:
    defaults: dict[str, object]
    profiles: dict[str, Profile]

    @property
    def timeout_seconds(self) -> int:
        return _to_int(self.defaults.get("timeout_seconds"), DEFAULT_TIMEOUT)

    @property
    def max_download_bytes(self) -> int:
        return _to_int(self.defaults.get("max_download_bytes"), DEFAULT_MAX_DOWNLOAD_BYTES)

    @property
    def max_list_entries(self) -> int:
        return _to_int(self.defaults.get("max_list_entries"), DEFAULT_MAX_LIST_ENTRIES)

    @property
    def download_dir(self) -> str:
        return str(self.defaults.get("download_dir", ""))


def default_config_path() -> Path:
    override = os.environ.get("FTPCTL_CONFIG")
    if override:
        return Path(override).expanduser()
    return Path(user_config_dir("ftpctl")) / "profiles.toml"


def check_config_perms(path: Path) -> list[str]:
    """Req 12: config/known_hosts must not be group/world-writable; warn if readable."""
    warnings: list[str] = []
    try:
        mode = path.stat().st_mode
    except OSError:
        return warnings
    if mode & (stat.S_IWGRP | stat.S_IWOTH):
        raise FtpctlError(f"config file is group/world-writable: {path}", 2)
    if mode & (stat.S_IRGRP | stat.S_IROTH):
        warnings.append(f"config file is group/world-readable: {path}")
    return warnings


def _interpolate(value: object, field_name: str, profile_name: str) -> str:
    if not isinstance(value, str):
        return "" if value is None else str(value)
    if field_name not in _INTERPOLATED_FIELDS:
        if "${" in value:
            raise FtpctlError(
                f"profile '{profile_name}': interpolation only allowed in username/password/host",
                2,
            )
        return value
    def replace(match: re.Match[str]) -> str:
        name = match.group(1)
        if not _NAME_RE.fullmatch(name):
            raise FtpctlError(f"profile '{profile_name}': disallowed env var reference", 2)
        resolved = os.environ.get(name, "")
        if not resolved:
            raise FtpctlError(f"missing environment variable: {name}", 3)
        register_secret(resolved)
        return resolved
    # A bare "$" or malformed reference that is not ${...} is left literal;
    # only ${...} triggers interpolation. Nested/escaped forms fail the NAME check.
    result = _REF_RE.sub(replace, value)
    if "${" in result:
        raise FtpctlError(f"profile '{profile_name}': disallowed env var reference", 2)
    return result


def _profile_from_dict(name: str, raw: dict[str, object], defaults: dict[str, object]) -> Profile:
    protocol = str(raw.get("protocol", "")).lower()
    if protocol not in ("sftp", "ftps", "ftp"):
        raise FtpctlError(f"profile '{name}': protocol must be sftp|ftps|ftp", 2)
    default_ports = {"sftp": 22, "ftps": 21, "ftp": 21}
    port_raw = raw.get("port", default_ports[protocol])
    try:
        port = int(str(port_raw))
    except ValueError:
        raise FtpctlError(f"profile '{name}': port must be an integer", 2) from None
    username = _interpolate(raw.get("username", ""), "username", name)
    password = _interpolate(raw.get("password", ""), "password", name)
    host = _interpolate(raw.get("host", ""), "host", name)
    if protocol != "ftp" and raw.get("allow_insecure", False):
        raise FtpctlError(f"profile '{name}': allow_insecure applies to plain ftp only", 2)
    ftps_mode = str(raw.get("ftps_mode", "explicit")).lower()
    if protocol == "ftps" and ftps_mode not in ("explicit", "implicit"):
        raise FtpctlError(f"profile '{name}': ftps_mode must be explicit|implicit", 2)
    root = str(raw.get("root", "/")) or "/"
    if not root.startswith("/"):
        raise FtpctlError(f"profile '{name}': root must be an absolute path", 2)
    profile = Profile(
        name=name,
        protocol=protocol,
        host=host,
        port=port,
        username=username,
        password=password,
        root=root,
        readonly=bool(raw.get("readonly", True)),
        known_hosts=str(raw.get("known_hosts", "")),
        ftps_mode=ftps_mode,
        ftp_passive=bool(raw.get("ftp_passive", True)),
        allow_insecure=bool(raw.get("allow_insecure", False)),
        timeout_seconds=_to_int(defaults.get("timeout_seconds"), DEFAULT_TIMEOUT),
        max_download_bytes=_to_int(defaults.get("max_download_bytes"), DEFAULT_MAX_DOWNLOAD_BYTES),
        max_list_entries=_to_int(defaults.get("max_list_entries"), DEFAULT_MAX_LIST_ENTRIES),
        download_dir=str(defaults.get("download_dir", "")),
        _secrets=tuple(v for v in (username, password) if v),
    )
    if not host:
        raise FtpctlError(f"profile '{name}': host is required", 2)
    return profile


def load_config(path: Path | None = None) -> tuple[Config, list[str]]:
    """Load TOML config; returns (config, warnings). Raises FtpctlError."""
    cfg_path = path or default_config_path()
    try:
        raw = tomllib.loads(cfg_path.read_text())
    except FileNotFoundError:
        raise FtpctlError(f"config file not found: {cfg_path}", 2) from None
    except tomllib.TOMLDecodeError as exc:
        raise FtpctlError(f"config file is not valid TOML: {exc}", 2) from None
    warnings = check_config_perms(cfg_path)
    defaults = dict(raw.get("defaults", {}))
    profiles: dict[str, Profile] = {}
    for name, praw in (raw.get("profiles", {}) or {}).items():
        if not isinstance(praw, dict):
            raise FtpctlError(f"profile '{name}': must be a TOML table", 2)
        profiles[str(name)] = _profile_from_dict(str(name), praw, defaults)
    return Config(defaults=defaults, profiles=profiles), warnings


def warn_stderr(text: str) -> None:
    print(f"warning: {text}", file=sys.stderr)
