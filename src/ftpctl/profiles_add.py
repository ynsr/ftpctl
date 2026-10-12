"""`ftpctl profiles add` — interactive profile onboarding with a live probe.

Flow: gather params (flags, else prompt) -> resolve password from
FTPCTL_<NAME>_PASSWORD (prompt hidden for the probe only; the file stores the
${VAR} reference, never the secret) -> connect+auth+list root -> on unknown
SFTP host key offer to pin (out-of-band verify) -> on probe failure ask once
whether to add anyway -> surgical TOML upsert preserving comments.

stdout: single JSON result. Prompts, hints, errors -> stderr.
Exit codes: 0 added · 2 usage/config/exists · 3 missing env var ·
4/5/6 probe failure the user refused to override · 1 other.
"""

from __future__ import annotations

import base64
import hashlib
import os
import re
import sys
import tomllib
from pathlib import Path

from .backends import connect_with_retries, make_backend
from .config import DEFAULT_TIMEOUT, _profile_from_dict, default_config_path
from .errors import FtpctlError, scrub
from .paths import confine_remote

EXIT_USAGE = 2

_NAME_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9_-]*$")
_NONALNUM_RE = re.compile(r"[^A-Z0-9]+")
_BLOCK_RE_TEMPLATE = r"(?ms)^\[profiles\.{name}\][^\S\n]*\n(.*?)(?=^\[|\Z)"


def derive_env_var(name: str) -> str:
    """FTPCTL_<SANITIZED-NAME>_PASSWORD, e.g. 'saman-pmr' -> FTPCTL_SAMAN_PMR_PASSWORD."""
    return f"FTPCTL_{_NONALNUM_RE.sub('_', name.upper()).strip('_')}_PASSWORD"


def validate_name(name: str) -> str:
    if not _NAME_RE.fullmatch(name or ""):
        raise FtpctlError(
            f"invalid profile name '{name}': use letters, digits, '-' or '_'",
            EXIT_USAGE,
        )
    return name


def _toml_str(value: str) -> str:
    return '"{}"'.format(value.replace("\\", "\\\\").replace('"', '\\"'))


def render_profile_block(
    name: str,
    protocol: str,
    host: str,
    port: int,
    username: str,
    env_var: str,
    root: str = "/",
    readonly: bool = True,
    known_hosts: str = "",
    ftps_mode: str = "explicit",
    ftp_passive: bool = True,
    allow_insecure: bool = False,
) -> str:
    """Render the [profiles.NAME] TOML block (password stored as ${VAR} reference)."""
    lines = [
        f"[profiles.{name}]",
        f"protocol = {_toml_str(protocol)}",
        f"host = {_toml_str(host)}",
        f"port = {port}",
        f"username = {_toml_str(username)}",
        f"password = {_toml_str('${' + env_var + '}')}",
        f"root = {_toml_str(root)}",
        f"readonly = {'true' if readonly else 'false'}",
    ]
    if known_hosts:
        lines.append(f"known_hosts = {_toml_str(known_hosts)}")
    if protocol == "ftps":
        lines.append(f"ftps_mode = {_toml_str(ftps_mode)}")
        lines.append(f"ftp_passive = {'true' if ftp_passive else 'false'}")
    if allow_insecure:
        lines.append("allow_insecure = true")
    return "\n".join(lines) + "\n"


def upsert_profile_block(text: str, name: str, block: str) -> tuple[str, bool]:
    """Replace the existing [profiles.NAME] block or append it. Returns (text, replaced)."""
    pattern = re.compile(_BLOCK_RE_TEMPLATE.format(name=re.escape(name)))
    match = pattern.search(text if text.endswith("\n") or not text else text + "\n")
    if match:
        return pattern.sub(lambda _: block, text if text.endswith("\n") or not text else text + "\n"), True
    base = text if not text or text.endswith("\n") else text + "\n"
    sep = "" if not base or base.endswith("\n\n") else "\n"
    if base and "[profiles" not in base and "[defaults" not in base:
        base = "[profiles]\n\n" + base if base.strip() else "[profiles]\n\n"
        sep = "" if base.endswith("\n\n") else "\n"
    return base + sep + block, False


def fetch_host_key(host: str, port: int, timeout_s: float) -> tuple[str, str, str]:
    """Fetch the server's SSH host key without authenticating. Returns (keytype, base64, sha256fp)."""
    import socket

    import paramiko

    sock = socket.create_connection((host, port), timeout=timeout_s)
    transport = paramiko.Transport(sock)
    try:
        transport.start_client(timeout=timeout_s)
        key = transport.get_remote_server_key()
    finally:
        transport.close()
    digest = hashlib.sha256(key.asbytes()).digest()
    fingerprint = "SHA256:" + base64.b64encode(digest).decode().rstrip("=")
    return key.get_name(), key.get_base64(), fingerprint


def pin_host_key(known_hosts_path: str, host: str, port: int, keytype: str, base64key: str) -> None:
    """Append a host-key pin; create the file (0600) with parents as needed."""
    target = f"[{host}]:{port}" if port != 22 else host
    path = Path(known_hosts_path).expanduser()
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "a", encoding="utf-8") as fh:
        fh.write(f"{target} {keytype} {base64key}\n")
    try:
        path.chmod(0o600)
    except OSError:
        pass


def _non_interactive(args: object) -> bool:
    if getattr(args, "no_input", False):
        return True
    if os.environ.get("CI", "").strip():
        return True
    try:
        return not sys.stdin.isatty()
    except Exception:
        return True


def _ask(args: object, prompt: str, default: str = "") -> str:
    """Prompt on stderr; raise usage error when non-interactive and no usable default."""
    suffix = f" [{default}]" if default else ""
    if _non_interactive(args):
        if default:
            return default
        raise FtpctlError(f"missing required value for '{prompt}' (non-interactive: pass the flag)", EXIT_USAGE)
    print(f"{prompt}{suffix}: ", end="", file=sys.stderr, flush=True)
    try:
        answer = sys.stdin.readline()
    except Exception as exc:
        raise FtpctlError(f"cannot read input: {exc}", 1) from None
    if not answer:
        raise FtpctlError(f"missing required value for '{prompt}' (got EOF)", EXIT_USAGE)
    answer = answer.strip()
    return answer or default


def _ask_password(env_var: str, args: object) -> str:
    """Password for the live probe only: env var wins, else hidden prompt; never stored."""
    existing = os.environ.get(env_var, "")
    if existing:
        return existing
    if _non_interactive(args):
        raise FtpctlError(f"missing environment variable: {env_var}", 3)
    import getpass

    try:
        value = getpass.getpass(f"Password for probe (stored as ${{{env_var}}}, not saved): ")
    except Exception as exc:
        raise FtpctlError(f"cannot read password: {exc}", 1) from None
    if not value:
        raise FtpctlError(f"missing environment variable: {env_var}", 3)
    return value


def _ask_yes_no(args: object, prompt: str, default_no: bool = True) -> bool:
    if getattr(args, "yes", False):
        return True
    if _non_interactive(args):
        return not default_no
    hint = "y/N" if default_no else "Y/n"
    print(f"{prompt} [{hint}]: ", end="", file=sys.stderr, flush=True)
    try:
        answer = (sys.stdin.readline() or "").strip().lower()
    except Exception:
        return False
    if not answer:
        return not default_no
    return answer in ("y", "yes")


def _probe(profile: object, timeout_s: float) -> tuple[dict[str, str], int]:
    """Connect+auth+list root. Returns (steps, exit_code); 0 means all ok."""
    from .config import Profile

    assert isinstance(profile, Profile)
    backend = make_backend(profile)
    steps: dict[str, str] = {}
    try:
        try:
            connect_with_retries(backend, timeout_s)
        except FtpctlError as exc:
            if exc.exit_code == 4:
                steps.update(connect="ok", auth="failed")
            elif exc.exit_code == 5:
                steps.update(connect="ok", auth="ok", host_key="failed")
            else:
                steps.update(connect="failed")
            return steps, exc.exit_code
        steps.update(connect="ok", auth="ok")
        try:
            backend.list(confine_remote(profile.root, "/"))
            steps["list_root"] = "ok"
        except FtpctlError as exc:
            steps["list_root"] = "failed"
            return steps, exc.exit_code
        return steps, 0
    finally:
        backend.close()


def _is_unknown_key(exc: FtpctlError) -> bool:
    return exc.exit_code == 5 and "not in known_hosts" in scrub(str(exc))


def cmd_profiles_add(args: object, config_path: str | None) -> int:
    """Implement `ftpctl profiles add`. Args come from argparse (duck-typed for tests)."""
    import json

    cfg_path = Path(config_path).expanduser() if config_path else default_config_path()

    def flag(key: str, default: object = None) -> object:
        return getattr(args, key, default)

    name = validate_name(str(flag("name") or _ask(args, "Profile name")))
    protocol = str(flag("protocol") or _ask(args, "Protocol (sftp|ftps|ftp)", "sftp")).lower()
    if protocol not in ("sftp", "ftps", "ftp"):
        raise FtpctlError(f"profile '{name}': protocol must be sftp|ftps|ftp", EXIT_USAGE)
    default_ports = {"sftp": 22, "ftps": 21, "ftp": 21}
    port_raw = flag("port")
    if port_raw is not None:
        port = int(str(port_raw))
    else:
        port = int(_ask(args, "Port", str(default_ports[protocol])) or default_ports[protocol])
    host = str(flag("host") or _ask(args, "Host"))
    if not host:
        raise FtpctlError(f"profile '{name}': host is required", EXIT_USAGE)
    username = str(flag("username") or _ask(args, "Username"))
    root = str(flag("root") or _ask(args, "Root", "/")) or "/"
    if not root.startswith("/"):
        raise FtpctlError(f"profile '{name}': root must be an absolute path", EXIT_USAGE)
    readonly = bool(flag("readonly", True))
    ftps_mode = str(flag("ftps_mode", "explicit")).lower()
    ftp_passive = bool(flag("ftp_passive", True))
    allow_insecure = bool(flag("allow_insecure", False))
    timeout_s = float(str(flag("timeout", DEFAULT_TIMEOUT) or DEFAULT_TIMEOUT))
    overwrite = bool(flag("overwrite", False))

    env_var = derive_env_var(name)
    known_hosts = str(flag("known_hosts") or "")
    if protocol == "sftp" and not known_hosts:
        known_hosts = str(cfg_path.parent / "known_hosts")

    existing_text = cfg_path.read_text() if cfg_path.exists() else ""
    if existing_text:
        try:
            tomllib.loads(existing_text)
        except tomllib.TOMLDecodeError as exc:
            raise FtpctlError(f"config file is not valid TOML: {exc}", EXIT_USAGE) from None
    name_exists = re.search(_BLOCK_RE_TEMPLATE.format(name=re.escape(name)), existing_text) is not None
    if name_exists and not overwrite:
        raise FtpctlError(
            f"profile '{name}' already exists (hint: re-run with --overwrite to replace it)", EXIT_USAGE
        )

    # Validate field rules (port/root/allow_insecure/ftps_mode) without touching the network.
    _profile_from_dict(
        name,
        {
            "protocol": protocol, "host": host, "port": port, "username": username,
            "password": "__probe__", "root": root, "readonly": readonly,
            "known_hosts": known_hosts, "ftps_mode": ftps_mode,
            "ftp_passive": ftp_passive, "allow_insecure": allow_insecure,
        },
        {},
    )

    password = _ask_password(env_var, args)
    from .config import Profile

    probe_profile = Profile(
        name=name, protocol=protocol, host=host, port=port, username=username,
        password=password, root=root, readonly=readonly, known_hosts=known_hosts,
        ftps_mode=ftps_mode, ftp_passive=ftp_passive, allow_insecure=allow_insecure,
        timeout_seconds=int(timeout_s),
    )
    pinned = False
    # SFTP pinning offer: unknown key -> fetch, show fingerprint, pin on confirm, retry.
    if protocol == "sftp":
        steps, code = _probe(probe_profile, timeout_s)
        if code == 5 and steps.get("host_key") == "failed":
            # Distinguish unknown-key (pinnable) from mismatch (never auto-pin).
            backend = make_backend(probe_profile)
            unknown = False
            try:
                try:
                    connect_with_retries(backend, timeout_s)
                except FtpctlError as exc:
                    unknown = _is_unknown_key(exc)
                finally:
                    backend.close()
            except Exception:
                unknown = False
            if unknown and (getattr(args, "yes", False) or not _non_interactive(args)):
                try:
                    keytype, b64, fingerprint = fetch_host_key(host, port, timeout_s)
                except Exception as exc:
                    raise FtpctlError(f"cannot fetch host key for pinning: {scrub(str(exc))}", 6) from None
                print(
                    f"Unknown host key for {host}:{port}:\n  {fingerprint} ({keytype})\n"
                    "Verify this fingerprint out-of-band before trusting it.",
                    file=sys.stderr,
                )
                if _ask_yes_no(args, "Pin this key for the new profile?"):
                    pin_host_key(known_hosts, host, port, keytype, b64)
                    pinned = True
                    steps, code = _probe(probe_profile, timeout_s)
            elif unknown:
                print(
                    f"Unknown host key for {host}:{port} — verify out-of-band, then pin with:\n"
                    f"  ssh-keyscan -p {port} {host} >> {known_hosts}",
                    file=sys.stderr,
                )
    else:
        steps, code = _probe(probe_profile, timeout_s)

    if code != 0:
        print(f"Connection probe failed (exit {code}): {json.dumps(steps)}", file=sys.stderr)
        if not _ask_yes_no(args, "Add the profile anyway?"):
            print(json.dumps({"profile": name, "added": False, "probe": steps, "ok": False}))
            from .transfer import audit

            audit("profiles-add", name, root, 0, "", code)
            return code

    block = render_profile_block(
        name, protocol, host, port, username, env_var, root, readonly,
        known_hosts, ftps_mode, ftp_passive, allow_insecure,
    )
    new_text, replaced = upsert_profile_block(existing_text, name, block)
    # Final sanity: the result must parse and the profile must load with the env ref.
    raw = tomllib.loads(new_text if new_text.strip() else "[profiles]\n")
    if name not in (raw.get("profiles", {}) or {}):
        raise FtpctlError(f"profile '{name}': write produced invalid config", 1)
    cfg_path.parent.mkdir(parents=True, exist_ok=True)
    cfg_path.write_text(new_text)
    try:
        cfg_path.chmod(0o600)
    except OSError:
        pass

    if not os.environ.get(env_var):
        print(
            f"Password is NOT saved. Set it before use:\n  export {env_var}='<password>'",
            file=sys.stderr,
        )
    from .transfer import audit

    audit("profiles-add", name, root, 0, "", 0)
    print(json.dumps({
        "profile": name, "added": True, "replaced": replaced,
        "probe": {**steps, "ok": code == 0},
        "env_var": env_var, "pinned_host_key": pinned,
        "config": str(cfg_path), "ok": True,
    }))
    return 0
