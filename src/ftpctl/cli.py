"""ftpctl — safe FTP/FTPS/SFTP wrapper for AI agents.

stdout: a single JSON object. stderr: human-readable errors.
Exit codes: 0 ok, 2 usage/config, 3 missing env var, 4 auth failure,
5 host key/cert failure, 6 network/timeout, 7 policy violation, 1 other.

Secrets come from FTPCTL_* env vars referenced by the TOML profile only —
never CLI args, never stdin. Resolved values are memory-only and scrubbed
from every error message.
"""

from __future__ import annotations

import argparse
import json
import sys
import typing
from dataclasses import asdict
from pathlib import Path
from typing import Any, cast

from . import __version__
from .backends import Backend, Entry, SftpBackend, connect_with_retries, make_backend
from .config import Config, Profile, load_config, warn_stderr
from .errors import FtpctlError, scrub, wrap
from .output import emit as emit_rows
from .paths import confine_remote
from .transfer import audit, cmd_get, cmd_put

EXIT_USAGE = 2


def emit_json(payload: object) -> None:
    print(json.dumps(payload, indent=2))


def fail(message: str, exit_code: int) -> typing.NoReturn:
    print(f"error: {scrub(message)}", file=sys.stderr)
    raise SystemExit(exit_code)




def _load(profile_name: str, config_path: str | None) -> tuple[Config, Profile]:
    path = Path(config_path).expanduser() if config_path else None
    config, warnings = load_config(path)
    for warning in warnings:
        warn_stderr(warning)
    profile = config.profiles.get(profile_name)
    if profile is None:
        available = ", ".join(sorted(config.profiles)) or "(none)"
        raise FtpctlError(f"unknown profile '{profile_name}' (available: {available})", EXIT_USAGE)
    return config, profile


def _open(profile: Profile) -> Backend:
    backend = make_backend(profile)
    connect_with_retries(backend, float(profile.timeout_seconds))
    return backend


def cmd_profiles(config: Config, warnings: list[str], output: str = "json") -> int:
    rows: list[dict[str, object]] = [
        {
            "name": p.name,
            "protocol": p.protocol,
            "host": p.host,
            "root": p.root,
            "readonly": p.readonly,
        }
        for p in (config.profiles[name] for name in sorted(config.profiles))
    ]
    if output == "json":
        payload: dict[str, object] = {"profiles": rows}
        if warnings:
            payload["warnings"] = warnings
        emit_json(payload)
    else:
        emit_rows(rows, output, fields=["name", "protocol", "host", "root", "readonly"])
    return 0


def _load_sample_toml() -> str:
    """Read the reference profiles.toml shipped as package data (single source)."""
    return (Path(__file__).with_name("profiles.sample.toml")).read_text()


def cmd_profiles_sample() -> int:
    print(_load_sample_toml(), end="")
    return 0

def _walk(backend: Backend, path: str, limit: int, out: list[dict[str, object]]) -> bool:
    """Depth-first recursive walk. Returns True when the global cap truncated output."""
    truncated = False
    try:
        entries = backend.list(path)
    except FtpctlError:
        return False
    for entry in entries:
        if len(out) >= limit:
            return True
        out.append(_entry_json(entry))
        if entry.type == "dir":
            if _walk(backend, entry.path, limit, out):
                truncated = True
    return truncated


def _entry_json(entry: Entry) -> dict[str, object]:
    d = asdict(cast(Any, entry))
    return {k: d[k] for k in ("name", "path", "type", "size", "mtime", "mode")}


def cmd_ls(profile: Profile, remote: str, recursive: bool, limit: int | None, output: str = "json") -> int:
    """remote must already be confined by the caller (policy before network)."""
    backend = _open(profile)
    try:
        out: list[dict[str, object]] = []
        cap = profile.max_list_entries
        if recursive:
            truncated = _walk(backend, remote, cap, out)
        else:
            try:
                probe = backend.stat(remote)
            except FtpctlError as exc:
                if exc.exit_code == 1:
                    raise FtpctlError("no such file or directory", 1) from None
                raise
            if probe.type == "file" or probe.type == "link":
                out.append(_entry_json(probe))
                truncated = False
            else:
                for entry in backend.list(remote):
                    if len(out) >= cap:
                        truncated = True
                        break
                    out.append(_entry_json(entry))
                else:
                    truncated = False
        if limit is not None and len(out) > limit:
            out = out[:limit]
            truncated = True
        if output == "json":
            payload: dict[str, object] = {"entries": out, "truncated": truncated}
            warning = getattr(backend, "insecure_warning", None)
            if warning:
                payload["warning"] = warning
            emit_json(payload)
        else:
            emit_rows(out, output, fields=["name", "path", "type", "size", "mtime", "mode"])
        return 0
    finally:
        backend.close()


def cmd_stat(profile: Profile, remote: str, output: str = "json") -> int:
    """remote must already be confined by the caller (policy before network)."""
    backend = _open(profile)
    try:
        entry = backend.stat(remote)
        if entry.type == "link":
            # Resolve-then-reconfine: a link escaping root is a policy violation.
            resolved = backend._resolve_link(remote) if isinstance(backend, SftpBackend) else remote
            confine_remote(profile.root, resolved)
        if output == "json":
            payload: dict[str, object] = _entry_json(entry)
            warning = getattr(backend, "insecure_warning", None)
            if warning:
                payload["warning"] = warning
            emit_json(payload)
        else:
            emit_rows([_entry_json(entry)], output, fields=["name", "path", "type", "size", "mtime", "mode"])
        return 0
    finally:
        backend.close()


def cmd_check(profile: Profile) -> int:
    steps: dict[str, str] = {}
    backend = make_backend(profile)
    try:
        try:
            connect_with_retries(backend, float(profile.timeout_seconds))
        except FtpctlError as exc:
            # Map the failing phase: connect/auth/list-root inferred from exit code.
            if exc.exit_code == 4:
                steps.update(connect="ok", auth="failed")
            elif exc.exit_code == 5:
                steps.update(connect="ok", auth="ok", host_key="failed")
            else:
                steps.update(connect="failed")
            emit_json({"profile": profile.name, "steps": steps, "ok": False})
            audit("check", profile.name, profile.root, 0, "", exc.exit_code)
            return exc.exit_code
        steps.update(connect="ok", auth="ok")
        try:
            backend.list(confine_remote(profile.root, "/"))
            steps["list_root"] = "ok"
        except FtpctlError as exc:
            steps["list_root"] = "failed"
            emit_json({"profile": profile.name, "steps": steps, "ok": False})
            audit("check", profile.name, profile.root, 0, "", exc.exit_code)
            return exc.exit_code
        emit_json({"profile": profile.name, "steps": steps, "ok": True})
        audit("check", profile.name, profile.root, 0, "", 0)
        return 0
    finally:
        backend.close()


class _Parser(argparse.ArgumentParser):
    """argparse that emits the error envelope (exit 2) instead of plain usage text."""

    def error(self, message: str) -> typing.NoReturn:
        from .output import fail as output_fail
        output_fail("invalid arguments", "usage", "run with --help", 2)
        raise AssertionError("unreachable: output_fail always exits")


def build_parser() -> argparse.ArgumentParser:
    parser = _Parser(
        prog="ftpctl",
        description="Safe FTP/FTPS/SFTP wrapper for AI agents. JSON on stdout; errors on stderr. "
        "Exit codes: 0 ok, 2 usage/config, 3 missing env var, 4 auth failure, "
        "5 host key/cert failure, 6 network/timeout, 7 policy violation, 1 other.",
    )
    parser.add_argument("--version", action="version", version=f"ftpctl {__version__}")
    parser.add_argument("--config", default=None, help="config path (default ~/.config/ftpctl/profiles.toml)")
    parser.add_argument(
        "--output", "-o", default="json",
        choices=["table", "json", "csv", "tsv"],
        help="output format for list-style commands (default json)",
    )
    parser.add_argument("--json", action="store_true", help="alias for --output json")
    _fmt_kwargs: dict[str, object] = {
        "default": argparse.SUPPRESS,
        "choices": ["table", "json", "csv", "tsv"],
        "help": "output format (default json)",
    }
    _json_kwargs: dict[str, object] = {
        "default": argparse.SUPPRESS, "action": "store_true", "help": "alias for --output json",
    }
    sub = parser.add_subparsers(dest="command", required=True)
    p_profiles = sub.add_parser("profiles", help="list profile names, protocol, host, root, readonly (no secrets)")
    p_profiles.add_argument("--output", "-o", **_fmt_kwargs)  # type: ignore[arg-type]
    p_profiles.add_argument("--json", **_json_kwargs)  # type: ignore[arg-type]
    p_profiles.add_argument("--sample", action="store_true",
                            help="print a reference profiles.toml with all fields and rules, then exit")
    p_ls = sub.add_parser("ls", help="list a remote directory as JSON")
    p_ls.add_argument("--profile", required=True)
    p_ls.add_argument("path", nargs="?", default="/")
    p_ls.add_argument("--recursive", action="store_true")
    p_ls.add_argument("--limit", type=int, default=None)
    p_ls.add_argument("--output", "-o", **_fmt_kwargs)  # type: ignore[arg-type]
    p_ls.add_argument("--json", **_json_kwargs)  # type: ignore[arg-type]
    p_stat = sub.add_parser("stat", help="stat a remote path as JSON")
    p_stat.add_argument("--profile", required=True)
    p_stat.add_argument("path")
    p_stat.add_argument("--output", "-o", **_fmt_kwargs)  # type: ignore[arg-type]
    p_stat.add_argument("--json", **_json_kwargs)  # type: ignore[arg-type]

    p_get = sub.add_parser("get", help="download a remote file atomically")
    p_get.add_argument("--profile", required=True)
    p_get.add_argument("remote_path")
    p_get.add_argument("local_path")
    p_get.add_argument("--overwrite", action="store_true")

    p_put = sub.add_parser("put", help="upload a local file (refused if readonly)")
    p_put.add_argument("--profile", required=True)
    p_put.add_argument("local_path")
    p_put.add_argument("remote_path")
    p_put.add_argument("--overwrite", action="store_true")

    p_check = sub.add_parser("check", help="connect+auth+list root; report which step failed")
    p_check.add_argument("--profile", required=True)
    return parser


def _resolve_output(args: argparse.Namespace) -> str:
    """Subcommand --output/-o wins over the global flag; --json forces json."""
    if getattr(args, "json", False):
        return "json"
    return str(getattr(args, "output", "json"))


def main(argv: list[str] | None = None) -> None:
    parser = build_parser()
    args = parser.parse_args(argv)  # usage errors exit via _Parser.error envelope
    try:
        if args.command == "profiles" and args.sample:
            raise SystemExit(cmd_profiles_sample())
        if args.command == "profiles":
            config, warnings = load_config(
                Path(args.config).expanduser() if args.config else None
            )
            for warning in warnings:
                warn_stderr(warning)
            raise SystemExit(cmd_profiles(config, warnings, _resolve_output(args)))
        _, profile = _load(args.profile, args.config)
        if args.command == "ls":
            if args.limit is not None and args.limit < 0:
                raise FtpctlError("--limit must be >= 0", EXIT_USAGE)
            remote = confine_remote(profile.root, args.path)  # policy before network
            raise SystemExit(cmd_ls(profile, remote, args.recursive, args.limit, _resolve_output(args)))
        if args.command == "stat":
            remote = confine_remote(profile.root, args.path)  # policy before network
            raise SystemExit(cmd_stat(profile, remote, _resolve_output(args)))
        if args.command == "get":
            remote = confine_remote(profile.root, args.remote_path)
            backend = _open(profile)
            try:
                emit_json(cmd_get(backend, profile, remote, args.local_path, args.overwrite))
            finally:
                backend.close()
            raise SystemExit(0)
        if args.command == "put":
            remote = confine_remote(profile.root, args.remote_path)
            backend = _open(profile)
            try:
                emit_json(cmd_put(backend, profile, args.local_path, remote, args.overwrite))
            finally:
                backend.close()
            raise SystemExit(0)
        if args.command == "check":
            raise SystemExit(cmd_check(profile))
    except FtpctlError as exc:
        fail(str(exc), exc.exit_code)
    except BrokenPipeError:
        raise SystemExit(1) from None
    except Exception as exc:  # last resort: scrub + exit 1, never a traceback
        fail(wrap(exc, 1).args[0], 1)


if __name__ == "__main__":
    main()
