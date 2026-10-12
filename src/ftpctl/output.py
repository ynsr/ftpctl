"""stdout data emitters (table/csv/tsv/json) + the stderr error envelope.

stdout carries data only; every log, prompt, and error goes to stderr
(universal contract §4.1.1/§4.1.7).
"""

import csv
import json
import os
import sys


class CliError(Exception):
    """Command-level failure: message + envelope code + hint + exit status."""

    def __init__(self, message: str, code: str = "error", hint: str = "", status: int = 1):
        super().__init__(message)
        self.code, self.hint, self.status = code, hint, status


AUDIENCE = "agent"  # scaffold flips to "human" for human tools; changes only the default --output


def emit(rows: list[dict[str, object]], fmt: str | None = None, fields: list[str] | None = None) -> None:
    """Print rows to stdout; fmt None → audience default (agent: csv, human: table)."""
    fmt = fmt or ("table" if AUDIENCE == "human" else "csv")
    if fmt not in ("table", "json", "csv", "tsv"):
        raise CliError(f"unknown output format: {fmt}", "usage",
                       "valid formats: table|json|csv|tsv (--output/-o)", 2)
    rows = [dict(r) for r in rows]
    keys = list(fields or (rows[0] if rows else ()))
    if fields:
        rows = [{k: r.get(k, "") for k in keys} for r in rows]
    if fmt == "json":
        print(json.dumps(rows, indent=2))
        return
    if not keys:
        return
    if fmt == "table":  # plain text: no ANSI, no box-drawing characters — stdout stays data
        widths = {k: max([len(k)] + [len(str(r.get(k, ""))) for r in rows]) for k in keys}
        print("  ".join(k.upper().ljust(widths[k]) for k in keys))
        for r in rows:
            print("  ".join(str(r.get(k, "")).ljust(widths[k]) for k in keys))
    else:  # csv / tsv
        writer = csv.writer(sys.stdout, delimiter="\t" if fmt == "tsv" else ",", lineterminator="\n")
        writer.writerow(keys)
        writer.writerows([[r.get(k, "") for k in keys] for r in rows])


def _wants_envelope() -> bool:
    """Agents: non-TTY stderr, or the user asked for machine (JSON) output."""
    if not sys.stderr.isatty():
        return True
    if os.environ.get("FTPCTL_OUTPUT", "").strip().lower() == "json":
        return True
    argv = [a.lower() for a in sys.argv]
    for i, a in enumerate(argv):
        if a == "--json" or a in ("-ojson", "--output=json"):
            return True
        if a in ("-o", "--output") and i + 1 < len(argv) and argv[i + 1] == "json":
            return True
    return False


def fail(message: str, code: str, hint: str, status: int) -> None:
    """Error to stderr — JSON envelope for agents, plain one-liner + hint for humans — then exit."""
    if _wants_envelope():
        print(json.dumps({"error": {"code": code, "message": message, "hint": hint}}), file=sys.stderr)
    else:
        hint = "" if os.environ.get("FTPCTL_QUIET") else hint
        print(f"error[{code}]: {message}" + (f"\nhint: {hint}" if hint else ""), file=sys.stderr)
    raise SystemExit(status)
