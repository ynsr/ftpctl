"""SFTP + FTP/FTPS backends with the mandatory security posture.

Req 1 (SFTP): paramiko.RejectPolicy only; known_hosts from the profile path;
missing host key -> exit 5 with out-of-band instructions. allow_agent=False,
look_for_keys=False (password auth only). Paramiko logger -> CRITICAL.
Req 2 (FTPS): ssl.create_default_context() with hostname+cert verification ON,
no disable switch; TLS session reuse on the data channel via ntransfercmd
override; prot_p() always.
"""

from __future__ import annotations

import ftplib
import logging
import os
import posixpath
import socket
import ssl
import time
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING, Any

from .config import Profile
from .errors import FtpctlError, scrub, wrap
from .paths import sanitize_name

if TYPE_CHECKING:
    import paramiko

logging.getLogger("paramiko").setLevel(logging.CRITICAL)


@dataclass
class Entry:
    name: str
    path: str
    type: str  # file | dir | link
    size: int | None
    mtime: str | None  # ISO 8601 UTC or None
    mode: str | None


def _iso_utc(epoch: float | None) -> str | None:
    if epoch is None:
        return None
    import datetime
    return datetime.datetime.fromtimestamp(epoch, tz=datetime.UTC).isoformat().replace(
        "+00:00", "Z"
    )


def _parse_mlsd_modify(facts: dict[str, str]) -> str | None:
    import datetime
    modify = facts.get("modify")
    if not modify:
        return None
    try:
        dt = datetime.datetime.strptime(modify[:14], "%Y%m%d%H%M%S").replace(
            tzinfo=datetime.UTC
        )
        return dt.isoformat().replace("+00:00", "Z")
    except ValueError:
        return None


class Backend:
    protocol: str = ""

    def connect(self) -> None:
        raise NotImplementedError

    def close(self) -> None:
        raise NotImplementedError

    def list(self, path: str) -> list[Entry]:
        raise NotImplementedError

    def stat(self, path: str) -> Entry:
        raise NotImplementedError

    def download(self, remote: str, local_tmp: Path, limit_bytes: int) -> int:
        """Stream remote -> local_tmp; returns bytes written. Enforces the size cap."""
        raise NotImplementedError

    def upload(self, local: Path, remote_tmp: str) -> int:
        raise NotImplementedError

    def rename(self, src: str, dst: str) -> None:
        raise NotImplementedError

    def size(self, path: str) -> int | None:
        return None


# ---------------------------------------------------------------- SFTP ---


class SftpBackend(Backend):
    protocol = "sftp"

    def __init__(self, profile: Profile) -> None:
        import paramiko

        self.profile = profile
        self._paramiko = paramiko
        self.client: paramiko.SSHClient | None = None
        self.sftp: paramiko.SFTPClient | None = None

    def connect(self) -> None:
        paramiko = self._paramiko
        client = paramiko.SSHClient()
        # Req 1: RejectPolicy only — NEVER AutoAddPolicy/WarningPolicy.
        client.set_missing_host_key_policy(paramiko.RejectPolicy())
        known_hosts = os.path.expanduser(self.profile.known_hosts) if self.profile.known_hosts else os.path.expanduser(
            "~/.ssh/known_hosts"
        )
        # Profile file ONLY — never the system store: a system-wide pin for the
        # same host would shadow the profile's pin (paramiko checks system keys
        # first with no conflict signal), breaking per-profile trust.
        try:
            client.load_host_keys(known_hosts)
        except FileNotFoundError:
            pass
        except OSError as exc:
            raise wrap(exc, 5, f"cannot read known_hosts file {known_hosts}") from None
        try:
            client.connect(
                hostname=self.profile.host,
                port=self.profile.port,
                username=self.profile.username,
                password=self.profile.password,
                timeout=self.profile.timeout_seconds,
                banner_timeout=self.profile.timeout_seconds,
                auth_timeout=self.profile.timeout_seconds,
                allow_agent=False,  # password auth only
                look_for_keys=False,
            )
        except paramiko.ssh_exception.NoValidConnectionsError as exc:
            raise wrap(exc, 6, "cannot reach host:port") from None
        except paramiko.ssh_exception.AuthenticationException as exc:
            # auth_password-only: keyboard-interactive servers land here too.
            raise wrap(exc, 4, "check username/password; keyboard-interactive auth is unsupported in v1") from None
        except paramiko.ssh_exception.BadHostKeyException as exc:
            raise wrap(exc, 5, "host key mismatch — possible MITM; verify out-of-band") from None
        except paramiko.ssh_exception.SSHException as exc:
            text = scrub(str(exc))
            if "not found in known_hosts" in text or "Unknown server" in text:
                raise FtpctlError(
                    f"host key verification failed for {self.profile.host}: "
                    f"host not in known_hosts file. Add it out-of-band with "
                    f"`ssh-keyscan -p {self.profile.port} {self.profile.host} >> <known_hosts file>` "
                    f"after verifying the fingerprint through a trusted channel.",
                    5,
                ) from None
            raise wrap(exc, 6) from None
        except TimeoutError as exc:
            raise wrap(exc, 6, "connection timed out") from None
        except OSError as exc:
            raise wrap(exc, 6) from None
        self.client = client
        try:
            self.sftp = client.open_sftp()
        except Exception as exc:
            client.close()
            raise wrap(exc, 6, "SSH connected but SFTP subsystem failed") from None

    def close(self) -> None:
        try:
            if self.sftp is not None:
                self.sftp.close()
        finally:
            if self.client is not None:
                self.client.close()
        self.sftp = None
        self.client = None

    def _sftp(self) -> paramiko.SFTPClient:
        assert self.sftp is not None, "not connected"
        return self.sftp

    def _entry(self, path: str, attrs: Any) -> Entry:
        import stat as statmod
        st_mode = int(getattr(attrs, "st_mode", 0) or 0)
        if statmod.S_ISDIR(st_mode):
            etype = "dir"
        elif statmod.S_ISLNK(st_mode):
            etype = "link"
        else:
            etype = "file"
        mtime = getattr(attrs, "st_mtime", None)
        size = getattr(attrs, "st_size", None)
        return Entry(
            name=sanitize_name(posixpath.basename(path.rstrip("/")) or path),
            path=path,
            type=etype,
            size=int(size) if size is not None else None,
            mtime=_iso_utc(float(mtime)) if mtime else None,
            mode=oct(statmod.S_IMODE(st_mode)) if st_mode else None,
        )

    def list(self, path: str) -> list[Entry]:
        try:
            names = self._sftp().listdir_attr(path)
        except FileNotFoundError as exc:
            raise wrap(exc, 1, "no such directory") from None
        except OSError as exc:
            raise wrap(exc, 1) from None
        out: list[Entry] = []
        for attrs in sorted(names, key=lambda a: a.filename):
            if attrs.filename in (".", ".."):
                continue
            full = path.rstrip("/") + "/" + attrs.filename
            out.append(self._entry(full, attrs))
        return out

    def stat(self, path: str) -> Entry:
        try:
            attrs = self._sftp().lstat(path)  # lstat: report links, don't follow
        except FileNotFoundError as exc:
            raise wrap(exc, 1, "no such file or directory") from None
        except OSError as exc:
            raise wrap(exc, 1) from None
        return self._entry(path, attrs)

    def _resolve_link(self, path: str) -> str:
        """Resolve a symlink then re-check confinement (escape -> exit 7)."""
        from .paths import confine_remote
        try:
            target = self._sftp().normalize(path)
        except OSError as exc:
            raise wrap(exc, 1) from None
        return confine_remote(self.profile.root, target)

    def download(self, remote: str, local_tmp: Path, limit_bytes: int) -> int:
        entry = self.stat(remote)
        if entry.type == "link":
            remote = self._resolve_link(remote)
            entry = self.stat(remote)
        if entry.type == "dir":
            raise FtpctlError("cannot download a directory", 2)
        written = 0
        try:
            with self._sftp().open(remote, "rb") as src, open(local_tmp, "wb") as dst:
                while True:
                    chunk = src.read(65536)
                    if not chunk:
                        break
                    written += len(chunk)
                    if written > limit_bytes:
                        raise FtpctlError(
                            f"download exceeds max_download_bytes ({limit_bytes})", 7
                        )
                    dst.write(chunk)
        except FtpctlError:
            raise
        except (OSError, EOFError) as exc:
            raise wrap(exc, 6, "transfer failed") from None
        return written

    def upload(self, local: Path, remote_tmp: str) -> int:
        size = local.stat().st_size
        try:
            self._sftp().put(str(local), remote_tmp)
        except OSError as exc:
            raise wrap(exc, 6, "upload failed") from None
        return size

    def rename(self, src: str, dst: str) -> None:
        try:
            self._sftp().rename(src, dst)
        except OSError as exc:
            raise wrap(exc, 1, "rename failed") from None

    def size(self, path: str) -> int | None:
        try:
            return int(self._sftp().stat(path).st_size or 0)
        except OSError:
            return None


# ---------------------------------------------------------------- FTP/S ---


class _ReuseSessionFTP_TLS(ftplib.FTP_TLS):
    """FTP_TLS with TLS session reuse on the data channel (req 2).

    Servers that require session reuse (proftpd without
    `TLSOptions NoSessionReuseRequired`, vsftpd with
    `require_ssl_reuse=YES`) abort data connections otherwise.
    """

    def ntransfercmd(self, cmd: str, rest: int | str | None = None) -> tuple[socket.socket, int | None]:
        conn, size = super().ntransfercmd(cmd, rest)
        # super() already wrapped the data socket when a TLS session exists.
        # Re-wrap with session reuse only when the connection is still plain
        # (servers like pyftpdlib that issue fresh sessions per connection).
        if isinstance(conn, ssl.SSLSocket):
            return conn, size
        session = getattr(self.sock, "session", None)
        if self.sock is not None and session is not None:
            try:
                conn = self.context.wrap_socket(conn, server_hostname=self.host, session=session)
            except Exception:
                pass
        return conn, size


class FtpBackend(Backend):
    def __init__(self, profile: Profile) -> None:
        self.profile = profile
        self.protocol = profile.protocol
        self.ftp: ftplib.FTP | _ReuseSessionFTP_TLS | None = None
        self.insecure_warning: str | None = None

    def connect(self) -> None:
        profile = self.profile
        if profile.protocol == "ftp" and not profile.allow_insecure:
            raise FtpctlError(
                "plain FTP refused: set allow_insecure = true to permit it (credentials travel in cleartext)",
                7,
            )
        if profile.protocol == "ftp":
            self.insecure_warning = "plain FTP in use: credentials and data travel in cleartext"
            ftp: ftplib.FTP | _ReuseSessionFTP_TLS = ftplib.FTP()
        else:
            context = ssl.create_default_context()  # verification ON, no disable switch
            ftp = _ReuseSessionFTP_TLS(context=context)
        try:
            if profile.protocol == "ftps" and profile.ftps_mode == "implicit":
                assert isinstance(ftp, _ReuseSessionFTP_TLS)
                # stdlib has no implicit mode: wrap before connect.
                raw = socket.create_connection(
                    (profile.host, profile.port), timeout=profile.timeout_seconds
                )
                try:
                    tls_sock = ftp.context.wrap_socket(raw, server_hostname=profile.host)
                except Exception:
                    raw.close()
                    raise
                ftp.sock = tls_sock
                ftp.connect(host=profile.host, port=profile.port, timeout=profile.timeout_seconds)
            else:
                ftp.connect(host=profile.host, port=profile.port, timeout=profile.timeout_seconds)
        except TimeoutError as exc:
            raise wrap(exc, 6, "connection timed out") from None
        except (OSError, EOFError) as exc:
            raise wrap(exc, 6, "cannot reach host:port") from None
        try:
            ftp.login(user=profile.username, passwd=profile.password)
        except ftplib.error_perm as exc:
            raise wrap(exc, 4, "check username/password") from None
        except (ftplib.error_temp, OSError, EOFError) as exc:
            raise wrap(exc, 6, "login failed") from None
        if profile.protocol == "ftps":
            assert isinstance(ftp, _ReuseSessionFTP_TLS)
            try:
                ftp.prot_p()  # private data channel, always
            except (ftplib.error_reply, ftplib.error_perm, ssl.SSLError, OSError) as exc:
                raise wrap(exc, 5, "server refused TLS protection (PROT P)") from None
        ftp.set_pasv(profile.ftp_passive)
        self.ftp = ftp

    def close(self) -> None:
        if self.ftp is not None:
            try:
                self.ftp.quit()
            except Exception:
                try:
                    self.ftp.close()
                except Exception:
                    pass
        self.ftp = None

    def _ftp(self) -> ftplib.FTP | _ReuseSessionFTP_TLS:
        assert self.ftp is not None, "not connected"
        return self.ftp

    def list(self, path: str) -> list[Entry]:
        ftp = self._ftp()
        try:
            lines = list(ftp.mlsd(path))
        except (ftplib.error_perm, ftplib.error_temp) as exc:
            raise wrap(exc, 1, "no such directory or LIST refused") from None
        except (OSError, EOFError, ssl.SSLError) as exc:
            raise wrap(exc, 6, "LIST failed") from None
        out: list[Entry] = []
        for name, facts in sorted(lines, key=lambda kv: kv[0]):
            if name in (".", ".."):
                continue
            ftype = facts.get("type", "file")
            etype = {"file": "file", "dir": "dir", "cdir": "dir", "pdir": "dir", "link": "link"}.get(
                ftype, "file"
            )
            size_raw = facts.get("size")
            try:
                size = int(size_raw) if size_raw is not None else None
            except ValueError:
                size = None
            full = path.rstrip("/") + "/" + name
            out.append(
                Entry(
                    name=sanitize_name(name),
                    path=full,
                    type=etype,
                    size=size,
                    mtime=_parse_mlsd_modify(facts),
                    mode=None,  # no trustworthy mode over FTP
                )
            )
        return out

    def stat(self, path: str) -> Entry:
        # FTP has no STAT-for-path primitive: list the parent and pick the child.
        # Root itself has no parent entry — synthesize it.
        norm = path.rstrip("/") or "/"
        if norm == "/":
            return Entry(name="/", path="/", type="dir", size=None, mtime=None, mode=None)
        parent = posixpath.dirname(norm) or "/"
        want = posixpath.basename(norm)
        try:
            for entry in self.list(parent):
                if entry.name == sanitize_name(want):
                    return entry
        except FtpctlError:
            raise
        raise FtpctlError("no such file or directory", 1)

    def download(self, remote: str, local_tmp: Path, limit_bytes: int) -> int:
        entry = self.stat(remote)
        if entry.type == "dir":
            raise FtpctlError("cannot download a directory", 2)
        written = 0
        failed = False
        try:
            with open(local_tmp, "wb") as dst:
                def sink(chunk: bytes) -> None:
                    nonlocal written, failed
                    written += len(chunk)
                    if written > limit_bytes:
                        failed = True
                        raise FtpctlError(
                            f"download exceeds max_download_bytes ({limit_bytes})", 7
                        )
                    dst.write(chunk)
                self._ftp().retrbinary(f"RETR {remote}", sink)
        except FtpctlError:
            raise
        except (ftplib.error_perm, ftplib.error_temp) as exc:
            raise wrap(exc, 1, "RETR refused") from None
        except (OSError, EOFError, ssl.SSLError) as exc:
            raise wrap(exc, 6, "transfer failed") from None
        if failed:
            raise FtpctlError(f"download exceeds max_download_bytes ({limit_bytes})", 7)
        return written

    def upload(self, local: Path, remote_tmp: str) -> int:
        size = local.stat().st_size
        try:
            with open(local, "rb") as src:
                self._ftp().storbinary(f"STOR {remote_tmp}", src)
        except (ftplib.error_perm, ftplib.error_temp) as exc:
            raise wrap(exc, 1, "STOR refused") from None
        except (OSError, EOFError, ssl.SSLError) as exc:
            raise wrap(exc, 6, "upload failed") from None
        return size

    def rename(self, src: str, dst: str) -> None:
        try:
            self._ftp().rename(src, dst)
        except (ftplib.error_perm, ftplib.error_temp) as exc:
            raise wrap(exc, 1, "rename failed") from None
        except (OSError, EOFError, ssl.SSLError) as exc:
            raise wrap(exc, 6, "rename failed") from None

    def size(self, path: str) -> int | None:
        try:
            result = self._ftp().size(path)
            return int(result) if result is not None else None
        except (ftplib.error_perm, ftplib.error_temp, OSError, EOFError):
            return None


def make_backend(profile: Profile) -> Backend:
    if profile.protocol == "sftp":
        backend: Backend = SftpBackend(profile)
    elif profile.protocol in ("ftp", "ftps"):
        backend = FtpBackend(profile)
    else:
        raise FtpctlError(f"unknown protocol: {profile.protocol}", 2)
    return backend


def retry_delay(attempt: int) -> float:
    return float(min(0.2 * (2**attempt), 5.0))


def connect_with_retries(backend: Backend, timeout_s: float) -> None:
    """Connect with a small backoff budget for transient network failures.

    Auth (4), host-key (5), and policy (7) errors are never retried.
    """
    deadline = time.monotonic() + timeout_s
    attempt = 0
    while True:
        try:
            backend.connect()
            return
        except FtpctlError as exc:
            if exc.exit_code in (4, 5, 7) or time.monotonic() >= deadline:
                raise
            time.sleep(retry_delay(attempt))
            attempt += 1
