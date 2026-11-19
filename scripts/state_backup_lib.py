"""Shared logic for scripts/backup-state.py and scripts/restore-state.py (issue #83).

Backs up n8n state (workflows, credentials as encrypted by n8n, n8n's key file)
and the Grafana database. Every archive holds secret material, so it is always
encrypted with age to public recipients before it leaves the temp directory.

All outside effects go through small interfaces so tests need no docker and no
age binary:

  Runtime    exec / cp_from / cp_to / stop / start / run_helper on a container
  Encryptor  encrypt / decrypt a file with age
  Remote     put / list / delete on an rclone remote

Standard library only (Python 3.11+ for tomllib). Nothing here prints secret
values: command stdout is never echoed and stderr is truncated.

Trust notes: the age header check below is a format sanity check, not proof of
encryption (a hostile encryptor could prepend the header to plaintext); the
sidecar manifest next to an archive is advisory (anyone who can write the
directory can rewrite it): authenticity comes from age plus the inner manifest.
"""
from __future__ import annotations

import gzip
import hashlib
import io
import json
import os
import re
import secrets
import shutil
import sqlite3
import stat
import subprocess
import tarfile
import tempfile
import tomllib
import zlib
from dataclasses import dataclass, field
from datetime import datetime, timezone

AGE_MAGIC = b"age-encryption.org/v1"
ARCHIVE_PREFIX = "siem-state"
SAFETY_PREFIX = "siem-prerestore"
MANIFEST_NAME = "MANIFEST.json"
N8N_MEMBERS = ("workflows.json", "credentials.json", "n8n-config")
GRAFANA_MEMBER = "grafana.db"
ALLOWED_MEMBERS = set(N8N_MEMBERS) | {GRAFANA_MEMBER}
NAME_RE = re.compile(r"^(?P<prefix>[a-z-]+)-(?P<ts>\d{8}T\d{6}Z)\.tar\.gz\.age$")
FORBIDDEN_FLAG = "--decrypted"
MAX_MEMBERS = 8  # tar entries accepted (a valid archive has at most 5)
MAX_MANIFEST_BYTES = 1 << 20
CHUNK = 1 << 16
NAME_OK = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]*$")  # container names
IMAGE_OK = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_./:@-]*$")
REMOTE_OK = re.compile(r"^[A-Za-z0-9_][A-Za-z0-9_.-]*:[^\x00-\x1f\x7f]*$")
MODE_OK = re.compile(r"^0?[0-7]{3,4}$")
HEX64 = re.compile(r"^[0-9a-f]{64}$")
TS_OK = re.compile(r"^\d{8}T\d{6}Z$")

# Runs inside a throwaway helper container that shares the target's volumes:
#   $1 temp file, $2 final path, $3 uid, $4 gid, $5 mode, rest = files to remove
# The new file is prepared first. The old file and its side files are only renamed
# aside, to paths made from a random token that Python generates; the script refuses
# to start if any aside path already exists (file, directory or symlink), so mv can
# never overwrite earlier material or move a live file into a directory. An EXIT trap
# puts everything back unless the final rename worked and checks that the restored
# paths are regular files, so a failure never leaves the old database without its WAL.
#   $1 temp file, $2 final path, $3 uid, $4 gid, $5 mode, $6 hex token, rest = side files
HELPER_SCRIPT = (
    'set -eu; t="$1"; f="$2"; u="$3"; g="$4"; m="$5"; s=".old.$6"; shift 6; '
    'for x in "$f" "$@"; do if [ -e "$x$s" ] || [ -L "$x$s" ]; then '
    'echo "aside path exists, refusing: $x$s" >&2; exit 1; fi; done; '
    'chown "$u:$g" "$t"; chmod "$m" "$t"; '
    'ok=0; '
    "trap 'if [ \"$ok\" -ne 1 ]; then for x in \"$f\" \"$@\"; do "
    'if [ -e "$x$s" ]; then mv -f "$x$s" "$x"; '
    'if [ ! -f "$x" ] || [ -L "$x" ]; then echo "rollback verification failed: $x" >&2; exit 70; fi; '
    'fi; done; fi\' EXIT; '
    'for x in "$@" "$f"; do if [ -e "$x" ]; then mv -f "$x" "$x$s"; fi; done; '
    'mv -f "$t" "$f"; ok=1; '
    'for x in "$@" "$f"; do rm -f -- "$x$s"; done'
)


class BackupError(Exception):
    """Any failure that must stop the run with a non-zero exit."""


# --------------------------------------------------------------------------
# Config
# --------------------------------------------------------------------------
@dataclass
class Config:
    n8n_container: str = "n8n"
    n8n_key_file: str = "/home/node/.n8n/config"
    grafana_container: str = "grafana"
    grafana_db_path: str = "/var/lib/grafana/grafana.db"
    grafana_data_host_dir: str = ""
    grafana_db_method: str = "auto"  # auto | host-sqlite | container-sqlite3 | stop-copy
    components: list = field(default_factory=lambda: ["n8n", "grafana"])
    age_recipients: list = field(default_factory=list)
    age_recipients_file: str = ""
    destination_dir: str = ""
    rclone_remote: str = ""
    retention: int = 14
    temp_dir: str = ""
    container_runtime: str = "docker"
    allow_missing_n8n_key: bool = False
    # Ownership of restored files. docker cp gives no useful owner, so container
    # restores go through a throwaway helper container (volumes-from) that
    # chowns, chmods and renames atomically. Unset (-1 or "") fails closed.
    helper_image: str = ""
    grafana_uid: int = -1
    grafana_gid: int = -1
    grafana_db_mode: str = "0600"
    n8n_uid: int = -1
    n8n_gid: int = -1
    n8n_key_mode: str = "0600"
    # Extraction ceilings in bytes, enforced before and while reading an archive.
    max_member_bytes: int = 1 << 30
    max_total_bytes: int = 2 << 30
    max_archive_bytes: int = 2 << 30


def _has_ctl(v: str) -> bool:
    return any(ord(c) < 32 or ord(c) == 127 for c in v)


def _is_public_recipient(r) -> bool:
    return isinstance(r, str) and (r.startswith("age1") or r.startswith("ssh-"))


def load_config(path: str) -> Config:
    try:
        with open(path, "rb") as fh:
            raw = tomllib.load(fh)
    except (OSError, tomllib.TOMLDecodeError) as exc:
        raise BackupError(f"cannot read config {path}: {exc}") from None
    unknown = sorted(set(raw) - set(Config.__dataclass_fields__))
    if unknown:
        raise BackupError(f"unknown config keys: {', '.join(unknown)}")
    try:
        cfg = Config(**raw)
    except TypeError as exc:
        raise BackupError(f"config: {exc}") from None
    return validate_config(cfg)


_FIELD_TYPES = {k: type(v) for k, v in vars(Config()).items()}
_TYPE_WORDS = {str: "a string", int: "an integer", bool: "true or false", list: "a list of strings"}


def validate_config(cfg: Config) -> Config:
    for key, want in _FIELD_TYPES.items():  # exact types first, so no regex ever sees a wrong type
        v = getattr(cfg, key)
        if type(v) is not want or (want is list and not all(isinstance(i, str) for i in v)):
            raise BackupError(f"config: {key} must be {_TYPE_WORDS[want]}")
    if not cfg.destination_dir:
        raise BackupError("config: destination_dir is required")
    if not isinstance(cfg.destination_dir, str):
        raise BackupError("config: destination_dir must be a string")
    if type(cfg.allow_missing_n8n_key) is not bool:
        raise BackupError("config: allow_missing_n8n_key must be true or false (a real boolean)")
    for key in ("components", "age_recipients"):
        v = getattr(cfg, key)
        if not isinstance(v, list) or not all(isinstance(i, str) for i in v):
            raise BackupError(f"config: {key} must be a list of strings")
    for key in ("destination_dir", "n8n_key_file", "grafana_db_path", "grafana_data_host_dir", "temp_dir",
                "age_recipients_file"):
        v = getattr(cfg, key)
        if not isinstance(v, str):
            raise BackupError(f"config: {key} must be a string")
        if v and (not v.startswith("/") or _has_ctl(v)):
            raise BackupError(f"config: {key} must be an absolute path without control characters")
    if not isinstance(cfg.rclone_remote, str):
        raise BackupError("config: rclone_remote must be a string")
    for key in ("n8n_container", "grafana_container"):
        v = getattr(cfg, key)
        if not isinstance(v, str) or not NAME_OK.match(v):
            raise BackupError(f"config: {key} is not a valid container name")
    if cfg.container_runtime not in ("docker", "podman"):
        raise BackupError("config: container_runtime must be docker or podman")
    if cfg.rclone_remote and (not isinstance(cfg.rclone_remote, str) or not REMOTE_OK.match(cfg.rclone_remote)):
        raise BackupError("config: rclone_remote must look like name:path (no leading dash or control characters)")
    if cfg.helper_image and not IMAGE_OK.match(cfg.helper_image):
        raise BackupError("config: helper_image is not a valid image reference")
    for key in ("grafana_db_mode", "n8n_key_mode"):
        v = getattr(cfg, key)
        if not isinstance(v, str) or not MODE_OK.match(v):
            raise BackupError(f'config: {key} must be an octal mode string such as "0600"')
    for key in ("grafana_uid", "grafana_gid", "n8n_uid", "n8n_gid", "max_member_bytes", "max_total_bytes",
                "max_archive_bytes"):
        v = getattr(cfg, key)
        low = -1 if key.endswith(("uid", "gid")) else 1
        if not isinstance(v, int) or isinstance(v, bool) or v < low:
            raise BackupError(f"config: {key} must be an integer >= {low}")
    if not isinstance(cfg.retention, int) or isinstance(cfg.retention, bool) or cfg.retention < 1:
        raise BackupError("config: retention must be an integer >= 1")
    if not cfg.components or any(c not in ("n8n", "grafana") for c in cfg.components):
        raise BackupError("config: components must be a non-empty list of n8n, grafana")
    if cfg.grafana_db_method not in ("auto", "host-sqlite", "container-sqlite3", "stop-copy"):
        raise BackupError("config: grafana_db_method must be auto, host-sqlite, container-sqlite3 or stop-copy")
    if cfg.grafana_db_method == "host-sqlite" and not cfg.grafana_data_host_dir:
        raise BackupError("config: host-sqlite needs grafana_data_host_dir")
    if not cfg.age_recipients and not cfg.age_recipients_file:
        raise BackupError("config: age_recipients (or age_recipients_file) is required; there is no unencrypted mode")
    for r in cfg.age_recipients:
        if isinstance(r, str) and r.upper().startswith("AGE-SECRET-KEY"):
            raise BackupError("config: age_recipients holds a SECRET key; list public recipients only")
        if not _is_public_recipient(r):
            raise BackupError("config: each age_recipients entry must be an age1... or ssh-... public key")
    return cfg


# --------------------------------------------------------------------------
# Interfaces and real implementations
# --------------------------------------------------------------------------
def _run(argv: list, what: str) -> subprocess.CompletedProcess:
    if FORBIDDEN_FLAG in argv:
        raise BackupError("refusing to run a command with --decrypted")
    try:
        proc = subprocess.run(argv, stdin=subprocess.DEVNULL, capture_output=True, check=False)
    except OSError as exc:
        raise BackupError(f"{what}: cannot run {argv[0]}: {exc.strerror}") from None
    if proc.returncode != 0:
        tail = proc.stderr.decode("utf-8", "replace").strip()[:300]
        raise BackupError(f"{what} failed (exit {proc.returncode}): {tail}")
    return proc


def _name(container: str) -> str:
    if not isinstance(container, str) or not NAME_OK.match(container):
        raise BackupError("invalid container name")
    return container


class DockerRuntime:
    """Container runtime via the docker (or podman) CLI. Output is never echoed.

    Names are validated (no leading dash, no colon or control characters) rather
    than separated with `--`, because `--` handling was not verified per subcommand.
    """

    def __init__(self, binary: str = "docker"):
        if binary not in ("docker", "podman"):
            raise BackupError("container runtime must be docker or podman")
        self.binary = binary

    def exec(self, container: str, argv: list) -> bytes:
        return _run([self.binary, "exec", _name(container), *argv], f"exec in {container}").stdout

    def cp_from(self, container: str, src: str, dest: str) -> None:
        _run([self.binary, "cp", f"{_name(container)}:{src}", dest], f"copy out of {container}")

    def cp_to(self, container: str, src: str, dest: str) -> None:
        _run([self.binary, "cp", src, f"{_name(container)}:{dest}"], f"copy into {container}")

    def is_running(self, container: str) -> bool:
        out = _run([self.binary, "inspect", "-f", "{{.State.Running}}", _name(container)],
                   f"inspect {container}").stdout.decode().strip()
        if out not in ("true", "false"):
            raise BackupError(f"cannot tell whether {container} is running")
        return out == "true"

    def stop(self, container: str) -> None:
        _run([self.binary, "stop", _name(container)], f"stop {container}")

    def start(self, container: str) -> None:
        _run([self.binary, "start", _name(container)], f"start {container}")

    def run_helper(self, container: str, image: str, argv: list) -> None:
        """Run argv in a throwaway container sharing `container`'s volumes (works while it is stopped)."""
        if not IMAGE_OK.match(image or ""):
            raise BackupError("invalid helper image")
        _run([self.binary, "run", "--rm", "--network", "none", "--cap-drop", "ALL",
              "--cap-add", "CHOWN", "--cap-add", "DAC_OVERRIDE", "--cap-add", "FOWNER",
              "--security-opt", "no-new-privileges", "--volumes-from", _name(container), image, *argv],
             f"helper for {container}")


class AgeEncryptor:
    """age with public recipients only; no passphrase mode exists here."""

    def __init__(self, binary: str = "age"):
        self.binary = binary

    def _need(self) -> None:
        if shutil.which(self.binary) is None:
            raise BackupError("age is not installed (see docs/backup-restore.md)")

    def encrypt(self, src: str, dest: str, recipients: list, recipients_file: str = "") -> None:
        self._need()
        argv = [self.binary]
        for r in recipients:
            argv += ["-r", r]
        if recipients_file:
            argv += ["-R", recipients_file]
        argv += ["-o", dest, src]
        _run(argv, "age encrypt")

    def decrypt(self, src: str, dest: str, identity: str) -> None:
        self._need()
        _run([self.binary, "-d", "-i", identity, "-o", dest, src], "age decrypt")


class Remote:
    """Optional rclone destination, e.g. 'myremote:siem-backups'."""

    def __init__(self, target: str, binary: str = "rclone"):
        if not isinstance(target, str) or not REMOTE_OK.match(target):
            raise BackupError("invalid rclone remote (expected name:path, no leading dash)")
        self.target = target.rstrip("/")
        self.binary = binary

    def put(self, local: str, name: str) -> None:
        _run([self.binary, "copyto", local, f"{self.target}/{name}"], "rclone copyto")

    def list(self) -> list:
        out = _run([self.binary, "lsf", self.target], "rclone lsf").stdout
        return [ln.strip() for ln in out.decode().splitlines() if ln.strip()]

    def delete(self, name: str) -> None:
        _run([self.binary, "deletefile", f"{self.target}/{name}"], "rclone deletefile")


# --------------------------------------------------------------------------
# Helpers
# --------------------------------------------------------------------------
def sha256_file(path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def make_temp_dir(cfg: Config) -> str:
    """Private (0700) scratch dir; callers remove it in a finally block."""
    base = cfg.temp_dir or None
    if base:
        os.makedirs(base, mode=0o700, exist_ok=True)
    path = tempfile.mkdtemp(prefix="siem-state-", dir=base)
    os.chmod(path, 0o700)
    return path


def timestamp(now: datetime | None = None) -> str:
    return (now or datetime.now(timezone.utc)).strftime("%Y%m%dT%H%M%SZ")


def archive_name(prefix: str, ts: str) -> str:
    return f"{prefix}-{ts}.tar.gz.age"


def manifest_name(archive: str) -> str:
    return archive + ".manifest.json"


def select_for_retention(names: list, keep: int, prefix: str = ARCHIVE_PREFIX) -> list:
    """Archive names (of the given prefix) to delete so exactly `keep` newest remain."""
    mine = []
    for n in names:
        m = NAME_RE.match(n)
        if m and m.group("prefix") == prefix:
            mine.append((m.group("ts"), n))
    mine.sort()
    return [n for _, n in mine[: max(0, len(mine) - keep)]]


def ensure_destination(path: str) -> None:
    """Create or vet the destination: a real directory we own that nobody else can write."""
    try:
        st = os.lstat(path)
    except FileNotFoundError:
        os.makedirs(path, mode=0o700)
        st = os.lstat(path)
    if stat.S_ISLNK(st.st_mode):
        raise BackupError("destination_dir is a symlink; refusing")
    if not stat.S_ISDIR(st.st_mode):
        raise BackupError("destination_dir is not a directory")
    if st.st_mode & 0o022:
        raise BackupError("destination_dir is writable by group or others; chmod 700 it")
    if st.st_uid != os.geteuid():
        raise BackupError("destination_dir is not owned by the user running the backup")


def _publish(partial: str, final: str) -> None:
    """Move partial to final without ever overwriting (hard link fails if final exists)."""
    try:
        os.link(partial, final)
    except FileExistsError:
        raise BackupError(f"{os.path.basename(final)} already exists; refusing to overwrite") from None
    except OSError as exc:
        raise BackupError(f"cannot publish {os.path.basename(final)}: {exc.strerror}") from None
    finally:
        try:
            os.unlink(partial)
        except FileNotFoundError:
            pass


def _write_private(path: str, data: bytes) -> None:
    fd = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, "wb") as fh:
        fh.write(data)
        fh.flush()
        os.fsync(fh.fileno())


def _partial_path(directory: str, name: str) -> str:
    return os.path.join(directory, f".{name}.{secrets.token_hex(6)}.partial")


def copy_bounded(src, out, limit: int, digest=None) -> int:
    """Copy at most `limit` bytes; raise before writing anything past it."""
    total = 0
    while True:
        chunk = src.read(CHUNK)
        if not chunk:
            return total
        total += len(chunk)
        if total > limit:
            raise BackupError("archive member exceeds the size limit")
        if digest is not None:
            digest.update(chunk)
        out.write(chunk)


class BoundedReader:
    """File-like wrapper that refuses to hand out more than `limit` bytes in total."""

    def __init__(self, raw, limit: int):
        self.raw = raw
        self.limit = limit
        self.total = 0

    def read(self, n: int = -1) -> bytes:
        if n is None or n < 0 or n > CHUNK:
            n = CHUNK
        data = self.raw.read(n)
        self.total += len(data)
        if self.total > self.limit:
            raise BackupError("decompressed archive exceeds the size limit")
        return data


def stream_ceiling(cfg: Config) -> int:
    """Most decompressed tar bytes a valid archive can need: payload caps plus tight header overhead."""
    return cfg.max_total_bytes + MAX_MANIFEST_BYTES + MAX_MEMBERS * 1024 + 20480


def cp_from_checked(rt, container: str, src: str, dest: str) -> None:
    """docker cp out of a container, then make sure we got a plain regular file."""
    rt.cp_from(container, src, dest)
    st = os.lstat(dest)
    if not stat.S_ISREG(st.st_mode):
        os.unlink(dest)
        raise BackupError(f"{src} in {container} is not a regular file; refusing")


# --------------------------------------------------------------------------
# Backup
# --------------------------------------------------------------------------
def _n8n_cli(rt, cfg: Config, argv: list) -> None:
    if FORBIDDEN_FLAG in argv:  # credentials stay encrypted by n8n's own key
        raise BackupError("refusing to run an n8n command with --decrypted")
    rt.exec(cfg.n8n_container, ["n8n", *argv])


def _quiet_rm(rt, container: str, args: list) -> None:
    try:
        rt.exec(container, args)
    except BackupError:
        pass


def run_while_stopped(rt, container: str, body, hint: str) -> None:
    """Stop `container`, run body(), and always attempt a start afterwards.

    A container that was already stopped is left stopped. A stop that reports
    failure may still have stopped the container, so the attempt itself (not its
    success) triggers the restart. start is idempotent.
    If the restart also fails, both errors are kept in the recovery message.
    """
    if not rt.is_running(container):  # also fails before any mutation if the state is unknown
        body()
        return  # it was stopped when we found it, so it stays stopped
    stop_attempted = False
    err = None
    try:
        stop_attempted = True
        rt.stop(container)
        body()
    except BaseException as exc:  # re-raised below once the restart was attempted
        err = exc
    restart_err = None
    if stop_attempted:
        try:
            rt.start(container)
        except BackupError as exc:
            restart_err = exc
    if restart_err is not None:
        raise BackupError(
            f"RECOVERY NEEDED: {container} may be stopped (restart failed: {restart_err}; "
            f"earlier error: {err if err is not None else 'none'}). {hint}") from None
    if err is not None:
        raise err


def collect_n8n(rt, cfg: Config, work: str) -> None:
    ctmp = f"/tmp/siem-backup-{secrets.token_hex(8)}"
    rt.exec(cfg.n8n_container, ["mkdir", "-m", "700", ctmp])
    try:
        _n8n_cli(rt, cfg, ["export:workflow", "--all", f"--output={ctmp}/workflows.json"])
        _n8n_cli(rt, cfg, ["export:credentials", "--all", f"--output={ctmp}/credentials.json"])
        cp_from_checked(rt, cfg.n8n_container, f"{ctmp}/workflows.json", os.path.join(work, "workflows.json"))
        cp_from_checked(rt, cfg.n8n_container, f"{ctmp}/credentials.json", os.path.join(work, "credentials.json"))
    finally:
        _quiet_rm(rt, cfg.n8n_container, ["rm", "-rf", ctmp])
    try:
        cp_from_checked(rt, cfg.n8n_container, cfg.n8n_key_file, os.path.join(work, "n8n-config"))
    except BackupError as exc:
        if "not a regular file" in str(exc):
            raise
        if not cfg.allow_missing_n8n_key:
            raise BackupError(
                "n8n key file not found in the container; without it the credentials cannot be "
                "decrypted. If n8n takes its key from N8N_ENCRYPTION_KEY, set allow_missing_n8n_key = true"
            ) from None
        print("WARNING: n8n key file absent; the key must be kept elsewhere")
    for name in os.listdir(work):
        os.chmod(os.path.join(work, name), 0o600)


def host_sqlite_copy(src: str, dest: str) -> None:
    """Consistent copy of a live SQLite database via the online backup API."""
    if os.path.islink(src) or not os.path.isfile(src):
        raise BackupError(f"grafana database not found (or a symlink) at {src}")
    s = sqlite3.connect(f"file:{src}?mode=ro", uri=True)
    d = sqlite3.connect(dest)
    try:
        s.backup(d)
    except sqlite3.Error as exc:
        raise BackupError(f"sqlite backup failed: {exc}") from None
    finally:
        d.close()
        s.close()


def collect_grafana(rt, cfg: Config, work: str) -> None:
    dest = os.path.join(work, GRAFANA_MEMBER)
    method = cfg.grafana_db_method
    if method == "auto":
        method = "host-sqlite" if cfg.grafana_data_host_dir else "container-sqlite3"
    if method == "host-sqlite":
        host_sqlite_copy(os.path.join(cfg.grafana_data_host_dir, "grafana.db"), dest)
    elif method == "container-sqlite3":
        # Needs the sqlite3 CLI inside the Grafana image; fails loudly if absent.
        ctmp = f"/tmp/siem-backup-{secrets.token_hex(8)}.db"
        try:
            rt.exec(cfg.grafana_container, ["sqlite3", cfg.grafana_db_path, f".backup '{ctmp}'"])
            cp_from_checked(rt, cfg.grafana_container, ctmp, dest)
        finally:
            _quiet_rm(rt, cfg.grafana_container, ["rm", "-f", ctmp])
    else:  # stop-copy: explicit opt-in, brief downtime, always restarted
        run_while_stopped(
            rt, cfg.grafana_container,
            lambda: cp_from_checked(rt, cfg.grafana_container, cfg.grafana_db_path, dest),
            "Start the grafana container by hand.")
    os.chmod(dest, 0o600)


def build_archive(work: str, out_tar: str, ts: str) -> dict:
    members = {}
    for name in sorted(os.listdir(work)):
        if name in ALLOWED_MEMBERS:
            p = os.path.join(work, name)
            members[name] = {"sha256": sha256_file(p), "size": os.path.getsize(p)}
    if not members:
        raise BackupError("nothing was collected")
    manifest = {"version": 1, "created": ts, "members": members}
    mpath = os.path.join(work, MANIFEST_NAME)
    with open(mpath, "w", encoding="utf-8") as fh:
        json.dump(manifest, fh, indent=2, sort_keys=True)
    with tarfile.open(out_tar, "w:gz", format=tarfile.USTAR_FORMAT) as tar:  # no PAX or GNU extension records
        for name in [MANIFEST_NAME, *members]:  # manifest first: restore streams and needs it up front
            info = tar.gettarinfo(os.path.join(work, name), arcname=name)
            info.uid = info.gid = 0
            info.uname = info.gname = ""
            info.mode = 0o600
            info.mtime = 0  # int: a float mtime would force a PAX record
            with open(os.path.join(work, name), "rb") as fh:
                tar.addfile(info, fh)
    return manifest


def encrypt_to(enc, cfg: Config, plain: str, final: str) -> None:
    """Encrypt plain -> final without overwriting; refuse output that is not age-shaped.

    The header check is a sanity check on the format, not proof of encryption.
    """
    partial = _partial_path(os.path.dirname(final), os.path.basename(final))
    try:
        enc.encrypt(plain, partial, list(cfg.age_recipients), cfg.age_recipients_file)
        st = os.lstat(partial)
        if not stat.S_ISREG(st.st_mode):
            raise BackupError("encryptor output is not a regular file")
        with open(partial, "rb") as fh:
            head = fh.read(len(AGE_MAGIC))
        if head != AGE_MAGIC:
            raise BackupError("encryptor output is not an age file; refusing to write an unencrypted archive")
        os.chmod(partial, 0o600)
        _publish(partial, final)
    finally:
        if os.path.lexists(partial):
            os.unlink(partial)


def run_backup(cfg: Config, rt, enc, remote=None, prefix: str = ARCHIVE_PREFIX, now=None) -> str:
    """Returns the final archive path. The temp dir is always removed."""
    old_umask = os.umask(0o077)
    work = None
    try:
        ensure_destination(cfg.destination_dir)
        if cfg.age_recipients_file:
            try:
                rst = os.lstat(cfg.age_recipients_file)
            except OSError:
                rst = None
            if rst is None or not stat.S_ISREG(rst.st_mode):
                raise BackupError("age recipients file is missing, a symlink or not a regular file")
        ts = timestamp(now)
        name = archive_name(prefix, ts)
        final = os.path.join(cfg.destination_dir, name)
        mfinal = os.path.join(cfg.destination_dir, manifest_name(name))
        for p in (final, mfinal):
            if os.path.lexists(p):
                raise BackupError(f"{os.path.basename(p)} already exists; refusing to overwrite")
        work = make_temp_dir(cfg)
        if "n8n" in cfg.components:
            collect_n8n(rt, cfg, work)
        if "grafana" in cfg.components:
            collect_grafana(rt, cfg, work)
        tar_path = os.path.join(work, "state.tar.gz")
        manifest = build_archive(work, tar_path, ts)
        encrypt_to(enc, cfg, tar_path, final)
        outer = {
            "version": 1,
            "archive": name,
            "created": ts,
            "sha256": sha256_file(final),
            "size": os.path.getsize(final),
            "members": sorted(manifest["members"]),
        }
        mpartial = _partial_path(cfg.destination_dir, os.path.basename(mfinal))
        try:
            _write_private(mpartial, json.dumps(outer, indent=2, sort_keys=True).encode())
            _publish(mpartial, mfinal)
        except BaseException:
            if os.path.lexists(mpartial):
                os.unlink(mpartial)
            os.unlink(final)  # never leave an archive without its sidecar
            raise
    finally:
        if work:
            shutil.rmtree(work, ignore_errors=True)
        os.umask(old_umask)
    if remote is not None:
        remote.put(final, name)
        remote.put(mfinal, manifest_name(name))
    if prefix == ARCHIVE_PREFIX:  # pre-restore safety backups are never pruned
        apply_retention_local(cfg.destination_dir, cfg.retention, prefix)
        if remote is not None:
            apply_retention_remote(remote, cfg.retention, prefix)
    return final


def apply_retention_local(directory: str, keep: int, prefix: str = ARCHIVE_PREFIX) -> list:
    doomed = select_for_retention(os.listdir(directory), keep, prefix)
    for n in doomed:
        for victim in (n, manifest_name(n)):
            p = os.path.join(directory, victim)
            if os.path.lexists(p):
                os.unlink(p)
    return doomed


def apply_retention_remote(remote, keep: int, prefix: str = ARCHIVE_PREFIX) -> list:
    doomed = select_for_retention(remote.list(), keep, prefix)
    for n in doomed:
        remote.delete(n)
        remote.delete(manifest_name(n))
    return doomed


# --------------------------------------------------------------------------
# Restore
# --------------------------------------------------------------------------
def verify_outer(archive: str) -> str:
    """Check the advisory sidecar next to the encrypted file. Returns a status line.

    The sidecar is not authentication: whoever can write the directory can
    rewrite it. It catches bit rot and truncation; the inner manifest, inside
    the age-authenticated archive, is what is trusted.
    """
    side = manifest_name(archive)
    if not os.path.exists(side):
        return "outer manifest missing (advisory; only the inner manifest is checked)"
    try:
        with open(side, encoding="utf-8") as fh:
            outer = json.load(fh)
    except (OSError, ValueError, RecursionError):
        raise BackupError("outer manifest unreadable") from None
    if not isinstance(outer, dict) or outer.get("sha256") != sha256_file(archive):
        raise BackupError("checksum mismatch: encrypted archive does not match its manifest")
    return "outer manifest checksum ok (advisory)"


def parse_manifest(raw: bytes, cfg: Config) -> dict:
    """Strict schema check of the inner manifest. Never raises anything but BackupError."""
    try:
        m = json.loads(raw.decode("utf-8"))
    except (ValueError, RecursionError):
        raise BackupError("inner manifest is not valid JSON") from None
    if not isinstance(m, dict) or set(m) != {"version", "created", "members"}:
        raise BackupError("inner manifest has an unexpected shape")
    if m["version"] != 1 or isinstance(m["version"], bool):
        raise BackupError("inner manifest version is not supported")
    if not isinstance(m["created"], str) or not TS_OK.match(m["created"]):
        raise BackupError("inner manifest timestamp is invalid")
    members = m["members"]
    if not isinstance(members, dict) or not members:
        raise BackupError("inner manifest lists no members")
    total = 0
    for name, meta in members.items():
        if name not in ALLOWED_MEMBERS:
            raise BackupError(f"inner manifest lists an unexpected member: {name!r}")
        if not isinstance(meta, dict) or set(meta) != {"sha256", "size"}:
            raise BackupError("inner manifest member entry is malformed")
        if not isinstance(meta["sha256"], str) or not HEX64.match(meta["sha256"]):
            raise BackupError("inner manifest digest is malformed")
        size = meta["size"]
        if not isinstance(size, int) or isinstance(size, bool) or size < 0:
            raise BackupError("inner manifest size is malformed")
        if size > cfg.max_member_bytes:
            raise BackupError(f"{name} exceeds the member size limit")
        total += size
    if total > cfg.max_total_bytes:
        raise BackupError("archive exceeds the total size limit")
    return m


def extract_verified(tar_path: str, dest: str, cfg: Config) -> dict:
    """Stream-extract known flat regular files within size limits, verifying as it goes."""
    if os.path.getsize(tar_path) > cfg.max_archive_bytes:
        raise BackupError("archive exceeds the size limit")
    manifest = None
    seen = set()
    try:
        # tarfile reads GNU long-name and PAX records into memory before it yields a
        # member, so the decompressed stream itself is capped, not just the members.
        with open(tar_path, "rb") as raw, gzip.GzipFile(fileobj=raw, mode="rb") as gz, \
                tarfile.open(fileobj=BoundedReader(gz, stream_ceiling(cfg)), mode="r|") as tar:
            for m in tar:
                if len(seen) >= MAX_MEMBERS:
                    raise BackupError("archive has too many members")
                if m.pax_headers:
                    raise BackupError("extended tar headers are not accepted")
                if m.name in seen:
                    raise BackupError(f"duplicate archive member refused: {m.name!r}")
                seen.add(m.name)
                if not m.isreg() or m.name not in ALLOWED_MEMBERS | {MANIFEST_NAME}:
                    raise BackupError(f"unexpected archive member refused: {m.name!r}")
                if manifest is None:
                    if m.name != MANIFEST_NAME:
                        raise BackupError("inner manifest must be the first archive member")
                    if m.size > MAX_MANIFEST_BYTES:
                        raise BackupError("inner manifest exceeds the size limit")
                    buf = io.BytesIO()
                    copy_bounded(tar.extractfile(m), buf, MAX_MANIFEST_BYTES)
                    manifest = parse_manifest(buf.getvalue(), cfg)
                    continue
                if m.name == MANIFEST_NAME:
                    raise BackupError("duplicate archive member refused: 'MANIFEST.json'")
                meta = manifest["members"].get(m.name)
                if meta is None:
                    raise BackupError(f"{m.name} is not listed in the inner manifest")
                if m.size != meta["size"]:
                    raise BackupError(f"checksum mismatch: {m.name} size differs from the manifest")
                digest = hashlib.sha256()
                out = os.path.join(dest, m.name)
                fd = os.open(out, os.O_CREAT | os.O_EXCL | os.O_WRONLY | os.O_NOFOLLOW, 0o600)
                with os.fdopen(fd, "wb") as fh:
                    written = copy_bounded(tar.extractfile(m), fh, meta["size"], digest)
                if written != meta["size"] or digest.hexdigest() != meta["sha256"]:
                    raise BackupError(f"checksum mismatch: {m.name}")
    except (tarfile.TarError, EOFError, OSError, zlib.error):
        raise BackupError("archive unreadable or not extractable") from None
    if manifest is None:
        raise BackupError("inner manifest missing")
    if seen - {MANIFEST_NAME} != set(manifest["members"]):
        raise BackupError("checksum mismatch: archive members differ from the manifest")
    return manifest


def check_sqlite(path: str, work: str) -> None:
    """integrity_check on a scratch copy (never touches the file that will be installed)."""
    probe = os.path.join(work, "integrity-probe.db")
    shutil.copyfile(path, probe)
    try:
        con = sqlite3.connect(probe)
        try:
            rows = con.execute("PRAGMA integrity_check").fetchall()
        finally:
            con.close()
    except sqlite3.Error:
        raise BackupError("grafana database failed the sqlite integrity check (not a valid database)") from None
    finally:
        for suffix in ("", "-wal", "-shm", "-journal"):
            if os.path.lexists(probe + suffix):
                os.unlink(probe + suffix)
    if rows != [("ok",)]:
        raise BackupError("grafana database failed the sqlite integrity check")


def install_argv(tmp: str, final: str, uid: int, gid: int, mode: str, remove: list) -> list:
    return ["sh", "-c", HELPER_SCRIPT, "sh", tmp, final, str(uid), str(gid), mode, secrets.token_hex(8), *remove]


def _require(cfg: Config, *keys: str) -> None:
    for k in keys:
        v = getattr(cfg, k)
        if v == "" or v == -1:
            raise BackupError(f"config: {k} must be set for this restore (file ownership cannot be guessed)")


def grafana_host_target(cfg: Config) -> str:
    return os.path.join(cfg.grafana_data_host_dir, "grafana.db")


def preflight_restore(cfg: Config, parts: list, src: str, work: str) -> None:
    """Everything that can be checked before anything is touched."""
    if "grafana" in parts:
        check_sqlite(os.path.join(src, GRAFANA_MEMBER), work)
        if cfg.grafana_data_host_dir:
            try:
                st = os.lstat(grafana_host_target(cfg))
            except FileNotFoundError:
                _require(cfg, "grafana_uid", "grafana_gid")  # fresh host: no owner to copy
            else:
                if stat.S_ISLNK(st.st_mode) or not stat.S_ISREG(st.st_mode):
                    raise BackupError("grafana.db target is a symlink or not a regular file; refusing")
        else:
            _require(cfg, "helper_image", "grafana_uid", "grafana_gid")


def require_n8n_running(rt, cfg: Config) -> None:
    """Fail closed before any mutation: the import steps and the key install's cleanup use docker exec,
    which cannot work on a stopped container. A state read that fails also refuses."""
    if not rt.is_running(cfg.n8n_container):
        raise BackupError(
            f"{cfg.n8n_container} is not running; the n8n restore needs it up. "
            "Start n8n and re-run the restore. Nothing was changed")


def restore_n8n(rt, cfg: Config, src: str, restore_key: bool) -> None:
    present = {n for n in N8N_MEMBERS if os.path.exists(os.path.join(src, n))}
    if not {"workflows.json", "credentials.json"} <= present:
        raise BackupError("archive has no n8n workflows and credentials")
    require_n8n_running(rt, cfg)
    if "n8n-config" in present:
        probe = tempfile.mkdtemp(prefix="siem-probe-", dir=cfg.temp_dir or None)
        try:
            cur = os.path.join(probe, "key")
            try:
                cp_from_checked(rt, cfg.n8n_container, cfg.n8n_key_file, cur)
                same = sha256_file(cur) == sha256_file(os.path.join(src, "n8n-config"))
            except BackupError:
                same = False
        finally:
            shutil.rmtree(probe, ignore_errors=True)
        if not same:
            if not restore_key:
                raise BackupError(
                    "the running n8n key differs from the backup's, so restored credentials would not "
                    "decrypt. Re-run with --restore-n8n-key to replace it (n8n is stopped and started)"
                )
            install_n8n_key(rt, cfg, os.path.join(src, "n8n-config"))
    ctmp = f"/tmp/siem-restore-{secrets.token_hex(8)}"
    rt.exec(cfg.n8n_container, ["mkdir", "-m", "700", ctmp])
    try:
        rt.cp_to(cfg.n8n_container, os.path.join(src, "credentials.json"), f"{ctmp}/credentials.json")
        rt.cp_to(cfg.n8n_container, os.path.join(src, "workflows.json"), f"{ctmp}/workflows.json")
        _n8n_cli(rt, cfg, ["import:credentials", f"--input={ctmp}/credentials.json"])
        _n8n_cli(rt, cfg, ["import:workflow", f"--input={ctmp}/workflows.json"])
    finally:
        _quiet_rm(rt, cfg.n8n_container, ["rm", "-rf", ctmp])


def install_n8n_key(rt, cfg: Config, src: str) -> None:
    """Replace n8n's key file. n8n is restarted whatever happens; the old key stays until the final rename."""
    _require(cfg, "helper_image", "n8n_uid", "n8n_gid")
    key = cfg.n8n_key_file
    tmp = key + ".restore"
    rt.cp_to(cfg.n8n_container, src, tmp)  # running container: the old key is untouched
    try:
        run_while_stopped(
            rt, cfg.n8n_container,
            lambda: rt.run_helper(cfg.n8n_container, cfg.helper_image,
                                  install_argv(tmp, key, cfg.n8n_uid, cfg.n8n_gid, cfg.n8n_key_mode, [])),
            f"Check the key file {key} (a leftover {tmp} may hold the new key), then start the container by hand.")
    finally:
        _remove_in_volume(rt, cfg, tmp)


def _remove_in_volume(rt, cfg: Config, path: str) -> None:
    """Best-effort removal of a file in n8n's volume that works whether or not the container is up."""
    try:
        up = rt.is_running(cfg.n8n_container)
    except BackupError:
        up = False
    try:
        if up:
            rt.exec(cfg.n8n_container, ["rm", "-f", path])
        else:  # docker exec needs a running container; a helper shares the volumes instead
            rt.run_helper(cfg.n8n_container, cfg.helper_image, ["sh", "-c", 'rm -f -- "$1"', "sh", path])
    except Exception:  # noqa: BLE001  cleanup must never mask the primary error
        pass


def restore_grafana(rt, cfg: Config, src: str) -> None:
    db = os.path.join(src, GRAFANA_MEMBER)
    c = cfg.grafana_container
    if rt.is_running(c):
        try:
            rt.stop(c)
        except BackupError as stop_err:
            # a stop that reports failure may or may not have worked: put it back as found
            try:
                rt.start(c)
            except BackupError as start_err:
                raise BackupError(
                    f"RECOVERY NEEDED: {c} may be stopped (restart failed: {start_err}; "
                    f"earlier error: {stop_err}). Start it by hand; nothing was replaced.") from None
            raise BackupError(f"{stop_err}; {c} was restarted and nothing was replaced") from None
    try:
        if cfg.grafana_data_host_dir:
            _restore_grafana_host(cfg, db)
        else:
            target = cfg.grafana_db_path
            tmp = target + ".restore"
            rt.cp_to(cfg.grafana_container, db, tmp)
            rt.run_helper(cfg.grafana_container, cfg.helper_image,
                          install_argv(tmp, target, cfg.grafana_uid, cfg.grafana_gid, cfg.grafana_db_mode,
                                       [target + "-wal", target + "-shm"]))
    except BackupError as exc:
        raise BackupError(f"{exc}; the grafana container was left stopped, check it before starting") from None


def _restore_grafana_host(cfg: Config, db: str) -> None:
    target = grafana_host_target(cfg)
    uid, gid = cfg.grafana_uid, cfg.grafana_gid
    try:
        st = os.lstat(target)
    except FileNotFoundError:
        st = None
    else:
        if stat.S_ISLNK(st.st_mode) or not stat.S_ISREG(st.st_mode):
            raise BackupError("grafana.db target is a symlink or not a regular file; refusing")
        uid = st.st_uid if uid < 0 else uid
        gid = st.st_gid if gid < 0 else gid
    if uid < 0 or gid < 0:
        _require(cfg, "grafana_uid", "grafana_gid")
    mode = int(cfg.grafana_db_mode, 8)
    tmp = os.path.join(cfg.grafana_data_host_dir, f".grafana.db.{secrets.token_hex(6)}.restore")
    fd = os.open(tmp, os.O_CREAT | os.O_EXCL | os.O_WRONLY | os.O_NOFOLLOW, 0o600)
    try:
        with os.fdopen(fd, "wb") as out, open(db, "rb") as src:
            shutil.copyfileobj(src, out)
            out.flush()
            try:
                os.fchown(out.fileno(), uid, gid)
            except PermissionError:
                raise BackupError("cannot set grafana.db owner; run the restore as root or set matching ids") from None
            os.fchmod(out.fileno(), mode)
            os.fsync(out.fileno())
        # The old db, WAL and SHM move aside as one rollback set and are only deleted
        # once the new database is in place; any failure puts them all back.
        token = secrets.token_hex(6)
        moved = []
        try:
            for path in (target + "-wal", target + "-shm", target):
                if os.path.lexists(path):
                    aside = f"{path}.old.{token}"
                    os.rename(path, aside)
                    moved.append((aside, path))
            os.replace(tmp, target)
        except OSError as exc:
            for aside, path in reversed(moved):
                try:
                    os.rename(aside, path)
                except OSError:
                    raise BackupError(
                        f"RECOVERY NEEDED: could not put {os.path.basename(path)} back from {aside}") from None
            raise BackupError(f"cannot install grafana.db: {exc.strerror}; the old database was restored") from None
        for aside, _ in moved:
            os.unlink(aside)
    finally:
        if os.path.lexists(tmp):
            os.unlink(tmp)
    final = os.lstat(target)
    if not stat.S_ISREG(final.st_mode) or (final.st_uid, final.st_gid) != (uid, gid) or stat.S_IMODE(final.st_mode) != mode:
        raise BackupError("restored grafana.db has unexpected ownership or mode")


def run_restore(cfg: Config, rt, enc, archive: str, identity: str, apply: bool = False,
                restore_key: bool = False, only=None, out=print, now=None) -> list:
    """Dry-run by default: decrypts and verifies in a private temp dir and changes nothing."""
    if not os.path.isfile(archive):
        raise BackupError(f"archive not found: {archive}")
    if not os.path.isfile(identity):
        raise BackupError(f"identity file not found: {identity}")
    if os.path.getsize(archive) > cfg.max_archive_bytes:
        raise BackupError("archive exceeds the size limit")
    out(verify_outer(archive))
    old_umask = os.umask(0o077)
    work = make_temp_dir(cfg)
    try:
        plain = os.path.join(work, "state.tar.gz")
        enc.decrypt(archive, plain, identity)
        extract_dir = os.path.join(work, "x")
        os.mkdir(extract_dir, 0o700)
        manifest = extract_verified(plain, extract_dir, cfg)
        names = sorted(manifest["members"])
        parts = []
        if set(N8N_MEMBERS[:2]) <= set(names) and only in (None, "n8n") and "n8n" in cfg.components:
            parts.append("n8n")
        if GRAFANA_MEMBER in names and only in (None, "grafana") and "grafana" in cfg.components:
            parts.append("grafana")
        out(f"archive created {manifest['created']}; members: {', '.join(names)}; checksums ok")
        for p in parts:
            out(f"would restore: {p}")
        if not apply:
            out("dry run: nothing changed. Re-run with --apply to restore.")
            return parts
        preflight_restore(cfg, parts, extract_dir, work)
        if "n8n" in parts:
            require_n8n_running(rt, cfg)  # before the safety backup, which also needs docker exec
        out("backing up what will be replaced (encrypted) first")
        safety = run_backup(cfg, rt, enc, None, prefix=SAFETY_PREFIX, now=now)
        out(f"safety backup: {safety}")
        if "n8n" in parts:
            restore_n8n(rt, cfg, extract_dir, restore_key)
            out("n8n workflows and credentials imported")
        if "grafana" in parts:
            restore_grafana(rt, cfg, extract_dir)
            out("grafana database replaced; container left stopped")
        out(manual_steps(cfg, parts))
        return parts
    finally:
        shutil.rmtree(work, ignore_errors=True)
        os.umask(old_umask)


def manual_steps(cfg: Config, parts: list) -> str:
    rt = cfg.container_runtime
    lines = ["Manual steps still needed:"]
    n = 1
    if "n8n" in parts:
        lines.append(f"  {n}. Imported workflows are inactive. Publish each: {rt} exec {cfg.n8n_container} n8n publish:workflow --id=<id>")
        n += 1
        lines.append(f"  {n}. Restart n8n so publishing takes effect: {rt} restart {cfg.n8n_container}")
        n += 1
    if "grafana" in parts:
        lines.append(f"  {n}. Start Grafana: {rt} start {cfg.grafana_container}")
        n += 1
    lines.append(f"  {n}. Trigger a test alert end to end and confirm delivery.")
    return "\n".join(lines)
