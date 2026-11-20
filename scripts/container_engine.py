"""Which container engine the helper scripts use: docker (default) or podman (issue #130).

One setting, CONTAINER_ENGINE, read the same way by every helper. The allowed values are exactly
`docker` and `podman`; unset or empty means docker; anything else is an error. The setting only
picks a NAME from that fixed list. The program that runs is found in fixed root-owned directories
(never through the caller's PATH), as scripts/gameday.py always did. The shell twin of this
module is scripts/lib-container-engine.sh; keep the two in step (tests/python/test_container_engine.py).

Standard library only, and no top-level statements besides definitions, because
scripts/deploy-n8n-soar.sh streams this file together with n8n_address.py to the SIEM host.
No shell string is ever built from the setting: callers pass argument lists.
"""
import contextlib
import os
import re
import shutil
import stat
import subprocess
import tempfile

ENGINES = ("docker", "podman")
DEFAULT_ENGINE = "docker"
ENV_NAME = "CONTAINER_ENGINE"
TRUSTED_DIRS = ("/usr/bin", "/usr/local/bin", "/bin", "/snap/bin")
TRUSTED_UID = 0  # the owner a trusted binary and every directory above it must have
TRUSTED_ROOT = "/"  # ownership is checked on every directory from here down to the binary
# The only variables an engine process inherits from the caller (plus a fixed PATH and a private
# empty HOME, see private_home). Everything else, notably DOCKER_HOST, DOCKER_CONTEXT,
# DOCKER_CONFIG, CONTAINER_HOST, CONTAINER_CONNECTION, HOME, XDG_*, LD_*, BASH_ENV, ENV and proxy
# variables, is dropped, so a trusted binary cannot be pointed at another daemon, a per-user
# config file, a plugin, a credential helper or a loader hook through the caller's environment.
ENV_KEEP = ("LANG", "LC_ALL", "TERM", "TZ")
# Each kept variable has its own pattern; a value that does not match in full is dropped. LANG and
# LC_ALL: C, POSIX, C.UTF-8 or ll_CC[.charset]. TERM: terminal-name characters only. TZ: a zone name
# like UTC or America/New_York (no leading colon or slash, no dots, so never a file path).
ENV_PATTERNS = {
    "LANG": re.compile(r"C|POSIX|C\.UTF-8|[a-z]{2}_[A-Z]{2}(\.[A-Za-z0-9-]{1,16})?"),
    "LC_ALL": re.compile(r"C|POSIX|C\.UTF-8|[a-z]{2}_[A-Z]{2}(\.[A-Za-z0-9-]{1,16})?"),
    "TERM": re.compile(r"[A-Za-z0-9][A-Za-z0-9._+-]{0,31}"),
    "TZ": re.compile(r"(?=.{1,40}$)[A-Za-z][A-Za-z0-9_+-]*(/[A-Za-z0-9_+-]+)*"),
}
# Where private homes are made. TMPDIR is never consulted. A base must be owned by HOME_BASE_UID and
# either not writable by others or sticky (so nobody else can rename our entry); the first usable one wins.
HOME_BASES = ("/run", "/var/tmp", "/tmp")
HOME_BASE_UID = 0


class ContainerEngineError(Exception):
    """The setting is invalid or no trusted binary exists; the message says what to do."""


def engine_name(env=None):
    """Return "docker" or "podman" from CONTAINER_ENGINE (unset or empty: docker).

    The value is matched exactly (no trimming, no case folding) and is never echoed in the error.
    """
    env = os.environ if env is None else env
    value = env.get(ENV_NAME)
    if value is None or value == "":
        return DEFAULT_ENGINE
    if value not in ENGINES:
        raise ContainerEngineError(f"{ENV_NAME} must be one of: {', '.join(ENGINES)} (unset means {DEFAULT_ENGINE})")
    return value


def _dirs_ok(path, owner_uid, root):
    """True when `path` (already canonical) is at or below `root` and every directory from root down
    to it is owned by owner_uid and not group or world writable."""
    root = os.path.realpath(root)
    if os.path.commonpath([root, path]) != root:
        return False
    chain, cur = [root], root
    for part in os.path.relpath(path, root).split(os.sep):
        if part in ("", "."):
            continue
        cur = os.path.join(cur, part)
        chain.append(cur)
    for d in chain:
        try:
            st = os.lstat(d)
        except OSError:
            return False
        if not stat.S_ISDIR(st.st_mode) or st.st_uid != owner_uid or st.st_mode & 0o022:
            return False
    return True


def resolve_cli(name, dirs=None, owner_uid=None, root=None):
    """Find `name` in a fixed set of trusted directories and return its CANONICAL absolute path, or None.

    The caller's PATH is never consulted. Links are resolved here, and the result (not the link) is
    what gets executed. The trusted directory itself and every directory from `root` down to the
    resolved file must be owned by owner_uid and not group or world writable, and the file must be a
    regular executable owned by owner_uid that is not group or world writable. Residual: the final
    parent is root-controlled, so a rename there needs root already.
    """
    dirs = TRUSTED_DIRS if dirs is None else dirs
    owner_uid = TRUSTED_UID if owner_uid is None else owner_uid
    root = TRUSTED_ROOT if root is None else root
    for d in dirs:
        real = os.path.realpath(os.path.join(d, name))
        if not os.path.isfile(real) or not _dirs_ok(os.path.realpath(d), owner_uid, root):
            continue
        if not _dirs_ok(os.path.dirname(real), owner_uid, root):
            continue
        try:
            st = os.lstat(real)
        except OSError:
            continue
        if stat.S_ISREG(st.st_mode) and st.st_mode & 0o111 and st.st_uid == owner_uid and not st.st_mode & 0o022:
            return real
    return None


def engine_exe(name):
    """Canonical path of the trusted `docker` or `podman` binary. Only those two names are resolved."""
    if name not in ENGINES:
        raise ContainerEngineError(f"container engine must be one of: {', '.join(ENGINES)}")
    exe = resolve_cli(name)
    if exe is None:
        raise ContainerEngineError(
            f"no trusted '{name}' found in {', '.join(TRUSTED_DIRS)} (root-owned, not writable by others)")
    return exe


def _base_ok(base):
    try:
        st = os.lstat(base)
    except OSError:
        return False
    return (stat.S_ISDIR(st.st_mode) and st.st_uid == HOME_BASE_UID
            and (not st.st_mode & 0o022 or bool(st.st_mode & 0o1000)))


def _make_home():
    for base in HOME_BASES:
        if not _base_ok(base):
            continue
        try:
            cand = tempfile.mkdtemp(prefix="engine-home-", dir=base)  # explicit dir: TMPDIR is ignored
        except OSError:
            continue
        st = os.lstat(cand)
        if stat.S_ISDIR(st.st_mode) and st.st_uid == os.geteuid() and stat.S_IMODE(st.st_mode) == 0o700:
            return cand
        shutil.rmtree(cand, ignore_errors=True)
    raise ContainerEngineError("no safe base directory for a private engine home (" + ", ".join(HOME_BASES) + ")")


@contextlib.contextmanager
def private_home():
    """A fresh private (mode 0700, checked after creation) empty directory under a validated fixed base,
    removed afterwards by try/finally, to serve as the engine's HOME.

    The directory is removed on a normal return, an exception, KeyboardInterrupt and SystemExit. This
    function installs no signal handler and touches no signal mask. Not covered: a signal whose default
    action ends the process without running Python (SIGKILL always; SIGTERM and SIGHUP unless the
    program has its own handler that raises) leaves the directory behind. A program that wants SIGTERM
    cleanup installs `signal.signal(signal.SIGTERM, lambda s, f: sys.exit(128 + s))` itself, in its main
    thread. Leftover engine-home-* directories under the base are safe to delete when no engine call runs."""
    d = _make_home()
    try:
        yield d
    finally:
        # an interrupt (KeyboardInterrupt, a handler that raises) during the deletion does not stop it:
        # the deletion is repeated until it completes, then the first interrupt is raised
        pending = None
        while True:
            try:
                shutil.rmtree(d, ignore_errors=True)
                break
            except BaseException as err:
                pending = pending or err
        if pending is not None:
            raise pending


def engine_env(home, path=None, environ=None):
    """The explicit child environment for an engine process: ENV_KEEP from `environ`, a PATH made of the
    trusted directories only (or `path`), and HOME, DOCKER_CONFIG and the XDG directories inside `home`
    (a private empty directory), so no per-user engine configuration is ever read."""
    environ = os.environ if environ is None else environ
    if path is None:
        good = [d for d in TRUSTED_DIRS if os.path.isdir(d) and _dirs_ok(os.path.realpath(d), TRUSTED_UID, TRUSTED_ROOT)]
        path = ":".join(good) or "/usr/bin:/bin"
    env = {k: environ[k] for k in ENV_KEEP if k in environ and ENV_PATTERNS[k].fullmatch(environ[k])}
    env["PATH"] = path
    env["HOME"] = home
    env["DOCKER_CONFIG"] = os.path.join(home, "docker")
    for k in ("CONFIG", "DATA", "CACHE", "STATE"):
        env[f"XDG_{k}_HOME"] = os.path.join(home, k.lower())
    return env


def engine_run(argv, run=subprocess.run, **kwargs):
    """subprocess.run with the engine pinned: when argv[0] is docker or podman, execute the resolved
    canonical binary (argv[0] stays the plain name) with an explicit minimal environment and a private
    empty HOME (engine_env; any `env` the caller passed is replaced); any other program is run unchanged."""
    if argv and argv[0] in ENGINES:
        kwargs["executable"] = engine_exe(argv[0])
        with private_home() as home:
            kwargs["env"] = engine_env(home)
            return run(argv, **kwargs)
    return run(argv, **kwargs)
