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
import os
import stat
import subprocess

ENGINES = ("docker", "podman")
DEFAULT_ENGINE = "docker"
ENV_NAME = "CONTAINER_ENGINE"
TRUSTED_DIRS = ("/usr/bin", "/usr/local/bin", "/bin", "/snap/bin")
TRUSTED_UID = 0  # the owner a trusted binary and every directory above it must have
TRUSTED_ROOT = "/"  # ownership is checked on every directory from here down to the binary


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


def engine_run(argv, run=subprocess.run, **kwargs):
    """subprocess.run with the engine pinned: when argv[0] is docker or podman, execute the resolved
    canonical binary (argv[0] stays the plain name); any other program is run unchanged."""
    if argv and argv[0] in ENGINES:
        kwargs["executable"] = engine_exe(argv[0])
    return run(argv, **kwargs)
