"""Shared helpers for the repo's Python tests."""
import importlib.util
import stat
import sys
import warnings
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]


_HELPER_ORIGINAL_MODES = {}


def pytest_configure(config):
    """The scripts refuse a sourced helper that is group or world writable. A checkout made with
    umask 002 leaves these files group writable (git records only 644), and the in-place tests run
    the real scripts. So the helpers are closed for the session and the original modes are restored
    at the end; a warning names each helper that was open and the fix (chmod g-w,o-w <helper>), so
    the real checkout mode is reported, not hidden. This runs once, in the controller process: under
    pytest-xdist the workers (they carry `workerinput`) leave the modes alone, so one worker
    finishing early can never reopen a helper while another worker is still running scripts."""
    if hasattr(config, "workerinput"):
        return
    for name in ("lib-secrets.sh", "lib-container-engine.sh"):
        path = REPO_ROOT / "scripts" / name
        if path.is_file():
            mode = stat.S_IMODE(path.stat().st_mode)
            if mode & (stat.S_IWGRP | stat.S_IWOTH):
                _HELPER_ORIGINAL_MODES[path] = mode
                warnings.warn(f"{path} is group or world writable (mode {mode:o}); the scripts refuse it. "
                              f"Fix: chmod g-w,o-w {path}. The tests close it for this session only.")
                path.chmod(mode & ~(stat.S_IWGRP | stat.S_IWOTH))


def pytest_unconfigure(config):
    if hasattr(config, "workerinput"):
        return
    for path, mode in _HELPER_ORIGINAL_MODES.items():
        path.chmod(mode)
    _HELPER_ORIGINAL_MODES.clear()


def skip_or_fail(reason, env=None):
    """A security-critical test cannot run here. Fail loudly when CI is set (a green CI
    must mean the test ran); otherwise skip with the reason printed."""
    import os
    import pytest

    env = os.environ if env is None else env
    if env.get("CI"):
        pytest.fail(f"required by CI but cannot run: {reason}", pytrace=False)
    pytest.skip(f"SECURITY TEST NOT RUN: {reason}")


def import_module_from_path(name: str, path: Path):
    """Import a module from an arbitrary file path (handles hyphenated names)."""
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


def root_copy(dest_dir, names, repo_scripts, stubs=None, stat_stub=True):
    """Copy scripts into dest_dir as a simulated-root sandbox (the tests are not root).

    The scripts ask the kernel who runs them with the absolute /usr/bin/id (or /bin/id), so the copy
    points those at a stub id program (in `stubs`) that answers 0. A stub stat there is used the same
    way. Everything else is the real script text."""
    dest_dir.mkdir(parents=True, exist_ok=True)
    dest_dir.chmod(0o755)
    for name in names:
        text = (repo_scripts / name).read_text(encoding="utf-8")
        if stubs is not None:
            text = text.replace("/usr/bin/id", str(stubs / "id")).replace("/bin/id", str(stubs / "id"))
            if stat_stub:
                text = text.replace("/usr/bin/stat", str(stubs / "stat"))
        (dest_dir / name).write_text(text, encoding="utf-8")
        (dest_dir / name).chmod(0o644)
    return dest_dir


def write_id_stub(stubs, uid="0"):
    stubs.mkdir(parents=True, exist_ok=True)
    (stubs / "id").write_text(f"#!/bin/sh\necho {uid}\n", encoding="utf-8")
    (stubs / "id").chmod(0o755)


STAT_STUB = """#!/bin/sh
fmt=; last=
for a in "$@"; do case "$a" in %u|%a) fmt=$a ;; esac; last=$a; done
{extra}
case "$fmt" in
  %u) echo {owner} ;;
  %a) echo {mode} ;;
  *) exec /usr/bin/stat "$@" ;;
esac
"""


def write_stat_stub(stubs, owner=0, mode="755", extra=""):
    stubs.mkdir(parents=True, exist_ok=True)
    (stubs / "stat").write_text(STAT_STUB.format(owner=owner, mode=mode, extra=extra), encoding="utf-8")
    (stubs / "stat").chmod(0o755)
    (stubs / "id").write_text("#!/bin/sh\necho 0\n", encoding="utf-8")
    (stubs / "id").chmod(0o755)
