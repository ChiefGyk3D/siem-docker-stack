"""Shared helpers for the repo's Python tests."""
import importlib.util
import stat
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]


@pytest.fixture(scope="session", autouse=True)
def _helpers_are_not_group_or_world_writable():
    """The scripts refuse a sourced helper that is group or world writable. A checkout made with
    umask 002 leaves these files group writable (git records only 644), so close them here, the
    same fix the refusal message names (chmod g-w,o-w)."""
    for name in ("lib-secrets.sh", "lib-container-engine.sh"):
        path = REPO_ROOT / "scripts" / name
        if path.is_file():
            path.chmod(path.stat().st_mode & ~(stat.S_IWGRP | stat.S_IWOTH) & 0o7777)
    yield


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
