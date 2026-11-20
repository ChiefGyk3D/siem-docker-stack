"""Shared helpers for the repo's Python tests."""
import importlib.util
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]


def import_module_from_path(name: str, path: Path):
    """Import a module from an arbitrary file path (handles hyphenated names)."""
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


def root_copy(dest_dir, names, repo_scripts, stubs=None):
    """Copy scripts into dest_dir as a simulated-root sandbox (the tests are not root).

    The scripts decide they are root from bash's EUID, so the copy has that test forced true, and
    when `stubs` is given the absolute /usr/bin/stat and /usr/bin/id calls point at stub programs
    there. Everything else is the real script text."""
    import shutil
    dest_dir.mkdir(parents=True, exist_ok=True)
    dest_dir.chmod(0o755)
    for name in names:
        text = (repo_scripts / name).read_text(encoding="utf-8")
        text = text.replace('"${EUID:-1}"', "0")
        if stubs is not None:
            text = text.replace("/usr/bin/stat", str(stubs / "stat")).replace("/usr/bin/id", str(stubs / "id"))
        (dest_dir / name).write_text(text, encoding="utf-8")
        (dest_dir / name).chmod(0o644)
    return dest_dir


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
