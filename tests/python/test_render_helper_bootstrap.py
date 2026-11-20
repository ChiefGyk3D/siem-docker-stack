"""The renderer, as root, sources its helper only through one checked open descriptor, and the
documentation says exactly where PATH is fixed.

The root cases run as real uid 0 inside a user namespace (`unshare -r`, no real privilege: the
caller's own files look root-owned). A stat wrapper treats the directories above the sandbox as
trusted and maps "nobody" to root, so the script, the helper and the sandbox directories are
checked for real while the system directories are not.
"""
import os
import re
import stat
import subprocess

import pytest

from conftest import REPO_ROOT, skip_or_fail

SCRIPTS = REPO_ROOT / "scripts"
RENDER = SCRIPTS / "render-prometheus-web-config.sh"
LIB = SCRIPTS / "lib-secrets.sh"
CMD = "render-prometheus-web-config.sh"


@pytest.fixture()
def rr(tmp_path):
    probe = subprocess.run(["unshare", "-r", "true"], capture_output=True, timeout=30)
    if probe.returncode != 0:
        skip_or_fail("unprivileged user namespaces are not available (unshare -r failed)")
    wrap = tmp_path / "stat-wrap" / "stat"
    wrap.parent.mkdir()
    wrap.parent.chmod(0o755)
    wrap.write_text(f"""#!/bin/sh
fmt=; last=
for a in "$@"; do case "$a" in %u|%a|"%u %a") fmt=$a ;; esac; last=$a; done
if [ -n "$FOREIGN_HELPER" ]; then
  case "$last" in *lib-secrets.sh|/proc/self/fd/*) case "$fmt" in %u) echo 4242; exit 0 ;; esac ;; esac
fi
case "{tmp_path}/" in "$last"/*|//*) above=1 ;; *) above=0 ;; esac
if [ "$above" = 1 ] || [ "$last" = / ]; then
  case "$fmt" in %u) echo 0; exit 0 ;; %a) echo 755; exit 0 ;; "%u %a") echo "0 755"; exit 0 ;; esac
fi
out=$(/usr/bin/stat "$@") || exit $?
printf '%s\\n' "$out" | /bin/sed 's/^65534/0/'
""", encoding="utf-8")
    wrap.chmod(0o755)
    outer = tmp_path / "outer"
    outer.mkdir()
    outer.chmod(0o755)
    copy_dir = outer / "scripts"
    copy_dir.mkdir()
    copy_dir.chmod(0o755)

    def run(script_mode="755", lib_mode="644", lib_link=False, dir_mode=None, outer_mode=None,
            foreign=False, via_bash=False):
        script = copy_dir / CMD
        script.write_text(RENDER.read_text(encoding="utf-8").replace("/usr/bin/stat", str(wrap)),
                          encoding="utf-8")
        script.chmod(int(script_mode, 8))
        lib = copy_dir / "lib-secrets.sh"
        if lib.exists() or lib.is_symlink():
            lib.unlink()
        if lib_link:
            real = tmp_path / "real-lib.sh"
            real.write_text(LIB.read_text(encoding="utf-8"), encoding="utf-8")
            lib.symlink_to(real)
        else:
            lib.write_text(LIB.read_text(encoding="utf-8"), encoding="utf-8")
            lib.chmod(int(lib_mode, 8))
        copy_dir.chmod(int(dir_mode or "755", 8))
        outer.chmod(int(outer_mode or "755", 8))
        env = {"PATH": "/usr/bin:/bin", "HOME": str(tmp_path)}
        if foreign:
            env["FOREIGN_HELPER"] = "1"
        launcher = ["/bin/bash", str(script)] if via_bash else [str(script)]
        return subprocess.run(["unshare", "-r", *launcher, str(tmp_path / "no-such-dir")], env=env,
                              text=True, capture_output=True, stdin=subprocess.DEVNULL, timeout=30)
    run.copy_dir = copy_dir
    return run


def test_a_trusted_tree_gets_past_the_helper_check(rr):
    proc = rr()
    assert "refusing to source" not in proc.stderr, proc.stderr
    assert "is not a directory" in proc.stderr  # reached the later target check


def test_a_group_writable_helper_is_refused_as_root(rr):
    proc = rr(lib_mode="664")
    assert proc.returncode != 0 and "refusing to source" in proc.stderr


def test_a_world_writable_helper_is_refused_as_root(rr):
    proc = rr(lib_mode="646")
    assert proc.returncode != 0 and "refusing to source" in proc.stderr


def test_a_symlinked_helper_is_refused_as_root(rr):
    proc = rr(lib_link=True)
    assert proc.returncode != 0 and "refusing to source" in proc.stderr


def test_a_foreign_owned_helper_is_refused_as_root(rr):
    proc = rr(foreign=True)
    assert proc.returncode != 0 and "refusing to source" in proc.stderr


def test_a_group_writable_script_directory_is_refused_as_root(rr):
    proc = rr(dir_mode="775")
    assert proc.returncode != 0 and "refusing to source" in proc.stderr


def test_a_writable_ancestor_directory_is_refused_as_root(rr):
    # An attacker who can write the parent can rename the checked directory away and put another
    # in its place; every directory above the helper must be closed.
    proc = rr(outer_mode="775")
    assert proc.returncode != 0 and "refusing to source" in proc.stderr


def test_a_group_writable_script_is_refused_as_root(rr):
    proc = rr(script_mode="775")
    assert proc.returncode != 0 and "refusing to source" in proc.stderr


def test_the_helper_is_sourced_from_the_checked_descriptor_only():
    code = "\n".join(ln for ln in RENDER.read_text(encoding="utf-8").splitlines()
                     if ln.strip() and not ln.lstrip().startswith("#"))
    assert "source /proc/self/fd/" in code
    assert not re.search(r'^\s*(\.|source)\s+"?\$\{?SCRIPT_DIR', code, re.M), \
        "the helper must not be sourced by pathname"
    assert "readlink -f" in code


# --- documentation says exactly where PATH is fixed -------------------------------------------

CONTAINER_DOC = (REPO_ROOT / "docs" / "container-engine.md").read_text(encoding="utf-8")
OTLP_DOC = (REPO_ROOT / "docs" / "prometheus-otlp.md").read_text(encoding="utf-8")


def _flat(text):
    return re.sub(r"\s+", " ", text.replace("\n# ", " "))


def test_docs_do_not_claim_the_renderer_fixes_path_first_or_for_every_run():
    flat = _flat(CONTAINER_DOC)
    assert "as root it fixes `PATH`; a non-root run keeps the caller's `PATH`, by design" in flat
    assert "`render-prometheus-web-config.sh`" in flat
    assert "(root or not)" not in flat
    assert "is the one exception to the PATH order" in flat


def test_docs_say_why_a_non_root_renderer_run_keeps_the_callers_path():
    flat = _flat(CONTAINER_DOC)
    assert "the tests and the owner's tools rely on it" in flat


def test_renderer_comment_states_the_path_rule_exactly():
    flat = _flat(RENDER.read_text(encoding="utf-8"))
    assert "Root run: fixed PATH. Non-root run: the caller's PATH is kept, by design" in flat


def test_otlp_doc_states_the_renderer_path_rule():
    assert "a non-root run keeps the caller's `PATH`" in _flat(OTLP_DOC)
