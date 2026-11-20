"""Every script that needs the placeholder rule loads `lib-secrets.sh` only through one checked open
descriptor, never by pathname.

Root cases run as real uid 0 inside a user namespace (`unshare -r`, no real privilege: the caller's own
files look root-owned), with a stat wrapper that treats the directories above the sandbox as trusted
and can report the helper as foreign-owned (same technique as test_render_helper_bootstrap.py). Non-root
cases run as the test user with the real stat, or a wrapper that swaps the helper path after the check.
The helper copy used here prints a marker when it is sourced, so a refusal and a load are both visible.
"""
import os
import re
import subprocess

import pytest

from conftest import REPO_ROOT, skip_or_fail

SCRIPTS = REPO_ROOT / "scripts"
LIB_TEXT = (SCRIPTS / "lib-secrets.sh").read_text(encoding="utf-8")
MARK = "SECRETS_HELPER_LOADED"
EVIL = "EVIL_HELPER_LOADED"

# script name -> (needs lib-container-engine.sh beside it, extra arguments)
CASES = {
    "check-env.sh": (False, ["ENVFILE"]),
    "deploy-n8n-soar.sh": (True, []),
    "08-crowdsec-smoketest.sh": (True, []),
}
ALL_SCRIPTS = sorted(CASES)


def wrapper_text(tmp_path):
    return f"""#!/bin/sh
fmt=; last=
for a in "$@"; do case "$a" in %u|%a|%h|"%u %a") fmt=$a ;; esac; last=$a; done
if [ "$last" = /proc/self/fd/7 ] && [ "$fmt" = %h ] && [ -n "$SWAP_FROM" ] && [ -e "$SWAP_FROM" ]; then
  out=$(/usr/bin/stat "$@") || exit $?
  /bin/mv -f "$SWAP_FROM" "$SWAP_TO"
  : > "$SWAP_DONE"
  printf '%s\\n' "$out"
  exit 0
fi
if [ -n "$FOREIGN_HELPER" ]; then
  case "$last" in *lib-secrets.sh|/proc/self/fd/7) case "$fmt" in %u) echo 4242; exit 0 ;; esac ;; esac
fi
if [ -n "$USERNS" ]; then
  case "{tmp_path}/" in "$last"/*|//*) above=1 ;; *) above=0 ;; esac
  if [ "$above" = 1 ] || [ "$last" = / ]; then
    case "$fmt" in %u) echo 0; exit 0 ;; %a) echo 755; exit 0 ;; "%u %a") echo "0 755"; exit 0 ;; esac
  fi
  out=$(/usr/bin/stat "$@") || exit $?
  printf '%s\\n' "$out" | /bin/sed 's/^65534/0/'
  exit 0
fi
exec /usr/bin/stat "$@"
"""


@pytest.fixture()
def sandbox(tmp_path):
    wrap = tmp_path / "stat-wrap" / "stat"
    wrap.parent.mkdir()
    wrap.parent.chmod(0o755)
    wrap.write_text(wrapper_text(tmp_path), encoding="utf-8")
    wrap.chmod(0o755)
    outer = tmp_path / "outer"
    outer.mkdir()
    outer.chmod(0o755)
    scripts_dir = outer / "scripts"
    scripts_dir.mkdir()
    scripts_dir.chmod(0o755)
    envfile = tmp_path / "empty.env"
    envfile.write_text("", encoding="utf-8")
    envfile.chmod(0o600)

    def run(name, userns=False, lib_mode="644", lib_link=False, hard_link=False, dir_mode="755",
            outer_mode="755", foreign=False, swap=False):
        needs_ce, extra = CASES[name]
        script = scripts_dir / name
        script.write_text((SCRIPTS / name).read_text(encoding="utf-8").replace("/usr/bin/stat", str(wrap)),
                          encoding="utf-8")
        script.chmod(0o755)
        if needs_ce:
            ce = scripts_dir / "lib-container-engine.sh"
            ce.write_text((SCRIPTS / "lib-container-engine.sh").read_text(encoding="utf-8").replace(
                "/usr/bin/stat", str(wrap)), encoding="utf-8")
            ce.chmod(0o644)
        lib = scripts_dir / "lib-secrets.sh"
        if lib.exists() or lib.is_symlink():
            lib.unlink()
        body = LIB_TEXT + f"\necho {MARK} >&2\n"
        if lib_link:
            real = tmp_path / "real-lib.sh"
            real.write_text(body, encoding="utf-8")
            lib.symlink_to(real)
        else:
            lib.write_text(body, encoding="utf-8")
            lib.chmod(int(lib_mode, 8))
        if hard_link:
            other = tmp_path / "hard-link-twin.sh"
            if other.exists():
                other.unlink()
            os.link(lib, other)
        scripts_dir.chmod(int(dir_mode, 8))
        outer.chmod(int(outer_mode, 8))
        env = {"PATH": "/usr/bin:/bin", "HOME": str(tmp_path)}
        if userns:
            env["USERNS"] = "1"
        if foreign:
            env["FOREIGN_HELPER"] = "1"
        done = tmp_path / "swap-done"
        if swap:
            evil = tmp_path / "evil.sh"
            evil.write_text(f"echo {EVIL} >&2\n", encoding="utf-8")
            env.update({"SWAP_FROM": str(evil), "SWAP_TO": str(lib), "SWAP_DONE": str(done)})
        args = [str(envfile) if a == "ENVFILE" else a for a in extra]
        launcher = ["unshare", "-r", str(script), *args] if userns else [str(script), *args]
        proc = subprocess.run(launcher, env=env, text=True, capture_output=True,
                              stdin=subprocess.DEVNULL, timeout=60)
        proc.swapped = done.exists()
        return proc
    return run


@pytest.fixture()
def need_userns():
    probe = subprocess.run(["unshare", "-r", "true"], capture_output=True, timeout=30)
    if probe.returncode != 0:
        skip_or_fail("unprivileged user namespaces are not available (unshare -r failed)")


def refused(proc):
    return proc.returncode != 0 and "refusing to source" in proc.stderr and MARK not in proc.stderr


# --- a clean tree works -------------------------------------------------------------------------

@pytest.mark.parametrize("name", ALL_SCRIPTS)
def test_a_clean_tree_loads_the_helper_as_a_normal_user(sandbox, name):
    proc = sandbox(name)
    assert "refusing to source" not in proc.stderr, proc.stderr
    assert MARK in proc.stderr, proc.stderr


@pytest.mark.parametrize("name", ALL_SCRIPTS)
def test_a_clean_tree_loads_the_helper_as_root(sandbox, need_userns, name):
    proc = sandbox(name, userns=True)
    assert "refusing to source" not in proc.stderr, proc.stderr
    assert MARK in proc.stderr, proc.stderr


@pytest.mark.parametrize("name", ALL_SCRIPTS)
def test_a_sticky_world_writable_ancestor_like_tmp_is_allowed_for_a_normal_user(sandbox, name):
    proc = sandbox(name, outer_mode="1777")
    assert "refusing to source" not in proc.stderr and MARK in proc.stderr, proc.stderr


# --- a bad helper or tree is refused -----------------------------------------------------------

@pytest.mark.parametrize("name", ALL_SCRIPTS)
def test_a_world_writable_helper_is_refused_as_a_normal_user(sandbox, name):
    assert refused(sandbox(name, lib_mode="646"))


@pytest.mark.parametrize("name", ALL_SCRIPTS)
def test_a_group_writable_helper_is_refused_as_a_normal_user(sandbox, name):
    # A group peer could write the same inode after the check and before the source; the refusal
    # comes first and names the exact fix, and the helper is never sourced.
    proc = sandbox(name, lib_mode="664")
    assert refused(proc)
    assert "chmod g-w,o-w" in proc.stderr


@pytest.mark.parametrize("name", ALL_SCRIPTS)
def test_a_group_writable_ancestor_is_allowed_for_a_normal_user(sandbox, name):
    # Replacing a directory entry after the open cannot change the opened inode.
    proc = sandbox(name, outer_mode="775", dir_mode="775")
    assert "refusing to source" not in proc.stderr and MARK in proc.stderr, proc.stderr


@pytest.mark.parametrize("name", ALL_SCRIPTS)
def test_a_symlinked_helper_is_refused_as_a_normal_user(sandbox, name):
    assert refused(sandbox(name, lib_link=True))


@pytest.mark.parametrize("name", ALL_SCRIPTS)
def test_a_hard_linked_helper_is_refused_as_a_normal_user(sandbox, name):
    assert refused(sandbox(name, hard_link=True))


@pytest.mark.parametrize("name", ALL_SCRIPTS)
def test_a_world_writable_ancestor_is_refused_as_a_normal_user(sandbox, name):
    assert refused(sandbox(name, outer_mode="777"))


@pytest.mark.parametrize("name", ALL_SCRIPTS)
def test_a_world_writable_script_directory_is_refused_as_a_normal_user(sandbox, name):
    assert refused(sandbox(name, dir_mode="777"))


@pytest.mark.parametrize("name", ALL_SCRIPTS)
def test_a_helper_swapped_after_the_check_is_not_sourced(sandbox, name):
    proc = sandbox(name, swap=True)
    assert proc.swapped, "the swap point was never reached: the helper is not checked on a descriptor"
    assert MARK in proc.stderr and EVIL not in proc.stderr, proc.stderr


@pytest.mark.parametrize("name", ALL_SCRIPTS)
def test_a_group_writable_helper_is_refused_as_root(sandbox, need_userns, name):
    assert refused(sandbox(name, userns=True, lib_mode="664"))


@pytest.mark.parametrize("name", ALL_SCRIPTS)
def test_a_world_writable_helper_is_refused_as_root(sandbox, need_userns, name):
    assert refused(sandbox(name, userns=True, lib_mode="646"))


@pytest.mark.parametrize("name", ALL_SCRIPTS)
def test_a_symlinked_helper_is_refused_as_root(sandbox, need_userns, name):
    assert refused(sandbox(name, userns=True, lib_link=True))


@pytest.mark.parametrize("name", ALL_SCRIPTS)
def test_a_hard_linked_helper_is_refused_as_root(sandbox, need_userns, name):
    assert refused(sandbox(name, userns=True, hard_link=True))


@pytest.mark.parametrize("name", ALL_SCRIPTS)
def test_a_foreign_owned_helper_is_refused_as_root(sandbox, need_userns, name):
    assert refused(sandbox(name, userns=True, foreign=True))


@pytest.mark.parametrize("name", ALL_SCRIPTS)
def test_a_group_writable_script_directory_is_refused_as_root(sandbox, need_userns, name):
    assert refused(sandbox(name, userns=True, dir_mode="775"))


@pytest.mark.parametrize("name", ALL_SCRIPTS)
def test_a_writable_ancestor_directory_is_refused_as_root(sandbox, need_userns, name):
    assert refused(sandbox(name, userns=True, outer_mode="775"))


# --- static: nothing sources the helper by pathname any more ---------------------------------------

def code_lines(path):
    return [ln for ln in path.read_text(encoding="utf-8").splitlines()
            if ln.strip() and not ln.lstrip().startswith("#")]


def test_no_script_sources_the_helper_by_pathname():
    pattern = re.compile(r"^\s*(\.|source)\s+.*lib-secrets", re.M)
    offenders = []
    for path in sorted(SCRIPTS.iterdir()):
        if path.is_file() and path.suffix in (".sh", "") and not path.name.startswith("."):
            try:
                text = "\n".join(code_lines(path))
            except UnicodeDecodeError:
                continue
            if pattern.search(text):
                offenders.append(path.name)
    assert not offenders, f"sourced by pathname: {offenders}"


@pytest.mark.parametrize("name", ALL_SCRIPTS + ["render-prometheus-web-config.sh"])
def test_every_user_of_the_helper_sources_a_descriptor(name):
    code = "\n".join(code_lines(SCRIPTS / name))
    assert re.search(r"^source /proc/self/fd/\d$", code, re.M), name
    assert "%h" in code, "the link count of the open helper is not checked"


def test_the_docs_describe_the_checked_helper_loading():
    text = re.sub(r"\s+", " ", (REPO_ROOT / "docs" / "container-engine.md").read_text(encoding="utf-8"))
    assert "no script sources it by pathname" in text
    assert "a shared loader file would itself have to be sourced unchecked first" in text
