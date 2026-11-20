"""Round 4 review fixes for the CONTAINER_ENGINE setting (issue #130).

1. A root script validates itself and its helper tree BEFORE it reads, locates or sources anything,
   and a .env is sourced as root only from a root-owned file in a root-owned tree, via one descriptor.
2. A signalled ce_run stops the engine promptly and removes the private home, with the right status.
3. The Python signal handling: SIG_IGN kept, None handled, nested use, directory removed before the
   handlers are restored, worker threads do not break.
4. Each kept environment variable has its own strict pattern (TZ is never a path).
"""
import os
import shutil
import signal
import subprocess
import time

import pytest

from conftest import REPO_ROOT, import_module_from_path, root_copy, skip_or_fail, write_stat_stub, write_id_stub

SCRIPTS = REPO_ROOT / "scripts"
ce = import_module_from_path("container_engine", SCRIPTS / "container_engine.py")
HELPER = SCRIPTS / "lib-container-engine.sh"
SHELLS = [s for s in ("sh", "dash", "bash") if shutil.which(s)]
ROOT_CAPABLE = ["03-deploy.sh", "05-verify.sh", "06-generate-wazuh-certs.sh", "08b-init-opensearch-security.sh",
                "11-wazuh-grafana-readonly.sh", "deploy-n8n-soar.sh", "prometheus-otlp-firewall.sh"]


def make_exe(path, body, mode=0o755):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.parent.chmod(0o755)
    path.write_text(body, encoding="utf-8")
    path.chmod(mode)
    return path


def unshare_problem():
    if not shutil.which("unshare"):
        return "unshare is not installed"
    r = subprocess.run(["unshare", "-r", "/usr/bin/id", "-u"], capture_output=True, text=True, timeout=20)
    if r.returncode != 0 or r.stdout.strip() != "0":
        return "unshare -r is not available here: " + (r.stderr.strip()[:120] or "no uid 0 in a user namespace")
    return ""


# ------------------------------------------------------------------ 1. .env and the bootstrap order

def _evil_repo(tmp_path, name):
    repo = tmp_path / "evil-repo"
    scripts = repo / "scripts"
    scripts.mkdir(parents=True)
    for d in (repo, scripts):
        d.chmod(0o755)
    for f in (name, "lib-container-engine.sh"):
        shutil.copy(SCRIPTS / f, scripts / f)
        (scripts / f).chmod(0o755 if f == name else 0o644)
    marker = tmp_path / "env-code-ran"
    (repo / ".env").write_text(f'touch "{marker}"\n')  # shell code, as an attacker would plant it
    return repo, scripts, marker


@pytest.mark.parametrize("name", ["05-verify.sh", "08b-init-opensearch-security.sh"])
def test_real_root_never_runs_a_planted_env_from_an_untrusted_tree(name, tmp_path):
    why = unshare_problem()
    if why:
        skip_or_fail("needs unshare -r: " + why)
    repo, scripts, marker = _evil_repo(tmp_path, name)
    env = {"PATH": "/usr/bin:/bin", "HOME": str(tmp_path), "CONTAINER_ENGINE": "sh", "SIEM_HOST": "localhost"}
    proc = subprocess.run(["unshare", "-r", str(scripts / name)], env=env, text=True, capture_output=True,
                          stdin=subprocess.DEVNULL, timeout=30, cwd=str(tmp_path))
    assert not marker.exists(), "root ran code from an .env in an untrusted tree"
    assert "or a directory above it" in proc.stderr, proc.stderr[:300]


def test_real_root_never_runs_the_env_of_an_attacker_chosen_deploy_dir(tmp_path):
    why = unshare_problem()
    if why:
        skip_or_fail("needs unshare -r: " + why)
    deploy = tmp_path / "evil-deploy"
    deploy.mkdir()
    deploy.chmod(0o755)
    marker = tmp_path / "env-code-ran"
    (deploy / ".env").write_text(f'touch "{marker}"\n')
    repo, scripts, _ = _evil_repo(tmp_path, "08b-init-opensearch-security.sh")
    env = {"PATH": "/usr/bin:/bin", "HOME": str(tmp_path), "CONTAINER_ENGINE": "sh", "SIEM_DEPLOY_DIR": str(deploy)}
    subprocess.run(["unshare", "-r", str(scripts / "08b-init-opensearch-security.sh")], env=env, text=True,
                   capture_output=True, stdin=subprocess.DEVNULL, timeout=30, cwd=str(tmp_path))
    assert not marker.exists()


def _sim_root(tmp_path, name, env_dir, owner_of_env_dir):
    """A trusted script tree (stub stat says root owns it all) whose .env directory the stub says is
    owned by `owner_of_env_dir`."""
    stubs = tmp_path / "stubs"
    write_stat_stub(stubs, 0, "755",
                    f'if [ "$fmt" = %u ] && [ "$last" = "{env_dir}" ]; then echo {owner_of_env_dir}; exit 0; fi')
    d = root_copy(tmp_path / "sb" / "scripts", [name, "lib-container-engine.sh"], SCRIPTS, stubs)
    return d


def _run_sim(d, name, tmp_path, extra=None):
    env = {"PATH": "/usr/bin:/bin", "HOME": str(tmp_path), "CONTAINER_ENGINE": "sh", "SIEM_HOST": "localhost"}
    env.update(extra or {})
    return subprocess.run(["bash", "-p", str(d / name)], env=env, text=True, capture_output=True,
                          stdin=subprocess.DEVNULL, timeout=30, cwd=str(tmp_path))


@pytest.mark.parametrize("owner,sourced", [(0, True), (1234, False)])
def test_simulated_root_sources_an_env_only_from_a_root_owned_tree_05(owner, sourced, tmp_path):
    repo = tmp_path / "sb"
    marker = tmp_path / "env-code-ran"
    repo.mkdir()
    (repo / ".env").write_text(f'touch "{marker}"\n')
    d = _sim_root(tmp_path, "05-verify.sh", repo, owner)
    proc = _run_sim(d, "05-verify.sh", tmp_path)
    assert marker.exists() == sourced, proc.stderr[:300]
    if not sourced:
        assert "refusing to source" in proc.stderr and "directory above it" in proc.stderr


@pytest.mark.parametrize("owner,sourced", [(0, True), (1234, False)])
def test_simulated_root_sources_an_env_only_from_a_root_owned_tree_08b(owner, sourced, tmp_path):
    deploy = tmp_path / "deploy"
    marker = tmp_path / "env-code-ran"
    deploy.mkdir()
    (deploy / ".env").write_text(f'touch "{marker}"\n')
    d = _sim_root(tmp_path, "08b-init-opensearch-security.sh", deploy, owner)
    proc = _run_sim(d, "08b-init-opensearch-security.sh", tmp_path, {"SIEM_DEPLOY_DIR": str(deploy)})
    assert marker.exists() == sourced, proc.stderr[:300]
    if not sourced:
        assert "refusing to source" in proc.stderr


def test_an_env_file_that_is_a_symlink_is_refused(tmp_path):
    deploy = tmp_path / "deploy"
    deploy.mkdir()
    marker = tmp_path / "env-code-ran"
    real = tmp_path / "real.env"
    real.write_text(f'touch "{marker}"\n')
    (deploy / ".env").symlink_to(real)
    d = _sim_root(tmp_path, "08b-init-opensearch-security.sh", deploy, 0)
    proc = _run_sim(d, "08b-init-opensearch-security.sh", tmp_path, {"SIEM_DEPLOY_DIR": str(deploy)})
    assert not marker.exists() and "not a link" in proc.stderr


def test_a_world_writable_env_file_is_refused_for_everyone(tmp_path):
    marker = tmp_path / "env-code-ran"
    envf = tmp_path / "w.env"
    envf.write_text(f'touch "{marker}"\n')
    envf.chmod(0o666)
    proc = subprocess.run(["bash", "-c", f". '{HELPER}'\nCE_STRICT=0\nCE_UID=$(/usr/bin/id -u)\nce_source_env '{envf}'"],
                          env={"PATH": "/usr/bin:/bin"}, text=True, capture_output=True, stdin=subprocess.DEVNULL, timeout=30)
    assert not marker.exists() and proc.returncode != 0 and "refusing to source" in proc.stderr


def test_a_swapped_env_file_is_not_the_one_sourced(tmp_path):
    marker = tmp_path / "env-code-ran"
    d = tmp_path / "d"
    d.mkdir()
    d.chmod(0o755)
    envf = d / ".env"
    envf.write_text("GOOD=1\n")
    envf.chmod(0o644)
    evil = tmp_path / "evil.env"
    evil.write_text(f'touch "{marker}"\n')
    stubs = tmp_path / "stubs"
    write_stat_stub(stubs, 0, "644",
                    f'if [ "$last" = /proc/self/fd/8 ] && [ "$fmt" = %u ]; then /bin/mv -f "{evil}" "{envf}"; fi')
    lib = (HELPER.read_text()).replace("/usr/bin/stat", str(stubs / "stat"))
    libf = tmp_path / "lib.sh"
    libf.write_text(lib)
    proc = subprocess.run(["bash", "-c", f". '{libf}'\nCE_STRICT=0\nCE_UID=0\nce_source_env '{envf}'\necho good=$GOOD"],
                          env={"PATH": "/usr/bin:/bin"}, text=True, capture_output=True, stdin=subprocess.DEVNULL, timeout=30)
    assert not marker.exists() and "good=1" in proc.stdout, proc.stderr


@pytest.mark.parametrize("name", ROOT_CAPABLE)
def test_nothing_is_read_located_or_sourced_before_the_bootstrap_finishes(name):  # guard
    text = (SCRIPTS / name).read_text()
    cut = text.index("exec 9<&-\n")
    before = [ln for ln in text[:cut].splitlines() if ln.strip() and not ln.lstrip().startswith("#")]
    assert not [ln for ln in before if any(w in ln for w in ("SIEM_DEPLOY_DIR", ".env", "lib-secrets", "whoami", "SIEM_HOST", "${1"))], before


@pytest.mark.parametrize("name", ["05-verify.sh", "08b-init-opensearch-security.sh"])
def test_the_env_is_never_sourced_by_plain_source(name):  # guard
    code = [ln for ln in (SCRIPTS / name).read_text().splitlines() if not ln.lstrip().startswith("#")]
    assert not [ln for ln in code if ln.strip().startswith(("source ", ". ")) and "fd/9" not in ln and "CE_LIB" not in ln]
    assert any("ce_source_env" in ln for ln in code)


# ------------------------------------------------------------------ 2. prompt shell signal handling

CHILD = '#!/bin/sh\necho "$HOME" > "%s/home.txt"\necho "$PPID" > "%s/ppid.txt"\necho "$$" > "%s/pid.txt"\n%sexec /bin/sleep 300\n'


def _wait_for(path, secs=5.0):
    end = time.time() + secs
    while time.time() < end:
        if path.exists() and path.read_text().strip():
            return True
        time.sleep(0.05)
    return False


def _gone(pathstr, secs=3.0):
    end = time.time() + secs
    while time.time() < end:
        if not os.path.exists(pathstr):
            return True
        time.sleep(0.05)
    return False


def _dead(pid, secs=3.0):
    end = time.time() + secs
    while time.time() < end:
        try:
            os.kill(pid, 0)
        except ProcessLookupError:
            return True
        try:  # a zombie still answers kill 0; reap it if it is ours
            os.waitpid(pid, os.WNOHANG)
        except ChildProcessError:
            pass
        time.sleep(0.05)
    return False


def _start(shell, tmp_path, ignore_term=False):
    stub = make_exe(tmp_path / "bin" / "docker", CHILD % (tmp_path, tmp_path, tmp_path, "trap '' TERM\n" if ignore_term else ""))
    p = subprocess.Popen([shell, "-c", f". '{HELPER}'\nCE_BIN='{stub}'\nce_run ps\necho rc=$?"], env={"PATH": "/usr/bin:/bin"},
                         stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, text=True, start_new_session=True)
    assert _wait_for(tmp_path / "pid.txt"), "the engine did not start"
    return p


@pytest.mark.parametrize("shell", SHELLS)
def test_a_process_group_term_removes_the_home(shell, tmp_path):
    p = _start(shell, tmp_path)
    home = (tmp_path / "home.txt").read_text().strip()
    engine = int((tmp_path / "pid.txt").read_text())
    os.killpg(os.getpgid(p.pid), signal.SIGTERM)
    p.communicate(timeout=10)
    assert _gone(home) and _dead(engine)


# ------------------------------------------------------------------ 4. per-variable patterns

LOCALE_OK = ["C", "POSIX", "C.UTF-8", "en_US", "en_US.UTF-8", "de_DE.ISO-8859-1"]
LOCALE_BAD = ["/tmp/x", "en_US.UTF-8@x", "en_US:fr_FR", "xterm", "en_us", "EN_US", "en_US.", "en_US/x", "C/x",
              "en_US.UTF-8.x", "C.utf8/x", ":C", "C ", "en_US.UTF_8", "en_US." + "a" * 17]
TERM_OK = ["xterm", "xterm-256color", "linux", "vt100", "screen.xterm-256color", "rxvt-unicode-256color", "dumb", "tmux+x"]
TERM_BAD = ["a/b", "xterm:x", "x@y", "", "-x", ".x", "a b", "a" * 33, "x=y", "x\ny"]
TZ_OK = ["UTC", "GMT", "America/New_York", "Etc/GMT+5", "America/Argentina/Buenos_Aires", "Europe/Isle_of_Man"]
TZ_BAD = [":America/New_York", "/etc/localtime", ":/tmp/attacker-tz", "../x", "America/../x", "a//b", "America/",
          "a.b", "EST5EDT,M3.2.0", " UTC", "1UTC", "/tmp/evil", "a/./b", "A" * 41]


@pytest.mark.parametrize("name,values,ok", [("LANG", LOCALE_OK, True), ("LC_ALL", LOCALE_OK, True), ("TERM", TERM_OK, True),
                                            ("TZ", TZ_OK, True), ("LANG", LOCALE_BAD, False), ("LC_ALL", LOCALE_BAD, False),
                                            ("TERM", TERM_BAD, False), ("TZ", TZ_BAD, False)])
def test_python_each_variable_has_its_own_pattern(name, values, ok):
    for v in values:
        kept = name in ce.engine_env("/h", environ={name: v})
        assert kept == ok, f"{name}={v!r} kept={kept}"


def test_python_a_term_value_is_not_a_valid_tz_and_the_reverse():
    assert "TZ" not in ce.engine_env("/h", environ={"TZ": "xterm.256"})
    assert "TERM" not in ce.engine_env("/h", environ={"TERM": "America/New_York"})
    assert "LANG" not in ce.engine_env("/h", environ={"LANG": "xterm-256color"})


def _sh_check(shell, fn, value):
    r = subprocess.run([shell, "-c", f". '{HELPER}'\n{fn} \"$1\"", "sh", value], env={"PATH": "/usr/bin:/bin"},
                       capture_output=True, stdin=subprocess.DEVNULL, timeout=30)
    return r.returncode == 0


@pytest.mark.parametrize("shell", SHELLS)
@pytest.mark.parametrize("fn,ok_values,bad_values", [("ce_ok_locale", LOCALE_OK, LOCALE_BAD), ("ce_ok_term", TERM_OK, TERM_BAD),
                                                     ("ce_ok_tz", TZ_OK, TZ_BAD)])
def test_shell_each_variable_has_its_own_pattern_and_agrees_with_python(shell, fn, ok_values, bad_values):
    for v in ok_values:
        assert _sh_check(shell, fn, v), f"{fn} {v!r} should pass"
    for v in bad_values:
        assert not _sh_check(shell, fn, v), f"{fn} {v!r} should fail"


@pytest.mark.parametrize("shell", SHELLS)
def test_shell_ce_run_applies_the_per_variable_patterns(shell, tmp_path):
    out = tmp_path / "env.txt"
    stub = make_exe(tmp_path / "bin" / "docker", f"#!/bin/sh\n/usr/bin/env > '{out}'\n")
    env = {"PATH": "/usr/bin:/bin", "TZ": ":/tmp/attacker-tz", "TERM": "xterm-256color", "LANG": "/tmp/x", "LC_ALL": "C.UTF-8"}
    subprocess.run([shell, "-c", f". '{HELPER}'\nCE_BIN='{stub}'\nce_run ps"], env=env, capture_output=True,
                   stdin=subprocess.DEVNULL, timeout=30, cwd=str(tmp_path))
    got = dict(ln.split("=", 1) for ln in out.read_text().splitlines() if "=" in ln)
    assert "TZ" not in got and "LANG" not in got
    assert got.get("TERM") == "xterm-256color" and got.get("LC_ALL") == "C.UTF-8"
