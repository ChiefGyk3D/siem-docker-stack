"""Round 3 review fixes for the CONTAINER_ENGINE setting (issue #130).

1. Allowlisted variables (LANG, LC_ALL, TERM, TZ) cannot smuggle other variables into the engine's
   environment: a strict value charset, dropped when invalid, USER and LOGNAME no longer passed, and the
   shell builds the env arguments one by one.
2. The private home is never made under TMPDIR: a fixed validated base, checked after creation.
3. Every root-capable script starts with an absolute interpreter, so PATH cannot pick bash.
4. The private home is removed when the engine fails or the caller is signalled.
"""
import os
import shutil
import signal
import stat
import subprocess
import sys
import time

import pytest

from conftest import REPO_ROOT, import_module_from_path, skip_or_fail

SCRIPTS = REPO_ROOT / "scripts"
ce = import_module_from_path("container_engine", SCRIPTS / "container_engine.py")
gd = import_module_from_path("gameday", SCRIPTS / "gameday.py")
HELPER = SCRIPTS / "lib-container-engine.sh"
SHELLS = [s for s in ("sh", "dash", "bash") if shutil.which(s)]
ROOT_CAPABLE = ["03-deploy.sh", "05-verify.sh", "06-generate-wazuh-certs.sh", "08b-init-opensearch-security.sh",
                "11-wazuh-grafana-readonly.sh", "deploy-n8n-soar.sh", "prometheus-otlp-firewall.sh"]

HOSTILE = ["C LD_PRELOAD=/tmp/pwn.so", "C\tDOCKER_HOST=tcp://192.0.2.99:2375", "C\nDOCKER_HOST=tcp://192.0.2.99:2375",
           "*", "x y", "$(id)", "`id`", "a=b", "=x", "a" * 65, "tab\there", "semi;colon", "q\"uote", "back\\slash"]
VALID = {"LANG": "en_US.UTF-8", "LC_ALL": "C.UTF-8", "TERM": "xterm-256color", "TZ": "America/New_York"}
DUMP = "#!/bin/sh\n/usr/bin/env > '%s'\n"


def make_exe(path, body, mode=0o755):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.parent.chmod(0o755)
    path.write_text(body, encoding="utf-8")
    path.chmod(mode)
    return path


def envfile(path):
    return dict(ln.split("=", 1) for ln in path.read_text().splitlines() if "=" in ln)


@pytest.fixture
def trusted(tmp_path, monkeypatch):
    good = tmp_path / "good"
    good.mkdir()
    good.chmod(0o755)
    monkeypatch.setattr(ce, "TRUSTED_DIRS", (str(good),))
    monkeypatch.setattr(ce, "TRUSTED_UID", os.geteuid())
    monkeypatch.setattr(ce, "TRUSTED_ROOT", str(tmp_path))
    return good


# ------------------------------------------------------------------ 1. allowlisted values

@pytest.mark.parametrize("name", ["LANG", "LC_ALL", "TERM", "TZ"])
@pytest.mark.parametrize("value", HOSTILE)
def test_python_drops_an_allowlisted_variable_with_a_hostile_value(name, value):
    env = ce.engine_env("/h", environ={name: value})
    assert name not in env and set(env) <= set(ce.ENV_KEEP) | {"PATH", "HOME", "DOCKER_CONFIG", "XDG_CONFIG_HOME",
                                                              "XDG_DATA_HOME", "XDG_CACHE_HOME", "XDG_STATE_HOME"}


def test_python_keeps_valid_values_and_no_longer_passes_user_or_logname():
    env = ce.engine_env("/h", environ={**VALID, "USER": "alice", "LOGNAME": "alice"})
    assert all(env[k] == v for k, v in VALID.items())
    assert "USER" not in env and "LOGNAME" not in env


@pytest.mark.parametrize("shell", SHELLS)
@pytest.mark.parametrize("name", ["LANG", "LC_ALL", "TERM", "TZ"])
@pytest.mark.parametrize("value", HOSTILE)
def test_shell_ce_run_never_lets_an_allowlisted_value_inject_a_variable(shell, name, value, tmp_path):
    out = tmp_path / "env.txt"
    stub = make_exe(tmp_path / "bin" / "docker", DUMP % out)
    proc = subprocess.run([shell, "-c", f". '{HELPER}'\nCE_BIN='{stub}'\nce_run ps"],
                          env={"PATH": "/usr/bin:/bin", name: value}, text=True, capture_output=True,
                          stdin=subprocess.DEVNULL, timeout=30, cwd=str(tmp_path))
    assert proc.returncode == 0, proc.stderr
    got = envfile(out)
    assert not {"LD_PRELOAD", "DOCKER_HOST"} & set(got), "a variable was injected through " + name
    assert name not in got, "an invalid value was passed"
    allowed = {"PATH", "HOME", "DOCKER_CONFIG", "XDG_CONFIG_HOME", "XDG_DATA_HOME", "XDG_CACHE_HOME",
               "XDG_STATE_HOME", "PWD", "SHLVL", "_", "OLDPWD"}
    if name != "TERM":
        allowed.add("TERM")  # bash sets TERM=dumb itself; a valid value is passed on, which is fine
    assert set(got) <= allowed, sorted(set(got) - allowed)


@pytest.mark.parametrize("shell", SHELLS)
def test_shell_ce_run_passes_valid_values_and_not_user(shell, tmp_path):
    out = tmp_path / "env.txt"
    stub = make_exe(tmp_path / "bin" / "docker", DUMP % out)
    env = {"PATH": "/usr/bin:/bin", "USER": "alice", "LOGNAME": "alice", **VALID}
    subprocess.run([shell, "-c", f". '{HELPER}'\nCE_BIN='{stub}'\nce_run ps"], env=env, capture_output=True,
                   stdin=subprocess.DEVNULL, timeout=30, cwd=str(tmp_path))
    got = envfile(out)
    assert all(got.get(k) == v for k, v in VALID.items())
    assert "USER" not in got and "LOGNAME" not in got


def test_the_shell_helper_never_expands_the_environment_unquoted():  # guard
    code = [ln for ln in HELPER.read_text().splitlines() if not ln.lstrip().startswith("#")]
    assert not [ln for ln in code if "${LANG+" in ln or "${TERM+" in ln or "${USER+" in ln]
    assert not [ln for ln in code if (" eval " in ln or ln.strip().startswith("eval"))
                and ln.strip() != 'eval "$_ce_saved"']  # the one replay of the caller's own trap listing


# ------------------------------------------------------------------ 2. TMPDIR and the home base

def attacker_dir(tmp_path):
    d = tmp_path / "attacker-owned"
    d.mkdir()
    d.chmod(0o777)  # writable by anyone, not sticky: its entries can be renamed by others
    return d


def test_python_home_is_not_made_under_tmpdir(trusted, tmp_path, monkeypatch):
    evil = attacker_dir(tmp_path)
    monkeypatch.setenv("TMPDIR", str(evil))
    monkeypatch.setattr(tempfile_module(), "tempdir", None)
    with ce.private_home() as home:
        assert not home.startswith(str(evil)) and os.path.isdir(home)
    assert list(evil.iterdir()) == []


def tempfile_module():
    import tempfile
    return tempfile


@pytest.mark.parametrize("shell", SHELLS)
def test_shell_home_is_not_made_under_tmpdir(shell, tmp_path):
    evil = attacker_dir(tmp_path)
    out = tmp_path / "env.txt"
    stub = make_exe(tmp_path / "bin" / "docker", DUMP % out)
    subprocess.run([shell, "-c", f". '{HELPER}'\nCE_BIN='{stub}'\nce_run ps"],
                   env={"PATH": "/usr/bin:/bin", "TMPDIR": str(evil)}, capture_output=True,
                   stdin=subprocess.DEVNULL, timeout=30, cwd=str(tmp_path))
    assert not envfile(out)["HOME"].startswith(str(evil)) and list(evil.iterdir()) == []


def test_python_refuses_a_base_others_can_rename_in(tmp_path, monkeypatch):
    evil = attacker_dir(tmp_path)
    monkeypatch.setattr(ce, "HOME_BASES", (str(evil),))
    monkeypatch.setattr(ce, "HOME_BASE_UID", os.geteuid())
    with pytest.raises(ce.ContainerEngineError, match="no safe base"):
        with ce.private_home():
            pass
    assert list(evil.iterdir()) == []


@pytest.mark.parametrize("mode,ok", [(0o755, True), (0o700, True), (0o1777, True), (0o777, False), (0o775, False), (0o757, False)])
def test_python_base_mode_rules(tmp_path, monkeypatch, mode, ok):
    base = tmp_path / "base"
    base.mkdir()
    base.chmod(mode)
    monkeypatch.setattr(ce, "HOME_BASES", (str(base),))
    monkeypatch.setattr(ce, "HOME_BASE_UID", os.geteuid())
    if ok:
        with ce.private_home() as home:
            assert os.path.dirname(home) == str(base)
    else:
        with pytest.raises(ce.ContainerEngineError):
            with ce.private_home():
                pass


def test_python_refuses_a_base_owned_by_someone_else(tmp_path, monkeypatch):
    base = tmp_path / "base"
    base.mkdir()
    base.chmod(0o755)  # fine in every way except its owner
    monkeypatch.setattr(ce, "HOME_BASES", (str(base),))
    monkeypatch.setattr(ce, "HOME_BASE_UID", os.geteuid() + 1)
    with pytest.raises(ce.ContainerEngineError):
        with ce.private_home():
            pass


def test_python_refuses_a_base_that_is_a_symlink(tmp_path, monkeypatch):
    real = tmp_path / "real"
    real.mkdir()
    real.chmod(0o755)  # fine in every way except that it is reached through a link
    link = tmp_path / "link"
    link.symlink_to(real)
    monkeypatch.setattr(ce, "HOME_BASES", (str(link),))
    monkeypatch.setattr(ce, "HOME_BASE_UID", os.geteuid())
    with pytest.raises(ce.ContainerEngineError):
        with ce.private_home():
            pass


def test_python_checks_the_home_after_creating_it(tmp_path, monkeypatch):
    base = tmp_path / "base"
    base.mkdir()
    base.chmod(0o755)
    monkeypatch.setattr(ce, "HOME_BASES", (str(base),))
    monkeypatch.setattr(ce, "HOME_BASE_UID", os.geteuid())
    real_mkdtemp = ce.tempfile.mkdtemp

    def loose(*a, **k):
        d = real_mkdtemp(*a, **k)
        os.chmod(d, 0o755)  # a directory that is not private
        return d

    monkeypatch.setattr(ce.tempfile, "mkdtemp", loose)
    with pytest.raises(ce.ContainerEngineError):
        with ce.private_home():
            pass
    assert list(base.iterdir()) == []


def test_python_falls_through_to_the_next_usable_base(tmp_path, monkeypatch):
    evil = attacker_dir(tmp_path)
    good = tmp_path / "good-base"
    good.mkdir()
    good.chmod(0o755)
    monkeypatch.setattr(ce, "HOME_BASES", (str(evil), str(tmp_path / "missing"), str(good)))
    monkeypatch.setattr(ce, "HOME_BASE_UID", os.geteuid())
    with ce.private_home() as home:
        assert os.path.dirname(home) == str(good)


def sh_home(shell, tmp_path, bases, uid, extra=""):
    out = tmp_path / "env.txt"
    stub = make_exe(tmp_path / "bin" / "docker", DUMP % out)
    proc = subprocess.run([shell, "-c", f". '{HELPER}'\nCE_HOME_BASES='{bases}'\nCE_HOME_BASE_UID={uid}\nCE_BIN='{stub}'\n{extra}ce_run ps"],
                          env={"PATH": "/usr/bin:/bin"}, text=True, capture_output=True,
                          stdin=subprocess.DEVNULL, timeout=30, cwd=str(tmp_path))
    return proc, out


@pytest.mark.parametrize("shell", SHELLS)
@pytest.mark.parametrize("mode,ok", [(0o755, True), (0o1777, True), (0o777, False), (0o775, False), (0o757, False)])
def test_shell_base_mode_rules(shell, tmp_path, mode, ok):
    base = tmp_path / "base"
    base.mkdir()
    base.chmod(mode)
    proc, out = sh_home(shell, tmp_path, base, os.geteuid())
    assert (proc.returncode == 0) == ok
    if ok:
        assert envfile(out)["HOME"].startswith(str(base) + "/")
    else:
        assert "no safe base" in proc.stderr and not out.exists() and list(base.iterdir()) == []


@pytest.mark.parametrize("shell", SHELLS)
def test_shell_refuses_a_base_owned_by_someone_else_or_a_link(shell, tmp_path):
    base = tmp_path / "base"
    base.mkdir()
    base.chmod(0o755)
    proc, _ = sh_home(shell, tmp_path, base, os.geteuid() + 1)
    assert proc.returncode != 0 and "no safe base" in proc.stderr
    link = tmp_path / "link"
    link.symlink_to(base)
    proc, _ = sh_home(shell, tmp_path, link, os.geteuid())
    assert proc.returncode != 0 and "no safe base" in proc.stderr


@pytest.mark.parametrize("shell", SHELLS)
def test_shell_ignores_a_home_base_from_the_environment(shell, tmp_path):
    evil = attacker_dir(tmp_path)
    out = tmp_path / "env.txt"
    stub = make_exe(tmp_path / "bin" / "docker", DUMP % out)
    subprocess.run([shell, "-c", f". '{HELPER}'\nCE_BIN='{stub}'\nce_run ps"],
                   env={"PATH": "/usr/bin:/bin", "CE_HOME_BASES": str(evil), "CE_HOME_BASE_UID": str(os.geteuid())},
                   capture_output=True, stdin=subprocess.DEVNULL, timeout=30, cwd=str(tmp_path))
    assert not envfile(out)["HOME"].startswith(str(evil))


# ------------------------------------------------------------------ 3. shebang

@pytest.mark.parametrize("name", ROOT_CAPABLE)
def test_the_interpreter_is_an_absolute_path(name):  # guard
    first = (SCRIPTS / name).read_text().splitlines()[0]
    assert first == "#!/bin/bash -p", first  # absolute interpreter, privileged mode


def git_executable(name):
    out = subprocess.run(["git", "ls-files", "-s", "--", f"scripts/{name}"], capture_output=True, text=True,
                         cwd=str(REPO_ROOT)).stdout.split()
    return bool(out) and out[0] == "100755"


@pytest.mark.parametrize("name", [n for n in ROOT_CAPABLE if git_executable(n)])
def test_direct_execution_with_a_hostile_path_never_picks_a_path_bash(name, tmp_path):
    evil = tmp_path / "evil"
    make_exe(evil / "bash", f'#!/bin/sh\ntouch "{tmp_path}/bash-marker"\nexit 99\n')
    env = {"PATH": f"{evil}:/usr/bin:/bin", "HOME": str(tmp_path), "CONTAINER_ENGINE": "sh", "SIEM_HOST": "localhost",
           "N8N_API_KEY": "Zx9-api-key-test-value", "GRAFANA_PASS": "Zx9-graf-pass-test-value"}
    subprocess.run([str(SCRIPTS / name), *(["192.0.2.1"] if name == "deploy-n8n-soar.sh" else [])], env=env,
                   capture_output=True, stdin=subprocess.DEVNULL, timeout=30, cwd=str(tmp_path))
    assert not (tmp_path / "bash-marker").exists()


# ------------------------------------------------------------------ 4. cleanup on failure and signals

HOME_DUMP = '#!/bin/sh\necho "$HOME" > "%s"\n%s'


@pytest.mark.parametrize("shell", ["bash", "dash"])
def test_shell_failing_engine_under_errexit_still_removes_the_home(shell, tmp_path):
    if not shutil.which(shell):
        pytest.skip(shell)
    rec = tmp_path / "home.txt"
    stub = make_exe(tmp_path / "bin" / "docker", HOME_DUMP % (rec, "exit 7\n"))
    proc = subprocess.run([shell, "-c", f"set -e\n. '{HELPER}'\nCE_BIN='{stub}'\nce_run ps\necho not-reached"],
                          env={"PATH": "/usr/bin:/bin"}, text=True, capture_output=True,
                          stdin=subprocess.DEVNULL, timeout=30, cwd=str(tmp_path))
    assert proc.returncode == 7 and "not-reached" not in proc.stdout
    assert not os.path.exists(rec.read_text().strip())


@pytest.mark.parametrize("shell", SHELLS)
@pytest.mark.parametrize("sig", ["TERM", "HUP", "INT"])
def test_shell_removes_the_home_when_the_call_is_signalled(shell, sig, tmp_path):
    rec = tmp_path / "home.txt"
    # the engine signals its parent (the ce_run subshell) and lingers a moment, like a stop request
    stub = make_exe(tmp_path / "bin" / "docker", HOME_DUMP % (rec, f"kill -{sig} $PPID\n/bin/sleep 1\n"))
    proc = subprocess.run([shell, "-c", f". '{HELPER}'\nCE_BIN='{stub}'\nce_run ps\necho rc=$?"],
                          env={"PATH": "/usr/bin:/bin"}, text=True, capture_output=True,
                          stdin=subprocess.DEVNULL, timeout=30, cwd=str(tmp_path))
    assert rec.exists() and not os.path.exists(rec.read_text().strip()), "the private home was left behind"
    assert "rc=" in proc.stdout


def test_python_removes_the_home_when_the_caller_gets_sigterm(trusted, tmp_path):
    rec = tmp_path / "home.txt"
    make_exe(trusted / "docker", HOME_DUMP % (rec, "kill -TERM $PPID\n/bin/sleep 5\n"))
    driver = f'''
import os, sys
sys.path.insert(0, "{SCRIPTS}")
import container_engine as ce
ce.TRUSTED_DIRS = ("{trusted}",)
ce.TRUSTED_UID = {os.geteuid()}
ce.TRUSTED_ROOT = "{tmp_path}"
ce.engine_run(["docker", "ps"], capture_output=True)
'''
    t0 = time.time()
    proc = subprocess.run([sys.executable, "-I", "-c", driver], capture_output=True, text=True, timeout=30)
    assert time.time() - t0 < 4, "the engine was not stopped"
    assert proc.returncode == 128 + signal.SIGTERM
    assert not os.path.exists(rec.read_text().strip()), "the private home was left behind"


def test_python_restores_the_signal_handlers_afterwards(trusted, tmp_path):
    before = signal.getsignal(signal.SIGTERM)
    with ce.private_home():
        assert signal.getsignal(signal.SIGTERM) is not before
    assert signal.getsignal(signal.SIGTERM) is before


def test_gameday_runner_reports_a_missing_safe_base_instead_of_crashing(tmp_path, monkeypatch):
    good = tmp_path / "good"
    make_exe(good / "docker", "#!/bin/sh\n")
    monkeypatch.setattr(gd, "TRUSTED_DIRS", (str(good),))
    monkeypatch.setattr(gd, "TRUSTED_UID", os.geteuid())
    monkeypatch.setattr(gd, "TRUSTED_ROOT", str(tmp_path))
    monkeypatch.setattr(ce, "HOME_BASES", ())
    rc, text = gd.real_runner(["docker", "ps"])
    assert rc == 127 and "no safe base" in text


# ------------------------------------------------------------------ 5. who is root: the kernel, never EUID

SOURCING = [n for n in ROOT_CAPABLE if n != "prometheus-otlp-firewall.sh"] + ["prometheus-otlp-firewall.sh"]
HOSTILE_EUID = ["1234", "0", "", "abc"]


def test_the_scripts_and_the_helper_never_read_euid_or_uid():  # guard
    import re
    for name in ROOT_CAPABLE + ["lib-container-engine.sh"]:
        text = (SCRIPTS / name).read_text()
        assert "EUID" not in text, name
        assert not re.search(r"\$\{?UID\b", text), name


@pytest.mark.parametrize("name", ROOT_CAPABLE)
def test_the_uid_comes_from_an_absolute_id_with_a_numeric_check(name):  # guard
    text = (SCRIPTS / name).read_text()
    assert '/usr/bin/id -u 2>/dev/null || /bin/id -u' in text
    assert "*[!0-9]*) ce_boot_fail" in text


def _unshare_ok():
    if not shutil.which("unshare"):
        return "unshare is not installed"
    r = subprocess.run(["unshare", "-r", "/usr/bin/id", "-u"], capture_output=True, text=True, timeout=20)
    if r.returncode != 0 or r.stdout.strip() != "0":
        return "unshare -r is not available here: " + (r.stderr.strip()[:120] or "no uid 0 in a user namespace")
    return ""


def _copy_real(tmp_path, name):
    d = tmp_path / "plain" / "scripts"
    d.mkdir(parents=True)
    d.chmod(0o755)
    for f in (name, "lib-container-engine.sh", "lib-secrets.sh"):
        shutil.copy(SCRIPTS / f, d / f)
        (d / f).chmod(0o644)
    return d


def _env(tmp_path, euid):
    return {"PATH": "/usr/bin:/bin", "HOME": str(tmp_path), "CONTAINER_ENGINE": "sh", "SIEM_HOST": "localhost",
            "N8N_API_KEY": "Zx9-api-key-test-value", "GRAFANA_PASS": "Zx9-graf-pass-test-value",
            "PROM_FW_NO_SUDO": "1", "EUID": euid, "UID": euid}


@pytest.mark.parametrize("euid", HOSTILE_EUID)
@pytest.mark.parametrize("name", SOURCING)
def test_a_hostile_euid_cannot_turn_the_root_checks_off(name, euid, tmp_path):
    why = _unshare_ok()
    if why:
        skip_or_fail("the root-decision test needs unshare -r: " + why)
    d = _copy_real(tmp_path, name)
    (d / name).chmod(0o755)  # run by its path, as root must
    args = ["192.0.2.1"] if name == "deploy-n8n-soar.sh" else []
    proc = subprocess.run(["unshare", "-r", str(d / name), *args], env=_env(tmp_path, euid), text=True,
                          capture_output=True, stdin=subprocess.DEVNULL, timeout=30, cwd=str(tmp_path))
    # really uid 0 (in a user namespace): the strict chain check runs and refuses the unprivileged parents
    assert "or a directory above it" in proc.stderr, proc.stderr[:300]


@pytest.mark.parametrize("euid", HOSTILE_EUID)
@pytest.mark.parametrize("name", SOURCING)
def test_a_hostile_euid_cannot_turn_the_root_checks_on_for_an_ordinary_user(name, euid, tmp_path):
    d = _copy_real(tmp_path, name)
    args = ["192.0.2.1"] if name == "deploy-n8n-soar.sh" else []
    proc = subprocess.run(["bash", str(d / name), *args], env=_env(tmp_path, euid), text=True, capture_output=True,
                          stdin=subprocess.DEVNULL, timeout=30, cwd=str(tmp_path))
    assert "or a directory above it" not in proc.stderr and "refusing to source" not in proc.stderr, proc.stderr[:300]


def _id_stub_copy(tmp_path, name, answer):
    from conftest import root_copy, write_id_stub
    stubs = tmp_path / "idstub"
    write_id_stub(stubs, answer)
    d = root_copy(tmp_path / "idsb" / "scripts", [name, "lib-container-engine.sh", "lib-secrets.sh"], SCRIPTS, stubs, stat_stub=False)
    return d


@pytest.mark.parametrize("name", SOURCING)
@pytest.mark.parametrize("answer", ["abc", "", "-1", "1 2", "0x0"])
def test_a_non_numeric_answer_from_id_stops_the_script(name, answer, tmp_path):
    d = _id_stub_copy(tmp_path, name, "'" + answer + "'" if answer else "''")
    args = ["192.0.2.1"] if name == "deploy-n8n-soar.sh" else []
    proc = subprocess.run(["bash", "-p", str(d / name), *args], env=_env(tmp_path, "0"), text=True, capture_output=True,
                          stdin=subprocess.DEVNULL, timeout=30, cwd=str(tmp_path))
    assert proc.returncode != 0 and "cannot tell who is running" in proc.stderr


@pytest.mark.parametrize("name", SOURCING)
def test_a_zero_with_leading_zeros_is_still_root(name, tmp_path):
    d = _id_stub_copy(tmp_path, name, "000")
    args = ["192.0.2.1"] if name == "deploy-n8n-soar.sh" else []
    proc = subprocess.run(["bash", "-p", str(d / name), *args], env=_env(tmp_path, "1234"), text=True, capture_output=True,
                          stdin=subprocess.DEVNULL, timeout=30, cwd=str(tmp_path))
    assert "or a directory above it" in proc.stderr


# ------------------------------------------------------------------ 6. bash startup environment (privileged shebang)

def _head(name):
    return [ln for ln in (SCRIPTS / name).read_text().splitlines() if ln.strip() and not ln.startswith("#")][:3]


@pytest.mark.parametrize("name", ROOT_CAPABLE)
def test_the_shebang_is_the_privileged_mode_bash(name):  # guard
    assert (SCRIPTS / name).read_text().splitlines()[0] == "#!/bin/bash -p"


@pytest.mark.parametrize("name", ROOT_CAPABLE)
def test_the_first_lines_clear_trace_and_startup_variables(name):  # guard
    assert _head(name)[:2] == ["set +x", "unset BASH_ENV ENV CDPATH GLOBIGNORE PS4"], _head(name)


@pytest.mark.parametrize("name", ROOT_CAPABLE)
def test_the_scripts_are_executable_in_git(name):  # guard: root runs them by path, so the bit must be set
    assert git_executable(name)


def _by_path_copy(tmp_path, name):
    d = _copy_real(tmp_path, name)
    (d / name).chmod(0o755)
    return d


@pytest.mark.parametrize("var", ["BASH_ENV", "ENV"])
@pytest.mark.parametrize("name", ROOT_CAPABLE)
def test_a_startup_file_named_in_the_environment_never_runs(name, var, tmp_path):
    d = _by_path_copy(tmp_path, name)
    marker = tmp_path / "startup-ran"
    rc = tmp_path / "rc.sh"
    rc.write_text(f'touch "{marker}"\n')
    env = {**_env(tmp_path, "1"), var: str(rc)}
    subprocess.run([str(d / name), *(["192.0.2.1"] if name == "deploy-n8n-soar.sh" else [])], env=env,
                   capture_output=True, stdin=subprocess.DEVNULL, timeout=30, cwd=str(tmp_path))
    assert not marker.exists(), f"{var} ran before the first line"


@pytest.mark.parametrize("fn", ["unset", "set", "id", "readlink", "stat", "dirname"])
@pytest.mark.parametrize("name", ROOT_CAPABLE)
def test_an_exported_function_never_runs(name, fn, tmp_path):
    d = _by_path_copy(tmp_path, name)
    marker = tmp_path / "function-ran"
    env = {**_env(tmp_path, "1"), f"BASH_FUNC_{fn}%%": f'() {{ touch "{marker}"; }}'}
    subprocess.run([str(d / name), *(["192.0.2.1"] if name == "deploy-n8n-soar.sh" else [])], env=env,
                   capture_output=True, stdin=subprocess.DEVNULL, timeout=30, cwd=str(tmp_path))
    assert not marker.exists(), f"an exported function named {fn} ran"


def test_the_control_without_privileged_mode_an_exported_function_does_run(tmp_path):
    # control: the same function DOES run when the interpreter is started without -p
    d = _by_path_copy(tmp_path, "06-generate-wazuh-certs.sh")
    marker = tmp_path / "function-ran"
    env = {**_env(tmp_path, "1"), "BASH_FUNC_unset%%": f'() {{ touch "{marker}"; }}'}
    subprocess.run(["bash", str(d / "06-generate-wazuh-certs.sh")], env=env, capture_output=True,
                   stdin=subprocess.DEVNULL, timeout=30, cwd=str(tmp_path))
    assert marker.exists()


@pytest.mark.parametrize("name", SOURCING)
def test_as_root_an_explicit_interpreter_is_refused(name, tmp_path):
    d = _id_stub_copy(tmp_path, name, "0")
    args = ["192.0.2.1"] if name == "deploy-n8n-soar.sh" else []
    proc = subprocess.run(["bash", str(d / name), *args], env=_env(tmp_path, "1"), text=True, capture_output=True,
                          stdin=subprocess.DEVNULL, timeout=30, cwd=str(tmp_path))
    assert proc.returncode != 0 and "run this script by its path" in proc.stderr


@pytest.mark.parametrize("name", SOURCING)
def test_as_root_the_privileged_interpreter_is_accepted(name, tmp_path):  # control for the refusal above
    d = _id_stub_copy(tmp_path, name, "0")
    (d / name).chmod(0o755)
    args = ["192.0.2.1"] if name == "deploy-n8n-soar.sh" else []
    by_flag = subprocess.run(["bash", "-p", str(d / name), *args], env=_env(tmp_path, "1"), text=True,
                             capture_output=True, stdin=subprocess.DEVNULL, timeout=30, cwd=str(tmp_path))
    by_path = subprocess.run([str(d / name), *args], env=_env(tmp_path, "1"), text=True, capture_output=True,
                             stdin=subprocess.DEVNULL, timeout=30, cwd=str(tmp_path))
    for proc in (by_flag, by_path):
        assert "run this script by its path" not in proc.stderr


@pytest.mark.parametrize("name", SOURCING)
def test_an_ordinary_user_may_still_use_an_explicit_interpreter(name, tmp_path):
    d = _copy_real(tmp_path, name)
    args = ["192.0.2.1"] if name == "deploy-n8n-soar.sh" else []
    proc = subprocess.run(["bash", str(d / name), *args], env=_env(tmp_path, "1"), text=True, capture_output=True,
                          stdin=subprocess.DEVNULL, timeout=30, cwd=str(tmp_path))
    assert "run this script by its path" not in proc.stderr


def test_skip_or_fail_fails_when_ci_is_set_and_skips_otherwise():
    with pytest.raises(pytest.fail.Exception):
        skip_or_fail("x", env={"CI": "true"})
    with pytest.raises(pytest.skip.Exception):
        skip_or_fail("x", env={})
