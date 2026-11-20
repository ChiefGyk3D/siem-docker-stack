"""Round 2 review fixes for the CONTAINER_ENGINE setting (issue #130).

1. Root-capable scripts fix PATH before running any command and call utilities by absolute path.
2. The engine gets a fresh private empty HOME (no per-user docker or podman configuration at all).
3. Every sourcing script reads the helper once through an open descriptor and sources that descriptor.

The tests are not root. A "simulated root" is a copy of the real script text in which the EUID test is
made to see a stub id that answers 0 (see conftest.root_copy); stat is stubbed by absolute path where a
test needs to control ownership.
"""
import os
import re
import shutil
import subprocess

import pytest

from conftest import REPO_ROOT, import_module_from_path, root_copy, write_id_stub, write_stat_stub

SCRIPTS = REPO_ROOT / "scripts"
ce = import_module_from_path("container_engine", SCRIPTS / "container_engine.py")
gd = import_module_from_path("gameday", SCRIPTS / "gameday.py")
lib = import_module_from_path("state_backup_lib", SCRIPTS / "state_backup_lib.py")
HELPER = SCRIPTS / "lib-container-engine.sh"
SHELLS = [s for s in ("sh", "dash", "bash") if shutil.which(s)]

ROOT_CAPABLE = ["03-deploy.sh", "05-verify.sh", "06-generate-wazuh-certs.sh", "08b-init-opensearch-security.sh",
                "11-wazuh-grafana-readonly.sh", "deploy-n8n-soar.sh", "prometheus-otlp-firewall.sh"]
SOURCING = [n for n in ROOT_CAPABLE if n != "prometheus-otlp-firewall.sh"] + ["prometheus-otlp-firewall.sh"]
EVIL_UTILS = ("id", "readlink", "stat", "dirname", "whoami", "mktemp", "rm", "env", "cat", "tr", "sort",
              "grep", "mkdir", "ssh", "date", "basename", "sed", "awk", "mv", "iptables")
EVIL_LIB = '''touch "$EVIL_MARKER"
ce_name() { printf docker; }
ce_init() { CE_NAME=docker; CE_BIN=/bin/true; }
ce_init_name() { CE_NAME=docker; }
ce_resolve() { printf /bin/true; }
ce_run() { :; }
exit 7
'''


def make_exe(path, body, mode=0o755):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.parent.chmod(0o755)
    path.write_text(body, encoding="utf-8")
    path.chmod(mode)
    return path


def evil_bin(tmp_path):
    """A directory of fake utilities that each leave a marker; put first on PATH to catch lookups."""
    d = tmp_path / "evil-bin"
    for u in EVIL_UTILS:
        make_exe(d / u, f'#!/bin/sh\ntouch "{tmp_path}/path-marker"\nexit 99\n')
    return d


def run_script(path, tmp_path, env_extra=None, args=()):
    env = {"PATH": f"{evil_bin(tmp_path)}:/usr/bin:/bin", "HOME": str(tmp_path), "CONTAINER_ENGINE": "sh",
           "SIEM_HOST": "localhost", "N8N_API_KEY": "Zx9-api-key-test-value", "GRAFANA_PASS": "Zx9-graf-pass-test-value",
           "EVIL_MARKER": str(tmp_path / "marker")}
    env.update(env_extra or {})
    return subprocess.run(["bash", "-p", str(path), *args], env=env, text=True, capture_output=True,
                          stdin=subprocess.DEVNULL, timeout=30, cwd=str(tmp_path))


def sandbox(tmp_path, name, stubs=None):
    stat_stub = stubs is not None
    if stubs is None:  # a stub id only: the script believes it is root, and uses the real stat
        stubs = tmp_path / "idstub"
        write_id_stub(stubs)
    d = root_copy(tmp_path / "root-sb" / "scripts", [name, "lib-container-engine.sh", "lib-secrets.sh"], SCRIPTS, stubs,
                  stat_stub=stat_stub)
    for extra in ("container_engine.py", "n8n_address.py"):
        shutil.copy(SCRIPTS / extra, d / extra)
    return d


# ------------------------------------------------------------------ 1. PATH before anything else

@pytest.mark.parametrize("name", ROOT_CAPABLE)
def test_simulated_root_never_runs_a_path_program(name, tmp_path):
    d = sandbox(tmp_path, name)
    proc = run_script(d / name, tmp_path, args=["192.0.2.1"] if name == "deploy-n8n-soar.sh" else [])
    assert not (tmp_path / "path-marker").exists(), f"a program from the inherited PATH ran: {proc.stderr[:200]}"


def test_the_hostile_path_control_the_fake_utilities_do_get_called_without_the_reset(tmp_path):
    # control: with the reset removed from a copy, the same hostile PATH does reach a fake utility
    stubs = tmp_path / "stubs"
    write_stat_stub(stubs, 0, "755")  # the chain checks pass, so the script runs on to its own commands
    d = sandbox(tmp_path, "05-verify.sh", stubs)
    text = (d / "05-verify.sh").read_text()
    text = re.sub(r'(?m)^PATH=.*export PATH.*\n', "", text)
    (d / "05-verify.sh").write_text(text)
    run_script(d / "05-verify.sh", tmp_path)
    assert (tmp_path / "path-marker").exists()


@pytest.mark.parametrize("shell", SHELLS)
def test_the_helper_functions_use_absolute_utilities(shell, tmp_path):
    good = tmp_path / "good"
    make_exe(good / "docker", "#!/bin/sh\n")
    snippet = (f". '{HELPER}'\nce_resolve docker '{good}' {os.geteuid()} '{tmp_path}' >/dev/null\n"
               f"CE_BIN='{good}/docker'; ce_run x >/dev/null 2>&1; true")
    subprocess.run([shell, "-c", snippet], env={"PATH": f"{evil_bin(tmp_path)}:/usr/bin:/bin"}, capture_output=True,
                   timeout=30, stdin=subprocess.DEVNULL)
    assert not (tmp_path / "path-marker").exists()


BOOT = re.compile(r"(?s)^.*?(?=exec 9<&-)")
BARE = re.compile(r"(^|[\s;&|(`$])(readlink|stat|dirname|id|mktemp|rm|env)\s")


def _code(text):
    return [ln for ln in text.splitlines() if not ln.lstrip().startswith("#") and not re.match(r"\s*(echo|printf)\b", ln)]


@pytest.mark.parametrize("name", ROOT_CAPABLE)
def test_the_first_command_of_each_script_fixes_path(name):  # guard
    code = [ln for ln in _code((SCRIPTS / name).read_text()) if ln.strip()]
    first = next(i for i, ln in enumerate(code) if not ln.startswith(("set ", "unset ")))
    assert re.search(r"PATH=(/usr/local/sbin:/usr/local/bin:)?/usr/sbin:/usr/bin:/sbin:/bin; export PATH", code[first]), code[first]


@pytest.mark.parametrize("name", ROOT_CAPABLE)
def test_no_utility_is_called_by_bare_name_in_the_bootstrap(name):  # guard
    text = (SCRIPTS / name).read_text()
    boot = BOOT.search(text).group(0)
    bad = [ln for ln in _code(boot) if BARE.search(ln.split("#")[0])]
    assert bad == [], bad


def test_the_helper_calls_no_utility_by_bare_name():  # guard
    bad = [ln for ln in _code(HELPER.read_text()) if BARE.search(ln.split("#")[0]) and "command -v" not in ln]
    assert bad == [], bad


# ------------------------------------------------------------------ 2. private empty HOME

PLANT = '''#!/bin/sh
out="%s"
{
  echo "home_empty=$([ -z "$(/bin/ls -A "$HOME")" ] && echo yes || echo no)"
  echo "home_mode=$(/usr/bin/stat -c %%a "$HOME")"
  echo "docker_config_in_home=$(case "$DOCKER_CONFIG" in "$HOME"/*) echo yes ;; *) echo no ;; esac)"
  echo "xdg_in_home=$(case "$XDG_CONFIG_HOME:$XDG_DATA_HOME:$XDG_CACHE_HOME:$XDG_STATE_HOME" in "$HOME"/*:"$HOME"/*:"$HOME"/*:"$HOME"/*) echo yes ;; *) echo no ;; esac)"
  echo "runtime_dir=${XDG_RUNTIME_DIR-unset}"
  echo "home=$HOME"
} >> "$out"
echo '{"siem-net": {"IPAddress": "192.0.2.44"}}'
'''


def plant_home(tmp_path):
    """A caller HOME holding the configuration an engine would obey: docker config, a CLI plugin, a
    credential helper setting, podman containers.conf, and a runtime dir."""
    h = tmp_path / "evil-home"
    (h / ".docker" / "cli-plugins").mkdir(parents=True)
    (h / ".docker" / "config.json").write_text('{"currentContext": "evil", "credsStore": "evil"}')
    make_exe(h / ".docker" / "cli-plugins" / "docker-compose", "#!/bin/sh\ntouch plugin-ran\n")
    (h / ".config" / "containers").mkdir(parents=True)
    (h / ".config" / "containers" / "containers.conf").write_text('[engine]\nhelper_binaries_dir=["/tmp/evil"]\n')
    rt = tmp_path / "evil-run"
    rt.mkdir()
    return h, rt


def report(path):
    return dict(ln.split("=", 1) for ln in path.read_text().splitlines() if "=" in ln)


def assert_private_empty(rep, caller_home):
    assert rep["home_empty"] == "yes" and rep["home_mode"] == "700"
    assert rep["docker_config_in_home"] == "yes" and rep["xdg_in_home"] == "yes"
    assert rep["runtime_dir"] == "unset"
    assert rep["home"] != str(caller_home)
    assert not os.path.exists(rep["home"]), "the private home was not removed"


@pytest.fixture
def trusted(tmp_path, monkeypatch):
    good = tmp_path / "good"
    good.mkdir()
    good.chmod(0o755)
    monkeypatch.setattr(ce, "TRUSTED_DIRS", (str(good),))
    monkeypatch.setattr(ce, "TRUSTED_UID", os.geteuid())
    monkeypatch.setattr(ce, "TRUSTED_ROOT", str(tmp_path))
    return good


def hostile_caller(tmp_path, monkeypatch):
    h, rt = plant_home(tmp_path)
    monkeypatch.setenv("HOME", str(h))
    monkeypatch.setenv("XDG_RUNTIME_DIR", str(rt))
    monkeypatch.setenv("XDG_CONFIG_HOME", str(h / ".config"))
    monkeypatch.setenv("DOCKER_CONFIG", str(h / ".docker"))
    return h


def test_engine_run_never_shows_the_engine_the_callers_home(trusted, tmp_path, monkeypatch):
    out = tmp_path / "rep.txt"
    make_exe(trusted / "docker", PLANT % out)
    h = hostile_caller(tmp_path, monkeypatch)
    ce.engine_run(["docker", "compose", "version"], capture_output=True)
    assert_private_empty(report(out), h)
    assert not (tmp_path / "plugin-ran").exists()


def test_each_engine_call_gets_its_own_fresh_home(trusted, tmp_path, monkeypatch):
    out = tmp_path / "rep.txt"
    make_exe(trusted / "docker", PLANT % out)
    hostile_caller(tmp_path, monkeypatch)
    ce.engine_run(["docker", "ps"], capture_output=True)
    ce.engine_run(["docker", "ps"], capture_output=True)
    homes = [ln.split("=", 1)[1] for ln in out.read_text().splitlines() if ln.startswith("home=")]
    assert len(homes) == 2 and homes[0] != homes[1]


def test_the_private_home_is_removed_even_when_the_engine_fails(trusted, tmp_path, monkeypatch):
    out = tmp_path / "rep.txt"
    make_exe(trusted / "docker", (PLANT % out) + "exit 3\n")
    hostile_caller(tmp_path, monkeypatch)
    r = ce.engine_run(["docker", "ps"], capture_output=True)
    assert r.returncode == 3 and not os.path.exists(report(out)["home"])


def test_backup_run_never_shows_the_engine_the_callers_home(trusted, tmp_path, monkeypatch):
    out = tmp_path / "rep.txt"
    make_exe(trusted / "podman", PLANT % out)
    h = hostile_caller(tmp_path, monkeypatch)
    lib._run(["podman", "ps"], "ps")
    assert_private_empty(report(out), h)


def test_gameday_real_runner_never_shows_the_engine_the_callers_home(trusted, tmp_path, monkeypatch):
    out = tmp_path / "rep.txt"
    make_exe(trusted / "docker", PLANT % out)
    monkeypatch.setattr(gd, "TRUSTED_DIRS", (str(trusted),))
    monkeypatch.setattr(gd, "TRUSTED_UID", os.geteuid())
    monkeypatch.setattr(gd, "TRUSTED_ROOT", str(tmp_path))
    h = hostile_caller(tmp_path, monkeypatch)
    gd.real_runner(["docker", "stop", "n8n"])
    assert_private_empty(report(out), h)


@pytest.mark.parametrize("shell", SHELLS)
def test_shell_ce_run_never_shows_the_engine_the_callers_home(shell, tmp_path):
    out = tmp_path / "rep.txt"
    stub = make_exe(tmp_path / "bin" / "docker", PLANT % out)
    h, rt = plant_home(tmp_path)
    env = {"PATH": "/usr/bin:/bin", "HOME": str(h), "XDG_RUNTIME_DIR": str(rt), "DOCKER_CONFIG": str(h / ".docker"),
           "XDG_CONFIG_HOME": str(h / ".config")}
    proc = subprocess.run([shell, "-c", f". '{HELPER}'\nCE_BIN='{stub}'\nce_run compose version"], env=env, text=True,
                          capture_output=True, stdin=subprocess.DEVNULL, timeout=30, cwd=str(tmp_path))
    assert proc.returncode == 0, proc.stderr
    assert_private_empty(report(out), h)


@pytest.mark.parametrize("shell", SHELLS)
def test_shell_ce_run_returns_the_engines_exit_status_and_cleans_up(shell, tmp_path):
    out = tmp_path / "rep.txt"
    stub = make_exe(tmp_path / "bin" / "docker", (PLANT % out) + "exit 5\n")
    proc = subprocess.run([shell, "-c", f". '{HELPER}'\nCE_BIN='{stub}'\nce_run x\necho rc=$?"], env={"PATH": "/usr/bin:/bin"},
                          text=True, capture_output=True, stdin=subprocess.DEVNULL, timeout=30)
    assert "rc=5" in proc.stdout and not os.path.exists(report(out)["home"])


def test_docs_describe_the_private_home_and_do_not_overclaim():  # guard
    doc = " ".join((REPO_ROOT / "docs" / "container-engine.md").read_text().split())
    assert "always talks to its local default endpoint" not in doc
    assert "private empty" in doc and "rootless" in doc.lower()


# ------------------------------------------------------------------ 3. one open descriptor, every script

def swap_stub(stubs, evil, lib_path):
    write_stat_stub(stubs, 0, "755",
                    f'if [ "$last" = /proc/self/fd/9 ] && [ "$fmt" = %u ]; then /bin/mv -f "{evil}" "{lib_path}"; fi')


@pytest.mark.parametrize("name", SOURCING)
def test_the_helper_swapped_after_the_check_is_never_sourced(name, tmp_path):
    stubs = tmp_path / "stubs"
    d = sandbox(tmp_path, name, stubs)
    evil = tmp_path / "evil.sh"
    evil.write_text(EVIL_LIB, encoding="utf-8")
    swap_stub(stubs, evil, d / "lib-container-engine.sh")
    proc = run_script(d / name, tmp_path, env_extra={"PATH": "/usr/bin:/bin"},
                      args=["192.0.2.1"] if name == "deploy-n8n-soar.sh" else [])
    assert not (tmp_path / "marker").exists(), "the swapped helper was sourced"
    assert "CONTAINER_ENGINE must be" in proc.stderr or "usage" in proc.stderr


@pytest.mark.parametrize("name", SOURCING)
def test_a_simulated_root_checks_every_directory_above_the_helper(name, tmp_path):
    stubs = tmp_path / "stubs"
    d = sandbox(tmp_path, name, stubs)
    write_stat_stub(stubs, 0, "755", f'if [ "$fmt" = %u ] && [ "$last" = "{tmp_path}" ]; then echo 1234; exit 0; fi')
    proc = run_script(d / name, tmp_path, env_extra={"PATH": "/usr/bin:/bin"},
                      args=["192.0.2.1"] if name == "deploy-n8n-soar.sh" else [])
    assert proc.returncode != 0 and "or a directory above it" in proc.stderr


@pytest.mark.parametrize("name", SOURCING)
def test_a_simulated_root_with_a_clean_chain_gets_past_the_helper(name, tmp_path):  # control for the refusal above
    stubs = tmp_path / "stubs"
    d = sandbox(tmp_path, name, stubs)
    write_stat_stub(stubs, 0, "755")
    proc = run_script(d / name, tmp_path, env_extra={"PATH": "/usr/bin:/bin"},
                      args=["192.0.2.1"] if name == "deploy-n8n-soar.sh" else [])
    assert "refusing to source" not in proc.stderr and "directory above it" not in proc.stderr
    assert "CONTAINER_ENGINE must be" in proc.stderr or "usage" in proc.stderr


@pytest.mark.parametrize("name", SOURCING)
def test_a_simulated_root_refuses_a_group_writable_helper(name, tmp_path):
    stubs = tmp_path / "stubs"
    d = sandbox(tmp_path, name, stubs)
    write_stat_stub(stubs, 0, "755", 'if [ "$fmt" = %a ] && [ "$last" = /proc/self/fd/9 ]; then echo 664; exit 0; fi')
    proc = run_script(d / name, tmp_path, env_extra={"PATH": "/usr/bin:/bin"},
                      args=["192.0.2.1"] if name == "deploy-n8n-soar.sh" else [])
    assert proc.returncode != 0 and "refusing to source" in proc.stderr


def test_every_script_sources_the_descriptor_with_one_identical_block():  # guard
    blocks = set()
    for name in SOURCING:
        text = (SCRIPTS / name).read_text()
        assert "source /proc/self/fd/9" in text and 'source "$CE_LIB"' not in text, name
        a = text.index("ce_boot_fail() {")
        b = text.index("exec 9<&-\n", a) + len("exec 9<&-\n")
        blocks.add(text[a:b])
    assert len(blocks) == 1, "the helper bootstrap block differs between scripts"


def test_firewall_as_simulated_root_refuses_a_script_file_that_is_not_root_owned(tmp_path):
    stubs = tmp_path / "stubs"
    d = sandbox(tmp_path, "prometheus-otlp-firewall.sh", stubs)
    # the helper and every directory are fine; only the script file itself is someone else's
    write_stat_stub(stubs, 0, "755",
                    f'if [ "$fmt" = %u ] && [ "$last" = "{d}/prometheus-otlp-firewall.sh" ]; then echo 1234; exit 0; fi')
    proc = run_script(d / "prometheus-otlp-firewall.sh", tmp_path, env_extra={"PATH": "/usr/bin:/bin"})
    assert proc.returncode != 0 and "or a directory above it" in proc.stderr and "prometheus-otlp-firewall.sh" in proc.stderr
