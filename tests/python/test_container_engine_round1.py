"""Round 1 review fixes for the CONTAINER_ENGINE setting (issue #130).

1. The engine child gets an explicit minimal environment (no DOCKER_HOST, config, loader variables).
2. Scripts source the helper next to the REAL script, never one beside a symlink, and refuse a link or
   a writable helper.
3. The root firewall script checks every ancestor and sources the verified open descriptor.
4. A game-day run uses one engine everywhere.
5. The docs say what is true.
"""
import os
import re
import shutil
import subprocess
import sys

import pytest

from conftest import REPO_ROOT, import_module_from_path

SCRIPTS = REPO_ROOT / "scripts"
ce = import_module_from_path("container_engine", SCRIPTS / "container_engine.py")
gd = import_module_from_path("gameday", SCRIPTS / "gameday.py")
lib = import_module_from_path("state_backup_lib", SCRIPTS / "state_backup_lib.py")
n8n = import_module_from_path("n8n_address", SCRIPTS / "n8n_address.py")
HELPER = SCRIPTS / "lib-container-engine.sh"
FIREWALL = SCRIPTS / "prometheus-otlp-firewall.sh"
SHELLS = [s for s in ("sh", "dash", "bash") if shutil.which(s)]

POISON = {
    "DOCKER_HOST": "tcp://192.0.2.99:2375", "DOCKER_CONTEXT": "evil", "DOCKER_CONFIG": "/tmp/evilcfg",
    "CONTAINER_HOST": "ssh://evil@192.0.2.99", "CONTAINER_CONNECTION": "evil", "XDG_CONFIG_HOME": "/tmp/evilxdg",
    "LD_PRELOAD": "/tmp/evil.so", "LD_LIBRARY_PATH": "/tmp/evil", "BASH_ENV": "/tmp/evil.sh", "ENV": "/tmp/evil.sh",
    "HTTPS_PROXY": "http://192.0.2.99:3128", "XDG_RUNTIME_DIR": "/run/user/evil", "DOCKER_CERT_PATH": "/tmp/evil", "PYTHONPATH": "/tmp/evil",
}
ALLOWED = set(ce.ENV_KEEP) | {"PATH", "HOME", "DOCKER_CONFIG", "XDG_CONFIG_HOME", "XDG_DATA_HOME", "XDG_CACHE_HOME",
                               "XDG_STATE_HOME"}


def make_exe(path, body, mode=0o755):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.parent.chmod(0o755)
    path.write_text(body, encoding="utf-8")
    path.chmod(mode)
    return path


ENV_DUMP = "#!/bin/sh\n/usr/bin/env > '%s'\necho '{\"siem-net\": {\"IPAddress\": \"192.0.2.44\"}}'\n"


@pytest.fixture
def trusted(tmp_path, monkeypatch):
    good = tmp_path / "good"
    good.mkdir()
    good.chmod(0o755)
    monkeypatch.setattr(ce, "TRUSTED_DIRS", (str(good),))
    monkeypatch.setattr(ce, "TRUSTED_UID", os.geteuid())
    monkeypatch.setattr(ce, "TRUSTED_ROOT", str(tmp_path))
    return good


@pytest.fixture
def poisoned(monkeypatch):
    for k, v in POISON.items():
        monkeypatch.setenv(k, v)
    monkeypatch.setenv("HOME", "/home/someone")
    monkeypatch.setenv("PATH", "/evil:/usr/bin")


def child_env(path):
    return dict(ln.split("=", 1) for ln in path.read_text().splitlines() if "=" in ln)


def assert_clean(got, good):
    got = {k: v for k, v in got.items() if k not in ("_", "PWD", "SHLVL", "OLDPWD")}  # added by the stub shell
    assert set(got) <= ALLOWED, sorted(set(got) - ALLOWED)
    assert not any(got.get(k) == v for k, v in POISON.items()), "a caller value reached the engine"
    assert not (set(got) & set(POISON) - ALLOWED)
    assert got["PATH"] == str(good)
    # a private empty home, not the caller's, with every config location inside it, removed afterwards
    home = got["HOME"]
    assert home != "/home/someone" and "XDG_RUNTIME_DIR" not in got
    assert got["DOCKER_CONFIG"].startswith(home + "/")
    assert all(got[k].startswith(home + "/") for k in got if k.startswith("XDG_"))
    assert not os.path.exists(home), "the private home was not removed"


# ------------------------------------------------------------------ 1. environment

def test_engine_run_gives_the_child_only_a_minimal_environment(trusted, tmp_path, poisoned):
    out = tmp_path / "env.txt"
    make_exe(trusted / "podman", ENV_DUMP % out)
    ce.engine_run(["podman", "ps"], capture_output=True)
    assert_clean(child_env(out), trusted)


def test_engine_run_replaces_an_env_the_caller_passes(trusted, tmp_path, poisoned):
    out = tmp_path / "env.txt"
    make_exe(trusted / "podman", ENV_DUMP % out)
    ce.engine_run(["podman", "ps"], capture_output=True, env={"DOCKER_HOST": "tcp://192.0.2.99:1", "PATH": "/evil"})
    assert "DOCKER_HOST" not in child_env(out) and child_env(out)["PATH"] == str(trusted)


def test_backup_run_gives_the_engine_a_minimal_environment(trusted, tmp_path, poisoned):
    out = tmp_path / "env.txt"
    make_exe(trusted / "docker", ENV_DUMP % out)
    lib._run(["docker", "ps"], "ps")
    assert_clean(child_env(out), trusted)


def test_n8n_address_real_path_gives_the_engine_a_minimal_environment(trusted, tmp_path, poisoned, monkeypatch):
    out = tmp_path / "env.txt"
    make_exe(trusted / "docker", ENV_DUMP % out)
    monkeypatch.setattr(n8n, "ce", ce)
    assert n8n.resolve_n8n_base({}) == "http://192.0.2.44:80"
    assert_clean(child_env(out), trusted)


def test_gameday_real_runner_gives_the_engine_a_minimal_environment(trusted, tmp_path, poisoned, monkeypatch):
    out = tmp_path / "env.txt"
    make_exe(trusted / "docker", ENV_DUMP % out)
    monkeypatch.setattr(gd, "TRUSTED_DIRS", (str(trusted),))
    monkeypatch.setattr(gd, "TRUSTED_UID", os.geteuid())
    monkeypatch.setattr(gd, "TRUSTED_ROOT", str(tmp_path))
    gd.real_runner(["docker", "stop", "n8n"])
    assert_clean(child_env(out), trusted)


@pytest.mark.parametrize("shell", SHELLS)
def test_shell_ce_run_gives_the_engine_a_minimal_environment(shell, tmp_path):
    out = tmp_path / "env.txt"
    stub = make_exe(tmp_path / "bin" / "docker", ENV_DUMP % out)
    env = {**POISON, "PATH": "/evil:/usr/bin:/bin", "HOME": "/home/someone"}
    proc = subprocess.run([shell, "-c", f". '{HELPER}'\nCE_BIN='{stub}'\nce_run info"], env=env, text=True,
                          capture_output=True, stdin=subprocess.DEVNULL, timeout=30)
    assert proc.returncode == 0, proc.stderr
    got = child_env(out)
    assert not any(got.get(k) == v for k, v in POISON.items()) and got["PATH"] == "/usr/bin:/usr/local/bin:/bin:/snap/bin"
    assert set(got) - {"_", "PWD", "SHLVL", "OLDPWD"} <= ALLOWED
    assert got["HOME"] != "/home/someone" and got["DOCKER_CONFIG"].startswith(got["HOME"] + "/")
    assert not os.path.exists(got["HOME"]), "the private home was not removed"


@pytest.mark.parametrize("shell", SHELLS)
def test_shell_ce_run_passes_arguments_and_stdin_untouched(shell, tmp_path):
    stub = make_exe(tmp_path / "bin" / "docker", '#!/bin/sh\nfor a in "$@"; do printf "[%s]" "$a"; done; cat\n')
    proc = subprocess.run([shell, "-c", f". '{HELPER}'\nCE_BIN='{stub}'\nce_run exec 'a b' '$(id)'"],
                          env={"PATH": "/usr/bin:/bin"}, input="in\n", text=True, capture_output=True, timeout=30)
    assert proc.stdout == "[exec][a b][$(id)]in\n"


@pytest.mark.parametrize("shell", SHELLS)
def test_shell_ce_run_refuses_to_run_without_a_resolved_engine(shell):
    proc = subprocess.run([shell, "-c", f". '{HELPER}'\nCE_BIN=\nce_run info"], env={"PATH": "/usr/bin:/bin"},
                          text=True, capture_output=True, timeout=30)
    assert proc.returncode != 0 and "ce_init" in proc.stderr


ENGINE_SH = ["06-generate-wazuh-certs.sh", "08b-init-opensearch-security.sh", "11-wazuh-grafana-readonly.sh",
             "05-verify.sh", "prometheus-otlp-firewall.sh"]


@pytest.mark.parametrize("name", ENGINE_SH)
def test_scripts_run_the_engine_only_through_ce_run(name):  # guard: a direct "$CE_BIN" call skips the scrub
    code = [ln for ln in (SCRIPTS / name).read_text().splitlines()
            if not ln.lstrip().startswith("#") and not re.match(r"\s*(echo|printf)\b", ln)]
    direct = [ln for ln in code if re.search(r'(^\s*|[;&|(]\s*|\$\(\s*)"\$(CE_BIN|CE_LOCAL|DOCKER_BIN)"\s', ln)]
    assert direct == [], direct


# ------------------------------------------------------------------ 2. canonical script directory

LAUNCH = ["06-generate-wazuh-certs.sh", "08b-init-opensearch-security.sh", "11-wazuh-grafana-readonly.sh",
          "03-deploy.sh", "05-verify.sh", "deploy-n8n-soar.sh"]
EVIL_LIB = '''touch "$EVIL_MARKER"
ce_name() { printf docker; }
ce_init() { CE_NAME=docker; CE_BIN=/bin/true; }
ce_init_name() { CE_NAME=docker; }
ce_resolve() { printf /bin/true; }
ce_run() { :; }
exit 7
'''


@pytest.mark.parametrize("name", LAUNCH)
def test_a_symlinked_launch_never_sources_a_helper_beside_the_link(name, tmp_path):
    launch = tmp_path / "launch"
    launch.mkdir()
    (launch / name).symlink_to(SCRIPTS / name)
    (launch / "lib-container-engine.sh").write_text(EVIL_LIB, encoding="utf-8")
    (launch / "lib-secrets.sh").write_text("require_secret() { :; }\nsecret_is_placeholder() { return 1; }\n", encoding="utf-8")
    marker = tmp_path / "marker"
    env = {"PATH": "/usr/bin:/bin", "HOME": str(tmp_path), "EVIL_MARKER": str(marker), "CONTAINER_ENGINE": "sh",
           "SIEM_HOST": "localhost", "N8N_API_KEY": "Zx9-api-key-test-value", "GRAFANA_PASS": "Zx9-graf-pass-test-value"}
    args = ["192.0.2.1"] if name == "deploy-n8n-soar.sh" else []
    proc = subprocess.run(["bash", str(launch / name), *args], env=env, text=True, capture_output=True,
                          stdin=subprocess.DEVNULL, timeout=30, cwd=str(tmp_path))
    assert not marker.exists(), "the helper beside the symlink was sourced"
    assert proc.returncode != 0 and "CONTAINER_ENGINE must be" in proc.stderr  # the REAL helper rejected "sh"


SANDBOXED = ["06-generate-wazuh-certs.sh", "08b-init-opensearch-security.sh", "11-wazuh-grafana-readonly.sh",
             "03-deploy.sh", "05-verify.sh"]


def sandbox(tmp_path, name):
    d = tmp_path / "sb" / "scripts"
    d.mkdir(parents=True)
    d.chmod(0o755)
    shutil.copy(SCRIPTS / name, d / name)
    shutil.copy(HELPER, d / "lib-container-engine.sh")
    (d / "lib-container-engine.sh").chmod(0o644)
    return d


def run_sandboxed(d, name, tmp_path):
    env = {"PATH": "/usr/bin:/bin", "HOME": str(tmp_path), "CONTAINER_ENGINE": "sh", "SIEM_HOST": "localhost"}
    return subprocess.run(["bash", str(d / name)], env=env, text=True, capture_output=True,
                          stdin=subprocess.DEVNULL, timeout=30, cwd=str(tmp_path))


@pytest.mark.parametrize("name", SANDBOXED)
def test_a_trusted_helper_is_accepted(name, tmp_path):  # control: the refusals below are not just "always fails"
    proc = run_sandboxed(sandbox(tmp_path, name), name, tmp_path)
    assert "refusing to source" not in proc.stderr and "CONTAINER_ENGINE must be" in proc.stderr


@pytest.mark.parametrize("name", SANDBOXED)
@pytest.mark.parametrize("mode", [0o666, 0o646, 0o606 | 0o002])
def test_a_world_writable_helper_is_refused(name, mode, tmp_path):
    d = sandbox(tmp_path, name)
    (d / "lib-container-engine.sh").chmod(mode)
    proc = run_sandboxed(d, name, tmp_path)
    assert proc.returncode != 0 and "refusing to source" in proc.stderr


@pytest.mark.parametrize("name", SANDBOXED)
def test_a_helper_that_is_a_symlink_is_refused(name, tmp_path):
    d = sandbox(tmp_path, name)
    real = tmp_path / "elsewhere.sh"
    shutil.copy(HELPER, real)
    (d / "lib-container-engine.sh").unlink()
    (d / "lib-container-engine.sh").symlink_to(real)
    proc = run_sandboxed(d, name, tmp_path)
    assert proc.returncode != 0 and "refusing to source" in proc.stderr


def test_scripts_derive_their_directory_from_the_real_path():  # guard
    for name in LAUNCH:
        text = (SCRIPTS / name).read_text()
        assert "readlink -f" in text, name
        assert 'dirname "$0"' not in text and 'dirname "${BASH_SOURCE[0]}"' not in text, name


# ------------------------------------------------------------------ 3. firewall as root

def _fw_root_sandbox(tmp_path):
    """The firewall plus its helper in a temp dir that believes it is root (see conftest.root_copy)."""
    from conftest import root_copy
    stubs = tmp_path / "stubs"
    d = root_copy(tmp_path / "rootcopy", ["prometheus-otlp-firewall.sh", "lib-container-engine.sh"], SCRIPTS)
    return d, stubs


def _stat_stub(stubs, body_extra=""):
    from conftest import write_stat_stub
    write_stat_stub(stubs, 0, "755", body_extra)


def _retarget(d, stubs):
    """Point the sandbox copy at the stubs (done after the stubs exist)."""
    for f in (x for x in d.iterdir() if not x.is_symlink()):  # never write through a link into the repo
        f.write_text(f.read_text().replace("/usr/bin/stat", str(stubs / "stat")).replace("/usr/bin/id", str(stubs / "id")))


def _run_fw(d, stubs, tmp_path, *args):
    _retarget(d, stubs)
    env = {"PATH": "/usr/bin:/bin", "EVIL_MARKER": str(tmp_path / "marker"), "HOME": str(tmp_path)}
    return subprocess.run(["bash", "-p", str(d / "prometheus-otlp-firewall.sh"), *args], env=env, text=True,
                          capture_output=True, stdin=subprocess.DEVNULL, timeout=30, cwd=str(tmp_path))


def test_firewall_root_via_a_symlink_never_sources_a_helper_beside_the_link(tmp_path):
    d, stubs = _fw_root_sandbox(tmp_path)
    _stat_stub(stubs)
    _retarget(d, stubs)
    launch = tmp_path / "launch"
    launch.mkdir()
    (launch / "prometheus-otlp-firewall.sh").symlink_to(d / "prometheus-otlp-firewall.sh")
    (launch / "lib-container-engine.sh").write_text(EVIL_LIB, encoding="utf-8")
    env = {"PATH": "/usr/bin:/bin", "EVIL_MARKER": str(tmp_path / "marker"), "HOME": str(tmp_path)}
    proc = subprocess.run(["bash", "-p", str(launch / "prometheus-otlp-firewall.sh")], env=env, text=True,
                          capture_output=True, stdin=subprocess.DEVNULL, timeout=30, cwd=str(tmp_path))
    assert not (tmp_path / "marker").exists()
    assert "usage" in proc.stderr  # the real helper was used and the script went on to its own checks


def test_firewall_root_refuses_a_helper_that_is_a_link(tmp_path):
    d, stubs = _fw_root_sandbox(tmp_path)
    _stat_stub(stubs)
    (d / "lib-container-engine.sh").unlink()
    (d / "lib-container-engine.sh").symlink_to(HELPER)
    proc = _run_fw(d, stubs, tmp_path)
    assert proc.returncode != 0 and "missing or is a link" in proc.stderr


def test_firewall_root_checks_every_ancestor_directory(tmp_path):
    d, stubs = _fw_root_sandbox(tmp_path)
    # everything is root-owned except one directory ABOVE the script directory
    _stat_stub(stubs, f'if [ "$fmt" = %u ] && [ "$last" = "{tmp_path}" ]; then echo 1234; exit 0; fi')
    proc = _run_fw(d, stubs, tmp_path)
    assert proc.returncode != 0 and "or a directory above it" in proc.stderr


def test_firewall_root_accepts_a_fully_root_owned_chain(tmp_path):  # control for the two refusals above
    d, stubs = _fw_root_sandbox(tmp_path)
    _stat_stub(stubs)
    proc = _run_fw(d, stubs, tmp_path)
    assert "not root-owned" not in proc.stderr and "directory above it" not in proc.stderr and "usage" in proc.stderr


def test_firewall_root_sources_the_verified_descriptor_not_the_path(tmp_path):
    d, stubs = _fw_root_sandbox(tmp_path)
    evil = tmp_path / "evil.sh"
    evil.write_text(EVIL_LIB, encoding="utf-8")
    # the moment the script checks the OPEN file, swap the path for the attacker's file
    _stat_stub(stubs, f'if [ "$last" = /proc/self/fd/9 ] && [ "$fmt" = %u ]; then /bin/mv -f "{evil}" "{d}/lib-container-engine.sh"; fi')
    proc = _run_fw(d, stubs, tmp_path)
    assert not (tmp_path / "marker").exists(), "the swapped file was sourced"
    assert "usage" in proc.stderr


def test_firewall_root_block_sources_from_the_descriptor():  # guard
    text = FIREWALL.read_text()
    assert "source /proc/self/fd/9" in text and 'source "$LIB"' not in text and 'source "$SELF_DIR' not in text


# ------------------------------------------------------------------ 4. one engine per game-day run

def test_gameday_n8n_lookup_uses_the_engine_the_run_chose(monkeypatch):
    seen = {}

    class Fake:
        @staticmethod
        def resolve_n8n_base(env):
            seen.update(env)
            return "http://192.0.2.9:80"

    monkeypatch.setitem(sys.modules, "n8n_address", Fake)
    monkeypatch.setenv("CONTAINER_ENGINE", "docker")
    cfg = gd.load_config({"CONTAINER_ENGINE": "docker", "GAMEDAY_DOCKER": "podman"})
    assert cfg["docker"] == "podman"
    gd.real_resolver(cfg)
    assert seen["CONTAINER_ENGINE"] == "podman"


# ------------------------------------------------------------------ 5. docs

def test_docs_do_not_claim_more_than_the_code_does():  # guard
    doc = " ".join((REPO_ROOT / "docs" / "container-engine.md").read_text().split())
    assert "never placed in a shell command string" not in doc
    assert "validated token" in doc and "fixed token" in doc
    assert "takes precedence" in doc  # the per-script precedence table
    assert "minimal" in doc and "DOCKER_HOST" in doc
    text = HELPER.read_text()
    assert "The raw value of" in text and "validated fixed token" in text
