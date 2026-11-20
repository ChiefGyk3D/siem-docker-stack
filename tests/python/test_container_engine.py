"""Tests for the CONTAINER_ENGINE setting (issue #130).

One setting (docker or podman, default docker) is read the same way by every helper, and the
binary is found only in fixed root-owned directories, never through the caller's PATH. The shared
Python module is scripts/container_engine.py; shell scripts source scripts/lib-container-engine.sh.
Every test here uses fake stub binaries in a temp directory; no container engine is needed.
"""
import os
import re
import shutil
import subprocess
import sys
import textwrap

import pytest

from conftest import REPO_ROOT, import_module_from_path

SCRIPTS = REPO_ROOT / "scripts"
ce = import_module_from_path("container_engine", SCRIPTS / "container_engine.py")
n8n = import_module_from_path("n8n_address", SCRIPTS / "n8n_address.py")
gd = import_module_from_path("gameday", SCRIPTS / "gameday.py")
lib = import_module_from_path("state_backup_lib", SCRIPTS / "state_backup_lib.py")
setup_router = import_module_from_path("n8n_setup_alert_router", SCRIPTS / "live-deploy" / "n8n-setup-alert-router.py")
HELPER = SCRIPTS / "lib-container-engine.sh"
SHELLS = [s for s in ("sh", "dash", "bash") if shutil.which(s)]

BAD_VALUES = ["Docker", "PODMAN", " docker", "docker ", "podman\n", "sh", "/usr/bin/docker", "/tmp/evil",
              "../docker", "docker;id", "$(id)", "--help", "-x", "dockerd", "nerdctl", "0", "true"]


def make_exe(path, body="#!/bin/sh\necho stub\n", mode=0o755):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.parent.chmod(0o755)  # the umask here may leave group write on
    path.write_text(body, encoding="utf-8")
    path.chmod(mode)
    return path


@pytest.fixture
def trusted(tmp_path, monkeypatch):
    """A fake trusted directory owned by the test user; the module is pointed at it."""
    good = tmp_path / "good"
    good.mkdir()
    good.chmod(0o755)
    monkeypatch.setattr(ce, "TRUSTED_DIRS", (str(good),))
    monkeypatch.setattr(ce, "TRUSTED_UID", os.geteuid())
    monkeypatch.setattr(ce, "TRUSTED_ROOT", str(tmp_path))
    return good


# ---------------------------------------------------------------- the setting

def test_default_is_docker_when_unset_or_empty():
    assert ce.engine_name({}) == "docker"
    assert ce.engine_name({"CONTAINER_ENGINE": ""}) == "docker"


@pytest.mark.parametrize("value", ["docker", "podman"])
def test_the_two_allowed_values_are_accepted(value):
    assert ce.engine_name({"CONTAINER_ENGINE": value}) == value


def test_the_allowed_list_is_exactly_docker_and_podman():  # guard: widening the list fails here
    assert ce.ENGINES == ("docker", "podman")


@pytest.mark.parametrize("value", BAD_VALUES)
def test_anything_else_is_a_clear_error(value):
    with pytest.raises(ce.ContainerEngineError) as exc:
        ce.engine_name({"CONTAINER_ENGINE": value})
    msg = str(exc.value)
    assert "CONTAINER_ENGINE" in msg and "docker" in msg and "podman" in msg


def test_the_error_never_echoes_the_value():  # a value with control characters must not reach a log
    with pytest.raises(ce.ContainerEngineError) as exc:
        ce.engine_name({"CONTAINER_ENGINE": "evil\x1b[31mred"})
    assert "evil" not in str(exc.value) and "\x1b" not in str(exc.value)


def test_engine_name_reads_the_process_environment_by_default(monkeypatch):
    monkeypatch.setenv("CONTAINER_ENGINE", "podman")
    assert ce.engine_name() == "podman"
    monkeypatch.delenv("CONTAINER_ENGINE")
    assert ce.engine_name() == "docker"


# ---------------------------------------------------------------- binary resolution

def test_resolution_uses_the_fixed_dirs_never_path(trusted, tmp_path, monkeypatch):
    make_exe(trusted / "podman")
    evil = tmp_path / "evil"
    make_exe(evil / "podman")
    monkeypatch.setenv("PATH", f"{evil}:/usr/bin")
    assert ce.engine_exe("podman") == str(trusted / "podman")


def test_a_binary_only_on_path_is_not_found(trusted, tmp_path, monkeypatch):
    evil = tmp_path / "evil"
    make_exe(evil / "docker")
    monkeypatch.setenv("PATH", str(evil))
    with pytest.raises(ce.ContainerEngineError, match="no trusted 'docker'"):
        ce.engine_exe("docker")


@pytest.mark.parametrize("mode", [0o775, 0o757])
def test_a_group_or_world_writable_binary_is_refused(trusted, mode):
    make_exe(trusted / "docker", mode=mode)
    with pytest.raises(ce.ContainerEngineError):
        ce.engine_exe("docker")


def test_a_binary_owned_by_someone_else_is_refused(trusted, monkeypatch):
    make_exe(trusted / "docker")
    monkeypatch.setattr(ce, "TRUSTED_UID", os.geteuid() + 1)
    with pytest.raises(ce.ContainerEngineError):
        ce.engine_exe("docker")


def test_engine_exe_only_resolves_the_two_names(trusted):
    make_exe(trusted / "sh")
    with pytest.raises(ce.ContainerEngineError):
        ce.engine_exe("sh")


def test_engine_run_pins_the_executable_and_keeps_argv(trusted):
    make_exe(trusted / "podman")
    seen = {}

    def fake(argv, **kw):
        seen["argv"], seen["kw"] = argv, kw
        return "ok"

    assert ce.engine_run(["podman", "ps"], run=fake, capture_output=True) == "ok"
    assert seen["argv"] == ["podman", "ps"] and seen["kw"]["executable"] == str(trusted / "podman")


def test_engine_run_with_no_trusted_binary_runs_nothing(trusted):
    def fake(argv, **kw):
        raise AssertionError("must not run")
    with pytest.raises(ce.ContainerEngineError):
        ce.engine_run(["docker", "ps"], run=fake)


def test_engine_run_leaves_other_programs_alone():
    seen = {}
    ce.engine_run(["echo", "x"], run=lambda argv, **kw: seen.update(kw=kw))
    assert "executable" not in seen["kw"]


# ---------------------------------------------------------------- n8n_address

def _runtime(seen):
    def run(cmd, **kw):
        seen.append((cmd, kw))
        return subprocess.CompletedProcess(cmd, 0, '{"siem-net": {"IPAddress": "192.0.2.9"}}', "")
    return run


def test_n8n_address_default_still_calls_docker():
    seen = []
    assert n8n.resolve_n8n_base({}, _runtime(seen)) == "http://192.0.2.9:80"
    assert seen[0][0][:2] == ["docker", "inspect"]


def test_n8n_address_uses_podman_when_set():
    seen = []
    assert n8n.resolve_n8n_base({"CONTAINER_ENGINE": "podman"}, _runtime(seen)) == "http://192.0.2.9:80"
    assert seen[0][0][:2] == ["podman", "inspect"]


def test_n8n_address_rejects_a_bad_engine_before_running_anything():
    seen = []
    with pytest.raises(n8n.N8nAddressError, match="CONTAINER_ENGINE"):
        n8n.resolve_n8n_base({"CONTAINER_ENGINE": "sh"}, _runtime(seen))
    assert seen == []


def test_n8n_address_override_wins_even_with_a_bad_engine():
    assert n8n.resolve_n8n_base({"N8N_BASE": "http://192.0.2.1:80", "CONTAINER_ENGINE": "sh"}) == "http://192.0.2.1:80"


def test_n8n_address_real_path_runs_the_trusted_binary_not_path(trusted, tmp_path, monkeypatch):
    make_exe(trusted / "podman", "#!/bin/sh\necho '{\"siem-net\": {\"IPAddress\": \"192.0.2.44\"}}'\n")
    evil = tmp_path / "evil"
    make_exe(evil / "podman", "#!/bin/sh\necho '{\"siem-net\": {\"IPAddress\": \"203.0.113.66\"}}'\n")
    monkeypatch.setenv("PATH", f"{evil}:/usr/bin:/bin")
    monkeypatch.setattr(n8n, "ce", ce)
    assert n8n.resolve_n8n_base({"CONTAINER_ENGINE": "podman"}) == "http://192.0.2.44:80"


def test_n8n_address_real_path_with_no_binary_says_which_engine(trusted):
    with pytest.raises(n8n.N8nAddressError, match="podman command not found"):
        n8n.resolve_n8n_base({"CONTAINER_ENGINE": "podman"})


def test_n8n_address_streamed_over_ssh_with_the_module_still_works(tmp_path):
    """deploy-n8n-soar.sh pipes container_engine.py and n8n_address.py to `python3 -I -` on the host."""
    stream = (SCRIPTS / "container_engine.py").read_text() + "\n" + (SCRIPTS / "n8n_address.py").read_text()
    proc = subprocess.run([sys.executable, "-I", "-"], input=stream, text=True, capture_output=True,
                          env={"PATH": str(tmp_path), "CONTAINER_ENGINE": "sh"})
    assert proc.returncode == 1 and "CONTAINER_ENGINE" in proc.stderr
    assert "Traceback" not in proc.stderr and "NameError" not in proc.stderr


# ---------------------------------------------------------------- gameday

def test_gameday_default_engine_is_docker():
    assert gd.load_config({})["docker"] == "docker"


def test_gameday_reads_container_engine():
    assert gd.load_config({"CONTAINER_ENGINE": "podman"})["docker"] == "podman"


def test_gameday_own_setting_still_wins_over_container_engine():
    assert gd.load_config({"CONTAINER_ENGINE": "podman", "GAMEDAY_DOCKER": "docker"})["docker"] == "docker"


def test_gameday_rejects_a_bad_container_engine():
    with pytest.raises(gd.GamedayError, match="CONTAINER_ENGINE"):
        gd.load_config({"CONTAINER_ENGINE": "sh"})


def test_gameday_has_no_resolver_of_its_own():  # guard: one resolver, shared
    src = (SCRIPTS / "gameday.py").read_text()
    assert "import container_engine" in src
    assert "os.path.realpath(os.path.join(d, name))" not in src


def test_gameday_resolver_is_the_shared_one(trusted):
    make_exe(trusted / "docker")
    assert gd.resolve_cli("docker", (str(trusted),), os.geteuid(), str(trusted.parent)) == ce.resolve_cli(
        "docker", (str(trusted),), os.geteuid(), str(trusted.parent))


# ---------------------------------------------------------------- state backup

def _toml(tmp_path, extra=""):
    p = tmp_path / "b.toml"
    p.write_text('destination_dir = "%s"\nage_recipients = ["age1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq"]\n%s'
                 % (tmp_path, extra), encoding="utf-8")
    return str(p)


@pytest.fixture
def real_age_recipient(monkeypatch):
    monkeypatch.setattr(lib, "_is_public_recipient", lambda r: True)


def test_backup_default_runtime_is_docker(tmp_path, monkeypatch, real_age_recipient):
    monkeypatch.delenv("CONTAINER_ENGINE", raising=False)
    assert lib.load_config(_toml(tmp_path)).container_runtime == "docker"


def test_backup_takes_the_runtime_from_container_engine(tmp_path, monkeypatch, real_age_recipient):
    monkeypatch.setenv("CONTAINER_ENGINE", "podman")
    assert lib.load_config(_toml(tmp_path)).container_runtime == "podman"


def test_backup_config_file_value_wins(tmp_path, monkeypatch, real_age_recipient):
    monkeypatch.setenv("CONTAINER_ENGINE", "podman")
    assert lib.load_config(_toml(tmp_path, 'container_runtime = "docker"\n')).container_runtime == "docker"


def test_backup_rejects_a_bad_container_engine(tmp_path, monkeypatch, real_age_recipient):
    monkeypatch.setenv("CONTAINER_ENGINE", "sh")
    with pytest.raises(lib.BackupError, match="CONTAINER_ENGINE"):
        lib.load_config(_toml(tmp_path))


def test_backup_run_pins_the_trusted_engine_binary(trusted, tmp_path, monkeypatch):
    out = tmp_path / "ran"
    make_exe(trusted / "podman", f"#!/bin/sh\necho trusted > '{out}'\n")
    evil = tmp_path / "evil"
    make_exe(evil / "podman", f"#!/bin/sh\necho evil > '{out}'\n")
    monkeypatch.setenv("PATH", f"{evil}:/usr/bin:/bin")
    lib._run(["podman", "ps"], "ps")
    assert out.read_text().strip() == "trusted"


def test_backup_run_with_no_trusted_engine_is_a_backup_error(trusted):
    with pytest.raises(lib.BackupError, match="podman"):
        lib._run(["podman", "ps"], "ps")


def test_backup_run_leaves_age_and_rclone_on_the_normal_path(trusted):
    assert lib._run(["echo", "hi"], "echo").stdout.strip() == b"hi"


# ---------------------------------------------------------------- live-deploy script

def test_setup_router_uses_the_selected_engine(trusted, tmp_path, monkeypatch):
    make_exe(trusted / "podman", "#!/bin/sh\necho \"podman:$*\"\n")
    monkeypatch.setenv("CONTAINER_ENGINE", "podman")
    rc, out = setup_router.docker_out("ps", "-a")
    assert rc == 0 and out == "podman:ps -a"
    rc, lines = setup_router.docker_in("true", "payload")
    assert rc == 0 and lines == ["podman:exec -i %s sh -c true" % setup_router.CONTAINER]


def test_setup_router_default_is_docker(trusted, monkeypatch):
    make_exe(trusted / "docker", "#!/bin/sh\necho \"docker:$*\"\n")
    monkeypatch.delenv("CONTAINER_ENGINE", raising=False)
    assert setup_router.docker_out("ps") == (0, "docker:ps")


def test_setup_router_bad_engine_exits_without_running(trusted, monkeypatch):
    monkeypatch.setenv("CONTAINER_ENGINE", "sh")
    with pytest.raises(SystemExit) as exc:
        setup_router.docker_out("ps")
    assert "CONTAINER_ENGINE" in str(exc.value)


# ---------------------------------------------------------------- shell helper

def sh_run(shell, snippet, env=None, tmp_path=None):
    full_env = {"PATH": "/usr/bin:/bin"}
    full_env.update(env or {})
    return subprocess.run([shell, "-c", f". '{HELPER}'\n{snippet}"], env=full_env, text=True,
                          capture_output=True, stdin=subprocess.DEVNULL, timeout=30)


@pytest.mark.parametrize("shell", SHELLS)
def test_shell_default_and_allowed_values(shell):
    assert sh_run(shell, "ce_name").stdout == "docker"
    assert sh_run(shell, "ce_name", {"CONTAINER_ENGINE": ""}).stdout == "docker"
    assert sh_run(shell, "ce_name", {"CONTAINER_ENGINE": "podman"}).stdout == "podman"
    assert sh_run(shell, "ce_name", {"CONTAINER_ENGINE": "docker"}).stdout == "docker"


@pytest.mark.parametrize("shell", SHELLS)
@pytest.mark.parametrize("value", BAD_VALUES)
def test_shell_rejects_what_python_rejects(shell, value):
    proc = sh_run(shell, "ce_name", {"CONTAINER_ENGINE": value})
    assert proc.returncode != 0 and proc.stdout == ""
    assert "CONTAINER_ENGINE" in proc.stderr and "docker" in proc.stderr and "podman" in proc.stderr
    assert "evil" not in proc.stderr


@pytest.mark.parametrize("shell", SHELLS)
def test_shell_resolver_uses_fixed_dirs_not_path(shell, tmp_path):
    good = tmp_path / "good"
    make_exe(good / "podman")
    evil = tmp_path / "evil"
    make_exe(evil / "podman")
    uid = os.geteuid()
    proc = sh_run(shell, f"ce_resolve podman '{good}' {uid} '{tmp_path}'", {"PATH": f"{evil}:/usr/bin:/bin"})
    assert proc.returncode == 0 and proc.stdout == str(good / "podman")
    only_evil = sh_run(shell, f"ce_resolve podman '{tmp_path}/nodir' {uid} '{tmp_path}'", {"PATH": f"{evil}:/usr/bin"})
    assert only_evil.returncode != 0 and only_evil.stdout == ""


@pytest.mark.parametrize("shell", SHELLS)
@pytest.mark.parametrize("mode", [0o775, 0o757])
def test_shell_resolver_refuses_a_writable_binary(shell, tmp_path, mode):
    good = tmp_path / "good"
    make_exe(good / "docker", mode=mode)
    proc = sh_run(shell, f"ce_resolve docker '{good}' {os.geteuid()} '{tmp_path}'")
    assert proc.returncode != 0 and proc.stdout == ""


@pytest.mark.parametrize("shell", SHELLS)
def test_shell_resolver_refuses_a_writable_parent_directory(shell, tmp_path):
    good = tmp_path / "good"
    make_exe(good / "docker")
    good.chmod(0o775)
    proc = sh_run(shell, f"ce_resolve docker '{good}' {os.geteuid()} '{tmp_path}'")
    assert proc.returncode != 0


@pytest.mark.parametrize("shell", SHELLS)
def test_shell_resolver_refuses_the_wrong_owner(shell, tmp_path):
    good = tmp_path / "good"
    make_exe(good / "docker")
    proc = sh_run(shell, f"ce_resolve docker '{good}' {os.geteuid() + 1} '{tmp_path}'")
    assert proc.returncode != 0


@pytest.mark.parametrize("shell", SHELLS)
def test_shell_resolver_returns_the_canonical_path_of_a_link(shell, tmp_path):
    real = tmp_path / "tools" / "realdocker"
    make_exe(real)
    good = tmp_path / "good"
    good.mkdir()
    good.chmod(0o755)
    (good / "docker").symlink_to(real)
    proc = sh_run(shell, f"ce_resolve docker '{good}' {os.geteuid()} '{tmp_path}'")
    assert proc.returncode == 0 and proc.stdout == str(real)


@pytest.mark.parametrize("shell", SHELLS)
def test_shell_resolver_only_resolves_the_two_names(shell, tmp_path):
    good = tmp_path / "good"
    make_exe(good / "sh")
    proc = sh_run(shell, f"ce_resolve sh '{good}' {os.geteuid()} '{tmp_path}'")
    assert proc.returncode != 0


@pytest.mark.parametrize("shell", SHELLS)
def test_shell_init_sets_name_and_reports_a_missing_binary(shell):
    # No trusted binary needed to prove the failure path: a bad value fails first.
    proc = sh_run(shell, 'ce_init || echo "failed"; echo "[$CE_NAME]"', {"CONTAINER_ENGINE": "sh"})
    assert "failed" in proc.stdout and "[]" in proc.stdout and "CONTAINER_ENGINE" in proc.stderr


@pytest.mark.parametrize("shell", SHELLS)
def test_shell_helper_never_evals_or_builds_commands(shell):
    text = HELPER.read_text()
    code = "\n".join(ln for ln in text.splitlines()
                     if not ln.lstrip().startswith("#") and ln.strip() != 'eval "$_ce_saved"')
    # the one allowed eval replays the caller's own `trap -p` listing (checked in test_container_engine_round6)
    assert not re.search(r"\beval\b|\bsh -c\b|\bbash -c\b|`", code)
    assert text.count('eval "$_ce_saved"') == 1


# ---------------------------------------------------------------- shell scripts use the helper

ENGINE_SCRIPTS = ["03-deploy.sh", "05-verify.sh", "06-generate-wazuh-certs.sh", "08b-init-opensearch-security.sh",
                  "11-wazuh-grafana-readonly.sh", "prometheus-otlp-firewall.sh"]
# an invocation, not a mention: docker as a command word followed by a subcommand
BARE_DOCKER = re.compile(r'(^|[\s;&|(`$"\'])docker\s+(exec|ps|port|run|info|inspect|compose|cp|logs|network|stop|start)\b')


def _code_lines(path):
    for n, ln in enumerate(path.read_text().splitlines(), 1):
        s = ln.strip()
        if s.startswith("#") or re.match(r"(echo|printf|die)\b", s):
            continue
        yield n, ln


@pytest.mark.parametrize("name", ENGINE_SCRIPTS)
def test_scripts_source_the_helper_and_name_no_bare_docker(name):
    path = SCRIPTS / name
    assert "lib-container-engine.sh" in path.read_text(), f"{name} does not source the helper"
    bare = [(n, ln.strip()) for n, ln in _code_lines(path) if BARE_DOCKER.search(ln)]
    assert bare == [], f"{name} still hard-codes docker: {bare}"


def test_the_bare_docker_pattern_bites():  # guard on the guard
    assert BARE_DOCKER.search('    docker exec opensearch-hot curl')
    assert BARE_DOCKER.search('x=$(docker ps --format y)')
    assert BARE_DOCKER.search('run_on_server "docker compose pull"')
    assert not BARE_DOCKER.search('"$CE_BIN" exec opensearch-hot')


PYTHON_HELPERS = ["n8n_address.py", "live-deploy/n8n-setup-alert-router.py"]


@pytest.mark.parametrize("name", PYTHON_HELPERS)
def test_python_helpers_do_not_hard_code_the_binary(name):
    text = (SCRIPTS / name).read_text()
    assert not re.search(r'\[\s*"(docker|podman)"\s*,', text), f"{name} hard-codes an engine in argv"


def test_grafana_deploy_is_untouched_and_starts_no_process():
    text = (SCRIPTS / "live-deploy" / "grafana-deploy.py").read_text()
    assert "container_engine" not in text and "subprocess" not in text


def _run_script(name, env, tmp_path):
    full = {"PATH": "/usr/bin:/bin", "HOME": str(tmp_path)}
    full.update(env)
    return subprocess.run(["bash", str(SCRIPTS / name)], env=full, text=True, capture_output=True,
                          stdin=subprocess.DEVNULL, timeout=30, cwd=str(tmp_path))


@pytest.mark.parametrize("name", [n for n in ENGINE_SCRIPTS if n != "prometheus-otlp-firewall.sh"])
def test_scripts_refuse_a_bad_engine_before_doing_anything(name, tmp_path):
    proc = _run_script(name, {"CONTAINER_ENGINE": "sh", "SIEM_HOST": "localhost"}, tmp_path)
    assert proc.returncode != 0 and "CONTAINER_ENGINE" in proc.stderr


def test_firewall_refuses_a_bad_engine_before_touching_iptables(tmp_path):
    proc = _run_script("prometheus-otlp-firewall.sh",
                       {"CONTAINER_ENGINE": "sh", "PROM_FW_NO_SUDO": "1", "IPTABLES": "/bin/false"}, tmp_path)
    assert proc.returncode != 0 and "CONTAINER_ENGINE" in proc.stderr


def test_soar_deploy_streams_the_module_with_the_lookup_and_sends_only_the_validated_name():
    text = (SCRIPTS / "deploy-n8n-soar.sh").read_text()
    assert "lib-container-engine.sh" in text and "ce_init_name" in text
    assert "container_engine.py" in text and "n8n_address.py" in text
    assert 'CONTAINER_ENGINE=$(printf \'%q\' "$CE_NAME")' in text  # the validated name, never the raw value


def test_env_example_names_the_setting_commented_out():
    lines = (REPO_ROOT / ".env.example").read_text().splitlines()
    assert "# CONTAINER_ENGINE=docker" in lines
    assert not any(ln.startswith("CONTAINER_ENGINE=") for ln in lines)


def test_docs_name_the_setting():
    doc = (REPO_ROOT / "docs" / "container-engine.md").read_text()
    assert "CONTAINER_ENGINE" in doc and "docker" in doc and "podman" in doc
    assert chr(0x2014) not in doc


@pytest.mark.parametrize("mode", [0o775, 0o757])
def test_a_writable_trusted_directory_is_refused(trusted, mode):
    make_exe(trusted / "docker")
    trusted.chmod(mode)  # the binary itself is fine; its directory is not
    with pytest.raises(ce.ContainerEngineError):
        ce.engine_exe("docker")


def test_a_writable_directory_above_the_binary_is_refused(trusted, tmp_path):
    make_exe(trusted / "docker")
    tmp_path.chmod(0o777)  # the ownership walk starts at the root, here tmp_path
    try:
        with pytest.raises(ce.ContainerEngineError):
            ce.engine_exe("docker")
    finally:
        tmp_path.chmod(0o700)
