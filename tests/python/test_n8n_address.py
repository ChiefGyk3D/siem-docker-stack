"""Tests for scripts/n8n_address.py: resolve the n8n address at run time (issue #90).

The container runtime is faked; no docker is needed.
"""
import json
import re
import subprocess
import sys

import pytest
import yaml

from conftest import REPO_ROOT, import_module_from_path

SCRIPT = REPO_ROOT / "scripts" / "n8n_address.py"
mod = import_module_from_path("n8n_address", SCRIPT)


def fake_runtime(networks, returncode=0, stderr="", missing=False, seen=None):
    def run(cmd, **kwargs):
        if seen is not None:
            seen.append(cmd)
        if missing:
            raise FileNotFoundError("docker")
        return subprocess.CompletedProcess(cmd, returncode, json.dumps(networks), stderr)
    return run


def test_env_override_wins_and_runtime_is_not_called():
    seen = []
    base = mod.resolve_n8n_base({"N8N_BASE": "http://192.0.2.7:80/"}, fake_runtime({}, seen=seen))
    assert base == "http://192.0.2.7:80"
    assert seen == []


def test_resolves_address_on_siem_network():
    seen = []
    nets = {"siem-net": {"IPAddress": "192.0.2.9"}, "macvlan": {"IPAddress": "198.51.100.4"}}
    base = mod.resolve_n8n_base({}, fake_runtime(nets, seen=seen))
    assert base == "http://192.0.2.9:80"
    assert seen[0][:2] == ["docker", "inspect"] and "n8n" in seen[0]


def test_container_network_and_port_are_configurable():
    env = {"N8N_CONTAINER": "n8n2", "SIEM_NETWORK": "docker_siem-net", "N8N_PORT": "5678"}
    seen = []
    nets = {"docker_siem-net": {"IPAddress": "192.0.2.12"}}
    assert mod.resolve_n8n_base(env, fake_runtime(nets, seen=seen)) == "http://192.0.2.12:5678"
    assert "n8n2" in seen[0]


def test_not_on_siem_network_message_names_the_fix():
    nets = {"macvlan": {"IPAddress": "198.51.100.4"}}
    with pytest.raises(mod.N8nAddressError) as exc:
        mod.resolve_n8n_base({}, fake_runtime(nets))
    msg = str(exc.value)
    assert "not attached to a siem network" in msg
    assert "macvlan" in msg  # lists what it is attached to
    assert "docker network connect <network-name> n8n" in msg
    assert "SIEM_NETWORK" in msg and "N8N_BASE" in msg


def test_compose_prefixed_network_resolves_without_siem_network_set():
    nets = {"automation-vlan25": {"IPAddress": "198.51.100.4"}, "siem_siem-net": {"IPAddress": "192.0.2.9"}}
    assert mod.resolve_n8n_base({}, fake_runtime(nets)) == "http://192.0.2.9:80"


def test_two_matching_networks_fail_and_list_candidates():
    nets = {"siem-net": {"IPAddress": "192.0.2.9"}, "other_siem-net": {"IPAddress": "192.0.2.20"}}
    with pytest.raises(mod.N8nAddressError) as exc:
        mod.resolve_n8n_base({}, fake_runtime(nets))
    msg = str(exc.value)
    assert "siem-net" in msg and "other_siem-net" in msg and "SIEM_NETWORK" in msg


def test_suffix_must_be_whole_name_part():
    nets = {"mysiem-net": {"IPAddress": "192.0.2.9"}}
    with pytest.raises(mod.N8nAddressError):
        mod.resolve_n8n_base({}, fake_runtime(nets))


def test_explicit_siem_network_is_an_exact_match():
    nets = {"siem_siem-net": {"IPAddress": "192.0.2.9"}}
    with pytest.raises(mod.N8nAddressError) as exc:
        mod.resolve_n8n_base({"SIEM_NETWORK": "siem-net"}, fake_runtime(nets))
    assert "siem_siem-net" in str(exc.value) and "siem-net" in str(exc.value)
    ok = mod.resolve_n8n_base({"SIEM_NETWORK": "siem_siem-net"}, fake_runtime(nets))
    assert ok == "http://192.0.2.9:80"


def test_empty_address_is_an_error():
    with pytest.raises(mod.N8nAddressError, match="no address"):
        mod.resolve_n8n_base({}, fake_runtime({"siem-net": {"IPAddress": ""}}))


def test_inspect_failure_message():
    with pytest.raises(mod.N8nAddressError) as exc:
        mod.resolve_n8n_base({}, fake_runtime({}, returncode=1, stderr="No such object: n8n"))
    assert "could not inspect container 'n8n'" in str(exc.value)
    assert "N8N_BASE" in str(exc.value)


def test_docker_missing_message():
    with pytest.raises(mod.N8nAddressError, match="docker command not found"):
        mod.resolve_n8n_base({}, fake_runtime({}, missing=True))


def test_bad_json_is_an_error():
    def run(cmd, **kwargs):
        return subprocess.CompletedProcess(cmd, 0, "not json", "")
    with pytest.raises(mod.N8nAddressError, match="unexpected output"):
        mod.resolve_n8n_base({}, run)


def test_cli_prints_base_from_override_and_fails_cleanly(tmp_path):
    # PATH points at an empty directory, so a docker call cannot succeed.
    ok = subprocess.run([sys.executable, "-I", str(SCRIPT)],
                        env={"PATH": str(tmp_path), "N8N_BASE": "http://192.0.2.7:80"},
                        capture_output=True, text=True)
    assert ok.returncode == 0 and ok.stdout.strip() == "http://192.0.2.7:80"
    bad = subprocess.run([sys.executable, "-I", str(SCRIPT)], env={"PATH": str(tmp_path)},
                         capture_output=True, text=True)
    assert bad.returncode != 0 and "N8N_BASE" in bad.stderr and bad.stdout == ""


# --- guards: nothing names a fixed n8n address; the reference compose keeps both networks ---

FIXED_N8N_ADDRESS = re.compile(r"(?i)n8n[^\n]{0,80}\b172\.20\.0\.\d+|\b172\.20\.0\.\d+[^\n]{0,80}n8n")


def _scanned_files():
    files = [p for p in (REPO_ROOT / "scripts").rglob("*") if p.is_file() and "__pycache__" not in p.parts]
    files += list((REPO_ROOT / "docs").rglob("*.md"))
    files += list((REPO_ROOT / "docs").rglob("*.yml"))
    return files


def test_guard_pattern_bites():
    assert FIXED_N8N_ADDRESS.search("N8N_BASE=http://172.20.0.16:80")
    assert FIXED_N8N_ADDRESS.search('N8N_IP="172.20.0.16"  # N8N on siem-net')
    assert not FIXED_N8N_ADDRESS.search("N8N_BASE=http://192.0.2.10:80")


def test_no_fixed_n8n_bridge_address_in_scripts_or_docs():
    files = _scanned_files()
    assert len(files) > 20  # something was collected
    hits = []
    for path in files:
        try:
            text = path.read_text(encoding="utf-8")
        except UnicodeDecodeError:
            continue
        for number, line in enumerate(text.splitlines(), 1):
            if FIXED_N8N_ADDRESS.search(line):
                hits.append(f"{path.relative_to(REPO_ROOT)}:{number}")
    assert hits == []


def test_reference_compose_attaches_n8n_to_both_networks():
    doc = yaml.safe_load((REPO_ROOT / "docs" / "examples" / "n8n-compose.example.yml").read_text(encoding="utf-8"))
    assert set(doc["services"]["n8n"]["networks"]) == {"siem-net", "n8n-macvlan"}
    assert doc["networks"]["siem-net"]["external"] is True
    assert doc["networks"]["siem-net"]["name"]
    assert doc["networks"]["n8n-macvlan"]["driver"] == "macvlan"
