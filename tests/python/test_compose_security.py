"""Guards for the threat-model High findings (issue #32): fail closed on
secrets, loopback-by-default published ports, opt-in Portainer, and
least-privilege accounts for Grafana and the UniFi poller."""
import json
import re

import yaml

from conftest import REPO_ROOT

COMPOSE = REPO_ROOT / "docker" / "docker-compose.yml"
CI_ENV = REPO_ROOT / "tests" / "compose.ci.env"
README = REPO_ROOT / "README.md"
PIPELINES = sorted((REPO_ROOT / "docker" / "logstash" / "pipeline").glob("*.conf"))
DATASOURCES = REPO_ROOT / "docker" / "grafana" / "provisioning" / "datasources" / "datasources.yml"
DASHBOARDS_YML = REPO_ROOT / "docker" / "wazuh" / "opensearch_dashboards.yml"

SECRET_NAME = re.compile(r"(PASSWORD|PASS|SECRET|TOKEN)(_|$)")
REF = re.compile(r"\$\{([A-Z0-9_]+)(:?[-?])?([^}]*)\}")
SAFE_BIND = re.compile(r"^(127\.0\.0\.1|\$\{(BIND_ADDR|INGEST_BIND_ADDR|PORTAINER_BIND_ADDR):-127\.0\.0\.1\}):")


def secret_fallbacks(text):
    """Variables whose name looks like a secret but carry a `:-` default."""
    return [m.group(1) for m in REF.finditer(text)
            if SECRET_NAME.search(m.group(1)) and m.group(2) in (":-", "-")]


def unsafe_ports(services):
    bad = []
    for name, svc in services.items():
        for port in svc.get("ports", []):
            if not SAFE_BIND.match(str(port)):
                bad.append((name, port))
    return bad


def _compose():
    return yaml.safe_load(COMPOSE.read_text(encoding="utf-8"))["services"]


def test_guard_bites_on_fallback_secret():
    assert secret_fallbacks("X=${GRAFANA_ADMIN_PASS:-changeme}") == ["GRAFANA_ADMIN_PASS"]
    assert secret_fallbacks("X=${GRAFANA_ADMIN_PASS:?set it}") == []
    assert secret_fallbacks("X=${GRAFANA_ADMIN_USER:-admin}") == []


def test_guard_bites_on_open_port():
    assert unsafe_ports({"s": {"ports": ["9443:9443"]}}) == [("s", "9443:9443")]
    assert unsafe_ports({"s": {"ports": ["0.0.0.0:9443:9443"]}}) != []
    assert unsafe_ports({"s": {"ports": ["${BIND_ADDR:-127.0.0.1}:1:1"]}}) == []


def test_compose_has_no_secret_fallbacks():
    assert COMPOSE.read_text(encoding="utf-8").count("services:") == 1
    assert secret_fallbacks(COMPOSE.read_text(encoding="utf-8")) == []


def test_every_published_port_defaults_to_loopback():
    services = _compose()
    assert sum(len(s.get("ports", [])) for s in services.values()) > 10
    assert unsafe_ports(services) == []


def test_portainer_is_opt_in():
    svc = _compose()["portainer"]
    assert svc.get("profiles") == ["portainer"]
    assert all(str(p).startswith("${PORTAINER_BIND_ADDR:-127.0.0.1}:") for p in svc["ports"])


def test_required_variables_are_in_ci_env_and_readme():
    text = COMPOSE.read_text(encoding="utf-8")
    required = sorted({m.group(1) for m in REF.finditer(text) if m.group(2) == ":?"})
    assert "WAZUH_DASHBOARD_PASSWORD" in required and "GRAFANA_INFLUX_PASSWORD" in required
    ci_env = CI_ENV.read_text(encoding="utf-8")
    readme = README.read_text(encoding="utf-8")
    for var in required:
        assert re.search(rf"^{var}=\S+", ci_env, re.M), f"{var} missing from tests/compose.ci.env"
        assert var in readme, f"{var} not documented in README upgrade notes"


def test_logstash_pipelines_read_password_without_default():
    assert PIPELINES
    for path in PIPELINES:
        for line in path.read_text(encoding="utf-8").splitlines():
            if re.match(r"\s*password\s*=>", line):
                assert re.search(r'"\$\{OPENSEARCH_LOGSTASH_PASSWORD\}"', line), f"{path.name}: {line}"


def test_wazuh_dashboard_password_comes_from_environment():
    cfg = yaml.safe_load(DASHBOARDS_YML.read_text(encoding="utf-8"))
    assert cfg["opensearch.password"] == "${DASHBOARD_PASSWORD}"
    env = _compose()["wazuh-dashboard"]["environment"]
    assert any(e.startswith("DASHBOARD_PASSWORD=${WAZUH_DASHBOARD_PASSWORD:?") for e in env)


def test_grafana_and_poller_do_not_hold_influx_admin():
    services = _compose()
    for name in ("grafana", "unifi-poller"):
        env = "\n".join(services[name]["environment"])
        assert "INFLUXDB_ADMIN" not in env, name
    ds = DATASOURCES.read_text(encoding="utf-8")
    assert "INFLUXDB_ADMIN" not in re.sub(r"(?m)^#.*$", "", ds)
    assert "GRAFANA_INFLUX_PASSWORD" in ds


def _run_check_env(tmp_path, body):
    import subprocess
    env = tmp_path / ".env"
    env.write_text(body, encoding="utf-8")
    return subprocess.run(["bash", str(REPO_ROOT / "scripts" / "check-env.sh"), str(env)],
                          capture_output=True, text=True, check=False)


def test_check_env_rejects_missing_and_known_defaults(tmp_path):
    names = [ln.split("=")[0] for ln in CI_ENV.read_text(encoding="utf-8").splitlines()
             if "=" in ln and not ln.startswith("#")]
    names.append("OPENSEARCH_ADMIN_PASSWORD")
    good = "".join(f"{n}=Zx9-unique-{i}\n" for i, n in enumerate(names))
    assert _run_check_env(tmp_path, good).returncode == 0
    bad = _run_check_env(tmp_path, good.replace("Zx9-unique-0", "changeme"))
    assert bad.returncode == 1 and "changeme" not in bad.stderr
    assert _run_check_env(tmp_path, good.replace("Zx9-unique-3", "")).returncode == 1
    assert _run_check_env(tmp_path, "").returncode == 1


def test_check_env_warns_loudly_when_ingest_stays_on_loopback(tmp_path):
    """Loopback ingest is the safe default, but an upgraded stack stops hearing
    from firewalls and agents without any error, so say so (non-fatal)."""
    names = [ln.split("=")[0] for ln in CI_ENV.read_text(encoding="utf-8").splitlines()
             if "=" in ln and not ln.startswith("#")]
    names.append("OPENSEARCH_ADMIN_PASSWORD")
    good = "".join(f"{n}=Zx9-unique-{i}\n" for i, n in enumerate(dict.fromkeys(names)))
    for body in (good, good + "INGEST_BIND_ADDR=127.0.0.1\n"):
        res = _run_check_env(tmp_path, body)
        assert res.returncode == 0
        assert "INGEST_BIND_ADDR" in res.stderr and "other hosts" in res.stderr
    res = _run_check_env(tmp_path, good + "INGEST_BIND_ADDR=192.0.2.10\n")
    assert res.returncode == 0 and "INGEST_BIND_ADDR" not in res.stderr


# --- Wazuh half of threat 17: Grafana gets a read-only Wazuh indexer account ---

WAZUH_SECURITY = REPO_ROOT / "docker" / "wazuh" / "security"
PROVISION = REPO_ROOT / "scripts" / "11-wazuh-grafana-readonly.sh"
WAZUH_SEC_CFG = "/usr/share/wazuh-indexer/config/opensearch-security"
READ_ONLY_ACTIONS = {"read", "indices:admin/mappings/get", "indices:admin/get", "indices:monitor/*"}
FAKE_DOCKER = r'''#!/usr/bin/env python3
import hashlib, json, os, shutil, sys
fs, log = os.environ["FAKE_FS"], os.environ["FAKE_LOG"]
argv = sys.argv[1:]
stdin = "" if sys.stdin.isatty() else sys.stdin.read()
with open(log, "a") as f:
    f.write(json.dumps({"argv": argv}) + "\n")
args = [a for a in argv if a != "-i"]
if args[:2] != ["exec", "wazuh-indexer"]:
    sys.exit(0)
rest = args[2:]
name = lambda p: os.path.join(fs, os.path.basename(p))
if rest[0] == "cat":
    sys.stdout.write(open(name(rest[1])).read())
elif rest[0] == "cp":
    shutil.copy(name(rest[1]), name(rest[2]))
elif rest[0] == "curl":
    method = rest[rest.index("-X") + 1] if "-X" in rest else "GET"
    with open(log, "a") as f:
        f.write(json.dumps({"curl_stdin": stdin, "method": method}) + "\n")
    print("200" if method == "GET" else os.environ.get("FAKE_WRITE_CODE", "403"))
elif rest[0] == "bash" and "hash.sh" in rest[2]:
    print("noise line")
    print("$2y$12$FAKE" + hashlib.sha256(stdin.strip().encode()).hexdigest()[:40])
elif rest[0] == "bash" and rest[2].startswith("cat >"):
    with open(name(rest[3]), "w") as f:
        f.write(stdin)
    with open(log, "a") as f:
        f.write(json.dumps({"wrote": os.path.basename(rest[3])}) + "\n")
elif rest[0] == "bash" and "securityadmin.sh" in rest[2]:
    print("Done with success")
'''

SEED = {
    "internal_users.yml": '_meta:\n  type: "internalusers"\n  config_version: 2\n\n'
                          'admin:\n  hash: "$2y$12$ADMINHASH"\n  reserved: true\n\n'
                          'kibanaserver:\n  hash: "$2y$12$KIBHASH"\n  reserved: true\n',
    "roles.yml": '_meta:\n  type: "roles"\n  config_version: 2\n\n'
                 'own_index:\n  reserved: true\n  index_permissions:\n    - index_patterns:\n        - "${user_name}"\n',
    "roles_mapping.yml": '_meta:\n  type: "rolesmapping"\n  config_version: 2\n\n'
                         'all_access:\n  reserved: false\n  users:\n    - "admin"\n',
}


def _run_provision(tmp_path, password="Zx9-grafana-ro-pw", extra_env=None, seed=True):
    import os
    import subprocess
    bindir, fs = tmp_path / "bin", tmp_path / "fs"
    bindir.mkdir(exist_ok=True)
    fs.mkdir(exist_ok=True)
    (bindir / "docker").write_text(FAKE_DOCKER, encoding="utf-8")
    (bindir / "docker").chmod(0o755)
    if seed:
        for fname, body in SEED.items():
            (fs / fname).write_text(body, encoding="utf-8")
    env = {"PATH": f"{bindir}:{os.environ['PATH']}", "HOME": str(tmp_path),
           "FAKE_FS": str(fs), "FAKE_LOG": str(tmp_path / "log.jsonl"),
           "SIEM_DEPLOY_DIR": str(REPO_ROOT / "docker")}
    if password is not None:
        env["WAZUH_GRAFANA_RO_PASSWORD"] = password
    env.update(extra_env or {})
    res = subprocess.run(["bash", str(PROVISION)], capture_output=True, text=True, env=env,
                         check=False, timeout=60)
    log = [json.loads(ln) for ln in (tmp_path / "log.jsonl").read_text().splitlines()] \
        if (tmp_path / "log.jsonl").exists() else []
    return res, fs, log


def test_wazuh_datasource_uses_readonly_account_not_admin():
    ds = yaml.safe_load(DATASOURCES.read_text(encoding="utf-8"))["datasources"]
    assert len(ds) >= 7
    wazuh = [d for d in ds if "wazuh-indexer" in d["url"]]
    assert len(wazuh) == 1
    assert wazuh[0]["basicAuthUser"] == "$WAZUH_GRAFANA_RO_USER"
    assert wazuh[0]["secureJsonData"]["basicAuthPassword"] == "$WAZUH_GRAFANA_RO_PASSWORD"
    for d in ds:  # no datasource of any type may authenticate as an admin account
        assert d.get("basicAuthUser", "").lower() not in ("admin", "kibanaserver"), d["name"]
        assert d.get("user", "").lower() not in ("admin", "root"), d["name"]
    code = re.sub(r"(?m)^\s*#.*$", "", DATASOURCES.read_text(encoding="utf-8"))
    assert "WAZUH_INDEXER_PASSWORD" not in code and "INFLUXDB_ADMIN" not in code


def test_grafana_container_has_no_wazuh_indexer_admin_password():
    env = _compose()["grafana"]["environment"]
    assert not any("WAZUH_INDEXER_PASSWORD" in e for e in env)
    assert any(e.startswith("WAZUH_GRAFANA_RO_PASSWORD=${WAZUH_GRAFANA_RO_PASSWORD:?") for e in env)
    assert any(e.startswith("WAZUH_GRAFANA_RO_USER=${WAZUH_GRAFANA_RO_USER:-grafana_ro}") for e in env)


def test_new_secret_is_checked_and_documented():
    assert "WAZUH_GRAFANA_RO_PASSWORD" in (REPO_ROOT / "scripts" / "check-env.sh").read_text(encoding="utf-8")
    assert re.search(r"^WAZUH_GRAFANA_RO_PASSWORD=\S+", CI_ENV.read_text(encoding="utf-8"), re.M)


def test_read_only_allowlist_rejects_write_actions():
    for action in ("write", "crud", "indices:data/write/*", "indices_all", "manage", "*", "delete"):
        assert action not in READ_ONLY_ACTIONS


def test_wazuh_readonly_role_is_read_only_and_scoped():
    role = yaml.safe_load((WAZUH_SECURITY / "roles.fragment.yml").read_text(encoding="utf-8"))
    assert list(role) == ["wazuh_grafana_readonly"]
    perms = role["wazuh_grafana_readonly"]
    assert set(perms["cluster_permissions"]) <= {"cluster_monitor", "cluster_composite_ops_ro"}
    patterns = set()
    for block in perms["index_permissions"]:
        patterns.update(block["index_patterns"])
        assert set(block["allowed_actions"]) <= READ_ONLY_ACTIONS, block["allowed_actions"]
    assert patterns == {"wazuh-alerts-*", "wazuh-archives-*", "wazuh-monitoring-*", "wazuh-statistics-*"}
    mapping = yaml.safe_load((WAZUH_SECURITY / "roles_mapping.fragment.yml").read_text(encoding="utf-8"))
    assert mapping["wazuh_grafana_readonly"]["users"] == ["__GRAFANA_RO_USER__"]
    users = yaml.safe_load((WAZUH_SECURITY / "internal_users.fragment.yml").read_text(encoding="utf-8"))
    assert users["__GRAFANA_RO_USER__"]["hash"] == "__GRAFANA_RO_HASH__"  # token, never a real hash
    assert not re.search(r"\$2[aby]\$", (WAZUH_SECURITY / "internal_users.fragment.yml").read_text(encoding="utf-8"))


def test_provision_creates_user_role_and_mapping_without_plaintext(tmp_path):
    res, fs, log = _run_provision(tmp_path)
    assert res.returncode == 0, res.stdout + res.stderr
    users = yaml.safe_load((fs / "internal_users.yml").read_text())
    assert users["grafana_ro"]["hash"].startswith("$2y$12$FAKE")
    assert users["admin"]["hash"] == "$2y$12$ADMINHASH" and "kibanaserver" in users
    roles = yaml.safe_load((fs / "roles.yml").read_text())
    assert "wazuh_grafana_readonly" in roles and "own_index" in roles
    mapping = yaml.safe_load((fs / "roles_mapping.yml").read_text())
    assert mapping["wazuh_grafana_readonly"]["users"] == ["grafana_ro"]
    assert mapping["all_access"]["users"] == ["admin"]
    applied = [a["argv"][-1] for a in log if "argv" in a and "securityadmin.sh" in a["argv"][-1]]
    assert {t for t in ("roles", "rolesmapping", "internalusers") if any(f"-t {t} " in c for c in applied)} \
        == {"roles", "rolesmapping", "internalusers"}
    # the plaintext password never appears in a command line or a written file
    assert "Zx9-grafana-ro-pw" not in json.dumps([a for a in log if "argv" in a])
    assert all("Zx9-grafana-ro-pw" not in p.read_text() for p in fs.iterdir())
    # verification used the new account (credential on stdin) and probed a write
    probes = [a for a in log if "method" in a]
    assert {p["method"] for p in probes} >= {"GET", "DELETE"}
    assert all("grafana_ro" in p["curl_stdin"] for p in probes)


def test_provision_is_idempotent_and_honors_custom_user(tmp_path):
    res, fs, _ = _run_provision(tmp_path, extra_env={"WAZUH_GRAFANA_RO_USER": "gf_wazuh_ro"})
    assert res.returncode == 0, res.stdout + res.stderr
    res2, fs, _ = _run_provision(tmp_path, extra_env={"WAZUH_GRAFANA_RO_USER": "gf_wazuh_ro"}, seed=False)
    assert res2.returncode == 0, res2.stdout + res2.stderr
    users = yaml.safe_load((fs / "internal_users.yml").read_text())
    assert "gf_wazuh_ro" in users and "grafana_ro" not in users
    assert (fs / "roles.yml").read_text().count("wazuh_grafana_readonly:") == 1
    assert (fs / "roles_mapping.yml").read_text().count("wazuh_grafana_readonly:") == 1
    assert yaml.safe_load((fs / "roles_mapping.yml").read_text())["wazuh_grafana_readonly"]["users"] == ["gf_wazuh_ro"]


def test_provision_refuses_without_password_and_touches_nothing(tmp_path):
    res, fs, log = _run_provision(tmp_path, password=None, extra_env={"HOME": str(tmp_path)})
    assert res.returncode != 0 and "WAZUH_GRAFANA_RO_PASSWORD" in res.stdout + res.stderr
    assert not any("wrote" in a for a in log)


def test_provision_fails_when_the_account_can_write(tmp_path):
    """Negative case: if the indexer lets the new account write, say so and fail."""
    res, _, _ = _run_provision(tmp_path, extra_env={"FAKE_WRITE_CODE": "200"})
    assert res.returncode != 0
    assert "can write" in (res.stdout + res.stderr)
