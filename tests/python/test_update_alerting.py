"""Guards for update alerting (issue #53): the n8n router's Pushover nodes,
the Grafana alert provisioning files, and the pfSense update metric script."""
import json
import re
import shutil
import subprocess

import pytest
import yaml

from conftest import REPO_ROOT

ROUTER = REPO_ROOT / "n8n" / "grafana-alert-router.json"
ALERTING = REPO_ROOT / "docker" / "grafana" / "provisioning" / "alerting"
RULE_FILES = sorted(ALERTING.glob("*rules*.yml"))
SCRIPT = REPO_ROOT / "scripts" / "pfsense-update-metric.sh"
ENV_EXAMPLE = REPO_ROOT / ".env.example"
DOC = REPO_ROOT / "docs" / "update-alerting.md"
POLICY = ALERTING / "update-notification-policy.yml.example"

PUSHOVER_VARS = ["PUSHOVER_ENABLED", "PUSHOVER_APP_TOKEN", "PUSHOVER_USER_KEY",
                 "PUSHOVER_RETRY", "PUSHOVER_EXPIRE"]
DISCORD_FIRING = "Discord — Firing"
DISCORD_RESOLVED = "Discord — Resolved"


def _workflow():
    return json.loads(ROUTER.read_text(encoding="utf-8"))


def _nodes():
    return {n["name"]: n for n in _workflow()["nodes"]}


def _send_node():
    sends = [n for n in _workflow()["nodes"] if "messages.json" in json.dumps(n["parameters"])]
    assert len(sends) == 1, "expected exactly one Pushover send node"
    return sends[0]


# --- n8n router ------------------------------------------------------------

def test_router_discord_nodes_still_present_and_connected():
    nodes = _nodes()
    for name in (DISCORD_FIRING, DISCORD_RESOLVED):
        assert nodes[name]["type"] == "n8n-nodes-base.discord"
    outs = _workflow()["connections"]["Alert Status"]["main"]
    assert any(c["node"] == DISCORD_FIRING for c in outs[0])
    assert any(c["node"] == DISCORD_RESOLVED for c in outs[1])


def test_router_has_pushover_http_node_gated_by_env():
    nodes = _nodes()
    send = _send_node()
    assert send["type"] == "n8n-nodes-base.httpRequest"
    body = json.dumps(send["parameters"])
    for var in PUSHOVER_VARS[1:]:
        assert f"$env.{var}" in body, var
    assert "300" in body and "10800" in body, "retry/expire defaults missing"
    gate = [n for n in nodes.values() if n["type"] == "n8n-nodes-base.if"
            and "$env.PUSHOVER_ENABLED" in json.dumps(n["parameters"])]
    assert len(gate) == 1
    assert all(n["type"].startswith("n8n-nodes-base.") for n in nodes.values()), \
        "community package node added"


def test_router_http_nodes_only_reachable_through_gate():
    wf = _workflow()
    gate = next(n["name"] for n in wf["nodes"] if "$env.PUSHOVER_ENABLED" in json.dumps(n["parameters"]))
    outs = wf["connections"]["Alert Status"]["main"]
    assert any(c["node"] == gate for c in outs[0])
    assert any(c["node"] == gate for c in outs[1])
    assert wf["connections"][gate]["main"][0], "gate true branch not wired"
    direct = {c["node"] for o in outs for c in o}
    http = {n["name"] for n in wf["nodes"] if n["type"] == "n8n-nodes-base.httpRequest"}
    assert http and not (direct & http)


def test_pushover_mapping_logic_matches_spec():
    node = shutil.which("node")
    if not node:
        pytest.skip("node not installed")
    expr = _send_node()["parameters"]["jsonBody"]
    assert expr.startswith("={{") and expr.rstrip().endswith("}}")
    js = expr[3:].rstrip()[:-2]
    harness = (
        "const run=(body,env)=>{const $json={body};const $env=env;return JSON.parse(" + js + ");};\n"
        "const mk=(status,labels)=>({status,alerts:[{labels:Object.assign({alertname:'A'},labels),"
        "annotations:{summary:'s'},fingerprint:'fp1'}]});\n"
        "const e={PUSHOVER_APP_TOKEN:'t',PUSHOVER_USER_KEY:'u'};\n"
        "const out={crit:run(mk('firing',{severity:'critical'}),e),"
        "sec:run(mk('firing',{severity:'warning',update_security:'true'}),e),"
        "warn:run(mk('firing',{severity:'warning'}),e),"
        "res:run(mk('resolved',{severity:'critical'}),e),"
        "clamp:run(mk('firing',{severity:'critical'}),"
        "Object.assign({PUSHOVER_EXPIRE:'99999',PUSHOVER_RETRY:'5'},e))};\n"
        "console.log(JSON.stringify(out));"
    )
    r = subprocess.run([node, "-e", harness], capture_output=True, text=True, timeout=30)
    assert r.returncode == 0, r.stderr
    out = json.loads(r.stdout)
    assert out["crit"]["priority"] == 2 and out["crit"]["retry"] == 300
    assert out["crit"]["expire"] == 10800
    assert out["sec"]["priority"] == 2
    assert out["warn"]["priority"] == 1
    assert "retry" not in out["warn"] and "expire" not in out["warn"]
    assert out["res"]["priority"] == 0 and "retry" not in out["res"]
    assert out["clamp"]["expire"] == 10800 and out["clamp"]["retry"] == 30
    assert len(out["crit"]["title"]) <= 250 and len(out["crit"]["message"]) <= 1024


def test_env_example_documents_pushover_names_without_secret_values():
    text = ENV_EXAMPLE.read_text(encoding="utf-8")
    for var in PUSHOVER_VARS:
        assert re.search(rf"^# {var}=", text, re.M), f"{var} missing"
    for var in ("PUSHOVER_APP_TOKEN", "PUSHOVER_USER_KEY"):
        assert re.search(rf"^# {var}=\s*$", text, re.M), f"{var} must have no value"


# --- Grafana provisioning --------------------------------------------------

def _rules():
    assert RULE_FILES, "no alert rule provisioning files"
    out = []
    for path in RULE_FILES:
        data = yaml.safe_load(path.read_text(encoding="utf-8"))
        assert data["apiVersion"] == 1
        for group in data["groups"]:
            for rule in group["rules"]:
                out.append((path.name, group, rule))
    return out


def test_rule_schema():
    rules = _rules()
    assert len(rules) >= 5
    uids = [r["uid"] for _, _, r in rules]
    assert len(uids) == len(set(uids))
    for fname, _group, rule in rules:
        assert rule["uid"] and rule["title"], fname
        refs = {d["refId"] for d in rule["data"]}
        assert rule["condition"] in refs, rule["title"]
        assert rule["noDataState"] == "OK", rule["title"]
        assert rule["labels"]["severity"] in {"warning", "critical"}, rule["title"]
        assert rule["labels"]["update_alert"] == "true", rule["title"]
        assert rule["for"], rule["title"]


def test_unifi_rules_escalate_24h_then_7d():
    by = {r["uid"]: r for _, _, r in _rules()}
    warn, crit = by["update-unifi-pending-24h"], by["update-unifi-pending-7d"]
    assert warn["for"] == "24h" and warn["labels"]["severity"] == "warning"
    assert crit["for"] == "168h" and crit["labels"]["severity"] == "critical"
    assert not warn.get("isPaused") and not crit.get("isPaused")
    assert "upgradable" in json.dumps(warn["data"])
    assert any(d["datasourceUid"] == "influxdb-unifi" for d in warn["data"])


def test_pfsense_rules_ship_paused_and_use_metric():
    pf = [r for _, _, r in _rules() if r["uid"].startswith("update-pfsense")]
    assert len(pf) >= 3
    for r in pf:
        assert r["isPaused"] is True, r["uid"]
        assert "pfsense_update_pending" in json.dumps(r["data"])
    assert any(r["labels"].get("update_security") == "true"
               and r["labels"]["severity"] == "critical" for r in pf)
    text = "\n".join(p.read_text(encoding="utf-8") for p in RULE_FILES)
    assert "Telegraf" in text, "comment explaining when pfSense rules are enabled"


def test_rules_have_no_manual_dismiss_logic():
    text = "\n".join(p.read_text(encoding="utf-8") for p in RULE_FILES).lower()
    for word in ("silence", "dismiss", "acknowledge"):
        assert word not in text, word


def test_notification_policy_repeats():
    data = yaml.safe_load(POLICY.read_text(encoding="utf-8"))
    root = data["policies"][0]
    routes = root["routes"][0]["routes"]
    rep = {next(m for m in r["object_matchers"] if m[0] == "severity")[2]: r["repeat_interval"]
           for r in routes}
    assert rep == {"warning": "4h", "critical": "1h"}


def test_contact_point_is_webhook_to_router():
    data = yaml.safe_load((ALERTING / "contact-points.yml").read_text(encoding="utf-8"))
    cp = data["contactPoints"][0]["receivers"][0]
    assert cp["type"] == "webhook"
    assert cp["settings"]["url"].endswith("/webhook/grafana-alerts")


# --- pfSense metric script -------------------------------------------------

def _fake_bin(tmp_path, upgrade_out, pkg_out, upgrade_rc=0):
    d = tmp_path / "bin"
    d.mkdir()
    (d / "pfSense-upgrade").write_text(
        f"#!/bin/sh\ncat <<'EOT'\n{upgrade_out}\nEOT\nexit {upgrade_rc}\n", encoding="utf-8")
    (d / "pkg-static").write_text(
        f"#!/bin/sh\ncat <<'EOT'\n{pkg_out}\nEOT\n", encoding="utf-8")
    for f in d.iterdir():
        f.chmod(0o755)
    return d


def _run(tmp_path, upgrade_out, pkg_out, **kw):
    d = _fake_bin(tmp_path, upgrade_out, pkg_out, **kw)
    env = {"PATH": f"{d}:/usr/bin:/bin"}
    return subprocess.run(["/bin/sh", str(SCRIPT)], capture_output=True, text=True,
                          env=env, timeout=30, check=False)


def _metrics(out):
    res = {}
    for line in out.strip().splitlines():
        m = re.match(r"pfsense_update_pending,kind=(\w+),security=(\w+) value=(\d)i$", line)
        assert m, line
        res[(m.group(1), m.group(2))] = int(m.group(3))
    return res


def test_script_syntax_and_shellcheck():
    assert subprocess.run(["sh", "-n", str(SCRIPT)], timeout=30).returncode == 0
    sc = shutil.which("shellcheck")
    if sc:
        assert subprocess.run([sc, "-s", "sh", str(SCRIPT)], timeout=60).returncode == 0


def test_script_is_read_only():
    text = SCRIPT.read_text(encoding="utf-8")
    code = "\n".join(ln for ln in text.splitlines() if not ln.lstrip().startswith("#"))
    for bad in ("pkg-static upgrade", "pkg-static install", "pfSense-upgrade -y",
                "pfSense-upgrade -d", "curl", "wget", "rm ", "reboot"):
        assert bad not in code, bad
    assert text.startswith("#!/bin/sh")


def test_up_to_date(tmp_path):
    r = _run(tmp_path, "Your system is up to date", "")
    assert r.returncode == 0
    m = _metrics(r.stdout)
    assert len(m) == 6 and sum(m.values()) == 0


def test_core_update_pending(tmp_path):
    r = _run(tmp_path, "Version 99.9 is available\n", "pfSense-99.9\n")
    m = _metrics(r.stdout)
    assert m[("core", "false")] == 1 and m[("core", "true")] == 0
    assert m[("kernel", "false")] == 0 and m[("package", "false")] == 0


def test_kernel_and_package_pending(tmp_path):
    r = _run(tmp_path, "Your system is up to date",
             "pfSense-kernel-pfSense-99.9\npfSense-pkg-Telegraf-1.2\n")
    m = _metrics(r.stdout)
    assert m[("kernel", "false")] == 1 and m[("package", "false")] == 1
    assert m[("core", "false")] == 0


def test_security_flag(tmp_path):
    r = _run(tmp_path, "Version 99.9 is available (security update)\n", "pfSense-99.9\n")
    m = _metrics(r.stdout)
    assert m[("core", "true")] == 1 and m[("core", "false")] == 0


def test_check_failure_emits_nothing_and_exits_zero(tmp_path):
    r = _run(tmp_path, "unable to reach update server", "", upgrade_rc=1)
    assert r.returncode == 0
    assert r.stdout.strip() == ""


def test_missing_tools_exit_zero_no_output(tmp_path):
    (tmp_path / "empty").mkdir()
    r = subprocess.run(["/bin/sh", str(SCRIPT)], capture_output=True, text=True, timeout=30,
                       env={"PATH": str(tmp_path / "empty")}, check=False)
    assert r.returncode == 0 and r.stdout.strip() == ""


def test_docs_exist_and_cover_env_vars():
    text = DOC.read_text(encoding="utf-8")
    for var in PUSHOVER_VARS + ["N8N_BLOCK_ENV_ACCESS_IN_NODE"]:
        assert var in text, var
    assert "—" not in text, "em dash in docs"
    assert "doppler" in text.lower()
