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


def _build_node():
    nodes = [n for n in _workflow()["nodes"] if n["type"] == "n8n-nodes-base.code"
             and "$env.PUSHOVER_APP_TOKEN" in n["parameters"].get("jsCode", "")]
    assert len(nodes) == 1, "expected exactly one Pushover payload Code node"
    return nodes[0]


def _run_build(body, env=None, origin=None):
    """Run the Code node under node with a fake $input/$env. Returns the payload."""
    node = shutil.which("node")
    if not node:
        pytest.skip("node not installed")
    js = _build_node()["parameters"]["jsCode"]
    if origin is not None:
        js, n = re.subn(r"(?m)^const ALLOWED_DASHBOARD_ORIGIN = '[^']*';",
                        "const ALLOWED_DASHBOARD_ORIGIN = " + json.dumps(origin) + ";", js)
        assert n == 1
    harness = (
        "const f=new Function('$input','$env'," + json.dumps(js) + ");\n"
        "const b=" + json.dumps(body) + ";\n"
        "const e=Object.assign({PUSHOVER_APP_TOKEN:'t',PUSHOVER_USER_KEY:'u'},"
        + json.dumps(env or {}) + ");\n"
        "const r=f({first:()=>({json:{body:b}})},e);\n"
        "console.log(JSON.stringify(r[0].json.pushover));"
    )
    r = subprocess.run([node, "-e", harness], capture_output=True, text=True, timeout=30)
    assert r.returncode == 0, r.stderr
    return json.loads(r.stdout)


def _alert(status, labels, **extra):
    a = {"labels": dict({"alertname": "A"}, **labels), "annotations": {"summary": "s"},
         "fingerprint": "fp1"}
    a.update(extra)
    return {"status": status, "alerts": [a]}


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
    assert "$json.pushover" in send["parameters"]["jsonBody"]
    body = _build_node()["parameters"]["jsCode"]
    for var in PUSHOVER_VARS[1:]:
        assert f"$env.{var}" in body, var
    assert "300" in body and "10800" in body, "retry/expire defaults missing"
    gate =[n for n in nodes.values() if n["type"] == "n8n-nodes-base.if"
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
    # the payload builder sits behind the gate, never directly behind the switch
    assert _build_node()["name"] not in direct


def test_pushover_mapping_logic_matches_spec():
    e = {}
    crit = _run_build(_alert("firing", {"severity": "critical"}), e)
    sec = _run_build(_alert("firing", {"severity": "warning", "update_security": "true"}), e)
    warn = _run_build(_alert("firing", {"severity": "warning"}), e)
    res = _run_build(_alert("resolved", {"severity": "critical"}), e)
    clamp = _run_build(_alert("firing", {"severity": "critical"}),
                       {"PUSHOVER_EXPIRE": "99999", "PUSHOVER_RETRY": "5"})
    assert crit["priority"] == 2 and crit["retry"] == 300 and crit["expire"] == 10800
    assert sec["priority"] == 2
    assert warn["priority"] == 1 and "retry" not in warn and "expire" not in warn
    assert res["priority"] == 0 and "retry" not in res
    assert clamp["expire"] == 10800 and clamp["retry"] == 30
    assert len(crit["title"]) <= 250 and len(crit["message"]) <= 1024


# --- webhook authentication and URL allowlist (round 2) ----------------------

def test_webhook_requires_header_auth_with_credential_reference():
    wf = _workflow()
    hooks = [n for n in wf["nodes"] if n["type"] == "n8n-nodes-base.webhook"]
    assert len(hooks) == 1, "the router must have exactly one entry point"
    hook = hooks[0]
    assert hook["parameters"]["authentication"] == "headerAuth"
    cred = hook["credentials"]["httpHeaderAuth"]
    assert set(cred) == {"id", "name"} and cred["name"] == "grafana-webhook-auth"
    # the entry point leads only to the switch, which fronts Discord and Pushover
    assert [c["node"] for o in wf["connections"][hook["name"]]["main"] for c in o] == ["Alert Status"]
    # no secret-looking literal anywhere in the credential reference
    assert not re.search(r"[A-Za-z0-9+/_-]{32,}", json.dumps(hook["credentials"]))


def test_unauthenticated_webhook_detected_by_guard():
    """Negative case: the guard's check fails on a node without auth."""
    hook = dict(_nodes()["Grafana Webhook"])
    hook["parameters"] = {k: v for k, v in hook["parameters"].items() if k != "authentication"}
    assert hook["parameters"].get("authentication") != "headerAuth"


def test_contact_point_sends_secret_from_environment_only():
    path = ALERTING / "contact-points.yml"
    settings = yaml.safe_load(path.read_text(encoding="utf-8"))["contactPoints"][0]["receivers"][0]["settings"]
    assert settings["authorization_scheme"] == "Bearer"
    assert settings["authorization_credentials"] == "$GRAFANA_WEBHOOK_SECRET"
    text = path.read_text(encoding="utf-8")
    assert not re.search(r"[A-Za-z0-9+/_-]{32,}", text), "literal secret-looking value"


def test_webhook_secret_is_declared_without_a_value():
    assert re.search(r"^# GRAFANA_WEBHOOK_SECRET=\s*$", ENV_EXAMPLE.read_text(encoding="utf-8"), re.M)
    compose = yaml.safe_load((REPO_ROOT / "docker" / "docker-compose.yml").read_text(encoding="utf-8"))
    assert "GRAFANA_WEBHOOK_SECRET" in compose["services"]["grafana"]["environment"], \
        "passed through by name, with no default"


ORIGIN = "https://grafana.example.com"


def test_dashboard_origin_constant_defaults_empty():
    js = _build_node()["parameters"]["jsCode"]
    assert re.search(r"(?m)^const ALLOWED_DASHBOARD_ORIGIN = '';", js)
    assert js.count("ALLOWED_DASHBOARD_ORIGIN") >= 2
    assert "ALLOWED_DASHBOARD_ORIGIN" in DOC.read_text(encoding="utf-8")


@pytest.mark.parametrize("url,origin,kept", [
    (ORIGIN + "/d/abc?orgId=1", ORIGIN, True),
    (ORIGIN + "/d/abc", "", False),                       # default: always dropped
    ("http://grafana.example.com/d/abc", ORIGIN, False),
    ("javascript:alert(1)", ORIGIN, False),
    ("https://evil.example.net/d/abc", ORIGIN, False),
    ("https://grafana.example.com.evil.example.net/", ORIGIN, False),
    ("https://grafana.example.com@evil.example.net/", ORIGIN, False),
    ("https://user:pw@grafana.example.com/d/abc", ORIGIN, False),
    (ORIGIN + "/d/" + "a" * 600, ORIGIN, False),          # over-long
    ("not a url", ORIGIN, False),
])
def test_dashboard_url_allowlist(url, origin, kept):
    if shutil.which("node"):
        out = _run_build(_alert("firing", {"severity": "warning"}, dashboardURL=url), {}, origin=origin)
        assert (out.get("url") == url) is kept
        assert kept or "url" not in out
    else:
        js = _build_node()["parameters"]["jsCode"]
        for needle in ("https:", "p.origin", "length", "username"):
            assert needle in js


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
    for needle in ("grafana-webhook-auth", "GRAFANA_WEBHOOK_SECRET", "ALLOWED_DASHBOARD_ORIGIN",
                   "authenticated Grafana caller"):
        assert needle in text, needle
