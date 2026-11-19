"""Tests for scripts/live-deploy: the tooling that deploys the alert setup to a live stack.

The scripts' pure logic is imported with importlib and tested without docker. The
command-line behavior is checked by running the scripts against temporary
directories (set through the documented environment variables).
"""
import copy
import json
import re
import shutil
import subprocess
import sys

import pytest
import yaml

from conftest import REPO_ROOT, import_module_from_path

LIVE = REPO_ROOT / "scripts" / "live-deploy"
ROUTER = REPO_ROOT / "n8n" / "grafana-alert-router.json"
CONTACT = REPO_ROOT / "docker" / "grafana" / "provisioning" / "alerting" / "contact-points.yml"
FILES = sorted(p for p in LIVE.iterdir() if p.is_file())


@pytest.fixture(scope="module")
def setup():
    return import_module_from_path("live_n8n_setup", LIVE / "n8n-setup-alert-router.py")


@pytest.fixture(scope="module")
def gdeploy():
    return import_module_from_path("live_grafana_deploy", LIVE / "grafana-deploy.py")


def workflow():
    return json.loads(ROUTER.read_text(encoding="utf-8"))


def node(wf, kind):
    return next(n for n in wf["nodes"] if n["type"].endswith(kind))


def builder(wf):
    return next(n for n in wf["nodes"] if "ALLOWED_ALERTNAMES" in n.get("parameters", {}).get("jsCode", ""))


# --- the file set ----------------------------------------------------------------

def test_expected_files_exist_and_scripts_are_executable():
    names = {p.name for p in FILES}
    assert {"siem-run", "n8n-setup-alert-router.py", "n8n-test-router.py",
            "grafana-deploy.py", "pfb-fix-feeds.php"} <= names
    for name in ("siem-run", "n8n-setup-alert-router.py", "n8n-test-router.py", "grafana-deploy.py"):
        assert (LIVE / name).stat().st_mode & 0o111, name + " is not executable"


def test_wrapper_passes_bash_syntax_check():
    bash = shutil.which("bash")
    if not bash:
        pytest.skip("bash is not installed here")
    assert subprocess.run([bash, "-n", str(LIVE / "siem-run")], timeout=30).returncode == 0
    text = (LIVE / "siem-run").read_text(encoding="utf-8")
    assert text.startswith("#!/usr/bin/env bash") and "set -euo pipefail" in text
    assert "SIEM_CONFIG_DIR" in text


def test_php_script_has_valid_syntax_if_php_exists():
    php = shutil.which("php")
    if not php:
        pytest.skip("php is not installed here")
    assert subprocess.run([php, "-l", str(LIVE / "pfb-fix-feeds.php")], capture_output=True, timeout=30).returncode == 0


def test_no_literal_secrets_or_real_addresses():
    # built from pieces so this file does not carry the strings it forbids
    forbidden = ["/home/" + "chiefgyk3d", "172." + "20.0.", "10." + "0.", "192.168." , "Chief" + "Gyk3D",
                 "doppler" + "_token=", "pushover" + "_token="]
    ip = re.compile(r"\b(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})\b")
    ok_prefix = ("192.0.2.", "198.51.100.", "203.0.113.", "127.0.0.", "0.0.0.")
    for path in FILES:
        text = path.read_text(encoding="utf-8")
        for bad in forbidden:
            assert bad not in text, f"{path.name}: {bad!r}"
        for m in ip.finditer(text):
            assert m.group(0).startswith(ok_prefix), f"{path.name}: address {m.group(0)}"
        # no long secret-looking token (32+ base64-ish characters)
        assert not re.search(r"(?<![A-Za-z0-9/._-])(?=[A-Za-z0-9+_-]*[0-9])(?=[A-Za-z0-9+_-]*[A-Za-z])[A-Za-z0-9+_-]{32,}(?![A-Za-z0-9/._-])", text), path.name
        # no secret-named assignment with a literal value
        assert not re.search(r"(SECRET|TOKEN|API_KEY|PASSWORD|USER_KEY)\s*=\s*[\"'][^\"'$ ]{8,}[\"']", text), path.name


def test_every_script_documents_its_environment_at_the_top():
    for name in ("siem-run", "n8n-setup-alert-router.py", "n8n-test-router.py", "grafana-deploy.py"):
        head = "\n".join((LIVE / name).read_text(encoding="utf-8").splitlines()[:45])
        assert "Environment" in head or "SIEM_CONFIG_DIR" in head, name
    assert "SIEM_DIR" in (LIVE / "grafana-deploy.py").read_text(encoding="utf-8")
    assert "N8N_BASE" in (LIVE / "n8n-test-router.py").read_text(encoding="utf-8")


# --- n8n setup: credentials, path, workflow patching ---------------------------------

def test_build_credentials_shapes(setup):
    creds = setup.build_credentials("S" * 8, "tok", "usr")
    by = {c["name"]: c for c in creds}
    assert set(by) == {"grafana-webhook-auth", "pushover-api"}
    h = by["grafana-webhook-auth"]
    assert h["type"] == "httpHeaderAuth" and h["data"] == {"name": "Authorization", "value": "Bearer " + "S" * 8}
    p = by["pushover-api"]
    assert p["type"] == "httpCustomAuth"
    assert json.loads(p["data"]["json"]) == {"body": {"token": "tok", "user": "usr"}}


def test_credential_id_map_covers_the_three_names(setup):
    ids = setup.credential_id_map()
    assert set(ids) == {"grafana-webhook-auth", "pushover-api", setup.DISCORD_NAME}
    assert ids["grafana-webhook-auth"] == setup.CRED_HEADER_ID and ids["pushover-api"] == setup.CRED_PUSHOVER_ID


def test_choose_webhook_path_reuses_a_good_saved_path(setup):
    saved = "grafana-alerts-" + "a" * 24
    assert setup.choose_webhook_path(saved + "\n", token_fn=lambda: "NEW") == saved


@pytest.mark.parametrize("bad", ["", None, "grafana-alerts", "grafana-alerts-x", "other-" + "a" * 30, "   "])
def test_choose_webhook_path_makes_a_new_one_otherwise(setup, bad):
    assert setup.choose_webhook_path(bad, token_fn=lambda: "NEWTOKEN") == "grafana-alerts-NEWTOKEN"


def test_choose_webhook_path_default_generator_is_random_and_prefixed(setup):
    a, b = setup.choose_webhook_path(""), setup.choose_webhook_path("")
    assert a != b and a.startswith("grafana-alerts-") and len(a) >= 20


@pytest.mark.parametrize("text,expected", [
    ("http://192.0.2.5:3000", "http://192.0.2.5:3000"),
    ("https://grafana.example.com/", "https://grafana.example.com"),
    ("javascript:alert(1)", ""), ("https://x.example.com/path", ""), ("", ""), (None, ""),
    ("https://user@grafana.example.com", ""),
])
def test_valid_origin(setup, text, expected):
    assert setup.valid_origin(text) == expected


def test_patch_workflow_id_handling(setup):
    wf = setup.patch_workflow(workflow(), webhook_path="grafana-alerts-x")
    assert re.fullmatch(r"[0-9a-f]{16}", wf["id"])
    assert wf["active"] is False and wf["name"] == setup.NEW_NAME
    assert setup.patch_workflow(workflow(), reuse_id="0123456789abcdef")["id"] == "0123456789abcdef"
    assert setup.patch_workflow(workflow(), new_id="fedcba9876543210")["id"] == "fedcba9876543210"
    for bad in ("short", "0123456789ABCDEF", "0123456789abcdeg", "0123456789abcdef0"):
        with pytest.raises(ValueError):
            setup.patch_workflow(workflow(), reuse_id=bad)


def test_patch_workflow_strips_instance_specific_keys(setup):
    src = workflow()
    src.update({"activeVersionId": "x", "shared": [1], "versionCounter": 3, "pinData": {}})
    out = setup.patch_workflow(src)
    for key in setup.STRIP_KEYS:
        assert key not in out


def test_patch_workflow_maps_credential_ids_by_name(setup):
    out = setup.patch_workflow(workflow())
    seen = {}
    for n in out["nodes"]:
        for cred in (n.get("credentials") or {}).values():
            seen[cred["name"]] = cred["id"]
    ids = setup.credential_id_map()
    assert {"grafana-webhook-auth", "pushover-api", setup.DISCORD_NAME} <= set(seen)
    for name, cid in seen.items():
        assert ids[name] == cid, name


def test_patch_workflow_sets_webhook_path_and_webhook_id(setup):
    out = setup.patch_workflow(workflow(), webhook_path="grafana-alerts-abc", webhook_id="11111111-2222-3333-4444-555555555555")
    hook = node(out, ".webhook")
    assert hook["parameters"]["path"] == "grafana-alerts-abc"
    assert hook["webhookId"] == "11111111-2222-3333-4444-555555555555"
    auto = node(setup.patch_workflow(workflow(), webhook_path="p"), ".webhook")
    assert re.fullmatch(r"[0-9a-f-]{36}", auto["webhookId"])


def test_patch_workflow_pushover_and_origin_constants(setup):
    off = builder(setup.patch_workflow(workflow()))["parameters"]["jsCode"]
    assert "const PUSHOVER_ENABLED = false;" in off and "const ALLOWED_DASHBOARD_ORIGIN = '';" in off
    on = builder(setup.patch_workflow(workflow(), pushover_on=True, origin="https://grafana.example.com"))["parameters"]["jsCode"]
    assert "const PUSHOVER_ENABLED = true;" in on
    assert "const ALLOWED_DASHBOARD_ORIGIN = 'https://grafana.example.com';" in on
    # the rest of the node is untouched
    back = on.replace("const PUSHOVER_ENABLED = true;", "const PUSHOVER_ENABLED = false;").replace(
        "const ALLOWED_DASHBOARD_ORIGIN = 'https://grafana.example.com';", "const ALLOWED_DASHBOARD_ORIGIN = '';")
    assert back == off


def test_patch_workflow_does_not_mutate_the_repo_file(setup):
    before = ROUTER.read_bytes()
    setup.patch_workflow(workflow(), pushover_on=True)
    assert ROUTER.read_bytes() == before


# --- Grafana deploy: compose edit, datasources, contact point ----------------------------

COMPOSE = (
    "services:\n"
    "  grafana:\n"
    "    environment:\n"
    "      - GF_SECURITY_ADMIN_USER=admin\n"
    "      - GF_SERVER_ROOT_URL=http://localhost:3000\n"
    "      - GF_INSTALL_PLUGINS=a\n"
    "    ports:\n"
    '      - "3000:3000"\n'
)


def test_compose_edit_inserts_the_line_once_after_the_anchor(gdeploy):
    new, note = gdeploy.compose_edit(COMPOSE)
    assert "insert after line 5" in note
    lines = new.splitlines()
    assert lines[5] == "      - GRAFANA_WEBHOOK_SECRET" and lines[4].startswith("      - GF_SERVER_ROOT_URL=")
    assert new.count("GRAFANA_WEBHOOK_SECRET") == 1
    assert [ln for ln in lines if ln != "      - GRAFANA_WEBHOOK_SECRET"] == COMPOSE.splitlines()


def test_compose_edit_is_idempotent(gdeploy):
    new, _ = gdeploy.compose_edit(COMPOSE)
    again, note = gdeploy.compose_edit(new)
    assert again is None and note == "already present"


def test_compose_edit_refuses_a_missing_anchor(gdeploy):
    with pytest.raises(ValueError, match="found 0"):
        gdeploy.compose_edit(COMPOSE.replace("GF_SERVER_ROOT_URL", "GF_OTHER"))


def test_compose_edit_refuses_an_ambiguous_anchor(gdeploy):
    with pytest.raises(ValueError, match="found 2"):
        gdeploy.compose_edit(COMPOSE + "      - GF_SERVER_ROOT_URL=http://other\n")


def test_compose_edit_ignores_a_similar_line_that_is_not_the_anchor(gdeploy):
    text = COMPOSE.replace("      - GF_SERVER_ROOT_URL=", "      # - GF_SERVER_ROOT_URL=")
    with pytest.raises(ValueError):
        gdeploy.compose_edit(text)


def test_datasources_yaml_content(gdeploy):
    data = yaml.safe_load(gdeploy.datasources_yaml())
    by = {d["uid"]: d for d in data["datasources"]}
    assert set(by) == {"influxdb-pfsense", "influxdb-unifi"}
    assert by["influxdb-pfsense"]["database"] == "pfsense" and by["influxdb-unifi"]["database"] == "unpoller"
    assert {d["name"] for d in data["datasources"]} == {"InfluxDB-pfSense-alerts", "InfluxDB-UniFi-alerts"}
    for d in data["datasources"]:
        assert d["type"] == "influxdb" and d["url"] == gdeploy.INFLUX_URL
        assert "password" not in json.dumps(d).lower()


def test_datasources_yaml_url_override(gdeploy):
    data = yaml.safe_load(gdeploy.datasources_yaml("http://192.0.2.7:8086"))
    assert {d["url"] for d in data["datasources"]} == {"http://192.0.2.7:8086"}


def test_contact_point_url_substitution(gdeploy):
    text = CONTACT.read_text(encoding="utf-8")
    out = gdeploy.contact_with_path(text, "grafana-alerts-abc123")
    assert "http://n8n/webhook/grafana-alerts-abc123" in out
    assert gdeploy.OLD_URL not in out.replace("grafana-alerts-abc123", "")
    assert yaml.safe_load(out)["contactPoints"][0]["receivers"][0]["settings"]["url"].endswith("/grafana-alerts-abc123")
    assert gdeploy.contact_with_path(text, "p", base="http://192.0.2.9/").count("http://192.0.2.9/webhook/p") == 1


def test_contact_point_substitution_refuses_when_the_url_is_missing(gdeploy):
    with pytest.raises(ValueError, match="contact point URL"):
        gdeploy.contact_with_path("url: http://elsewhere/hook\n", "grafana-alerts-abc123")


@pytest.mark.parametrize("path,ok", [("grafana-alerts-" + "a" * 10, True), ("grafana-alerts-shor", False),
                                     ("other-" + "a" * 30, False), ("", False)])
def test_router_path_validation(gdeploy, path, ok):
    assert gdeploy.valid_router_path(path) is ok


# --- command-line behavior ----------------------------------------------------------------

STAGED = ("contact-points.yml", "update-alert-rules-unifi.yml", "update-alert-rules-pfsense.yml",
          "heartbeat-alert-rule.yml")


def _run(script, args, env):
    base = {"PATH": "/usr/bin:/bin"}
    base.update(env)
    return subprocess.run([sys.executable, "-I", str(LIVE / script)] + args, capture_output=True,
                          text=True, timeout=60, env=base, check=False)


def _stage_dirs(tmp_path, compose_text=COMPOSE):
    siem, stage, cfg = tmp_path / "siem", tmp_path / "stage", tmp_path / "cfg"
    for d in (siem, stage, cfg):
        d.mkdir()
    (siem / "docker-compose.yml").write_text(compose_text, encoding="utf-8")
    (cfg / "router-path").write_text("grafana-alerts-" + "z" * 20, encoding="utf-8")
    for name in STAGED:
        src = REPO_ROOT / "docker" / "grafana" / "provisioning" / "alerting" / name
        shutil.copy(src, stage / name)
    return {"SIEM_DIR": str(siem), "SIEM_STAGE_DIR": str(stage), "SIEM_CONFIG_DIR": str(cfg)}


def test_grafana_deploy_stage_prints_the_plan(tmp_path):
    env = _stage_dirs(tmp_path)
    r = _run("grafana-deploy.py", ["--stage"], env)
    assert r.returncode == 0, r.stderr
    assert r.stdout.strip() == "staged files ok; router path length 35; compose: insert after line 5"
    assert "GRAFANA_WEBHOOK_SECRET" not in (tmp_path / "siem" / "docker-compose.yml").read_text(encoding="utf-8"), \
        "--stage must not change anything"


def test_grafana_deploy_ships_the_heartbeat_rule_file(gdeploy):
    assert "heartbeat-alert-rule.yml" in gdeploy.FILES
    assert len(set(gdeploy.FILES)) == len(gdeploy.FILES)
    # every file the deploy copies exists in the repository's alerting folder
    for name in gdeploy.FILES:
        assert (CONTACT.parent / name).is_file(), name


def test_grafana_deploy_stage_requires_the_heartbeat_rule_file(tmp_path):
    env = _stage_dirs(tmp_path)
    (tmp_path / "stage" / "heartbeat-alert-rule.yml").unlink()
    r = _run("grafana-deploy.py", ["--stage"], env)
    assert r.returncode != 0 and "missing staged file: heartbeat-alert-rule.yml" in r.stderr


def test_grafana_deploy_apply_copies_the_heartbeat_rule_with_mode_644(gdeploy, tmp_path, monkeypatch):
    env = _stage_dirs(tmp_path)
    alert = tmp_path / "alerting"
    alert.mkdir()
    (alert / "unrelated.yml").write_text("keep", encoding="utf-8")
    (alert / "heartbeat-alert-rule.yml").write_text("old", encoding="utf-8")
    (alert / "heartbeat-alert-rule.yml").chmod(0o600)
    monkeypatch.setattr(gdeploy, "STAGE", env["SIEM_STAGE_DIR"])
    monkeypatch.setattr(gdeploy, "PATH_FILE", str(tmp_path / "cfg" / "router-path"))
    monkeypatch.setattr(gdeploy, "COMPOSE", str(tmp_path / "siem" / "docker-compose.yml"))
    monkeypatch.setattr(gdeploy, "SIEM", str(tmp_path / "siem"))
    monkeypatch.setattr(gdeploy, "ALERT_DIR", str(alert))
    monkeypatch.setattr(gdeploy, "DS_FILE", str(tmp_path / "ds.yml"))
    monkeypatch.setenv("GRAFANA_WEBHOOK_SECRET", "x")
    calls = []

    def fake_run(cmd, **kwargs):
        calls.append(cmd)
        return subprocess.CompletedProcess(cmd, 0, b"", b"")

    monkeypatch.setattr(gdeploy.subprocess, "run", fake_run)
    assert gdeploy.main(["--apply"]) == 0
    src = (CONTACT.parent / "heartbeat-alert-rule.yml").read_text(encoding="utf-8")
    assert (alert / "heartbeat-alert-rule.yml").read_text(encoding="utf-8") == src
    assert (alert / "heartbeat-alert-rule.yml").stat().st_mode & 0o777 == 0o644
    assert (alert / "unrelated.yml").read_text(encoding="utf-8") == "keep", "deploys stay additive"
    assert calls and calls[0][-3:] == ["up", "-d", gdeploy.SERVICE]


def test_grafana_deploy_stage_refuses_bad_inputs(tmp_path):
    env = _stage_dirs(tmp_path, COMPOSE.replace("GF_SERVER_ROOT_URL", "GF_OTHER"))
    r = _run("grafana-deploy.py", ["--stage"], env)
    assert r.returncode != 0 and "expected exactly one GF_SERVER_ROOT_URL line, found 0" in r.stderr
    env = _stage_dirs(tmp_path / "b" if (tmp_path / "b").mkdir() is None else tmp_path)
    (tmp_path / "b" / "cfg" / "router-path").write_text("bad", encoding="utf-8")
    r = _run("grafana-deploy.py", ["--stage"], env)
    assert r.returncode != 0 and "router path file looks wrong" in r.stderr


def test_setup_check_reports_presence_without_values(tmp_path):
    r = _run("n8n-setup-alert-router.py", ["--check"],
             {"GRAFANA_WEBHOOK_SECRET": "x" * 12, "PUSHOVER_API_KEY": "y" * 12})
    assert r.returncode == 1
    assert "GRAFANA_WEBHOOK_SECRET: present" in r.stdout and "PUSHOVER_USER_KEY: MISSING" in r.stdout
    assert "x" * 12 not in r.stdout + r.stderr and "y" * 12 not in r.stdout + r.stderr


def test_test_router_refuses_without_the_credential(tmp_path):
    r = _run("n8n-test-router.py", [], {"SIEM_CONFIG_DIR": str(tmp_path)})
    assert r.returncode != 0 and "missing environment value: GRAFANA_WEBHOOK_SECRET" in r.stderr


# --- the runbook ------------------------------------------------------------------------

RUNBOOK = REPO_ROOT / "docs" / "live-deploy-runbook.md"


def test_runbook_covers_the_required_topics_in_order():
    text = RUNBOOK.read_text(encoding="utf-8")
    flat = " ".join(text.split())
    order = ["## 1. Prerequisites", "## 2. The read-only token file", "## 3. What lives only inside n8n",
             "## 4. Test through the Docker bridge", "## 5. Additive Grafana deploy",
             "## 6. The manual Grafana notification policy route", "## 7. What is not in git",
             "## 8. One-time firewall feed fix"]
    positions = [text.index(h) for h in order]
    assert positions == sorted(positions)
    for needle in ("grafana-webhook-auth", "pushover-api", "Header Auth", "Custom Auth", "webhookId",
                   "restart", "macvlan", "influxdb-pfsense", "influxdb-unifi", "pass-through",
                   "siem-docker-stack#61", "pfsense-siem-stack#66", "#67", "Rollback", "mode-600",
                   "overwrites by id", "backup"):
        assert needle in flat, needle
    assert text.count("Rollback") >= 5 and text.count("Check") >= 5
    assert "—" not in text, "em dash"


def test_runbook_has_no_real_addresses_or_values():
    text = RUNBOOK.read_text(encoding="utf-8")
    for m in re.finditer(r"\b(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})\b", text):
        assert m.group(0).startswith("192.0.2."), m.group(0)
    assert "/home/" + "chiefgyk3d" not in text
    assert not re.search(r"grafana-alerts-[A-Za-z0-9_-]{8,}", text), "a real webhook path"
    assert not re.search(r"(?<![A-Za-z0-9/._-])(?=[A-Za-z0-9+_-]*[0-9])(?=[A-Za-z0-9+_-]*[A-Za-z])[A-Za-z0-9+_-]{32,}", text)


def test_update_alerting_doc_links_the_runbook():
    text = (REPO_ROOT / "docs" / "update-alerting.md").read_text(encoding="utf-8")
    assert "(live-deploy-runbook.md)" in text
    assert RUNBOOK.is_file()


# --- the error workflow (issues #78 and #79) ------------------------------------------------

HANDLER = REPO_ROOT / "n8n" / "alert-router-error-handler.json"


def handler():
    return json.loads(HANDLER.read_text(encoding="utf-8"))


def test_router_ships_a_placeholder_that_patching_fills_or_removes(setup):
    assert workflow()["settings"]["errorWorkflow"] == setup.ERROR_PLACEHOLDER
    filled = setup.patch_workflow(workflow(), error_workflow_id="0123456789abcdef")
    assert filled["settings"]["errorWorkflow"] == "0123456789abcdef"
    # without an id the placeholder must not reach n8n (it would point at nothing)
    bare = setup.patch_workflow(workflow())
    assert "errorWorkflow" not in bare["settings"]
    for key in ("saveDataErrorExecution", "saveDataSuccessExecution"):
        assert bare["settings"][key] == "none"


@pytest.mark.parametrize("bad", ["short", "0123456789ABCDEF", "ERROR_WORKFLOW_ID", "0123456789abcdeg"])
def test_error_workflow_id_must_be_16_hex(setup, bad):
    with pytest.raises(ValueError, match="error workflow id"):
        setup.patch_workflow(workflow(), error_workflow_id=bad)
    with pytest.raises(ValueError):
        setup.patch_error_workflow(handler(), reuse_id=bad)


def test_patch_error_workflow(setup):
    out = setup.patch_error_workflow(handler())
    assert re.fullmatch(r"[0-9a-f]{16}", out["id"]) and out["active"] is False
    assert out["name"] == setup.HANDLER_NAME
    assert setup.patch_error_workflow(handler(), reuse_id="0123456789abcdef")["id"] == "0123456789abcdef"
    assert setup.patch_error_workflow(handler(), new_id="fedcba9876543210")["id"] == "fedcba9876543210"
    ids = setup.credential_id_map()
    seen = {c["name"]: c["id"] for n in out["nodes"] for c in (n.get("credentials") or {}).values()}
    assert {"pushover-api", setup.DISCORD_NAME} <= set(seen)
    assert all(ids[name] == cid for name, cid in seen.items())
    assert not any(n["type"].endswith(".webhook") for n in out["nodes"])


def test_patch_error_workflow_is_idempotent(setup):
    first = setup.patch_error_workflow(handler(), reuse_id="0123456789abcdef")
    second = setup.patch_error_workflow(copy.deepcopy(first), reuse_id="0123456789abcdef")
    assert first == second


def test_patch_error_workflow_keeps_the_no_storage_settings(setup):
    s = setup.patch_error_workflow(handler())["settings"]
    assert s["saveDataSuccessExecution"] == "none" and s["saveDataErrorExecution"] == "none"


@pytest.mark.parametrize("rest,expected", [
    ([], ("", False, "")),
    (["0123456789abcdef"], ("0123456789abcdef", False, "")),
    (["--pushover-on"], ("", True, "")),
    (["0123456789abcdef", "--pushover-on", "--error-workflow-id", "fedcba9876543210"],
     ("0123456789abcdef", True, "fedcba9876543210")),
    (["--error-workflow-id", "fedcba9876543210"], ("", False, "fedcba9876543210")),
])
def test_parse_workflow_args(setup, rest, expected):
    assert setup.parse_workflow_args(rest) == expected


@pytest.mark.parametrize("rest", [["--error-workflow-id"], ["a", "b"]])
def test_parse_workflow_args_refuses_bad_input(setup, rest):
    with pytest.raises(ValueError):
        setup.parse_workflow_args(rest)


def test_cli_refuses_a_bad_error_workflow_id_before_touching_docker(tmp_path):
    r = _run("n8n-setup-alert-router.py", ["--workflow", str(ROUTER), "--error-workflow-id", "nope"],
             {"SIEM_CONFIG_DIR": str(tmp_path)})
    assert r.returncode != 0 and "error workflow id must be 16 hex characters" in r.stderr
    r = _run("n8n-setup-alert-router.py", ["--error-workflow", str(HANDLER), "nope"],
             {"SIEM_CONFIG_DIR": str(tmp_path)})
    assert r.returncode != 0 and "workflow id must be 16 hex characters" in r.stderr
    r = _run("n8n-setup-alert-router.py", ["--workflow", str(ROUTER), "--error-workflow-id"],
             {"SIEM_CONFIG_DIR": str(tmp_path)})
    assert r.returncode != 0 and "needs an id" in r.stderr
