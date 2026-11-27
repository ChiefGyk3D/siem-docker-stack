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


@pytest.fixture(autouse=True)
def _umask_022():
    """grafana-deploy.py refuses group-writable directories; keep temp dirs 755 whatever the user's umask."""
    import os
    old = os.umask(0o022)
    yield
    os.umask(old)


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


def test_credential_id_map_covers_the_known_names(setup):
    ids = setup.credential_id_map()
    assert set(ids) == {"grafana-webhook-auth", "pushover-api", setup.DISCORD_NAME, "matrix-bot-auth",
                        "grafana-viewer-auth"}
    assert ids["grafana-viewer-auth"] == setup.CRED_GRAFANA_VIEWER_ID
    assert ids["matrix-bot-auth"] == setup.CRED_MATRIX_ID
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
    out = gdeploy.contact_with_path(text, "grafana-alerts-abc12345")
    assert "http://n8n/webhook/grafana-alerts-abc12345" in out
    assert gdeploy.OLD_URL not in out.replace("grafana-alerts-abc12345", "")
    assert yaml.safe_load(out)["contactPoints"][0]["receivers"][0]["settings"]["url"].endswith("/grafana-alerts-abc12345")
    assert gdeploy.contact_with_path(text, "grafana-alerts-abc12345", base="http://192.0.2.9/").count("http://192.0.2.9/webhook/grafana-alerts-abc12345") == 1


def test_contact_point_substitution_refuses_when_the_url_is_missing(gdeploy):
    with pytest.raises(ValueError, match="contact point URL"):
        gdeploy.contact_with_path("url: http://elsewhere/hook\n", "grafana-alerts-abc12345")


@pytest.mark.parametrize("path,ok", [("grafana-alerts-" + "a" * 10, True), ("grafana-alerts-shor", False),
                                     ("other-" + "a" * 30, False), ("", False)])
def test_router_path_validation(gdeploy, path, ok):
    assert gdeploy.valid_router_path(path) is ok


# --- command-line behavior ----------------------------------------------------------------

STAGED = ("contact-points.yml", "update-alert-rules-unifi.yml", "update-alert-rules-pfsense.yml",
          "heartbeat-alert-rule.yml", "notification-failure-alert-rule.yml")


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
        (stage / name).chmod(0o644)
    return {"SIEM_DIR": str(siem), "SIEM_STAGE_DIR": str(stage), "SIEM_CONFIG_DIR": str(cfg)}


def test_grafana_deploy_stage_prints_the_plan(tmp_path):
    env = _stage_dirs(tmp_path)
    r = _run("grafana-deploy.py", ["--stage"], env)
    assert r.returncode == 0, r.stderr
    assert r.stdout.strip().splitlines()[0] == "staged files ok; router path length 35"
    assert "INFLUX_URL in effect: http://influxdb:8086" in r.stdout


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


# --- issue #53: matrix credential and the weekly digest import ------------------------

DIGEST = REPO_ROOT / "n8n" / "weekly-update-digest.json"


def digest():
    return json.loads(DIGEST.read_text(encoding="utf-8"))


def test_build_matrix_credential_shape(setup):
    cred = setup.build_matrix_credential("tok" + "9" * 10)
    assert cred["name"] == "matrix-bot-auth" and cred["type"] == "httpCustomAuth" and cred["id"] == setup.CRED_MATRIX_ID
    assert json.loads(cred["data"]["json"]) == {"headers": {"Authorization": "Bearer tok" + "9" * 10}}


def test_build_credentials_without_matrix_is_unchanged(setup):
    assert {c["name"] for c in setup.build_credentials("S" * 8, "t", "u")} == {"grafana-webhook-auth", "pushover-api"}


def test_matrix_token_never_reaches_argv_or_output(setup, monkeypatch, capsys):  # GUARD
    seen = {}

    def fake(script, payload):
        seen["script"], seen["payload"] = script, payload
        return 0, ["Successfully imported 1 credential."]

    monkeypatch.setattr(setup, "docker_in", fake)
    monkeypatch.setenv("MATRIX_BOT_TOKEN", "MATRIXSECRET-0123456789")
    assert setup.matrix_credentials() == 0
    assert "MATRIXSECRET" not in seen["script"] and "MATRIXSECRET" in seen["payload"]
    assert "MATRIXSECRET" not in capsys.readouterr().out
    assert [c["name"] for c in json.loads(seen["payload"])] == ["matrix-bot-auth"]


def test_matrix_credentials_need_the_token(setup, monkeypatch):
    monkeypatch.delenv("MATRIX_BOT_TOKEN", raising=False)
    with pytest.raises(SystemExit):
        setup.matrix_credentials()


def test_check_with_matrix_reports_presence_only(tmp_path):
    r = _run("n8n-setup-alert-router.py", ["--check", "--with-matrix"],
             {"GRAFANA_WEBHOOK_SECRET": "x" * 12, "PUSHOVER_API_KEY": "y" * 12, "PUSHOVER_USER_KEY": "z" * 12,
              "MATRIX_BOT_TOKEN": "m" * 12})
    assert r.returncode == 0 and "MATRIX_BOT_TOKEN: present" in r.stdout
    assert "m" * 12 not in r.stdout + r.stderr


def test_patch_digest_workflow_imports_inactive_with_mapped_credentials(setup):
    out = setup.patch_digest_workflow(digest(), error_workflow_id="0123456789abcdef")
    assert out["active"] is False and re.fullmatch(r"[0-9a-f]{16}", out["id"])
    assert out["settings"]["errorWorkflow"] == "0123456789abcdef"
    ids = setup.credential_id_map()
    seen = {c["name"]: c["id"] for n in out["nodes"] for c in (n.get("credentials") or {}).values()}
    assert {"matrix-bot-auth", setup.DISCORD_NAME} <= set(seen)
    assert all(ids[name] == cid for name, cid in seen.items())
    assert not any(v == "YOUR_CREDENTIAL_ID" for v in seen.values())


def test_patch_digest_workflow_drops_the_placeholder_error_id_and_keeps_the_repo_file(setup):
    before = DIGEST.read_text(encoding="utf-8")
    out = setup.patch_digest_workflow(digest())
    assert "errorWorkflow" not in out["settings"]
    assert setup.patch_digest_workflow(digest(), reuse_id="0123456789abcdef")["id"] == "0123456789abcdef"
    with pytest.raises(ValueError):
        setup.patch_digest_workflow(digest(), reuse_id="nope")
    assert DIGEST.read_text(encoding="utf-8") == before


def test_cli_digest_flag_refuses_a_bad_id_before_touching_docker(tmp_path):
    r = _run("n8n-setup-alert-router.py", ["--digest-workflow", str(DIGEST), "nothex"], {})
    assert r.returncode != 0 and "16 hex" in r.stderr


def test_runbook_documents_issue_53_n8n_changes():
    text = " ".join((REPO_ROOT / "docs" / "live-deploy-runbook.md").read_text(encoding="utf-8").split())
    for needle in ("matrix-bot-auth", "--with-matrix", "MATRIX_BOT_TOKEN", "--digest-workflow",
                   "weekly-update-digest.json", "MATRIX_HOMESERVER", "MATRIX_ROOM_ID", "not secrets"):
        assert needle in text, needle
    assert "—" not in text


# --- issue #202: grafana-viewer-auth credential for the digest collectors ----------------

def test_build_grafana_viewer_credential_shape(setup):
    cred = setup.build_grafana_viewer_credential("tok" + "7" * 10)
    assert cred["name"] == "grafana-viewer-auth" and cred["type"] == "httpCustomAuth"
    assert cred["id"] == setup.CRED_GRAFANA_VIEWER_ID
    assert json.loads(cred["data"]["json"]) == {"headers": {"Authorization": "Bearer tok" + "7" * 10}}


def test_grafana_viewer_token_never_reaches_argv_or_output(setup, monkeypatch, capsys):  # GUARD
    seen = {}

    def fake(script, payload):
        seen["script"], seen["payload"] = script, payload
        return 0, ["Successfully imported 1 credential."]

    monkeypatch.setattr(setup, "docker_in", fake)
    monkeypatch.setenv("GRAFANA_VIEWER_TOKEN", "VIEWERSECRET-0123456789")
    assert setup.grafana_viewer_credentials() == setup.EXIT_DOMAIN_LOCK_UNVERIFIED
    assert "VIEWERSECRET" not in seen["script"] and "VIEWERSECRET" in seen["payload"]
    assert "VIEWERSECRET" not in capsys.readouterr().out
    assert [c["name"] for c in json.loads(seen["payload"])] == ["grafana-viewer-auth"]


def test_grafana_viewer_credentials_need_the_token(setup, monkeypatch):
    monkeypatch.delenv("GRAFANA_VIEWER_TOKEN", raising=False)
    with pytest.raises(SystemExit):
        setup.grafana_viewer_credentials()


def test_check_with_grafana_viewer_reports_presence_only():
    base = {"GRAFANA_WEBHOOK_SECRET": "x" * 12, "PUSHOVER_API_KEY": "y" * 12, "PUSHOVER_USER_KEY": "z" * 12}
    r = _run("n8n-setup-alert-router.py", ["--check", "--with-grafana-viewer"],
             dict(base, GRAFANA_VIEWER_TOKEN="g" * 12))
    assert r.returncode == 0 and "GRAFANA_VIEWER_TOKEN: present" in r.stdout
    assert "g" * 12 not in r.stdout + r.stderr
    r = _run("n8n-setup-alert-router.py", ["--check", "--with-grafana-viewer"], base)
    assert r.returncode == 1 and "GRAFANA_VIEWER_TOKEN: MISSING" in r.stdout


def test_check_with_both_flags_needs_both_tokens():
    base = {"GRAFANA_WEBHOOK_SECRET": "x" * 12, "PUSHOVER_API_KEY": "y" * 12, "PUSHOVER_USER_KEY": "z" * 12,
            "MATRIX_BOT_TOKEN": "m" * 12}
    r = _run("n8n-setup-alert-router.py", ["--check", "--with-matrix", "--with-grafana-viewer"], base)
    assert r.returncode == 1 and "MATRIX_BOT_TOKEN: present" in r.stdout and "GRAFANA_VIEWER_TOKEN: MISSING" in r.stdout


def test_patch_digest_workflow_maps_the_viewer_credential_on_every_query_node(setup):
    out = setup.patch_digest_workflow(digest())
    viewer = [c for n in out["nodes"] for c in (n.get("credentials") or {}).values() if c["name"] == "grafana-viewer-auth"]
    assert len(viewer) == 3 and all(c["id"] == setup.CRED_GRAFANA_VIEWER_ID for c in viewer)


def test_runbook_documents_grafana_viewer_credential():
    text = " ".join((REPO_ROOT / "docs" / "live-deploy-runbook.md").read_text(encoding="utf-8").split())
    for needle in ("grafana-viewer-auth", "--with-grafana-viewer", "GRAFANA_VIEWER_TOKEN", "GRAFANA_BASE_URL"):
        assert needle in text, needle
    assert "—" not in text


# --- issue #202 fix round 1: preflight before any change, id and token validation --------------

ENV_ALL = {"GRAFANA_WEBHOOK_SECRET": "s" * 12, "PUSHOVER_API_KEY": "k" * 12, "PUSHOVER_USER_KEY": "u" * 12,
           "MATRIX_BOT_TOKEN": "m" * 12, "GRAFANA_VIEWER_TOKEN": "g" * 12}
FLAGS = ["--credentials", "--with-matrix", "--with-grafana-viewer"]


def _env(monkeypatch, **over):
    for k in ENV_ALL:
        monkeypatch.delenv(k, raising=False)
    for k, v in {**ENV_ALL, **over}.items():
        if v is None:
            monkeypatch.delenv(k, raising=False)
        else:
            monkeypatch.setenv(k, v)


def _record_docker(setup, monkeypatch):
    calls = []

    def fake(script, payload):
        calls.append((script, payload))
        return 0, ["Successfully imported 1 credential."]

    monkeypatch.setattr(setup, "docker_in", fake)
    return calls


def test_credentials_run_changes_nothing_when_a_later_value_is_missing(setup, monkeypatch):  # GUARD
    calls = _record_docker(setup, monkeypatch)
    for missing in ("GRAFANA_VIEWER_TOKEN", "MATRIX_BOT_TOKEN", "PUSHOVER_USER_KEY"):
        _env(monkeypatch, **{missing: None})
        with pytest.raises(SystemExit):
            setup.main(FLAGS)
        assert calls == [], missing + ": nothing may be imported before every value is checked"
    _env(monkeypatch)
    assert setup.main(FLAGS) == setup.EXIT_DOMAIN_LOCK_UNVERIFIED
    assert len(calls) == 3, "the base credentials, then matrix, then the viewer"


def test_credentials_run_changes_nothing_when_a_token_is_bad(setup, monkeypatch):  # GUARD
    calls = _record_docker(setup, monkeypatch)
    for bad in ("", "   ", "\n", "abc\ndef", "abc\r\ndef", "abc\tdef", "abc" + chr(27) + "def"):
        _env(monkeypatch, GRAFANA_VIEWER_TOKEN=bad)
        with pytest.raises(SystemExit):
            setup.main(FLAGS)
        _env(monkeypatch, MATRIX_BOT_TOKEN=bad)
        with pytest.raises(SystemExit):
            setup.main(FLAGS)
    assert calls == []


def test_viewer_and_matrix_tokens_lose_surrounding_whitespace_only(setup, monkeypatch):
    calls = _record_docker(setup, monkeypatch)
    _env(monkeypatch, GRAFANA_VIEWER_TOKEN="  tok-VIEW-1234 \n", MATRIX_BOT_TOKEN="\tsyt_matrix_1234  ")
    assert setup.main(FLAGS) == setup.EXIT_DOMAIN_LOCK_UNVERIFIED
    sent = {json.loads(p)[0]["name"]: json.loads(json.loads(p)[0]["data"]["json"]) for _s, p in calls[1:]}
    assert sent["grafana-viewer-auth"] == {"headers": {"Authorization": "Bearer tok-VIEW-1234"}}
    assert sent["matrix-bot-auth"] == {"headers": {"Authorization": "Bearer syt_matrix_1234"}}


def test_viewer_credential_alone_rejects_empty_and_multiline_tokens(setup, monkeypatch):
    calls = _record_docker(setup, monkeypatch)
    for bad in ("", " \n ", "a\nb"):
        monkeypatch.setenv("GRAFANA_VIEWER_TOKEN", bad)
        with pytest.raises(SystemExit):
            setup.grafana_viewer_credentials()
    assert calls == []


@pytest.mark.parametrize("bad", ["", "short", "has space 12345", "semi;colon1234", "x" * 33, "../../etc/pass", "id\nid123456"])
def test_viewer_credential_id_must_pass_the_same_id_check(setup, monkeypatch, bad):  # GUARD
    calls = _record_docker(setup, monkeypatch)
    _env(monkeypatch)
    monkeypatch.setattr(setup, "CRED_GRAFANA_VIEWER_ID", bad)
    with pytest.raises(SystemExit):
        setup.main(["--credentials", "--with-grafana-viewer"])
    with pytest.raises(SystemExit):
        setup.grafana_viewer_credentials()
    assert calls == []


def test_every_credential_id_is_checked_and_defaults_pass(setup, monkeypatch):
    setup.check_credential_ids()
    for attr in ("CRED_HEADER_ID", "CRED_PUSHOVER_ID", "CRED_MATRIX_ID", "CRED_DISCORD_ID"):
        with monkeypatch.context() as m:
            m.setattr(setup, attr, "bad id!")
            with pytest.raises(SystemExit):
                setup.check_credential_ids()


@pytest.mark.parametrize("other", ["CRED_HEADER_ID", "CRED_PUSHOVER_ID", "CRED_MATRIX_ID", "CRED_DISCORD_ID"])
def test_viewer_credential_id_equal_to_another_credential_is_refused(setup, monkeypatch, other):  # GUARD
    calls = _record_docker(setup, monkeypatch)
    _env(monkeypatch)
    monkeypatch.setattr(setup, "CRED_GRAFANA_VIEWER_ID", getattr(setup, other))
    with pytest.raises(SystemExit) as err:
        setup.main(["--credentials", "--with-grafana-viewer"])
    assert "own id" in str(err.value)
    with pytest.raises(SystemExit):
        setup.grafana_viewer_credentials()
    assert calls == []


# --- issue #202 fix round 2: no secret on any error path, private credential file, host reminder ---------

CANARY = "CANARYTOKEN-9f3a7c51d2"
IMPORTERS = [("credentials", "credentials import exit code:"),
             ("matrix_credentials", "matrix credential import exit code:"),
             ("grafana_viewer_credentials", "grafana viewer credential import exit code:")]


def _canary_env(monkeypatch):
    _env(monkeypatch, GRAFANA_WEBHOOK_SECRET=CANARY + "-w", PUSHOVER_API_KEY=CANARY + "-p",
         PUSHOVER_USER_KEY=CANARY + "-u", MATRIX_BOT_TOKEN=CANARY + "-m", GRAFANA_VIEWER_TOKEN=CANARY + "-v")


class _Proc:
    def __init__(self, rc, out, err):
        self.returncode, self.stdout, self.stderr = rc, out, err


@pytest.mark.parametrize("fn,status_line", IMPORTERS)
@pytest.mark.parametrize("rc", [0, 1, 127])
def test_credential_import_never_prints_child_output(setup, monkeypatch, capsys, fn, status_line, rc):  # GUARD
    """The container runner returns the payload on both streams (what a failing CLI could do): nothing of it is shown."""
    _canary_env(monkeypatch)
    echoed = []

    def fake_engine_run(args, **kwargs):
        echoed.append(kwargs["input"])
        return _Proc(rc, kwargs["input"], kwargs["input"] + b"\nError: " + kwargs["input"])

    monkeypatch.setattr(setup, "engine_run", fake_engine_run)
    expected = setup.EXIT_DOMAIN_LOCK_UNVERIFIED if (fn == "grafana_viewer_credentials" and rc == 0) else rc
    assert getattr(setup, fn)() == expected
    seen = capsys.readouterr()
    assert echoed and CANARY.encode() in echoed[0], "the fake really did see the token"
    assert CANARY not in seen.out and CANARY not in seen.err
    assert status_line in seen.out


@pytest.mark.parametrize("fn,status_line", IMPORTERS)
def test_credential_import_lines_from_a_runner_are_ignored(setup, monkeypatch, capsys, fn, status_line):  # GUARD
    _canary_env(monkeypatch)
    monkeypatch.setattr(setup, "docker_in", lambda script, payload: (1, ["Authorization: Bearer " + CANARY, payload]))
    assert getattr(setup, fn)() == 1
    seen = capsys.readouterr()
    assert CANARY not in seen.out and CANARY not in seen.err and "Bearer" not in seen.out


@pytest.mark.parametrize("fn,status_line", IMPORTERS)
def test_credential_import_engine_errors_carry_no_secret(setup, monkeypatch, capsys, fn, status_line):  # GUARD
    _canary_env(monkeypatch)

    def boom(*a, **kw):
        raise setup.container_engine.ContainerEngineError("container engine is not usable")

    monkeypatch.setattr(setup.container_engine, "engine_run", boom)
    with pytest.raises(SystemExit) as err:
        getattr(setup, fn)()
    seen = capsys.readouterr()
    assert CANARY not in str(err.value) and CANARY not in seen.out and CANARY not in seen.err


def test_every_credential_import_uses_the_private_script(setup, monkeypatch):
    calls = _record_docker(setup, monkeypatch)
    _canary_env(monkeypatch)
    assert setup.main(FLAGS) == setup.EXIT_DOMAIN_LOCK_UNVERIFIED
    assert len(calls) == 3 and all(script == setup.CRED_IMPORT_SCRIPT for script, _p in calls)
    assert "/tmp/cred.json" not in setup.CRED_IMPORT_SCRIPT


_STUB = """#!/bin/sh
for a in "$@"; do case "$a" in --input=*) f=${a#--input=};; esac; done
d=$(dirname "$f")
{ echo "$f"; stat -c %a "$f"; stat -c %a "$d"; cat "$f"; } > "$REC"
echo "CANARY-OUT"; echo "CANARY-ERR" >&2
exit 3
"""


def _run_cred_script(script, tmp_path, payload, umask=0o000, use_shm=False, fs="ext4"):
    """Run the credential script under sh with a stub n8n; returns (result, record lines, listing of the temp base)."""
    import os
    stub = tmp_path / "bin"
    stub.mkdir(exist_ok=True)
    (stub / "n8n").write_text(_STUB, encoding="utf-8")
    (stub / "n8n").chmod(0o755)
    (stub / "stat").write_text('#!/bin/sh\ncase "$1" in -f) echo "$FSTYPE";; *) exec /usr/bin/stat "$@";; esac\n', encoding="utf-8")
    (stub / "stat").chmod(0o755)
    base = tmp_path / "base"
    base.mkdir(exist_ok=True)
    assert 'base=/tmp;' in script and 'shm=/dev/shm;' in script
    shm = tmp_path / "shm"
    shm.mkdir(exist_ok=True)
    local = script.replace('base=/tmp;', 'base=' + str(base) + ';').replace('shm=/dev/shm;', 'shm=' + str(shm if use_shm else tmp_path / "no-shm") + ';')
    rec = tmp_path / "rec.txt"
    env = {"PATH": str(stub) + ":" + os.environ["PATH"], "REC": str(rec), "FSTYPE": fs}
    r = subprocess.run(["sh", "-c", local], input=payload.encode(), capture_output=True, env=env, timeout=30,
                       preexec_fn=lambda: os.umask(umask))
    lines = rec.read_text(encoding="utf-8").splitlines() if rec.exists() else []
    if rec.exists():
        rec.unlink()
    return r, lines, sorted(p.name for d in (base, shm) for p in d.iterdir())


def check_cred_script(script, tmp_path, use_shm=True, fs="tmpfs"):
    names = set()
    memory = use_shm and fs == "tmpfs"
    for i in range(3):
        r, lines, left = _run_cred_script(script, tmp_path, "PAYLOAD-" + str(i) + "-" + CANARY, use_shm=use_shm, fs=fs)
        assert r.returncode == 3, "the n8n exit code must come back"
        assert r.stderr == b"", "n8n output is discarded inside the container"
        assert (r.stdout == b"") if memory else (r.stdout.decode().strip().startswith("warning: /dev/shm is not a memory-backed mount")), r.stdout
        assert b"CANARY-OUT" not in r.stdout and b"CANARY-ERR" not in r.stdout
        path, fmode, dmode, content = lines[0], lines[1], lines[2], "\n".join(lines[3:])
        assert fmode == "600" and dmode == "700", (fmode, dmode)
        assert content == "PAYLOAD-" + str(i) + "-" + CANARY
        assert re.search(r"/n8n-cred\.[A-Za-z0-9]{10}/c\.json$", path), path
        assert ("/shm/" in path) if memory else ("/base/" in path), "directory choice: " + path
        assert left == [], "the file and its directory are removed afterwards: " + str(left)
        names.add(path)
    assert len(names) == 3, "the file name is unpredictable: a fresh random directory every run"


def test_credential_script_creates_a_private_unpredictable_file_and_removes_it(setup, tmp_path):  # GUARD
    check_cred_script(setup.CRED_IMPORT_SCRIPT, tmp_path)


@pytest.mark.parametrize("use_shm,fs", [(True, "ext4"), (True, "overlay"), (True, ""), (False, "tmpfs")])
def test_credential_dir_falls_back_to_tmp_with_a_warning_unless_shm_is_memory_backed(setup, tmp_path, use_shm, fs):  # GUARD
    check_cred_script(setup.CRED_IMPORT_SCRIPT, tmp_path, use_shm=use_shm, fs=fs)


def test_credential_dir_choice_is_memory_backed_only_for_tmpfs(setup, tmp_path):
    """Negative case for the guard: a script that always picks the shm directory is caught on a non-tmpfs mount."""
    always = setup.CRED_IMPORT_SCRIPT.replace('= tmpfs ]', '= tmpfs ] || true')
    assert always != setup.CRED_IMPORT_SCRIPT
    with pytest.raises(AssertionError):
        check_cred_script(always, tmp_path, use_shm=True, fs="ext4")


def test_import_prints_only_the_fixed_fallback_warning(setup, monkeypatch, capsys):
    monkeypatch.setattr(setup, "docker_in", lambda script, payload: (0, [setup.WARN_NOT_TMPFS, "CANARYLEAK"]))
    assert setup.import_credential_records([{"a": 1}]) == 0
    out = capsys.readouterr().out
    assert setup.WARN_NOT_TMPFS in out and "CANARYLEAK" not in out


@pytest.mark.parametrize("old,new", [
    ("umask 077; ", ""),                                             # file would be 0644 under a normal umask
    ("trap 'rm -f \"$d/c.json\"; rmdir \"$d\"' EXIT HUP INT TERM; ", ""),   # nothing removes the plaintext
    (">/dev/null 2>&1", ""),                                         # n8n output would reach the caller
])
def test_mutant_credential_script_weakened_is_caught(setup, tmp_path, old, new):
    script = setup.CRED_IMPORT_SCRIPT
    assert script.count(old) == 1
    with pytest.raises(AssertionError):
        check_cred_script(script.replace(old, new), tmp_path)


def test_mutant_credential_script_with_a_fixed_name_is_caught(setup, tmp_path):
    script = setup.CRED_IMPORT_SCRIPT
    fixed = re.sub(r"d=\$\(mktemp -d [^)]*\) \|\| exit 70", "d=$base/n8n-cred.FIXED00000; mkdir -m 700 \"$d\" 2>/dev/null || true", script)
    assert fixed != script
    with pytest.raises(AssertionError):
        check_cred_script(fixed, tmp_path)


def test_viewer_import_prints_the_host_restriction_reminder_without_the_token(setup, monkeypatch, capsys):
    _canary_env(monkeypatch)
    _record_docker(setup, monkeypatch)
    assert setup.grafana_viewer_credentials() == setup.EXIT_DOMAIN_LOCK_UNVERIFIED
    out = capsys.readouterr().out
    assert "REQUIRED NEXT STEP" in out and "Allowed HTTP Request Domains" in out and "grafana-viewer-auth" in out
    assert "post-import check" in out and CANARY not in out


def test_viewer_import_failure_does_not_claim_a_next_step(setup, monkeypatch, capsys):
    _canary_env(monkeypatch)
    monkeypatch.setattr(setup, "docker_in", lambda script, payload: (1, []))
    assert setup.grafana_viewer_credentials() == 1
    assert "REQUIRED NEXT STEP" not in capsys.readouterr().out


def test_full_credentials_run_ends_with_the_reminder(setup, monkeypatch, capsys):
    _canary_env(monkeypatch)
    _record_docker(setup, monkeypatch)
    assert setup.main(FLAGS) == setup.EXIT_DOMAIN_LOCK_UNVERIFIED
    assert "sent to any https host that GRAFANA_BASE_URL names." in capsys.readouterr().out


# --- issue #202 fix round 3: distinct exit code for "imported, domain lock not verified" ------------------

def check_viewer_exit_code(setup, monkeypatch, capsys):
    assert setup.EXIT_DOMAIN_LOCK_UNVERIFIED == 40
    _canary_env(monkeypatch)
    _record_docker(setup, monkeypatch)
    for argv in (["--credentials", "--with-grafana-viewer"], FLAGS):
        assert setup.main(argv) == 40
    out = capsys.readouterr().out
    assert "REQUIRED NEXT STEP" in out and "exit code 40: imported, domain lock not verified" in out and CANARY not in out
    assert setup.main(["--credentials"]) == 0, "without the viewer the run is fully done"


def test_viewer_success_never_exits_zero_and_uses_the_documented_code(setup, monkeypatch, capsys):  # GUARD
    check_viewer_exit_code(setup, monkeypatch, capsys)


@pytest.mark.parametrize("rc", [1, 2, 3, 40, 127])
def test_viewer_import_failure_keeps_its_own_nonzero_code(setup, monkeypatch, capsys, rc):
    _canary_env(monkeypatch)
    monkeypatch.setattr(setup, "docker_in", lambda script, payload: (rc, []))
    got = setup.grafana_viewer_credentials()
    assert got == (1 if rc == 40 else rc) and got != setup.EXIT_DOMAIN_LOCK_UNVERIFIED and got != 0
    assert "domain lock not verified" not in capsys.readouterr().out


@pytest.mark.parametrize("rc", [3, 40])
def test_failed_import_code_never_equals_the_unverified_code_on_any_path(setup, monkeypatch, rc):
    _canary_env(monkeypatch)
    monkeypatch.setattr(setup, "engine_run", lambda args, **kw: _Proc(rc, b"", b""))
    for argv in (["--credentials"], ["--credentials", "--with-grafana-viewer"]):
        got = setup.main(argv)
        assert got != setup.EXIT_DOMAIN_LOCK_UNVERIFIED and got != 0, (argv, got)


def test_mutant_failure_mapping_removed_is_caught(setup, monkeypatch, capsys):
    monkeypatch.setattr(setup, "failure_code", lambda rc: rc)
    with pytest.raises(AssertionError):
        test_viewer_import_failure_keeps_its_own_nonzero_code(setup, monkeypatch, capsys, 40)


def test_mutant_viewer_success_returning_zero_is_caught(setup, monkeypatch, capsys):
    monkeypatch.setattr(setup, "EXIT_DOMAIN_LOCK_UNVERIFIED", 0)
    with pytest.raises(AssertionError):
        check_viewer_exit_code(setup, monkeypatch, capsys)


def test_runbook_explains_exit_code_3_and_the_accepted_residuals():
    run = " ".join((REPO_ROOT / "docs" / "live-deploy-runbook.md").read_text(encoding="utf-8").split())
    for needle in ("exit code 40", "imported, domain lock not verified", "/dev/shm"):
        assert needle in run, needle
    doc = " ".join((REPO_ROOT / "docs" / "update-digest.md").read_text(encoding="utf-8").split())
    for needle in ("Accepted residuals", "owner must accept", "before the workflow is activated", "no response size limit"):
        assert needle in doc, needle
