"""Guards for the Synology DSM update alert (issue #257): the Telegraf SNMPv3 example, the
provisioned Grafana rules (shipped paused), the router allow-list and the owner doc.

Collection is loose (fixed file list that must exist); the assertions are strict, and negative
cases prove the secret guard and the exclusive-range check bite.
"""
import json
import os
import re
import subprocess
import tomllib

import pytest
import yaml

from conftest import REPO_ROOT

CONF = REPO_ROOT / "docs" / "examples" / "synology-snmp-telegraf.conf.example"
RULES = REPO_ROOT / "docker" / "grafana" / "provisioning" / "alerting" / "update-alert-rules-synology.yml"
DOC = REPO_ROOT / "docs" / "synology-update-alert.md"
ROUTER = REPO_ROOT / "n8n" / "grafana-alert-router.json"
POLICY = REPO_ROOT / "docker" / "grafana" / "provisioning" / "alerting" / "update-notification-policy.yml.example"

OID_VERSION = ".1.3.6.1.4.1.6574.1.5.3.0"
OID_UPGRADE = ".1.3.6.1.4.1.6574.1.5.4.0"
SECRET_NAMES = ["SYNOLOGY_SNMP_AGENT", "SYNOLOGY_SNMP_USER", "SYNOLOGY_SNMP_AUTH_PASSWORD",
                "SYNOLOGY_SNMP_PRIV_PASSWORD", "SYNOLOGY_INFLUX_URL", "SYNOLOGY_INFLUX_USER",
                "SYNOLOGY_INFLUX_PASSWORD"]
SENSITIVE_KEY = re.compile(r"(password|passphrase|sec_name|username|secret|token|community)", re.I)
ENV_REF = re.compile(r"^\$\{[A-Z][A-Z0-9_]*:\?[A-Z][A-Z0-9_]* is required\}$")


def _conf():
    return tomllib.loads(CONF.read_text(encoding="utf-8"))


def literal_secrets(node, path=""):
    """Return the paths of sensitive keys whose value is not a pure ${ENV_VAR} reference."""
    bad = []
    if isinstance(node, dict):
        for k, v in node.items():
            if isinstance(v, (dict, list)):
                bad += literal_secrets(v, f"{path}.{k}")
            elif SENSITIVE_KEY.search(k) and not (isinstance(v, str) and ENV_REF.match(v)):
                bad.append(f"{path}.{k}")
    elif isinstance(node, list):
        for i, v in enumerate(node):
            bad += literal_secrets(v, f"{path}[{i}]")
    return bad


def _rules():
    data = yaml.safe_load(RULES.read_text(encoding="utf-8"))
    assert data["apiVersion"] == 1
    (group,) = data["groups"]
    return group, {r["uid"]: r for r in group["rules"]}


def _data(rule, ref):
    return next(d for d in rule["data"] if d["refId"] == ref)


# --- Telegraf example ------------------------------------------------------

def test_conf_parses_and_polls_snmpv3_authpriv_hourly():
    (snmp,) = _conf()["inputs"]["snmp"]
    assert snmp["version"] == 3 and snmp["sec_level"] == "authPriv"
    assert snmp["interval"] == "1h"
    assert snmp["agents"] == ["udp://${SYNOLOGY_SNMP_AGENT:?SYNOLOGY_SNMP_AGENT is required}:161"]
    # exact pair; SHA/AES is the documented compatibility residual (SYN-07), a weaker one must fail
    assert (snmp["auth_protocol"], snmp["priv_protocol"]) == ("SHA", "AES")
    fields = {f["name"]: f["oid"] for f in snmp["field"]}
    assert fields == {"dsm_version": OID_VERSION, "upgrade_available": OID_UPGRADE}
    assert snmp["name"] == "synology_dsm"
    assert snmp["tags"]["nas"] == "nas-example"


def test_conf_has_no_literal_secret_only_environment_references():
    conf = _conf()
    assert literal_secrets(conf) == []
    text = CONF.read_text(encoding="utf-8")
    for name in SECRET_NAMES:
        assert "${" + name + ":?" + name + " is required}" in text, name
    assert not re.search(r"\$\{[A-Z_]+\}", text), "a bare ${VAR} does not fail closed on unset or empty"
    (out,) = conf["outputs"]["influxdb"]
    assert out["database"] == "telegraf" and out["namepass"] == ["synology_dsm"]
    assert out["urls"] == ["${SYNOLOGY_INFLUX_URL:?SYNOLOGY_INFLUX_URL is required}"]


@pytest.mark.parametrize("bad", [
    {"inputs": {"snmp": [{"auth_password": "hunter2hunter2"}]}},
    {"inputs": {"snmp": [{"sec_name": "monitor"}]}},
    {"outputs": {"influxdb": [{"password": "x${A}"}]}},
    {"outputs": {"influxdb": [{"password": "${SYNOLOGY_INFLUX_PASSWORD}"}]}},  # bare form: not fail closed
    {"inputs": {"snmp": [{"community": "public"}]}},
])
def test_secret_guard_bites(bad):
    assert literal_secrets(bad) != []


def test_secret_guard_accepts_required_env_reference():
    ref = "${SYNOLOGY_INFLUX_PASSWORD:?SYNOLOGY_INFLUX_PASSWORD is required}"
    assert literal_secrets({"a": [{"password": ref}]}) == []


# --- Grafana rules ---------------------------------------------------------

def test_rules_are_the_four_expected_and_all_paused():
    group, rules = _rules()
    assert set(rules) == {"update-synology-pending-24h", "update-synology-pending-7d",
                          "update-synology-data-stale", "update-synology-check-failing"}
    assert group["folder"] == "Update Alerts"
    for uid, r in rules.items():
        assert r["isPaused"] is True, uid
        assert r["execErrState"] == "Alerting", uid
        # SYN-01: a dead poller must not page as "pending over 7 days"; the stale rule (phone false)
        # owns no data. Same as the UniFi pending rules (noDataState OK).
        want_nodata = "OK" if uid.startswith("update-synology-pending") else "Alerting"
        assert r["noDataState"] == want_nodata, uid
        assert r["labels"]["source"] == "synology" and r["labels"]["update_alert"] == "true", uid
        assert r["labels"]["alert_group"] == "updates", uid
        assert any(d["datasourceUid"] == "influxdb-twingate" for d in r["data"]), uid
        assert "synology_dsm" in json.dumps(r["data"]), uid


def test_severity_tier_and_phone_labels_follow_the_existing_update_pattern():
    _, rules = _rules()
    lab = {u: (r["labels"]["severity"], r["labels"]["tier"], r["labels"]["phone"]) for u, r in rules.items()}
    assert lab["update-synology-pending-24h"] == ("warning", "P2", "false")
    assert lab["update-synology-pending-7d"] == ("critical", "P1", "true")
    assert lab["update-synology-data-stale"] == ("warning", "P2", "false")
    assert lab["update-synology-check-failing"] == ("warning", "P2", "false")


def test_pending_rules_have_no_for_clock_and_share_one_bucket_query():
    _, rules = _rules()
    warn, crit = rules["update-synology-pending-24h"], rules["update-synology-pending-7d"]
    assert warn["for"] == crit["for"] == "0s"
    pw, pc = _data(warn, "P"), _data(crit, "P")
    assert pw["model"]["query"] == pc["model"]["query"]
    assert pw["relativeTimeRange"] == pc["relativeTimeRange"] == {"from": 604800, "to": 0}
    assert "GROUP BY time(1h)" in pw["model"]["query"] and '"upgrade_available" = 1' in pw["model"]["query"]


def bands(expr_w, expr_c):
    mw = re.fullmatch(r"\$B == 1 && \$Pc >= (\d+) && \$Pc < (\d+)", expr_w)
    mc = re.fullmatch(r"\$B == 1 && \$Pc >= (\d+)", expr_c)
    assert mw and mc, (expr_w, expr_c)
    return int(mw.group(1)), int(mw.group(2)), int(mc.group(1))


def check_exclusive(w_lo, w_hi, c_lo):
    assert (w_lo, w_hi, c_lo) == (24, 160, 160)
    for n in range(0, 208):
        w, c = w_lo <= n < w_hi, n >= c_lo
        assert not (w and c), f"overlap at {n}"
        expected = "none" if n < 24 else ("warning" if n < 160 else "critical")
        assert ("warning" if w else "critical" if c else "none") == expected, n


def test_warning_and_critical_are_exclusive_with_no_gap():
    _, rules = _rules()
    ew = _data(rules["update-synology-pending-24h"], "C")["model"]["expression"]
    ec = _data(rules["update-synology-pending-7d"], "C")["model"]["expression"]
    check_exclusive(*bands(ew, ec))


def test_exclusive_range_check_bites():
    with pytest.raises(AssertionError):
        check_exclusive(24, 170, 160)  # overlap
    with pytest.raises(AssertionError):
        check_exclusive(24, 150, 160)  # gap
    with pytest.raises(AssertionError):
        bands("$B > 0 && $Pc >= 24 && $Pc < 160", "$B == 1 && $Pc >= 160")


def test_check_failing_rule_fires_on_enum_3_or_4_only_and_persists():
    _, rules = _rules()
    r = rules["update-synology-check-failing"]
    expr = _data(r, "C")["model"]["expression"]
    # SYN-05: any fresh value outside {1, 2} (3, 4, 5, or anything unexpected) is a failed check
    assert expr == "$B != 1 && $B != 2"
    assert r["for"] == "6h"


def test_check_failing_truth_table():
    expr = _data(_rules()[1]["update-synology-check-failing"], "C")["model"]["expression"]
    fires = lambda b: eval(expr.replace("$B", str(b)).replace("&&", "and").replace("||", "or"))  # fixed repo expression, ints only
    assert [b for b in range(0, 8) if fires(b)] == [0, 3, 4, 5, 6, 7]


def test_data_stale_rule_watches_the_three_hour_window_for_the_hourly_poll():
    _, rules = _rules()
    r = rules["update-synology-data-stale"]
    assert _data(r, "A")["relativeTimeRange"] == {"from": 10800, "to": 0}
    assert "now() - 3h" in _data(r, "A")["model"]["query"]
    assert _data(r, "C")["model"]["conditions"][0]["evaluator"] == {"type": "lt", "params": [1]}


def test_titles_are_on_the_router_allow_list_and_policy_repeats_match():
    _, rules = _rules()
    wf = json.loads(ROUTER.read_text(encoding="utf-8"))
    js = next(n["parameters"]["jsCode"] for n in wf["nodes"] if "ALLOWED_ALERTNAMES" in n["parameters"].get("jsCode", ""))
    listed = set(re.findall(r"'([^']*)'", re.search(r"const ALLOWED_ALERTNAMES = \[(.*?)\];", js, re.S).group(1)))
    assert {r["title"] for r in rules.values()} <= listed
    routes = yaml.safe_load(POLICY.read_text(encoding="utf-8"))["policies"][0]["routes"][0]["routes"]
    rep = {next(m for m in r["object_matchers"] if m[0] == "severity")[2]: r["repeat_interval"] for r in routes}
    assert rep == {"warning": "84h", "critical": "24h"}


# --- Doc -------------------------------------------------------------------

def test_doc_covers_scope_limits_secrets_and_the_live_check():
    text = DOC.read_text(encoding="utf-8")
    for name in SECRET_NAMES:
        assert name in text, name
    for needle in ["snmpget -v3", OID_UPGRADE, OID_VERSION, "update-alert-rules-synology.yml",
                   "nas-example", "paused", "screenshot", "Packages", "authPriv", "isPaused",
                   "Not verified", "udp://", "telegraf"]:
        assert needle in text, needle


def test_doc_never_puts_a_passphrase_on_a_command_line():  # the -u/-A/-X scan covers every block
    text = DOC.read_text(encoding="utf-8")
    assert not re.search(r"\s-[AXaxu]\s+\S", re.sub(r"env( -u \w+)+", "env", text).replace("-v3", "")), "no -A/-X/-u option with a value"
    assert "SNMPCONFPATH" in text


# --- Doc commands (SYN-02, SYN-04) -------------------------------------------

def _block(marker):
    text = DOC.read_text(encoding="utf-8")
    for m in re.finditer(r"```\n(.*?)```", text, re.S):
        if m.group(1).startswith("# " + marker):
            return m.group(1)
    raise AssertionError("no doc block " + marker)


def _run(script, env, **kw):
    return subprocess.run(["bash", "-c", script], env=env, capture_output=True, text=True, timeout=30, **kw)


def _fake_tools(tmp_path):
    """siem-run and docker stand-ins that record that they ran and the SQL text they were fed."""
    bindir = tmp_path / "bin"
    bindir.mkdir()
    log = tmp_path / "calls.log"
    for name in ("siem-run", "docker"):
        (bindir / name).write_text(f'#!/bin/bash\necho "{name}" >> "{log}"\n'
                                   f'if [ "{name}" = siem-run ]; then bash -c "$3" >> "{log}" 2>&1; fi\n')
        (bindir / name).chmod(0o700)
    return bindir, log


@pytest.mark.parametrize("user,password,ok", [
    ("synology_wo", "pw-Ok_1.2@3", True),
    ('x"; DROP DATABASE "telegraf"; --', "pw-Ok_1.2@3", False),
    ('syn"x', "pw-Ok_1.2@3", False),
    ("synology_wo", "pw'x", False),
    ("synology_wo", "pw\\x", False),
    ("synology_wo", "pw\nDROP", False),
    ("", "pw-Ok_1.2@3", False),
    ("synology_wo", "", False),
    ("a b", "pw-Ok_1.2@3", False),
])
def test_the_one_account_script_validates_before_it_runs_anything_privileged(tmp_path, user, password, ok):
    bindir, log = _fake_tools(tmp_path)
    env = {"PATH": f"{bindir}:{os.environ['PATH']}", "SYNOLOGY_INFLUX_USER": user,
           "SYNOLOGY_INFLUX_PASSWORD": password}
    r = _run(_block("create-influx-account"), env)
    calls = log.read_text() if log.exists() else ""
    assert (r.returncode == 0) is ok, r.stderr
    assert ("siem-run" in calls) is ok, "a bad value must stop the script before the privileged call"
    if not ok:
        assert "DROP" not in calls


def test_there_is_no_separate_validation_block_to_skip():
    text = DOC.read_text(encoding="utf-8")
    assert "# validate-influx-names" not in text
    block = _block("create-influx-account")
    assert block.index("set -eu") < block.index("[!A-Za-z0-9_]") < block.index("siem-run")
    assert "docker exec -e SYNOLOGY_INFLUX_USER" in block and "SHOW GRANTS FOR" in block
    assert "-password" not in block


def test_pending_rules_use_the_unifi_no_data_and_error_states():
    # SYN-R2-01: same tuple as the UniFi pending rules (reviewed residual: a failed query can still page)
    unifi = yaml.safe_load((REPO_ROOT / "docker/grafana/provisioning/alerting/update-alert-rules-unifi.yml")
                           .read_text(encoding="utf-8"))["groups"][0]["rules"]
    ref = {(r["noDataState"], r["execErrState"], r["for"]) for r in unifi if "pending" in r["uid"]}
    _, rules = _rules()
    mine = {(r["noDataState"], r["execErrState"], r["for"]) for u, r in rules.items() if "pending" in u}
    assert ref == mine == {("OK", "Alerting", "0s")}


def _snmp_env(tmp_path, fake_body):
    bindir = tmp_path / "bin"
    bindir.mkdir()
    (bindir / "snmpget").write_text("#!/bin/bash\n" + fake_body)
    (bindir / "snmpget").chmod(0o700)
    run = tmp_path / "run"
    run.mkdir(mode=0o700)
    env = {"PATH": f"{bindir}:{os.environ['PATH']}", "XDG_RUNTIME_DIR": str(run),
           "SYNOLOGY_SNMP_AGENT": "nas.example.invalid", "SYNOLOGY_SNMP_USER": "monitor",
           "SYNOLOGY_SNMP_AUTH_PASSWORD": "authpass-123", "SYNOLOGY_SNMP_PRIV_PASSWORD": "privpass-456"}
    return env, run


def test_snmpget_script_removes_the_passphrase_file_on_success_failure_and_signal(tmp_path):
    script = _block("snmpget-confirm")
    probe = 'grep -q authpass-123 "$SNMPCONFPATH/snmp.conf" || exit 9\n'
    cases = {"ok": probe + "exit 0\n", "fail": probe + "exit 3\n",
             "term": probe + "kill -TERM $PPID; sleep 5\n", "int": probe + "kill -INT $PPID; sleep 5\n"}
    for name, body in cases.items():
        case_dir = tmp_path / name
        case_dir.mkdir()
        env, run = _snmp_env(case_dir, body)
        r = _run(script, env)
        assert list(run.iterdir()) == [], f"{name}: passphrase file left behind"
        assert "authpass-123" not in r.stdout + r.stderr and "privpass-456" not in r.stdout + r.stderr
        assert (r.returncode == 0) is (name == "ok"), (name, r.returncode, r.stderr)


def test_snmpget_does_not_inherit_the_passphrases(tmp_path):
    env, run = _snmp_env(tmp_path, 'env | grep -q "SYNOLOGY_SNMP_.*PASSWORD" && exit 7\nexit 0\n')
    r = _run(_block("snmpget-confirm"), env)
    assert r.returncode == 0, "snmpget saw a passphrase in its environment"


def test_snmpget_script_refuses_to_run_without_a_passphrase(tmp_path):
    env, run = _snmp_env(tmp_path, "exit 0\n")
    del env["SYNOLOGY_SNMP_PRIV_PASSWORD"]
    r = _run(_block("snmpget-confirm"), env)
    assert r.returncode != 0 and list(run.iterdir()) == []


def test_doc_states_bucket_semantics_and_the_value_five_rule():
    text = " ".join(DOC.read_text(encoding="utf-8").split())
    assert "hourly buckets" in text and "about 6 days 16 hours" in text
    assert "3, 4, 5" in text
    assert "SHA-2" in text
