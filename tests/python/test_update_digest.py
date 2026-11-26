"""Guards for the weekly update digest workflow shell (issue #202): n8n/weekly-update-digest.json.

Node is REQUIRED: the Code node logic is executed for real, never string-matched. Each guarantee has
a check function; the real workflow must pass it and a mutated copy of the workflow must FAIL it
(revert-proof mutants), so a guard that cannot bite is caught here.
"""
import copy
import datetime as _dt
import json
import re
import shutil
import subprocess

import pytest

from conftest import REPO_ROOT

DIGEST = REPO_ROOT / "n8n" / "weekly-update-digest.json"
DOC = REPO_ROOT / "docs" / "update-digest.md"

NOW = "2026-11-30T12:00:00.000Z"  # Monday 07:00 America/New_York
COLLECTORS = ["UniFi Collector", "OS Packages Collector", "Twingate Collector", "pfSense Collector"]
FIELD_SOURCES = ["unifi", "os", "twingate", "pfsense"]
ZWSP = "\u200b"


def _wf():
    return json.loads(DIGEST.read_text(encoding="utf-8"))


def _node(wf, name):
    hits = [n for n in wf["nodes"] if n["name"] == name]
    assert len(hits) == 1, f"expected exactly one node named {name}"
    return hits[0]


def _js(wf, name):
    return _node(wf, name)["parameters"]["jsCode"]


def _run(js, ctx, static=None, now=NOW):
    """Run Code node source under node. ctx maps node name -> json (a missing name throws, like n8n)."""
    node = shutil.which("node")
    assert node, "node is required for these tests (it must not be skipped or faked)"
    harness = (
        "const ctx=" + json.dumps(ctx) + ";\n"
        "const sd=" + json.dumps(static or {}) + ";\n"
        "const REAL=Date;\n"
        "class FD extends REAL{constructor(...a){if(a.length){super(...a);}else{super(" + json.dumps(now) + ");}}"
        "static now(){return new REAL(" + json.dumps(now) + ").getTime();}}\n"
        "const $=(n)=>({first:()=>{if(!(n in ctx))throw new Error('no node '+n);return {json:ctx[n]};}});\n"
        "const f=new Function('$','$getWorkflowStaticData','Date'," + json.dumps(js) + ");\n"
        "const r=f($,()=>sd,FD);\n"
        "console.log(JSON.stringify({items:r,sd:sd}));"
    )
    r = subprocess.run([node, "-"], input=harness, capture_output=True, text=True, timeout=60)
    return r


def _ok_run(js, ctx, **kw):
    r = _run(js, ctx, **kw)
    if r.returncode != 0:
        raise RuntimeError("node failed (a broken mutant must not count as caught): " + r.stderr[-400:])
    return json.loads(r.stdout)


WINDOW = {"windowStart": "2026-11-23T12:00:00.000Z", "windowEnd": NOW}


def _src(status="ok", applied=None, pending=None, **extra):
    d = {"status": status, "applied": applied or [], "pending": pending or []}
    d.update(extra)
    return d


def _build(wf, sources=None, window=None):
    """sources: dict collector name -> json (default: all ok, empty). Returns the single output json."""
    ctx = {"Window": window or WINDOW}
    for c in COLLECTORS:
        ctx[c] = _src()
    ctx.update(sources or {})
    out = _ok_run(_js(wf, "Build Digest"), ctx)["items"]
    assert len(out) == 1, "the digest must emit exactly one item"
    return out[0]["json"]


# --- graph: no phone path, schedule only ---------------------------------------------------------

def check_no_phone_path(wf):
    blob = json.dumps(wf).lower()
    assert "pushover" not in blob, "no Pushover anything in the digest"
    assert "phone" not in blob, "no phone path in the digest"
    for n in wf["nodes"]:
        assert "pushover" not in n["type"].lower()
        for cred in (n.get("credentials") or {}):
            assert "pushover" not in cred.lower()
        assert not n["type"].endswith(".webhook"), "no webhook trigger: Schedule Trigger only"
        assert "trigger" not in n["type"].lower() or n["type"] == "n8n-nodes-base.scheduleTrigger"
    triggers = [n for n in wf["nodes"] if n["type"].lower().endswith("trigger")]
    assert len(triggers) == 1 and triggers[0]["type"] == "n8n-nodes-base.scheduleTrigger"
    for n in wf["nodes"]:
        if n["type"] == "n8n-nodes-base.httpRequest":
            url = n["parameters"]["url"]
            assert "/_matrix/client/" in url or "/api/ds/query" in url, "only Matrix and Grafana queries"


def test_digest_has_no_phone_path_and_schedule_trigger_only():
    check_no_phone_path(_wf())


def test_mutant_pushover_node_is_caught():
    wf = _wf()
    wf["nodes"].append({"parameters": {"url": "https://api.pushover.net/1/messages.json"},
                        "type": "n8n-nodes-base.httpRequest", "name": "Pushover Notify"})
    with pytest.raises(AssertionError):
        check_no_phone_path(wf)


def test_mutant_pushover_credential_is_caught():
    wf = _wf()
    _node(wf, "Matrix Digest")["credentials"]["pushoverApi"] = {"id": "x", "name": "pushover-api"}
    with pytest.raises(AssertionError):
        check_no_phone_path(wf)


def test_mutant_webhook_trigger_is_caught():
    wf = _wf()
    wf["nodes"].append({"parameters": {"path": "x"}, "type": "n8n-nodes-base.webhook", "name": "Extra Hook"})
    with pytest.raises(AssertionError):
        check_no_phone_path(wf)


def test_mutant_second_trigger_is_caught():
    wf = _wf()
    wf["nodes"].append({"parameters": {}, "type": "n8n-nodes-base.manualTrigger", "name": "Manual"})
    with pytest.raises(AssertionError):
        check_no_phone_path(wf)


def check_schedule(wf):
    t = _node(wf, "Weekly Schedule")
    assert t["type"] == "n8n-nodes-base.scheduleTrigger"
    rules = t["parameters"]["rule"]["interval"]
    assert len(rules) == 1 and rules[0] == {"field": "cronExpression", "expression": "0 7 * * 1"}
    assert wf["settings"]["timezone"] == "America/New_York"


def test_schedule_is_monday_0700_eastern():
    check_schedule(_wf())


def test_mutant_schedule_timezone_is_caught():
    wf = _wf()
    wf["settings"]["timezone"] = "UTC"
    with pytest.raises(AssertionError):
        check_schedule(wf)


def test_mutant_schedule_cron_is_caught():
    wf = _wf()
    _node(wf, "Weekly Schedule")["parameters"]["rule"]["interval"][0]["expression"] = "0 7 * * *"
    with pytest.raises(AssertionError):
        check_schedule(wf)


# --- graph: channels ------------------------------------------------------------------------------

def check_channels(wf):
    d = _node(wf, "Discord Digest")
    assert d["type"] == "n8n-nodes-base.discord"
    assert list(d["credentials"]) == ["discordWebhookApi"]
    m = _node(wf, "Matrix Digest")
    p = m["parameters"]
    assert m["type"] == "n8n-nodes-base.httpRequest" and p["method"] == "PUT"
    assert "/_matrix/client/v3/rooms/" in p["url"] and "/send/m.room.message/" in p["url"]
    assert "$env.MATRIX_HOMESERVER" in p["url"] and "$env.MATRIX_ROOM_ID" in p["url"]
    assert "msgtype: 'm.notice'" in p["jsonBody"]
    assert p["authentication"] == "genericCredentialType" and p["genericAuthType"] == "httpCustomAuth"
    assert m["credentials"] == {"httpCustomAuth": {"id": "YOUR_CREDENTIAL_ID", "name": "matrix-bot-auth"}}
    blob = json.dumps(wf)
    assert not re.search(r"https?://[^'\"]*(matrix|element|synapse)", blob, re.I), "no homeserver in JSON"
    assert not re.search(r"![A-Za-z0-9]+:[A-Za-z0-9.-]+", blob), "no literal room id in JSON"
    assert not re.search(r"(?i)bearer\s+[A-Za-z0-9_-]{8,}|syt_|access_token", blob), "no token in JSON"
    for n in wf["nodes"]:
        assert not n.get("disabled"), "no disabled nodes"


def test_channels_discord_webhook_and_matrix_put_with_env_and_credential():
    check_channels(_wf())


def test_mutant_matrix_hardcoded_homeserver_is_caught():
    wf = _wf()
    _node(wf, "Matrix Digest")["parameters"]["url"] = "https://matrix.example.org/_matrix/client/v3/rooms/x/send/m.room.message/1"
    with pytest.raises(AssertionError):
        check_channels(wf)


def test_mutant_matrix_wrong_method_is_caught():
    wf = _wf()
    _node(wf, "Matrix Digest")["parameters"]["method"] = "POST"
    with pytest.raises(AssertionError):
        check_channels(wf)


def test_mutant_matrix_wrong_msgtype_is_caught():
    wf = _wf()
    p = _node(wf, "Matrix Digest")["parameters"]
    p["jsonBody"] = p["jsonBody"].replace("m.notice", "m.text")
    with pytest.raises(AssertionError):
        check_channels(wf)


def test_mutant_matrix_credential_is_caught():
    wf = _wf()
    _node(wf, "Matrix Digest")["credentials"]["httpCustomAuth"]["name"] = "other"
    with pytest.raises(AssertionError):
        check_channels(wf)


def check_always_reaches_both_channels(wf):
    """Every node from the trigger to both sends is a plain pass-through: no IF/Filter/Switch that
    could swallow a quiet week, and the sends do not depend on each other succeeding."""
    edges = {}
    for src, conn in wf["connections"].items():
        for branch in conn["main"]:
            for c in branch:
                edges.setdefault(src, []).append(c["node"])
    seen, todo = set(), ["Weekly Schedule"]
    while todo:
        n = todo.pop()
        if n in seen:
            continue
        seen.add(n)
        todo.extend(edges.get(n, []))
    assert {"Build Digest", "Discord Digest", "Matrix Digest", "Record Window"} <= seen
    for n in wf["nodes"]:
        assert n["type"] not in ("n8n-nodes-base.if", "n8n-nodes-base.filter", "n8n-nodes-base.switch"), \
            "a branching node could swallow a quiet week"
    for name in ("Discord Digest", "Matrix Digest"):
        assert _node(wf, name).get("onError") == "continueRegularOutput", "one channel failing must not stop the other"


def test_every_run_reaches_both_channels():
    check_always_reaches_both_channels(_wf())


def test_mutant_if_node_is_caught():
    wf = _wf()
    wf["nodes"].append({"parameters": {}, "type": "n8n-nodes-base.if", "name": "Anything To Report?"})
    with pytest.raises(AssertionError):
        check_always_reaches_both_channels(wf)


def test_mutant_discord_failure_stops_run_is_caught():
    wf = _wf()
    del _node(wf, "Discord Digest")["onError"]
    with pytest.raises(AssertionError):
        check_always_reaches_both_channels(wf)


# --- collectors ----------------------------------------------------------------------------------

def test_os_collector_is_a_stub_pointing_at_219_and_others_are_real():
    wf = _wf()
    j = _ok_run(_js(wf, "OS Packages Collector"), {})["items"][0]["json"]
    assert j["status"] == "not-deployed" and "#219" in j["reason"] and j["applied"] == [] and j["pending"] == []
    for c in ("UniFi Collector", "Twingate Collector", "pfSense Collector"):
        assert "STUB" not in _js(wf, c), c
        # no query result at all: failed, never ok and never a silent not-deployed
        j = _ok_run(_js(wf, c), {})["items"][0]["json"]
        assert j["status"] == "failed", c


# --- window --------------------------------------------------------------------------------------

def _window(wf, last=None):
    static = {"lastDigestEnd": last} if last is not None else {}
    j = _ok_run(_js(wf, "Window"), {}, static=static)["items"][0]["json"]
    return j


def check_window(wf):
    assert _window(wf)["windowStart"] == "2026-11-23T12:00:00.000Z"                       # fallback 7 days
    assert _window(wf, "2026-11-23T12:00:00.000Z")["windowStart"] == "2026-11-23T12:00:00.000Z"
    assert _window(wf, "2026-11-27T00:00:00.000Z")["windowStart"] == "2026-11-27T00:00:00.000Z"
    assert _window(wf, "2026-09-01T00:00:00.000Z")["windowStart"] == "2026-11-16T12:00:00.000Z"  # cap 14 days
    assert _window(wf, "garbage")["windowStart"] == "2026-11-23T12:00:00.000Z"
    assert _window(wf, "2027-01-01T00:00:00.000Z")["windowStart"] == "2026-11-23T12:00:00.000Z"  # future
    assert _window(wf)["windowEnd"] == NOW


def test_window_from_last_digest_capped_14_days_fallback_7():
    check_window(_wf())


def test_mutant_window_cap_is_caught():
    wf = _wf()
    n = _node(wf, "Window")
    assert "14 * DAY" in n["parameters"]["jsCode"]
    n["parameters"]["jsCode"] = n["parameters"]["jsCode"].replace("14 * DAY", "60 * DAY")
    with pytest.raises(AssertionError):
        check_window(wf)


def test_mutant_window_fallback_is_caught():
    wf = _wf()
    n = _node(wf, "Window")
    n["parameters"]["jsCode"] = n["parameters"]["jsCode"].replace("7 * DAY", "1 * DAY")
    with pytest.raises(AssertionError):
        check_window(wf)


def test_record_window_advances_only_after_delivery():
    wf = _wf()
    js = _js(wf, "Record Window")
    ctx = {"Window": WINDOW, "Discord Digest": {"ok": True}, "Matrix Digest": {"ok": True}}
    assert _ok_run(js, ctx)["sd"]["lastDigestEnd"] == NOW
    ctx["Discord Digest"] = {"error": "boom"}
    assert _ok_run(js, ctx)["sd"]["lastDigestEnd"] == NOW      # one channel still delivered
    ctx["Matrix Digest"] = {"error": "boom"}
    r = _run(js, ctx)
    assert r.returncode != 0 and "delivery failed" in r.stderr   # both failed: error, window not advanced


# --- message: decision, sections, failed sources --------------------------------------------------

def test_message_shape_and_decision_sentence():
    wf = _wf()
    j = _build(wf, {
        "UniFi Collector": _src(applied=[{"name": "U7 Pro", "from": "6.6.1", "to": "6.6.2"}],
                                pending=[{"name": "USW-24", "version": "7.0.1"}]),
        "OS Packages Collector": _src(applied=[{"name": "openssl", "from": "3.0.1", "to": "3.0.2"}]),
        "Twingate Collector": _src("failed", reason="API 500"),
        "pfSense Collector": _src("not-deployed"),
    })
    assert j["title"] == "Weekly update digest: Nov 23, 2026 to Nov 30, 2026 (Eastern)"
    assert j["counts"] == {"applied": 2, "pending": 1, "notChecked": 2}
    d = j["description"]
    assert "2 applied, 1 still pending, 2 sources not checked" in d
    for sec in ("**Applied**", "**Still pending**", "**Not checked**"):
        assert sec in d
    assert "Twingate: check failed - API 500" in d and "pfSense: not deployed yet" in d
    assert j["sources"] == {"unifi": "ok", "os": "ok", "twingate": "failed", "pfsense": "not-deployed"}
    assert "Mondays 07:00 Eastern" in d
    assert j["allowed_mentions"] == {"parse": []}
    assert j["matrixBody"].startswith(j["title"]) and "**" not in j["matrixBody"]


def check_failed_source_not_zero(wf):
    j = _build(wf, {"UniFi Collector": _src("failed", reason="timeout")})
    assert j["counts"]["notChecked"] == 1
    assert "1 source not checked" in j["description"]
    assert "UniFi: check failed - timeout" in j["description"]
    # an unknown status, a collector error item and a missing collector are all failures too
    for bad in ({"status": "OK"}, {"error": "node crashed"}, {"status": "ok", "error": "x"}, None):
        ctx = {"Window": WINDOW, **{c: _src() for c in COLLECTORS[1:]}}
        if bad is not None:
            ctx["UniFi Collector"] = bad
        j = _ok_run(_js(wf, "Build Digest"), ctx)["items"][0]["json"]
        assert j["sources"]["unifi"] == "failed", bad
        assert j["counts"]["notChecked"] == 1, bad
        assert "0 applied, 0 still pending, 1 source not checked" in j["description"], bad


def test_failed_source_is_never_shown_as_zero_updates():
    check_failed_source_not_zero(_wf())


def test_mutant_unknown_status_treated_as_ok_is_caught():
    wf = _wf()
    n = _node(wf, "Build Digest")
    assert "const status = ok ? j.status : 'failed';" in n["parameters"]["jsCode"]
    n["parameters"]["jsCode"] = n["parameters"]["jsCode"].replace("const status = ok ? j.status : 'failed';",
                                                                   "const status = ok ? j.status : 'ok';")
    with pytest.raises(AssertionError):
        check_failed_source_not_zero(wf)


def test_mutant_failed_counted_as_checked_is_caught():
    wf = _wf()
    n = _node(wf, "Build Digest")
    assert "if (s.status !== 'ok') {" in n["parameters"]["jsCode"]
    n["parameters"]["jsCode"] = n["parameters"]["jsCode"].replace("if (s.status !== 'ok') {",
                                                                   "if (s.status === 'not-deployed') {")
    with pytest.raises(AssertionError):
        check_failed_source_not_zero(wf)


def test_failed_source_items_are_ignored():
    """A failed source that still carries lists must not leak them in as updates."""
    j = _build(_wf(), {"UniFi Collector": _src("failed", applied=[{"name": "x", "from": "1", "to": "2"}])})
    assert j["counts"]["applied"] == 0


# --- quiet week ------------------------------------------------------------------------------------

def check_quiet_week_sends(wf):
    j = _build(wf)
    assert "0 applied, 0 still pending, 0 sources not checked" in j["description"]
    assert "Nothing applied." in j["description"] and "All sources checked." in j["description"]
    assert j["title"] and j["matrixBody"]


def test_quiet_week_still_sends():
    check_quiet_week_sends(_wf())


def test_mutant_quiet_week_swallowed_is_caught():
    wf = _wf()
    n = _node(wf, "Build Digest")
    anchor = "return [{ json: out }];"
    assert anchor in n["parameters"]["jsCode"]
    n["parameters"]["jsCode"] = n["parameters"]["jsCode"].replace(
        anchor, "return out.counts.applied + out.counts.pending + out.counts.notChecked === 0 ? [] : [{ json: out }];")
    with pytest.raises(AssertionError):
        check_quiet_week_sends(wf)


# --- sanitization ----------------------------------------------------------------------------------

HOSTILE = [
    "@everyone", "@here", "<@123456789012345678>", "<@&123>", "<#123>", "[click](https://x.test)",
    "**bold**", "`code`", "~~s~~", "|spoiler|", "> quote", "# head", "a\nb\r\nc\x00d\u202ee",
    {"nested": "obj"}, ["list"], None, 12345, True,
]


def _hostile_sources():
    items_a = [{"name": h, "from": h, "to": h} for h in HOSTILE]
    items_p = [{"name": h, "version": h} for h in HOSTILE]
    items_a.insert(0, {"name": "L" * 300, "from": "F" * 300, "to": "T" * 300})
    return {
        "UniFi Collector": _src(applied=items_a, pending=items_p),
        "OS Packages Collector": _src(applied=["@everyone", 7, None], pending=[["x"], {"name": "@here"}]),
        "Twingate Collector": _src("failed", reason="<@123> @everyone " + "x" * 5000),
        "pfSense Collector": _src(applied="not a list", pending={"a": 1}),
    }


def check_sanitized(wf):
    j = _build(wf, _hostile_sources())
    for text in (j["description"], j["matrixBody"], j["title"]):
        assert not re.search(r"@(?!\u200b)", text), "a mention survived: " + text[:300]
        assert "\x00" not in text and "\u202e" not in text
        assert "[object Object]" not in text
    d = j["description"]
    assert not re.search(r"(?<!\\)<[@#]", d), "an unescaped mention or channel token survived"
    assert "\\*\\*bold\\*\\*" in d and "\\[click\\]" in d and "\\`code\\`" in d and "\\~\\~s\\~\\~" in d
    assert "\\|spoiler\\|" in d and "\\> quote" in d and "\\# head" in d
    assert "x" * 200 not in d, "reason text must be capped"
    assert "L" * 100 not in d and "F" * 100 not in d and "T" * 100 not in d, "item text must be capped"
    assert "\\(invalid\\)" in d and "nested" not in d, "non-string values are replaced, not serialized"
    assert j["allowed_mentions"] == {"parse": []}
    assert j["counts"]["notChecked"] == 1


def test_all_device_package_version_text_is_sanitized():
    check_sanitized(_wf())


def _mutate_build(old, new):
    wf = _wf()
    n = _node(wf, "Build Digest")
    if old not in n["parameters"]["jsCode"]:
        raise RuntimeError("mutation anchor not found: " + old)
    n["parameters"]["jsCode"] = n["parameters"]["jsCode"].replace(old, new)
    return wf


def test_mutant_mentions_not_broken_is_caught():
    with pytest.raises(AssertionError):
        check_sanitized(_mutate_build("s = s.replace(/@/g, '@\\u200b');", ""))


def test_mutant_markdown_not_escaped_is_caught():
    with pytest.raises(AssertionError):
        check_sanitized(_mutate_build("if (md) s = s.replace(", "if (false) s = s.replace("))


def test_mutant_non_string_not_coerced_is_caught():
    with pytest.raises(AssertionError):
        check_sanitized(_mutate_build("else if (v !== null && v !== undefined) s = '(invalid)';",
                                      "else if (v !== null && v !== undefined) s = JSON.stringify(v);"))


def test_mutant_reason_not_capped_is_caught():
    with pytest.raises(AssertionError):
        check_sanitized(_mutate_build("const REASON_MAX = 120;", "const REASON_MAX = 100000;"))


def test_mutant_control_chars_not_stripped_is_caught():
    with pytest.raises(AssertionError):
        check_sanitized(_mutate_build("s = s.replace(/[\\u0000-\\u001f", "s = s.replace(/[\\u0001-\\u0001"))


def test_garbage_collector_shapes_do_not_crash():
    j = _build(_wf(), {"UniFi Collector": "a string", "OS Packages Collector": 5,
                       "Twingate Collector": {"status": "ok", "applied": [[], [[]], 3]}})
    assert j["sources"]["unifi"] == "failed" and j["sources"]["os"] == "failed"


# --- truncation ------------------------------------------------------------------------------------

DISCORD_DESC = 4096
DISCORD_TOTAL = 6000


def check_truncation(wf):
    big = [{"name": f"package-{i}-" + "n" * 70, "from": "1." + "0" * 70, "to": "2." + "0" * 70} for i in range(1500)]
    pend = [{"name": f"pending-{i}-" + "p" * 70, "version": "v" * 70} for i in range(1500)]
    j = _build(wf, {"UniFi Collector": _src(applied=big, pending=pend),
                    "Twingate Collector": _src("failed", reason="r" * 400)})
    d = j["description"]
    assert len(d) <= DISCORD_DESC
    assert len(j["title"]) + len(d) <= DISCORD_TOTAL
    assert len(j["title"]) <= 256
    assert re.search(r"\+\d+ more", d), "truncation must say how many were dropped"
    assert j["counts"]["applied"] == 1500 and "1500 applied, 1500 still pending, 1 source not checked" in d
    # the Not checked section and the footer are never the part that gets cut
    assert "Twingate: check failed" in d and "Mondays 07:00 Eastern" in d
    assert len(j["matrixBody"]) <= 8000


def test_long_lists_are_truncated_under_discord_limits_with_more_marker():
    check_truncation(_wf())


def test_short_lists_are_not_truncated():
    j = _build(_wf(), {"UniFi Collector": _src(applied=[{"name": "a", "from": "1", "to": "2"}] * 5)})
    assert "more" not in j["description"] and j["description"].count("UniFi: a 1 -> 2") == 5


def test_mutant_no_description_cap_is_caught():
    with pytest.raises(AssertionError):
        check_truncation(_mutate_build("const DESC_MAX = 4000;", "const DESC_MAX = 400000;"))


def test_mutant_no_total_cap_is_caught():
    with pytest.raises(AssertionError):
        check_truncation(_mutate_build("const DESC_MAX = 4000;", "const DESC_MAX = 5990;"))


def test_mutant_no_more_marker_is_caught():
    with pytest.raises(AssertionError):
        check_truncation(_mutate_build("out.push('+' + rest + ' more');", "out.push('...');"))


def test_mutant_item_not_capped_is_caught():
    with pytest.raises(AssertionError):
        check_sanitized(_mutate_build("const ITEM_MAX = 80;", "const ITEM_MAX = 100000;"))


# --- docs --------------------------------------------------------------------------------------------

def test_doc_names_env_and_credentials_with_placeholders_only():
    text = DOC.read_text(encoding="utf-8")
    for needle in ("MATRIX_HOMESERVER", "MATRIX_ROOM_ID", "matrix-bot-auth", "Discord Webhook Alerts",
                   "not-deployed", "America/New_York", "14 days", "never"):
        assert needle in text, needle
    assert "\u2014" not in text, "no em dashes"
    assert not re.search(r"![A-Za-z0-9]{10,}:[A-Za-z0-9.-]+", text), "no real room id"
    assert not re.search(r"syt_[A-Za-z0-9]+", text), "no token"


# --- real collectors (Grafana data source query API) -------------------------------------------------

NOW_MS = int(_dt.datetime(2026, 11, 30, 12, 0, tzinfo=_dt.timezone.utc).timestamp() * 1000)
H = 3600 * 1000
REAL = {  # collector -> (query node, source key)
    "UniFi Collector": ("UniFi Query", "unifi"),
    "Twingate Collector": ("Twingate Query", "twingate"),
    "pfSense Collector": ("pfSense Query", "pfsense"),
}
QUERY_UIDS = {"UniFi Query": "influxdb-unifi", "Twingate Query": "influxdb-twingate", "pfSense Query": "influxdb-pfsense"}


def _frame(labels, points):
    return {"schema": {"fields": [{"name": "Time", "type": "time"},
                                  {"name": "v", "type": "number", "labels": labels}]},
            "data": {"values": [[t for t, _ in points], [v for _, v in points]]}}


def _res(*frames, **extra):
    d = {"status": 200, "frames": list(frames)}
    d.update(extra)
    return d


def _answer(**refs):
    return {"statusCode": 200, "body": {"results": refs}}


def _collect(wf, name, answer):
    qn = REAL[name][0]
    return _ok_run(_js(wf, name), {qn: answer})["items"][0]["json"]


def _unifi(wf, cur, ever=()):
    """cur: [(name, age_ms, upgradeable)], ever: [(name, count)]"""
    a = _res(*[_frame({"name": n}, [(NOW_MS - age, up)]) for n, age, up in cur])
    b = _res(*[_frame({"name": n}, [(NOW_MS - H, c)]) for n, c in ever])
    return _collect(wf, "UniFi Collector", _answer(A=a, B=b))


def _pfsense(wf, cur, ever=(), check=((0, 1),)):
    a = _res(*[_frame({"kind": k, "security": sec}, [(NOW_MS - age, v)]) for k, sec, age, v in cur])
    b = _res(*[_frame({"kind": k, "security": sec}, [(NOW_MS - H, v)]) for k, sec, v in ever])
    c = _res(*[_frame({}, [(NOW_MS - age, v)]) for age, v in check])
    return _collect(wf, "pfSense Collector", _answer(A=a, B=b, C=c))


def _twingate(wf, cur, ever=(), check=((0, 1),)):
    a = _res(*[_frame({"connector": n}, [(NOW_MS - age, v)]) for n, age, v in cur])
    b = _res(*[_frame({"connector": n}, [(NOW_MS - H, v)]) for n, v in ever])
    c = _res(*[_frame({}, [(NOW_MS - age, v)]) for age, v in check])
    return _collect(wf, "Twingate Collector", _answer(A=a, B=b, C=c))


def _good_answer(name):
    """A healthy, fresh answer (one pending item) for the named collector."""
    if name == "UniFi Collector":
        return _answer(A=_res(_frame({"name": "ap1"}, [(NOW_MS - 60000, True)])), B=_res())
    if name == "pfSense Collector":
        return _answer(A=_res(_frame({"kind": "core", "security": "false"}, [(NOW_MS - H, 1)])), B=_res(),
                       C=_res(_frame({}, [(NOW_MS - H, 1)])))
    return _answer(A=_res(_frame({"connector": "c1"}, [(NOW_MS - H, 2)])), B=_res(),
                   C=_res(_frame({}, [(NOW_MS - H, 1)])))


def check_collector_config(wf):
    for name, (qn, key) in REAL.items():
        n = _node(wf, qn)
        p = n["parameters"]
        assert n["type"] == "n8n-nodes-base.httpRequest" and p["method"] == "POST"
        assert "$env.GRAFANA_BASE_URL" in p["url"] and p["url"].endswith("'/api/ds/query' }}")
        assert not re.search(r"https?://", p["url"]), "base URL only from the environment"
        assert p["authentication"] == "genericCredentialType" and p["genericAuthType"] == "httpCustomAuth"
        assert n["credentials"] == {"httpCustomAuth": {"id": "YOUR_CREDENTIAL_ID", "name": "grafana-viewer-auth"}}
        o = p["options"]
        assert 0 < o["timeout"] <= 30000, "bounded timeout"
        assert o["redirect"]["redirect"]["followRedirects"] is False, "no redirects (the bearer token must not follow one)"
        assert o["response"]["response"] == {"fullResponse": True, "neverError": True}
        assert n.get("onError") == "continueRegularOutput"
        body = json.loads(p["jsonBody"])
        assert body["from"] == "now-7d" and body["to"] == "now"
        assert body["queries"] and all(q["datasource"]["uid"] == QUERY_UIDS[qn] for q in body["queries"])
        assert all(q["rawQuery"] is True and "now() - 7d" in q["query"] for q in body["queries"])
        assert all("SLIMIT" in q["query"] or "check_success" in q["query"] for q in body["queries"])
        assert _js(wf, name).count("MAX_BYTES") >= 2, "response size cap present"
    blob = json.dumps(wf)
    assert not re.search(r"(?i)bearer\s+[A-Za-z0-9_-]{8,}|glsa_", blob), "no token in JSON"


def test_collector_query_nodes_are_authenticated_bounded_and_do_not_redirect():
    check_collector_config(_wf())


@pytest.mark.parametrize("mutate", [
    lambda o: o["redirect"]["redirect"].update(followRedirects=True),
    lambda o: o.pop("timeout"),
    lambda o: o["response"]["response"].update(neverError=False),
])
def test_mutant_query_option_is_caught(mutate):
    wf = _wf()
    mutate(_node(wf, "pfSense Query")["parameters"]["options"])
    with pytest.raises((AssertionError, KeyError)):
        check_collector_config(wf)


def test_mutant_query_hardcoded_url_or_credential_is_caught():
    wf = _wf()
    _node(wf, "UniFi Query")["parameters"]["url"] = "https://grafana.example.org/api/ds/query"
    with pytest.raises(AssertionError):
        check_collector_config(wf)
    wf = _wf()
    _node(wf, "Twingate Query")["credentials"]["httpCustomAuth"]["name"] = "other"
    with pytest.raises(AssertionError):
        check_collector_config(wf)


def check_graph_order(wf):
    edges = {s: c["main"][0][0]["node"] for s, c in wf["connections"].items()}
    for qn, col in (("UniFi Query", "UniFi Collector"), ("Twingate Query", "Twingate Collector"),
                    ("pfSense Query", "pfSense Collector")):
        assert edges[qn] == col, "each query feeds its collector"
    assert edges["pfSense Collector"] == "Build Digest"


def test_query_nodes_feed_their_collectors():
    check_graph_order(_wf())


# -- failure is never "0 updates" --

BAD_ANSWERS = {
    "request error item": {"error": {"message": "ECONNREFUSED"}},
    "no item": None,
    "HTTP 401": {"statusCode": 401, "body": {"message": "Unauthorized"}},
    "HTTP 302 redirect": {"statusCode": 302, "body": ""},
    "HTTP 500": {"statusCode": 500, "body": {"results": {}}},
    "body not json": {"statusCode": 200, "body": "<html>login</html>"},
    "no results": {"statusCode": 200, "body": {}},
    "per-query error": _answer(A={"status": 400, "error": "bad query", "frames": []}, B=_res(), C=_res()),
    "missing ref": _answer(A=_res()),
    "frames not a list": _answer(A={"status": 200, "frames": "x"}, B=_res(), C=_res()),
    "malformed frame": _answer(A=_res({"schema": {}, "data": {}}), B=_res(), C=_res()),
    "bad timestamp": _answer(A=_res(_frame({"name": "a"}, [("x", True)])), B=_res(), C=_res()),
}


def check_failures_are_failed(wf):
    for name in REAL:
        for label, ans in BAD_ANSWERS.items():
            qn = REAL[name][0]
            ctx = {} if ans is None else {qn: ans}
            j = _ok_run(_js(wf, name), ctx)["items"][0]["json"]
            assert j["status"] == "failed", (name, label, j["status"])
            assert j["applied"] == [] and j["pending"] == [] and j["reason"], (name, label)


def test_query_failures_are_failed_never_ok_with_empty_lists():
    check_failures_are_failed(_wf())


def test_query_failure_never_renders_as_zero_updates_in_the_digest():
    wf = _wf()
    j = _collect(wf, "UniFi Collector", BAD_ANSWERS["HTTP 401"])
    out = _build(wf, {"UniFi Collector": j})
    assert out["counts"] == {"applied": 0, "pending": 0, "notChecked": 1}
    assert "UniFi: check failed - " in out["description"] and out["sources"]["unifi"] == "failed"


def test_grafana_error_text_is_not_copied_into_the_reason():
    j = _collect(_wf(), "UniFi Collector", {"statusCode": 500, "body": {"message": "SECRET-DETAIL"}})
    assert "SECRET-DETAIL" not in json.dumps(j)


def test_mutant_error_treated_as_ok_is_caught():
    wf = _wf()
    n = _node(wf, "UniFi Collector")
    anchor = "if (r.statusCode !== 200) return failed("
    assert anchor in n["parameters"]["jsCode"]
    n["parameters"]["jsCode"] = n["parameters"]["jsCode"].replace(anchor, "if (r.statusCode !== 200) return done('ok', '', [], []) || failed(")
    with pytest.raises(AssertionError):
        check_failures_are_failed(wf)


def test_mutant_request_error_treated_as_empty_is_caught():
    wf = _wf()
    n = _node(wf, "pfSense Collector")
    anchor = "if (r.error) return failed("
    assert anchor in n["parameters"]["jsCode"]
    n["parameters"]["jsCode"] = n["parameters"]["jsCode"].replace(anchor, "if (r.error) return done('ok') || failed(")
    with pytest.raises(AssertionError):
        check_failures_are_failed(wf)


# -- response size cap --

def check_size_caps(wf):
    for name in REAL:
        big = _good_answer(name)
        big["body"]["results"]["X"] = {"pad": "x" * 300000}
        j = _collect(wf, name, big)
        assert j["status"] == "failed" and "too large" in j["reason"], name
        many = _good_answer(name)
        many["body"]["results"]["A"]["frames"] = many["body"]["results"]["A"]["frames"] * 250
        j = _collect(wf, name, many)
        assert j["status"] == "failed" and j["pending"] == [], name
        pts = _good_answer(name)
        fr = pts["body"]["results"]["A"]["frames"][0]
        fr["data"]["values"] = [list(range(2500)), [True] * 2500]
        assert _collect(wf, name, pts)["status"] == "failed", name
        assert _collect(wf, name, _good_answer(name))["status"] == "ok", name


def test_oversized_answers_too_many_series_and_too_many_points_are_failed():
    check_size_caps(_wf())


@pytest.mark.parametrize("old,new", [
    ("const MAX_BYTES = 262144;", "const MAX_BYTES = 1e12;"),
    ("const MAX_SERIES = 200;", "const MAX_SERIES = 1e9;"),
    ("const MAX_POINTS = 2000;", "const MAX_POINTS = 1e9;"),
])
def test_mutant_size_cap_removed_is_caught(old, new):
    wf = _wf()
    n = _node(wf, "Twingate Collector")
    assert old in n["parameters"]["jsCode"]
    n["parameters"]["jsCode"] = n["parameters"]["jsCode"].replace(old, new)
    with pytest.raises(AssertionError):
        check_size_caps(wf)


# -- ok / not-deployed / stale --

def check_unifi(wf):
    j = _unifi(wf, [("ap1", 60000, True), ("sw1", 60000, False), ("sw2", 60000, False)], ever=[("sw2", 12)])
    assert j["status"] == "ok"
    assert j["pending"] == [{"name": "ap1", "version": "upgrade available"}]
    assert j["applied"] == [{"name": "sw2", "from": "upgrade pending", "to": "up to date"}]
    j = _unifi(wf, [("sw1", 60000, False)])
    assert j["status"] == "ok" and j["pending"] == [] and j["applied"] == []          # fresh and nothing pending
    # a device whose last point is old is not current: ignored while another device is fresh
    j = _unifi(wf, [("ap1", 60000, False), ("gone", 5 * H, True)])
    assert j["status"] == "ok" and j["pending"] == []
    # stale: newest point older than 2 hours is failed, never ok with an empty list
    j = _unifi(wf, [("ap1", 3 * H, True), ("sw1", 4 * H, False)])
    assert j["status"] == "failed" and "stale" in j["reason"] and j["pending"] == []
    j = _unifi(wf, [("ap1", 2 * H + 1, False)])
    assert j["status"] == "failed"
    # empty series: the source does not exist
    j = _unifi(wf, [])
    assert j["status"] == "not-deployed" and j["pending"] == []
    j = _collect(wf, "UniFi Collector", _answer(A={"status": 200}, B={"status": 200}))
    assert j["status"] == "not-deployed"


def test_unifi_collector_ok_stale_and_empty():
    check_unifi(_wf())


def _mutate(name, old, new):
    wf = _wf()
    n = _node(wf, name)
    assert old in n["parameters"]["jsCode"], old
    n["parameters"]["jsCode"] = n["parameters"]["jsCode"].replace(old, new)
    return wf


@pytest.mark.parametrize("old,new", [
    ("if (state.size === 0) return failed(", "if (false) return failed("),
    ("const FRESH_MS = 7200000;", "const FRESH_MS = 1e12;"),
    ("if (cur.length === 0) return done('not-deployed',", "if (cur.length === 0) return done('ok',"),
])
def test_mutant_unifi_proof_removed_is_caught(old, new):
    with pytest.raises(AssertionError):
        check_unifi(_mutate("UniFi Collector", old, new))


def check_pfsense(wf):
    j = _pfsense(wf, [("core", "false", H, 1), ("kernel", "true", H, 1), ("package", "false", H, 0),
                      ("package", "true", H, 0)], ever=[("package", "false", 1)])
    assert j["status"] == "ok"
    assert j["pending"] == [{"name": "core", "version": "update available"},
                            {"name": "kernel (security)", "version": "security update available"}]
    assert j["applied"] == [{"name": "package", "from": "update pending", "to": "up to date"}]
    j = _pfsense(wf, [("core", "false", H, 0)])
    assert j["status"] == "ok" and j["pending"] == [] and j["applied"] == []
    assert _pfsense(wf, [("core", "false", H, 1)], check=((14 * H, 1),))["status"] == "failed"   # stale check
    j = _pfsense(wf, [("core", "false", H, 0)], check=((H, 0),))                                 # check reported failure
    assert j["status"] == "failed" and j["pending"] == []
    j = _pfsense(wf, [("core", "false", H, 0)], check=())                                        # no proof of currency
    assert j["status"] == "failed" and "missing" in j["reason"]
    j = _pfsense(wf, [], check=())
    assert j["status"] == "not-deployed" and "#70" in j["reason"]


def test_pfsense_collector_ok_stale_failed_check_and_empty():
    check_pfsense(_wf())


@pytest.mark.parametrize("old,new", [
    ("if (!truthy(cp.v)) return failed(", "if (false) return failed("),
    ("if (chk.length === 0) return failed(", "if (false) return failed("),
    ("const FRESH_MS = 46800000;", "const FRESH_MS = 1e12;"),
    ("if (cur.length === 0 && chk.length === 0) return done('not-deployed',",
     "if (cur.length === 0 && chk.length === 0) return done('ok',"),
])
def test_mutant_pfsense_proof_removed_is_caught(old, new):
    with pytest.raises(AssertionError):
        check_pfsense(_mutate("pfSense Collector", old, new))


def check_twingate(wf):
    j = _twingate(wf, [("c1", H, 2), ("c2", H, 1), ("c3", H, 0), ("c4", H, 0)], ever=[("c3", 3)])
    assert j["status"] == "ok"
    assert j["pending"] == [{"name": "c1", "version": "2 releases behind"}, {"name": "c2", "version": "1 release behind"}]
    assert j["applied"] == [{"name": "c3", "from": "3 behind", "to": "current"}]
    assert _twingate(wf, [("c1", H, 0)])["pending"] == []
    assert _twingate(wf, [("c1", H, 2)], check=((4 * H, 1),))["status"] == "failed"
    assert _twingate(wf, [("c1", H, 0)], check=((H, 0),))["status"] == "failed"
    j = _twingate(wf, [("c1", H, 0)], check=())
    assert j["status"] == "failed" and "missing" in j["reason"]
    # not deployed yet: no series at all is not-deployed (not ok, not failed)
    j = _twingate(wf, [], check=())
    assert j["status"] == "not-deployed" and j["applied"] == [] and j["pending"] == []


def test_twingate_collector_ok_stale_failed_check_and_not_deployed():
    check_twingate(_wf())


@pytest.mark.parametrize("old,new", [
    ("const FRESH_MS = 10800000;", "const FRESH_MS = 1e12;"),
    ("if (!truthy(cp.v)) return failed(", "if (false) return failed("),
    ("if (cur.length === 0 && chk.length === 0) return done('not-deployed',",
     "if (cur.length === 0 && chk.length === 0) return done('ok',"),
])
def test_mutant_twingate_proof_removed_is_caught(old, new):
    with pytest.raises(AssertionError):
        check_twingate(_mutate("Twingate Collector", old, new))


# -- injection through device and connector names, end to end through Build Digest --

EVIL = ["@everyone <@123456789012345678> [x](https://evil.test) **b** `c`", "a\nb\u202ec\x00", "z" * 5000]


def check_injection(wf):
    ans_u = _answer(A=_res(*[_frame({"name": n}, [(NOW_MS - 60000, True)]) for n in EVIL],
                           _frame({"name": {"x": 1}}, [(NOW_MS - 60000, True)])), B=_res())
    ans_t = _answer(A=_res(*[_frame({"connector": n}, [(NOW_MS - H, 1)]) for n in EVIL]), B=_res(),
                    C=_res(_frame({}, [(NOW_MS - H, 1)])))
    ans_p = _answer(A=_res(_frame({"kind": EVIL[0], "security": "true"}, [(NOW_MS - H, 1)])), B=_res(),
                    C=_res(_frame({}, [(NOW_MS - H, 1)])))
    srcs = {"UniFi Collector": _collect(wf, "UniFi Collector", ans_u),
            "Twingate Collector": _collect(wf, "Twingate Collector", ans_t),
            "pfSense Collector": _collect(wf, "pfSense Collector", ans_p)}
    for j in srcs.values():
        assert j["status"] == "ok" and j["pending"], j
    out = _build(wf, srcs)
    d = out["description"]
    assert out["counts"]["pending"] == 8
    assert "@everyone" not in d and not re.search("@(?!" + ZWSP + ")", d) and "@" + ZWSP in d
    assert "[x](" not in d and "\\[x\\]\\(" in d and "**b**" not in d
    assert "\x00" not in d and "\u202e" not in d and "\\(invalid\\)" in d
    assert "z" * 100 not in d and len(d) <= 4096
    assert out["allowed_mentions"] == {"parse": []}
    assert "@everyone" not in out["matrixBody"] and "\x00" not in out["matrixBody"]
    for j in srcs.values():
        assert all(len(p["name"]) <= 120 for p in j["pending"]), "collector caps name length"


def test_hostile_device_connector_and_kind_names_are_neutralized_end_to_end():
    check_injection(_wf())


def test_mutant_collector_name_not_capped_or_coerced_is_caught():
    old = "function str(v) { return (typeof v === 'string' || typeof v === 'number') ? String(v).slice(0, NAME_MAX) : '(invalid)'; }"
    with pytest.raises((AssertionError, RuntimeError)):
        check_injection(_mutate("UniFi Collector", old, "function str(v) { return v; }"))


def test_mutant_digest_mention_break_removed_is_caught_with_collector_data():
    with pytest.raises(AssertionError):
        check_injection(_mutate("Build Digest", "s = s.replace(/@/g, '@\\u200b');", ""))


# -- docs --

def test_doc_covers_grafana_collectors():
    text = DOC.read_text(encoding="utf-8")
    for needle in ("GRAFANA_BASE_URL", "grafana-viewer-auth", "Viewer", "/api/ds/query", "#219",
                   "redirect", "response size", "stale", "applied"):
        assert needle in text, needle
    assert "\u2014" not in text
    assert not re.search(r"glsa_[A-Za-z0-9_]+", text), "no token"
