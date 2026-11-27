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
    assert _window(wf, "2026-11-20T00:00:00.000Z")["windowStart"] == "2026-11-23T12:00:00.000Z"  # cap 7 days (the query lookback)
    assert _window(wf, "2026-09-01T00:00:00.000Z")["windowStart"] == "2026-11-23T12:00:00.000Z"
    assert _window(wf, "garbage")["windowStart"] == "2026-11-23T12:00:00.000Z"
    assert _window(wf, "2027-01-01T00:00:00.000Z")["windowStart"] == "2026-11-23T12:00:00.000Z"  # future
    assert _window(wf)["windowEnd"] == NOW


def test_window_from_last_digest_capped_7_days_fallback_7():
    check_window(_wf())


def test_mutant_window_cap_is_caught():
    wf = _wf()
    n = _node(wf, "Window")
    assert "CAP_MS = 7 * DAY" in n["parameters"]["jsCode"]
    n["parameters"]["jsCode"] = n["parameters"]["jsCode"].replace("CAP_MS = 7 * DAY", "CAP_MS = 14 * DAY")
    with pytest.raises(AssertionError):
        check_window(wf)


def test_mutant_window_fallback_is_caught():
    wf = _wf()
    n = _node(wf, "Window")
    n["parameters"]["jsCode"] = n["parameters"]["jsCode"].replace("FALLBACK_MS = 7 * DAY", "FALLBACK_MS = 1 * DAY")
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
    assert j["counts"] == {"applied": 2, "pending": 1, "notChecked": 2, "stale": 0}
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
                   "not-deployed", "America/New_York", "7 days", "never"):
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


def _ident(name, label):
    """The identity labels a collector requires, for a series called label."""
    return {"UniFi Collector": {"name": label}, "Twingate Collector": {"connector": label},
            "pfSense Collector": {"kind": label, "security": "false"}}[name]


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
        assert "$env.GRAFANA_BASE_URL" in p["url"] and "'/api/ds/query'" in p["url"]
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
        cap = int(re.search(r"const MAX_SERIES = (\d+);", _js(wf, name)).group(1))
        for q in body["queries"]:
            m = re.search(r"SLIMIT (\d+)", q["query"])
            assert m is None or int(m.group(1)) == cap + 1, "query limit is one above the series cap"
        lookbacks = {int(x) for q in body["queries"] for x in re.findall(r"now\(\) - (\d+)d", q["query"])}
        lookbacks |= {int(re.fullmatch(r"now-(\d+)d", body["from"]).group(1))}
        assert lookbacks == {WINDOW_CAP_DAYS(wf)}, "every query looks back as far as the Window node allows"
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
    assert out["counts"] == {"applied": 0, "pending": 0, "notChecked": 1, "stale": 0}
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
        many["body"]["results"]["A"]["frames"] = [_frame(_ident(name, "d%d" % i), [(NOW_MS - 60000, 1)]) for i in range(250)]
        j = _collect(wf, name, many)
        assert j["status"] == "failed" and j["pending"] == [], name
        pts = _good_answer(name)
        fr = pts["body"]["results"]["A"]["frames"][0]
        fr["data"]["values"] = [[NOW_MS - 60000 - i for i in range(2500)], [1] * 2500]
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
    # a device whose last point is old is not current: it never vanishes, it is listed as stale
    j = _unifi(wf, [("ap1", 60000, False), ("gone", 5 * H, True)])
    assert j["status"] == "ok" and j["pending"] == [] and j["stale"] == [{"name": "gone", "ageMs": 5 * H}]
    # stale: newest point older than 2 hours is failed, never ok with an empty list
    j = _unifi(wf, [("ap1", 3 * H, True), ("sw1", 4 * H, False)])
    assert j["status"] == "failed" and "stale" in j["reason"] and j["pending"] == []
    j = _unifi(wf, [("ap1", 2 * H + 1, False)])
    assert j["status"] == "failed"
    # empty series: the source does not exist
    j = _unifi(wf, [])
    assert j["status"] == "not-deployed" and j["pending"] == []
    j = _collect(wf, "UniFi Collector", _answer(A=_res(), B=_res()))
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

EVIL = ["@everyone <@123456789012345678> [x](https://evil.test) **b** `c`", "a\nb\u202ec\x00", "z" * 120]


def check_injection(wf):
    ans_u = _answer(A=_res(*[_frame({"name": n}, [(NOW_MS - 60000, True)]) for n in EVIL],
                           ), B=_res())
    ans_t = _answer(A=_res(*[_frame({"connector": n}, [(NOW_MS - H, 1)]) for n in EVIL]), B=_res(),
                    C=_res(_frame({}, [(NOW_MS - H, 1)])))
    ans_p = _answer(A=_res(_frame({"kind": EVIL[0], "security": "true"}, [(NOW_MS - H, 1)])), B=_res(),
                    C=_res(_frame({}, [(NOW_MS - H, 1)])))
    srcs = {"UniFi Collector": _collect(wf, "UniFi Collector", ans_u),
            "Twingate Collector": _collect(wf, "Twingate Collector", ans_t),
            "pfSense Collector": _collect(wf, "pfSense Collector", ans_p)}
    # round 3: the collectors now refuse hostile identities outright (a failed source, never data) ...
    for j in srcs.values():
        assert j["status"] == "failed" and j["pending"] == [], j
    # ... and the digest still neutralizes the same text if it ever arrives (defense in depth)
    srcs = {c: _src(pending=[{"name": n[:120], "version": "x"} for n in EVIL]) for c in ("UniFi Collector", "Twingate Collector")}
    srcs["pfSense Collector"] = _src(pending=[{"name": EVIL[0][:120] + " (security)", "version": "x"}])
    out = _build(wf, srcs)
    d = out["description"]
    assert out["counts"]["pending"] == 7
    assert "@everyone" not in d and not re.search("@(?!" + ZWSP + ")", d) and "@" + ZWSP in d
    assert "[x](" not in d and "\\[x\\]\\(" in d and "**b**" not in d
    assert "\x00" not in d and "\u202e" not in d
    assert "z" * 100 not in d and len(d) <= 4096
    assert out["allowed_mentions"] == {"parse": []}
    assert "@everyone" not in out["matrixBody"] and "\x00" not in out["matrixBody"]


def test_hostile_device_connector_and_kind_names_are_neutralized_end_to_end():
    check_injection(_wf())


def test_mutant_collector_name_not_capped_or_coerced_is_caught():
    old = "function str(v) { return (typeof v === 'string' || typeof v === 'number') ? String(v).slice(0, NAME_MAX) : '(invalid)'; }"
    for name in ALL:
        with pytest.raises(AssertionError):
            check_str_cap_and_coercion(_mut(name, old, "function str(v) { return v; }"))


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


# =================================================================================================
# Fix round 1 (adversarial review): stale series are listed, the lookback matches the window, bad
# values fail, truncation fails, the Grafana URL is guarded, and every guard has a test that bites.
# =================================================================================================

def WINDOW_CAP_DAYS(wf):
    return int(re.search(r"const CAP_MS = (\d+) \* DAY;", _js(wf, "Window")).group(1))


class _Worker:
    """One long-lived node process per Code node source: many cases, one process start (mutant runs stay fast)."""

    def __init__(self, js):
        node = shutil.which("node")
        assert node, "node is required for these tests (it must not be skipped or faked)"
        harness = (
            "const REAL=Date;\n"
            "const NOWV=" + json.dumps(NOW) + ";\n"
            "class FD extends REAL{constructor(...a){if(a.length){super(...a);}else{super(NOWV);}}"
            "static now(){return new REAL(NOWV).getTime();}}\n"
            "const rl=require('readline').createInterface({input:process.stdin});\n"
            "let f=null;\n"
            "rl.on('line',(line)=>{\n"
            "  if(f===null){f=new Function('$','$getWorkflowStaticData','Date',JSON.parse(line));return;}\n"
            "  let out;\n"
            "  try{const ctx=new Function('return ('+line+')')();\n"
            "    const $=(n)=>({first:()=>{if(!(n in ctx))throw new Error('no node '+n);return {json:ctx[n]};}});\n"
            "    out={ok:true,items:f($,()=>({}),FD)};}\n"
            "  catch(e){out={ok:false,err:String(e&&e.message)};}\n"
            "  process.stdout.write(JSON.stringify(out)+'\\n');\n"
            "});\n"
        )
        self.proc = subprocess.Popen([node, "-e", harness], stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                     stderr=subprocess.DEVNULL, text=True)
        self.proc.stdin.write(json.dumps(js) + "\n")
        self.proc.stdin.flush()

    def call(self, ctx):
        self.proc.stdin.write(json.dumps(ctx) + "\n")
        self.proc.stdin.flush()
        line = self.proc.stdout.readline()
        assert line, "collector worker died"
        return json.loads(line)

    def close(self):
        try:
            self.proc.stdin.close()
            self.proc.wait(timeout=10)
        except Exception:
            self.proc.kill()
            self.proc.wait()
        self.proc.stdout.close()


_WORKER = {"js": None, "w": None}


def _close_worker():
    if _WORKER["w"] is not None:
        _WORKER["w"].close()
    _WORKER["js"] = _WORKER["w"] = None


@pytest.fixture(scope="module", autouse=True)
def _worker_cleanup():
    yield
    _close_worker()


def _strict(wf, name, answer):
    """Run a collector; a crash is an AssertionError (a crashing mutant counts as caught, never as a pass)."""
    js = _js(wf, name)
    if _WORKER["js"] != js:
        _close_worker()
        _WORKER["js"], _WORKER["w"] = js, _Worker(js)
    qn = REAL[name][0]
    out = _WORKER["w"].call({qn: answer} if answer is not None else {})
    assert out["ok"], "collector crashed: " + str(out.get("err"))
    return out["items"][0]["json"]


class MutantSetupError(Exception):
    """A mutant whose target text is not in the source: a broken mutant must fail loudly, never count as caught."""


def _mut(name, old, new):
    wf = _wf()
    n = _node(wf, name)
    if n["parameters"]["jsCode"].count(old) != 1:
        raise MutantSetupError((name, old))
    n["parameters"]["jsCode"] = n["parameters"]["jsCode"].replace(old, new)
    return wf


def _mut_line(name, prefix, new_line):
    """Replace the whole source line that starts with prefix."""
    wf = _wf()
    n = _node(wf, name)
    lines = n["parameters"]["jsCode"].split("\n")
    idx = [i for i, ln in enumerate(lines) if ln.startswith(prefix)]
    if len(idx) != 1:
        raise MutantSetupError(prefix)
    lines[idx[0]] = new_line
    n["parameters"]["jsCode"] = "\n".join(lines)
    return wf


def _refs(name):
    return "AB" if name == "UniFi Collector" else "ABC"


def _one(name, label, t, v, extra_pts=()):
    """A one-series answer: ref A carries (t, v) and any extra points; B is empty; C (where used) is a fresh true check."""
    labels = {"UniFi Collector": {"name": label}, "Twingate Collector": {"connector": label},
              "pfSense Collector": {"kind": label, "security": "false"}}[name]
    refs = {"A": _res(_frame(labels, [(t, v), *extra_pts])), "B": _res()}
    if name != "UniFi Collector":
        refs["C"] = _res(_frame({}, [(NOW_MS - H, 1)]))
    return _answer(**refs)


def _with_ref(name, ref, res):
    ans = _good_answer(name)
    ans["body"]["results"][ref] = res
    return ans


def _raw_frame(fields, values):
    return {"schema": {"fields": fields}, "data": {"values": values}}


ALL = list(REAL)
NAN, INF, NINF = float("nan"), float("inf"), float("-inf")


# -- 1. a stale series never vanishes --

def check_stale_listed(wf):
    j = _unifi(wf, [("ap1", 60000, True), ("gone", 5 * H, True), ("old", 3 * H, False)])
    assert j["status"] == "ok" and j["pending"] == [{"name": "ap1", "version": "upgrade available"}]
    assert j["stale"] == [{"name": "gone", "ageMs": 5 * H}, {"name": "old", "ageMs": 3 * H}]
    j = _twingate(wf, [("c1", H, 2), ("c2", 4 * H, 1)])
    assert j["status"] == "ok" and [p["name"] for p in j["pending"]] == ["c1"]
    assert j["stale"] == [{"name": "c2", "ageMs": 4 * H}]
    j = _pfsense(wf, [("core", "false", H, 1), ("kernel", "false", 14 * H, 1)])
    assert j["status"] == "ok" and [p["name"] for p in j["pending"]] == ["core"]
    assert j["stale"] == [{"name": "kernel", "ageMs": 14 * H}]
    # every series stale: failed, never ok
    assert _unifi(wf, [("a", 3 * H, True), ("b", 9 * H, False)])["status"] == "failed"
    assert _twingate(wf, [("c1", 4 * H, 2), ("c2", 5 * H, 1)])["status"] == "failed"
    assert _pfsense(wf, [("core", "false", 14 * H, 1), ("kernel", "false", 15 * H, 1)])["status"] == "failed"
    # a series with no points at all is listed too
    a = _answer(A=_res(_frame({"name": "ap1"}, [(NOW_MS - 60000, False)]), _frame({"name": "empty"}, [])), B=_res())
    j = _strict(wf, "UniFi Collector", a)
    assert j["status"] == "ok" and j["stale"] == [{"name": "empty", "ageMs": None}]


def test_stale_series_are_listed_and_all_stale_is_failed():
    check_stale_listed(_wf())


@pytest.mark.parametrize("name,old,new", [
    ("UniFi Collector", "stale.push({ name, ageMs: lp ? now - lp.t : null }); continue;", "continue;"),
    ("Twingate Collector", "stale.push({ name, ageMs: lp ? now - lp.t : null }); continue;", "continue;"),
    ("pfSense Collector", "stale.push({ name, ageMs: lp ? now - lp.t : null }); continue;", "continue;"),
    ("UniFi Collector", "if (state.size === 0) return failed(", "if (false) return failed("),
    ("Twingate Collector", "if (seen === 0) return failed(", "if (false) return failed("),
    ("pfSense Collector", "if (seen === 0) return failed(", "if (false) return failed("),
    ("UniFi Collector", "return done('ok', '', applied, pending, stale);", "return done('ok', '', applied, pending);"),
])
def test_mutant_stale_listing_removed_is_caught(name, old, new):
    with pytest.raises(AssertionError):
        check_stale_listed(_mut(name, old, new))


def _stale_digest(wf, stale):
    return _build(wf, {"UniFi Collector": _src(pending=[{"name": "ap1", "version": "v"}], stale=stale)})


def check_digest_prints_stale(wf):
    out = _stale_digest(wf, [{"name": "gone", "ageMs": 5 * H + 10}, {"name": "m", "ageMs": 30 * 60000},
                             {"name": "d", "ageMs": 72 * H}, {"name": "fut", "ageMs": -H}, {"name": "nul", "ageMs": None}])
    d = out["description"]
    assert out["counts"]["stale"] == 5 and out["counts"]["notChecked"] == 0
    assert "5 stale series not checked" in d
    for line in ("UniFi: gone (not checked, stale: last data 5 h ago)", "UniFi: m (not checked, stale: last data 30 min ago)",
                 "UniFi: d (not checked, stale: last data 3 d ago)", "UniFi: fut (not checked, stale: timestamp in the future)",
                 "UniFi: nul (not checked, stale: no usable timestamp)"):
        assert line in d and line in out["matrixBody"], line
    assert out["color"] == 15105570, "stale series make the digest orange, not green"
    assert "1 stale series not checked" in _stale_digest(wf, [{"name": "x", "ageMs": H}])["description"]
    quiet = _stale_digest(wf, [])
    assert quiet["color"] == 3066993 and "stale" not in quiet["description"]
    # a failed source never prints a stale list; a hostile name is sanitized like every other name
    bad = _build(wf, {"UniFi Collector": _src("failed", reason="x", stale=[{"name": "zz", "ageMs": 1}])})
    assert bad["counts"]["stale"] == 0 and "zz" not in bad["description"]
    evil = _stale_digest(wf, [{"name": "@everyone [x](u)", "ageMs": H}, "plain", 7, None])["description"]
    assert "@everyone" not in evil and "[x](" not in evil
    # a long list is cut with a more marker inside the Not checked section; the footer survives
    many = _stale_digest(wf, [{"name": "n" + str(i), "ageMs": H} for i in range(200)])
    md = many["description"]
    assert many["counts"]["stale"] == 200 and len(md) <= 4096
    assert "more" in md.split("**Not checked**")[1] and "Mondays 07:00 Eastern" in md and "+ truncated" not in md


def test_digest_prints_every_stale_series_with_name_and_age():
    check_digest_prints_stale(_wf())


@pytest.mark.parametrize("old,new", [
    ("for (const x of s.stale) staleAll.push(", "for (const x of []) staleAll.push("),
    ("stale: status === 'ok' ? list(j.stale) : [],", "stale: [],"),
    ("if (ms < 0) return 'timestamp in the future';", ""),
    ("return h < 48 ? 'last data ' + h + ' h ago'", "return h < 0 ? 'last data ' + h + ' h ago'"),
    ("if (typeof ms !== 'number' || !isFinite(ms)) return 'no usable timestamp';", ""),
    ("const m = Math.floor(ms / 60000);", "const m = 0;"),
    ("fit(staleLines, STALE_BUDGET).text.split('\\n')", "staleLines"),
    ("(nStale ? ', ' + nStale", "(false ? ', ' + nStale"),
    ("color: (nNot === 0 && nStale === 0) ? 3066993 : 15105570,", "color: nNot === 0 ? 3066993 : 15105570,"),
])
def test_mutant_digest_stale_printing_is_caught(old, new):
    with pytest.raises(AssertionError):
        check_digest_prints_stale(_mutate("Build Digest", old, new))


# -- 2. the Window never claims more than the queries look back --

def test_window_cap_equals_every_query_lookback():
    wf = _wf()
    days = WINDOW_CAP_DAYS(wf)
    for qn in QUERY_UIDS:
        body = json.loads(_node(wf, qn)["parameters"]["jsonBody"])
        assert body["from"] == "now-%dd" % days
        assert all("now() - %dd" % days in q["query"] for q in body["queries"])
    assert _window(wf, "2026-09-01T00:00:00.000Z")["windowStart"] == "2026-11-23T12:00:00.000Z"


def test_mutant_query_lookback_not_matching_window_is_caught():
    wf = _wf()
    n = _node(wf, "Twingate Query")
    n["parameters"]["jsonBody"] = n["parameters"]["jsonBody"].replace("now() - 7d", "now() - 3d")
    with pytest.raises(AssertionError):
        check_collector_config(wf)
    wf = _wf()
    n = _node(wf, "UniFi Query")
    n["parameters"]["jsonBody"] = n["parameters"]["jsonBody"].replace('"from":"now-7d"', '"from":"now-14d"')
    with pytest.raises(AssertionError):
        check_collector_config(wf)
    wf = _wf()
    n = _node(wf, "Window")
    n["parameters"]["jsCode"] = n["parameters"]["jsCode"].replace("CAP_MS = 7 * DAY", "CAP_MS = 14 * DAY")
    with pytest.raises(AssertionError):
        check_collector_config(wf)


# -- 3. null, NaN and non-numeric values fail the source --

BAD_VALUES = [None, NAN, INF, "1", "true", {"x": 1}, [1]]


def check_bad_values_fail(wf):
    for name in ALL:
        for bad in BAD_VALUES:
            j = _strict(wf, name, _one(name, "d1", NOW_MS - 60000, bad))
            assert j["status"] == "failed" and j["pending"] == [] and j["applied"] == [], (name, bad)
            assert "is not a" in j["reason"], (name, bad, j["reason"])
        assert _strict(wf, name, _one(name, "d1", NOW_MS - 60000, 0))["status"] == "ok", name
    # the history query and the check series carry the same rule
    for name, ref in (("UniFi Collector", "B"), ("Twingate Collector", "B"), ("pfSense Collector", "B"),
                      ("Twingate Collector", "C"), ("pfSense Collector", "C")):
        for bad in (None, NAN, "1"):
            labels = {"name": "d1", "connector": "c1", "kind": "core", "security": "false"}
            j = _strict(wf, name, _with_ref(name, ref, _res(_frame(labels, [(NOW_MS - H, bad)]))))
            assert j["status"] == "failed" and j["pending"] == [], (name, ref, bad)
            assert "is not a" in j["reason"], (name, ref, bad, j["reason"])
    # Twingate counts are numbers: a boolean is not a count
    assert _strict(wf, "Twingate Collector", _one("Twingate Collector", "c1", NOW_MS - H, True))["status"] == "failed"


def test_null_nan_and_non_numeric_values_fail_the_source():
    check_bad_values_fail(_wf())


def test_a_bad_value_on_a_stale_series_is_listed_not_fatal():
    a = _answer(A=_res(_frame({"name": "ap1"}, [(NOW_MS - 60000, False)]), _frame({"name": "old"}, [(NOW_MS - 9 * H, None)])), B=_res())
    j = _strict(_wf(), "UniFi Collector", a)
    assert j["status"] == "ok" and j["stale"] == [{"name": "old", "ageMs": 9 * H}]


@pytest.mark.parametrize("name,old", [
    ("UniFi Collector", "if (!isBoolNum(lp.v)) return failed('UniFi current-state"),
    ("UniFi Collector", "if (!isNum(lp.v)) return failed('UniFi history"),
    ("Twingate Collector", "if (!isNum(lp.v)) return failed('Twingate connector"),
    ("Twingate Collector", "if (!isNum(lp.v)) return failed('Twingate history"),
    ("Twingate Collector", "if (!isBoolNum(cp.v)) return failed("),
    ("pfSense Collector", "if (!isBoolNum(lp.v)) return failed('pfSense update value"),
    ("pfSense Collector", "if (!isBoolNum(lp.v)) return failed('pfSense history"),
    ("pfSense Collector", "if (!isBoolNum(cp.v)) return failed("),
])
def test_mutant_value_validation_removed_is_caught(name, old):
    with pytest.raises(AssertionError):
        check_bad_values_fail(_mut(name, old, old.replace("if (!", "if (false && !", 1)))


@pytest.mark.parametrize("name", ["UniFi Collector", "Twingate Collector"])
@pytest.mark.parametrize("old,new", [
    ("const isNum = (v) => typeof v === 'number' && isFinite(v);", "const isNum = (v) => typeof v === 'number';"),
    ("const isNum = (v) => typeof v === 'number' && isFinite(v);", "const isNum = (v) => isFinite(v);"),
    ("const isBoolNum = (v) => typeof v === 'boolean' || isNum(v);",
     "const isBoolNum = (v) => typeof v === 'boolean' || typeof v === 'string' || isNum(v);"),
])
def test_mutant_value_type_predicates_are_caught(name, old, new):
    with pytest.raises(AssertionError):
        check_bad_values_fail(_mut(name, old, new))


# -- 4. truncated or empty answers do not pass as ok --

def check_truncation_fails(wf):
    for name in ALL:
        cap = int(re.search(r"const MAX_SERIES = (\d+);", _js(wf, name)).group(1))
        key = {"UniFi Collector": "name", "Twingate Collector": "connector", "pfSense Collector": "kind"}[name]

        def mk(n):
            return _res(*[_frame({key: "d%d" % i, "security": "false"}, [(NOW_MS - 60000, 0)]) for i in range(n)])
        assert _strict(wf, name, _with_ref(name, "A", mk(cap)))["status"] == "ok", (name, "exactly the cap is fine")
        j = _strict(wf, name, _with_ref(name, "A", mk(cap + 1)))
        assert j["status"] == "failed" and "too many series" in j["reason"], (name, "one over the cap: truncated")
        j = _strict(wf, name, _with_ref(name, "B", mk(cap + 1)))
        assert j["status"] == "failed" and "too many series" in j["reason"], (name, "B")
    # a current check with no current-state series is not a clean ok with zero entries
    j = _twingate(wf, [], check=((H, 1),))
    assert j["status"] == "failed" and "0 connectors" in j["reason"] and j["pending"] == []
    j = _pfsense(wf, [], check=((H, 1),))
    assert j["status"] == "failed" and "0 kinds" in j["reason"]


def test_query_limit_truncation_and_empty_current_state_fail():
    check_truncation_fails(_wf())


@pytest.mark.parametrize("name,old,new", [
    ("UniFi Collector", "res.frames.length > MAX_SERIES", "res.frames.length > MAX_SERIES + 1"),
    ("Twingate Collector", "res.frames.length > MAX_SERIES", "res.frames.length > MAX_SERIES + 1"),
    ("pfSense Collector", "res.frames.length > MAX_SERIES", "res.frames.length > MAX_SERIES + 1"),
    ("pfSense Collector", "res.frames.length > MAX_SERIES", "res.frames.length >= MAX_SERIES"),
    ("Twingate Collector", "if (cur.length === 0) return failed('the Twingate check is current",
     "if (false) return failed('the Twingate check is current"),
    ("pfSense Collector", "if (cur.length === 0) return failed('the pfSense check is current",
     "if (false) return failed('the pfSense check is current"),
])
def test_mutant_truncation_guard_removed_is_caught(name, old, new):
    with pytest.raises(AssertionError):
        check_truncation_fails(_mut(name, old, new))


@pytest.mark.parametrize("qn,old,new", [
    ("UniFi Query", "SLIMIT 201", "SLIMIT 200"),
    ("Twingate Query", "SLIMIT 201", "SLIMIT 200"),
    ("pfSense Query", "SLIMIT 51", "SLIMIT 50"),
])
def test_mutant_query_limit_equal_to_cap_is_caught(qn, old, new):
    wf = _wf()
    n = _node(wf, qn)
    assert old in n["parameters"]["jsonBody"]
    n["parameters"]["jsonBody"] = n["parameters"]["jsonBody"].replace(old, new)
    with pytest.raises(AssertionError):
        check_collector_config(wf)


# -- 5. the Grafana URL is https (plain http only for loopback) --

def _urls(wf, qn, bases):
    """Evaluate the node's URL expression for each base value (None = variable unset), in one node run."""
    expr = _node(wf, qn)["parameters"]["url"]
    assert expr.startswith("={{") and expr.endswith("}}")
    harness = ("const bases=" + json.dumps(bases) + ";\n"
               "const out=bases.map((b)=>{const $env=b===null?{}:{GRAFANA_BASE_URL:b};"
               "return new Function('$env','return (' + " + json.dumps(expr[3:-2]) + " + ')')($env);});\n"
               "process.stdout.write(JSON.stringify(out));")
    r = subprocess.run([shutil.which("node"), "-"], input=harness, capture_output=True, text=True, timeout=30)
    assert r.returncode == 0, r.stderr[-200:]
    return json.loads(r.stdout)


GOOD_URLS = {
    "https://grafana.example.org": "https://grafana.example.org/api/ds/query",
    "https://grafana.example.org/": "https://grafana.example.org/api/ds/query",
    "https://grafana.example.org:3000/sub//": "https://grafana.example.org:3000/sub/api/ds/query",
    "http://localhost:3000": "http://localhost:3000/api/ds/query",
    "http://127.0.0.1": "http://127.0.0.1/api/ds/query",
    "http://[::1]:3000/": "http://[::1]:3000/api/ds/query",
}
BAD_URLS = [None, "", "http://grafana.example.org", "ftp://grafana.example.org", "https://", "grafana.example.org",
            "http://localhost.evil.test", "http://127.0.0.1.evil.test", "http://localhost@evil.test",
            "https://user:pw@evil.test", "https://grafana.example.org?x=1", " https://grafana.example.org",
            "https://graf ana.example.org", "https://grafana.example.org\n", "http://localhost:80a"]


def check_grafana_url_guard(wf):
    for qn in QUERY_UIDS:
        got = _urls(wf, qn, list(GOOD_URLS) + BAD_URLS)
        for base, want, have in zip(list(GOOD_URLS) + BAD_URLS, list(GOOD_URLS.values()) + ["invalid-grafana-base-url"] * len(BAD_URLS), got):
            assert have == want, (qn, base, have)


def test_grafana_base_url_must_be_https_or_loopback_http():
    check_grafana_url_guard(_wf())


@pytest.mark.parametrize("old,new", [
    (r"https:\/\/[^\s", r"https?:\/\/[^\s"),
    (r"(localhost|127\.0\.0\.1|\[::1\])", r"(localhost|127\.0\.0\.1|\[::1\]|[a-z.]+)"),
    (r"[^\s\/?#@]+", r"[^\s\/?#]+"),
    (r"(\/[^\s?#]*)?$/", r"(\/[^\s?#]*)?/"),
    ("'/api/ds/query' : 'invalid-grafana-base-url'", "'/api/ds/query' : String($env.GRAFANA_BASE_URL)"),
])
def test_mutant_url_guard_weakened_is_caught(old, new):
    wf = _wf()
    for qn in QUERY_UIDS:
        n = _node(wf, qn)
        assert old in n["parameters"]["url"], old
        n["parameters"]["url"] = n["parameters"]["url"].replace(old, new)
    with pytest.raises(AssertionError):
        check_grafana_url_guard(wf)


# -- 6. one test per guard whose mutant survived --

def check_status_and_error_item(wf):
    for name in ALL:
        good = _good_answer(name)
        assert _strict(wf, name, good)["status"] == "ok"
        for code in (500, 401, 302, 204, "200", None):
            assert _strict(wf, name, dict(good, statusCode=code))["status"] == "failed", (name, code)
        assert _strict(wf, name, dict(good, error={"message": "ECONNREFUSED"}))["status"] == "failed", name
        assert _strict(wf, name, dict(good, error="x"))["status"] == "failed", name


def test_bad_status_or_error_item_with_a_valid_body_is_failed():
    check_status_and_error_item(_wf())


@pytest.mark.parametrize("name", ALL)
@pytest.mark.parametrize("old,new", [
    ("if (r.statusCode !== 200) return failed(", "if (false) return failed("),
    ("if (r.error) return failed(", "if (false) return failed("),
])
def test_mutant_status_or_error_guard_removed_is_caught(name, old, new):
    with pytest.raises(AssertionError):
        check_status_and_error_item(_mut(name, old, new))


def check_future_points(wf):
    soon = NOW_MS + 10 * 60000
    for name in ALL:
        # a series whose newest point is in the future is not current: listed, never pending
        ans = _one(name, "d1", soon, 1)
        ans["body"]["results"]["A"]["frames"].append(
            _frame({"name": "ok1", "connector": "ok1", "kind": "package", "security": "false"}, [(NOW_MS - 60000, 0)]))
        j = _strict(wf, name, ans)
        assert j["status"] == "ok" and j["pending"] == [], (name, j)
        assert len(j["stale"]) == 1 and j["stale"][0]["ageMs"] == -10 * 60000, (name, j)
        # all series in the future: failed
        assert _strict(wf, name, _one(name, "d1", soon, 1))["status"] == "failed", name
        # slightly ahead (clock skew under 5 minutes) is still current
        assert _strict(wf, name, _one(name, "d1", NOW_MS + 60000, 1))["status"] == "ok", name
    for name in ("Twingate Collector", "pfSense Collector"):
        ans = _good_answer(name)
        ans["body"]["results"]["C"] = _res(_frame({}, [(soon, 1)]))
        assert _strict(wf, name, ans)["status"] == "failed", name


def test_future_timestamps_are_not_current_for_series_and_checks():
    check_future_points(_wf())


@pytest.mark.parametrize("name", ALL)
def test_mutant_future_guard_removed_is_caught(name):
    with pytest.raises(AssertionError):
        check_future_points(_mut(name, "FUTURE_MS = 300000;", "FUTURE_MS = 1e15;"))


def check_time_values(wf):
    for name in ALL:
        for bad in ("x", "5", None, NAN, INF, NINF, True, [1]):
            j = _strict(wf, name, _one(name, "d1", bad, 1))
            assert j["status"] == "failed" and "malformed" in j["reason"], (name, bad, j)
    for name in ("Twingate Collector", "pfSense Collector"):
        ans = _good_answer(name)
        ans["body"]["results"]["C"] = _res(_frame({}, [(NAN, 1)]))
        j = _strict(wf, name, ans)
        assert j["status"] == "failed" and "malformed" in j["reason"], name


def test_non_finite_and_non_number_timestamps_are_failed():
    check_time_values(_wf())


@pytest.mark.parametrize("name", ALL)
@pytest.mark.parametrize("new", ["if (typeof t !== 'number')", "if (!isFinite(t))"])
def test_mutant_time_check_weakened_is_caught(name, new):
    with pytest.raises(AssertionError):
        check_time_values(_mut(name, "if (typeof t !== 'number' || !isFinite(t))", new))


def check_frame_shape(wf):
    t = [NOW_MS - 60000]
    tf = {"name": "Time", "type": "time"}
    vf = {"name": "value", "type": "number", "labels": {"name": "ap1", "connector": "ap1", "kind": "core", "security": "false"}}
    for name in ALL:
        def run(frame):
            return _strict(wf, name, _with_ref(name, "A", _res(frame)))

        def bad(frame):
            j = run(frame)
            assert j["status"] == "failed" and "malformed" in j["reason"], (name, frame, j)
        assert run(_raw_frame([tf, vf], [t, [1]]))["status"] == "ok", name
        bad(_raw_frame([tf, vf], [t, [1], [2]]))                       # more value arrays than fields
        bad(_raw_frame([tf, vf], [t]))                                 # fewer
        bad(_raw_frame([tf, vf], [t, [1, 0]]))                         # value column longer than the time column
        bad(_raw_frame([tf, vf], [[t[0], t[0]], [1]]))                 # time column longer
        bad({"schema": {"fields": "ab"}, "data": {"values": [[1], [2]]}})
        bad(_raw_frame([tf, vf], "x"))
        bad(_raw_frame([tf, vf], [t, "x"]))                            # value column is not an array
        bad(_raw_frame([tf, None], [t, [1]]))
        bad(_raw_frame([vf], [[1]]))                                   # no time field
        bad(_raw_frame([tf], [t]))                                     # no value field
        bad(None)
        n = 2001                                                       # more than MAX_POINTS points
        bad(_raw_frame([tf, vf], [[NOW_MS - 60000 - i for i in range(n)], [0] * n]))


def test_frame_length_and_shape_checks():
    check_frame_shape(_wf())


@pytest.mark.parametrize("name", ALL)
@pytest.mark.parametrize("old,new", [
    ("vals.length !== fields.length", "false"),
    ("vals[ti].length !== vals[vi].length ||", "false ||"),
    ("|| vals[ti].length > MAX_POINTS", "|| false"),
    ("if (fields.some((f) => !f || typeof f !== 'object')) return 'query ' + ref + ' answer malformed';", ""),
    ("!Array.isArray(vals[vi])", "false"),
    ("if (!Array.isArray(fields) ||", "if ("),
])
def test_mutant_frame_checks_removed_are_caught(name, old, new):
    with pytest.raises(AssertionError):
        check_frame_shape(_mut(name, old, new))


def check_newest_point(wf):
    for name in ALL:
        for pts in ([(NOW_MS - 60000, 1), (NOW_MS - 5 * H, 0)], [(NOW_MS - 5 * H, 0), (NOW_MS - 60000, 1)],
                    [(NOW_MS - 2 * H, 0), (NOW_MS - 60000, 1), (NOW_MS - 4 * H, 0)]):
            j = _strict(wf, name, _one(name, "d1", pts[0][0], pts[0][1], extra_pts=pts[1:]))
            assert j["status"] == "ok" and len(j["pending"]) == 1 and j["stale"] == [], (name, pts, j)
        # the NEWEST point decides: an old pending point, then a newer clear point
        j = _strict(wf, name, _one(name, "d1", NOW_MS - 5 * H, 1, extra_pts=[(NOW_MS - 60000, 0)]))
        assert j["status"] == "ok" and j["pending"] == [], (name, j)
    # the newest point of the one check series decides, whatever the point order
    for name, old in (("Twingate Collector", 20 * H), ("pfSense Collector", 30 * H)):
        for pts, ok in (([(old, 0), (H, 1)], True), ([(H, 1), (old, 0)], True),
                        ([(old, 1), (H, 0)], False), ([(H, 0), (old, 1)], False)):
            ans = _good_answer(name)
            ans["body"]["results"]["C"] = _res(_frame({}, [(NOW_MS - age, v) for age, v in pts]))
            assert (_strict(wf, name, ans)["status"] == "ok") == ok, (name, pts)


def test_newest_point_of_many_decides():
    check_newest_point(_wf())


@pytest.mark.parametrize("name", ALL)
@pytest.mark.parametrize("new", ["(a, b) => a", "(a, b) => b", "(a, b) => (b.t > a.t ? a : b)"])
def test_mutant_newest_point_selection_is_caught(name, new):
    with pytest.raises(AssertionError):
        check_newest_point(_mut(name, "(a, b) => (b.t >= a.t ? b : a)", new))


_ID_KEY = {"UniFi Collector": "name", "Twingate Collector": "connector", "pfSense Collector": "kind"}


def _no_fabrication(j, name, why):
    assert j["status"] == "failed" and j["pending"] == [] and j["applied"] == [], (name, why, j)


def check_duplicate_series(wf):
    """Split frames for one series, or two series with one identity, are never merged or fabricated."""
    for name in ALL:
        for order in ((1, 0), (0, 1)):
            for ref in "AB":
                frames = [_frame(_ident(name, "x1"), [(NOW_MS - 60000, v)]) for v in order]
                j = _strict(wf, name, _with_ref(name, ref, _res(*frames)))
                _no_fabrication(j, name, ("split", ref, order))
                assert "duplicate" in j["reason"], (name, ref, j)
    # the one check series is also never split
    for name in ("Twingate Collector", "pfSense Collector"):
        j = _strict(wf, name, _with_ref(name, "C", _res(*[_frame({}, [(NOW_MS - H, v)]) for v in (1, 0)])))
        _no_fabrication(j, name, "split check")
    # pfSense: kind "core (security)" with security false has the same display identity as kind core + security true
    j = _strict(wf, "pfSense Collector", _with_ref("pfSense Collector", "A", _res(
        _frame({"kind": "core (security)", "security": "false"}, [(NOW_MS - H, 1)]),
        _frame({"kind": "core", "security": "true"}, [(NOW_MS - H, 0)]))))
    _no_fabrication(j, "pfSense Collector", "display collision")
    # distinct identities stay distinct (core vs core + security)
    j = _strict(wf, "pfSense Collector", _with_ref("pfSense Collector", "A", _res(
        _frame({"kind": "core", "security": "false"}, [(NOW_MS - H, 1)]),
        _frame({"kind": "core", "security": "true"}, [(NOW_MS - H, 1)]))))
    assert j["status"] == "ok" and len(j["pending"]) == 2, j


def test_split_frames_and_duplicate_identities_are_failed_never_fabricated():
    check_duplicate_series(_wf())


_DUP_REMOVED = "    if (seenIds.has(id)) return 'query ' + ref + ' has duplicate series (split frames)';\n"


@pytest.mark.parametrize("name", ALL)
def test_mutant_duplicate_guard_removed_is_caught(name):
    with pytest.raises(AssertionError):
        check_duplicate_series(_mut(name, _DUP_REMOVED, ""))


def check_identities(wf):
    for name in ALL:
        key = _ID_KEY[name]
        good = _ident(name, "ok-1")
        assert _strict(wf, name, _with_ref(name, "A", _res(_frame({**good, key: "n" * 120}, [(NOW_MS - H, 1)]))))["status"] == "ok"
        bad_labels = [{k: v for k, v in good.items() if k != key}, {}]
        bad_labels += [{**good, key: v} for v in (None, "", "   ", 42, True, {"x": 1}, ["a"], "n" * 121)]
        if name == "pfSense Collector":
            bad_labels += [{k: v for k, v in good.items() if k != "security"}]
            bad_labels += [{**good, "security": v} for v in (None, "", "yes", "True", True, 1, False)]
        for labels in bad_labels:
            for ref in "AB":
                j = _strict(wf, name, _with_ref(name, ref, _res(_frame(labels, [(NOW_MS - H, 1)]))))
                _no_fabrication(j, name, (ref, labels))
                assert "identity" in j["reason"], (name, ref, labels, j)
    # an unnamed current series next to a valid history never becomes an item named "(invalid)"
    j = _strict(wf, "UniFi Collector", _answer(A=_res(_frame({}, [(NOW_MS - 60000, 0)])),
                                              B=_res(_frame({}, [(NOW_MS - H, 3)]))))
    _no_fabrication(j, "UniFi Collector", "unnamed")


def test_malformed_identities_are_failed_never_fabricated():
    check_identities(_wf())


_ID_LINES = {
    "UniFi Collector": [
        "const idOf = (l) => String(l.name);",
        "const idOf = (l) => (typeof l.name === 'string' && l.name.length <= NAME_MAX) ? l.name : null;",
        "const idOf = (l) => (typeof l.name === 'string' && l.name.trim() !== '') ? l.name : null;",
        "const idOf = (l) => (l.name !== undefined && l.name !== null && l.name !== '' && l.name.length <= NAME_MAX) ? String(l.name) : null;",
    ],
    "Twingate Collector": [
        "const idOf = (l) => String(l.connector);",
        "const idOf = (l) => (typeof l.connector === 'string' && l.connector.length <= NAME_MAX) ? l.connector : null;",
        "const idOf = (l) => (typeof l.connector === 'string' && l.connector.trim() !== '') ? l.connector : null;",
        "const idOf = (l) => (l.connector !== undefined && l.connector !== null && l.connector !== '' && l.connector.length <= NAME_MAX) ? String(l.connector) : null;",
    ],
    "pfSense Collector": [
        "const idOf = (l) => String(l.kind) + (l.security === 'true' ? ' (security)' : '');",
        "const idOf = (l) => (typeof l.kind === 'string' && l.kind.trim() !== '' && l.kind.length <= NAME_MAX) ? l.kind + (l.security === 'true' ? ' (security)' : '') : null;",
        "const idOf = (l) => (typeof l.kind === 'string' && l.kind.length <= NAME_MAX && (l.security === 'true' || l.security === 'false')) ? l.kind + (l.security === 'true' ? ' (security)' : '') : null;",
        "const idOf = (l) => (typeof l.kind === 'string' && l.kind.trim() !== '' && l.kind.length <= NAME_MAX) ? l.kind + (l.security === 'true' ? ' (security)' : '') : null;",
        "const idOf = (l) => (typeof l.kind === 'string' && l.kind.trim() !== '' && (l.security === 'true' || l.security === 'false')) ? l.kind + (l.security === 'true' ? ' (security)' : '') : null;",
    ],
}


@pytest.mark.parametrize("name,line", [(n, ln) for n, lines in _ID_LINES.items() for ln in lines])
def test_mutant_identity_validation_weakened_is_caught(name, line):
    with pytest.raises(AssertionError):
        check_identities(_mut_line(name, "const idOf", line))


@pytest.mark.parametrize("name", ALL)
def test_mutant_missing_identity_guard_removed_is_caught(name):
    old = "    if (id === null) return 'query ' + ref + ' series identity missing or invalid';\n"
    with pytest.raises(AssertionError):
        check_identities(_mut(name, old, ""))


def check_str_cap_and_coercion(wf):
    """str() now only renders the HTTP status in a reason: capped and coerced there."""
    for name in ALL:
        for code, test in (("n" * 500, lambda r: "n" * 120 in r and "n" * 121 not in r), ({"x": 1}, lambda r: "(invalid)" in r),
                           (None, lambda r: "(invalid)" in r), (404, lambda r: "404" in r)):
            r = _strict(wf, name, {"statusCode": code, "body": {}})
            assert r["status"] == "failed" and test(r["reason"]), (name, code, r)


def test_status_text_in_a_reason_is_capped_and_coerced_for_every_collector():
    check_str_cap_and_coercion(_wf())


@pytest.mark.parametrize("name", ALL)
@pytest.mark.parametrize("old,new", [
    ("String(v).slice(0, NAME_MAX)", "String(v)"),
    ("(typeof v === 'string' || typeof v === 'number') ?", "true ?"),
])
def test_mutant_name_cap_or_coercion_removed_is_caught(name, old, new):
    with pytest.raises(AssertionError):
        check_str_cap_and_coercion(_mut(name, old, new))


# -- fix round 2 (#202): partial, error-bearing and contradictory answers are failed, never ok or not-deployed --

def _bodied(name, **body_extra):
    ans = _good_answer(name)
    ans["body"].update(body_extra)
    return ans


def check_partial_answers(wf):
    for name in ALL:
        assert _strict(wf, name, _good_answer(name))["status"] == "ok", name
        # an error or message at the top of a 200 body, next to otherwise valid results
        for extra in ({"error": "partial backend failure"}, {"error": ""}, {"error": None}, {"message": "oops"}):
            j = _strict(wf, name, _bodied(name, **extra))
            _no_fabrication(j, name, extra)
        # extra or missing result refs
        ans = _good_answer(name)
        ans["body"]["results"]["Z"] = _res()
        _no_fabrication(_strict(wf, name, ans), name, "extra ref")
        # per-result: frames absent or not an array, status absent or not exactly 200, any error marker
        for ref in _refs(name):
            for res in ({"status": 200}, {"status": 200, "frames": None}, {"frames": []}, {"status": "200", "frames": []},
                        {"status": 200, "frames": [], "error": ""}, {"status": 200, "frames": [], "errorSource": "plugin"},
                        {"status": 207, "frames": []}):
                j = _strict(wf, name, _with_ref(name, ref, res))
                _no_fabrication(j, name, (ref, res))
        # history proves it was deployed but the current (and check) queries came back empty
        hist = _res(_frame(_ident(name, "d1"), [(NOW_MS - H, 2)]))
        ans = _answer(A=_res(), B=hist) if name == "UniFi Collector" else _answer(A=_res(), B=hist, C=_res())
        j = _strict(wf, name, ans)
        _no_fabrication(j, name, "history without current")
        assert "history" in j["reason"], (name, j)
        # every query empty and successful: not deployed
        empty = _answer(A=_res(), B=_res()) if name == "UniFi Collector" else _answer(A=_res(), B=_res(), C=_res())
        assert _strict(wf, name, empty)["status"] == "not-deployed", name


def test_partial_and_error_bearing_answers_are_failed_never_ok_or_not_deployed():
    check_partial_answers(_wf())


_BODY_ERR = "body.error !== undefined || body.message !== undefined"
_RES_ERR = "hasErr(res) || res.status !== 200"


@pytest.mark.parametrize("name", ALL)
@pytest.mark.parametrize("old,new", [
    (_BODY_ERR, "body.message !== undefined"),
    (_BODY_ERR, "body.error !== undefined"),
    (_BODY_ERR, "false"),
    ("if (gotRefs.length !== EXPECTED.length) return", "if (false) return"),
    (_RES_ERR, "res.status !== 200"),
    (_RES_ERR, "hasErr(res)"),
    (_RES_ERR, "hasErr(res) || (res.status !== undefined && res.status !== 200)"),
    ("const ERR_KEYS = ['error', 'errorSource', 'message', 'errors'];", "const ERR_KEYS = ['errorSource', 'message', 'errors'];"),
    ("const ERR_KEYS = ['error', 'errorSource', 'message', 'errors'];", "const ERR_KEYS = ['error', 'message', 'errors'];"),
    ("if (!Array.isArray(res.frames)) return", "if (res.frames === undefined || res.frames === null) return []; if (false) return"),
])
def test_mutant_partial_answer_guard_removed_is_caught(name, old, new):
    with pytest.raises(AssertionError):
        check_partial_answers(_mut(name, old, new))


@pytest.mark.parametrize("name,old,new", [
    ("UniFi Collector", "if (cur.length === 0 && ever.length === 0)", "if (cur.length === 0)"),
    ("UniFi Collector", "if (cur.length === 0) return failed('UniFi history exists", "if (false) return failed('UniFi history exists"),   # reason text must still name the history
    ("Twingate Collector", "chk.length === 0 && mx.length > 0) return failed(", "chk.length === 0 && false) return failed("),
    ("pfSense Collector", "chk.length === 0 && mx.length > 0) return failed(", "chk.length === 0 && false) return failed("),
])
def test_mutant_history_without_current_guard_removed_is_caught(name, old, new):
    with pytest.raises(AssertionError):
        check_partial_answers(_mut(name, old, new))


def check_ref_errors(wf):
    for name in ALL:
        for ref in _refs(name):
            for res in ({"status": 400, "error": "bad query", "frames": []}, {"status": 500, "frames": []},
                        {"error": "x"}, "x", None, {"status": 200, "frames": {"a": 1}}):
                j = _strict(wf, name, _with_ref(name, ref, res))
                assert j["status"] == "failed" and j["pending"] == [], (name, ref, res)
            ans = _good_answer(name)
            del ans["body"]["results"][ref]
            assert _strict(wf, name, ans)["status"] == "failed", (name, ref, "missing")


def test_an_error_in_any_query_of_the_answer_fails_the_source():
    check_ref_errors(_wf())


@pytest.mark.parametrize("name,old", [
    ("UniFi Collector", "if (typeof cur === 'string') return failed(cur);"),
    ("UniFi Collector", "if (typeof ever === 'string') return failed(ever);"),
    ("Twingate Collector", "if (typeof cur === 'string') return failed(cur);"),
    ("Twingate Collector", "if (typeof mx === 'string') return failed(mx);"),
    ("Twingate Collector", "if (typeof chk === 'string') return failed(chk);"),
    ("pfSense Collector", "if (typeof cur === 'string') return failed(cur);"),
    ("pfSense Collector", "if (typeof mx === 'string') return failed(mx);"),
    ("pfSense Collector", "if (typeof chk === 'string') return failed(chk);"),
])
def test_mutant_query_error_handling_removed_is_caught(name, old):
    with pytest.raises(AssertionError):
        check_ref_errors(_mut(name, old, ""))


@pytest.mark.parametrize("name", ALL)
@pytest.mark.parametrize("old,new", [
    ("if (hasErr(res) || res.status !== 200)", "if (res.error)"),
    ("if (hasErr(res) || res.status !== 200)", "if (hasErr(res))"),
    ("if (!res || typeof res !== 'object') return 'query ' + ref + ' missing from the answer';", ""),
    ("if (!Array.isArray(res.frames)) return", "if (false) return"),
])
def test_mutant_per_query_guard_removed_is_caught(name, old, new):
    with pytest.raises(AssertionError):
        check_ref_errors(_mut(name, old, new))


# -- truthy handling, and 8: any positive number is pending, not only 1 --

def check_pending_values(wf):
    for name in ("UniFi Collector", "pfSense Collector"):
        for v, pending in ((True, 1), (1, 1), (2, 1), (7.5, 1), (False, 0), (0, 0), (-1, 0)):
            j = _strict(wf, name, _one(name, "d1", NOW_MS - 60000, v))
            assert j["status"] == "ok" and len(j["pending"]) == pending, (name, v, j)
    # history: a positive number that is not 1 still counts as "was pending", so the clear is applied
    ans = _one("pfSense Collector", "core", NOW_MS - 60000, 0)
    for v, applied in ((2, True), (True, True), (1, True), (0, False), (False, False)):
        ans["body"]["results"]["B"] = _res(_frame({"kind": "core", "security": "false"}, [(NOW_MS - H, v)]))
        j = _strict(wf, "pfSense Collector", ans)
        assert (j["applied"] == [{"name": "core", "from": "update pending", "to": "up to date"}]) == applied, (v, j)
    # check success: true or 1 only
    for name in ("Twingate Collector", "pfSense Collector"):
        for v, ok in ((True, True), (1, True), (False, False), (0, False), (2, False), (-1, False)):
            ans = _good_answer(name)
            ans["body"]["results"]["C"] = _res(_frame({}, [(NOW_MS - H, v)]))
            assert (_strict(wf, name, ans)["status"] == "ok") == ok, (name, v)


def test_pending_values_positive_number_or_true_and_check_success_true_or_one():
    check_pending_values(_wf())


@pytest.mark.parametrize("name", ["UniFi Collector", "pfSense Collector"])
@pytest.mark.parametrize("new", [
    "const pendingVal = (v) => v === 1;",
    "const pendingVal = (v) => typeof v === 'number' && v > 0;",
    "const pendingVal = (v) => v === true || v === 1;",
    "const pendingVal = (v) => v === true || (typeof v === 'number' && v >= 0);",
    "const pendingVal = (v) => !!v;",
])
def test_mutant_pending_predicate_is_caught(name, new):
    with pytest.raises(AssertionError):
        check_pending_values(_mut_line(name, "const pendingVal", new))


@pytest.mark.parametrize("name", ["Twingate Collector", "pfSense Collector"])
@pytest.mark.parametrize("new", [
    "const successVal = (v) => v === 1;",
    "const successVal = (v) => v === true;",
    "const successVal = (v) => v === true || v >= 1;",
    "const successVal = (v) => v === true || v >= 0;",
])
def test_mutant_check_success_predicate_is_caught(name, new):
    with pytest.raises(AssertionError):
        check_pending_values(_mut_line(name, "const successVal", new))


# -- 9. the value field is chosen by name; ambiguity fails --

def check_value_field_selection(wf):
    tf = {"name": "Time", "type": "time"}
    lab = {"name": "ap1", "connector": "ap1", "kind": "core", "security": "false"}
    host = {"name": "host", "type": "string"}

    def num(field_name):
        return {"name": field_name, "type": "number", "labels": lab}
    t = [NOW_MS - 60000]
    for name in ALL:
        def run(fields, values):
            return _strict(wf, name, _with_ref(name, "A", _res(_raw_frame(fields, values))))
        # an extra non-time field before or after the value field: the named one is used
        j = run([tf, host, num("last")], [t, ["h1"], [1]])
        assert j["status"] == "ok" and len(j["pending"]) == 1, (name, j)
        j = run([tf, num("last"), host], [t, [0], ["h1"]])
        assert j["status"] == "ok" and j["pending"] == [], (name, j)
        j = run([host, tf, num("value")], [["h1"], t, [1]])
        assert j["status"] == "ok" and len(j["pending"]) == 1, (name, j)
        # a single non-time field is used whatever it is called
        assert run([tf, num("weird")], [t, [1]])["status"] == "ok", name
        # ambiguity fails: two value-named fields, two unnamed fields, an unnamed one beside a host field, two time fields
        for fields, values in (([tf, num("last"), num("max")], [t, [1], [0]]), ([tf, num("a"), num("b")], [t, [1], [0]]),
                               ([tf, host, num("x")], [t, ["h"], [1]]), ([tf, {"name": "T2", "type": "time"}, num("last")], [t, t, [1]])):
            j = run(fields, values)
            assert j["status"] == "failed" and "malformed" in j["reason"], (name, fields, j)


def test_value_field_is_selected_by_name_and_ambiguity_fails():
    check_value_field_selection(_wf())


@pytest.mark.parametrize("name", ALL)
@pytest.mark.parametrize("old,new", [
    ("if (others.length === 1) vi = others[0];", "if (others.length >= 1) vi = others[0];"),
    ("if (named.length === 1) vi = named[0];", "if (named.length >= 1) vi = named[0];"),
    ("if (named.length === 1) vi = named[0];", "if (others.length >= 1) vi = others[0];"),
    ("const named = others.filter((i) => VALUE_NAMES.includes(fields[i].name));", "const named = others;"),
    ("const named = others.filter((i) => VALUE_NAMES.includes(fields[i].name));", "const named = others.slice(-1);"),
    ("const ti = times.length === 1 ? times[0] : -1;", "const ti = times.length >= 1 ? times[0] : -1;"),
])
def test_mutant_value_field_selection_is_caught(name, old, new):
    with pytest.raises(AssertionError):
        check_value_field_selection(_mut(name, old, new))


# -- docs --

def test_doc_covers_round_1_review_fixes():
    text = " ".join(DOC.read_text(encoding="utf-8").split())
    for needle in ("not checked (stale)", "every series of a source is stale", "https", "loopback", "Allowed HTTP Request Domains",
                   "N8N_BLOCK_ENV_ACCESS_IN_NODE=false", "datasources:query", "one above", "7 days",
                   "boolean or a finite number", "0 connectors"):
        assert needle in text, needle
    assert "older devices are ignored" not in text and "are ignored)" not in text
    assert "14 days" not in text and "max 14" not in text
    assert "—" not in text


# =================================================================================================
# Fix round 2 (adversarial review round 1): query design bounds the answer, and the docs are honest
# about what code cannot close (download size, host restriction of the credential).
# =================================================================================================

def check_query_design(wf):
    """Every series query is one aggregate with no time grouping (one point per series) and a series limit."""
    seen = 0
    for qn in QUERY_UIDS:
        body = json.loads(_node(wf, qn)["parameters"]["jsonBody"])
        for q in body["queries"]:
            sql = q["query"]
            seen += 1
            assert re.match(r'SELECT (last|max|count)\("', sql), (qn, sql)
            assert not re.search(r"group by[^;]*time\(", sql, re.I), (qn, sql)
            if re.search(r"group by", sql, re.I):
                assert re.search(r"SLIMIT \d+$", sql), (qn, sql)
    assert seen == 8, seen


def test_queries_return_one_point_per_series_with_a_series_limit():
    check_query_design(_wf())


def _mut_query(old, new):
    wf = _wf()
    hit = 0
    for qn in QUERY_UIDS:
        n = _node(wf, qn)
        if old in n["parameters"]["jsonBody"]:
            n["parameters"]["jsonBody"] = n["parameters"]["jsonBody"].replace(old, new, 1)
            hit += 1
            break
    if hit != 1:
        raise MutantSetupError(old)
    return wf


@pytest.mark.parametrize("old,new", [
    ("SELECT last(", "SELECT ("),                                    # raw points: every sample returned
    ("GROUP BY \\\"name\\\" SLIMIT 201", "GROUP BY \\\"name\\\", time(1m) SLIMIT 201"),   # a point per minute per series
    ("GROUP BY \\\"name\\\" SLIMIT 201", "GROUP BY \\\"name\\\""),   # no series limit
])
def test_mutant_unbounded_query_design_is_caught(old, new):
    with pytest.raises(AssertionError):
        check_query_design(_mut_query(old, new))


def test_doc_round_2_is_honest_about_what_code_cannot_close():
    text = " ".join(DOC.read_text(encoding="utf-8").split())
    for needle in ("no option to cap the response size", "compromised or fake Grafana", "memory limit",
                   "required step, not an optional hardening", "cannot lock it to a host",
                   "post-import check", "not-deployed", "exactly one series",
                   "split frames", "read 2026-11-26"):
        assert needle in text, needle
    assert "the real bound on download size is the `SLIMIT`" not in text
    run = " ".join((REPO_ROOT / "docs" / "live-deploy-runbook.md").read_text(encoding="utf-8").split())
    for needle in ("post-import check", "Allowed HTTP Request Domains", "mktemp -d", "umask 077", "trap",
                   "no stdin form is documented", "dummy token"):
        assert needle in run, needle


# -- fix round 3: frame-level errors and identity normalization --

def _with_notice(name, **notice):
    a = _good_answer(name)
    a["body"]["results"]["A"]["frames"][0]["schema"]["meta"] = {"notices": [notice]}
    return a


def check_frame_errors(wf):
    for name in REAL:
        assert _collect(wf, name, _good_answer(name))["status"] == "ok", name
        info = _with_notice(name, severity="info", text="ok")
        assert _collect(wf, name, info)["status"] == "ok", name
        for notice in ({"severity": "error", "text": "partial result"}, {"severity": "ERROR", "text": "x"},
                       {"text": "no severity"}, {"severity": "fatal", "text": "x"}):
            j = _collect(wf, name, _with_notice(name, **notice))
            assert j["status"] == "failed" and j["pending"] == [] and "partial result" not in json.dumps(j), (name, notice)
        bad = _good_answer(name)
        bad["body"]["results"]["A"]["frames"][0]["schema"]["meta"] = {"notices": "x"}
        assert _collect(wf, name, bad)["status"] == "failed", name
        bad = _good_answer(name)
        bad["body"]["results"]["A"]["frames"][0]["error"] = "boom"
        assert _collect(wf, name, bad)["status"] == "failed", name
        # error-bearing keys at the result, frame, schema and data levels, not only schema.meta
        for where in ("result", "frame", "schema", "data", "meta"):
            for key, val in (("notices", [{"severity": "error"}]), ("notices", []), ("message", "x"), ("errors", ["x"]), ("errorSource", "plugin")):
                bad = _good_answer(name)
                res = bad["body"]["results"]["A"]
                fr = res["frames"][0]
                target = {"result": res, "frame": fr, "schema": fr["schema"], "data": fr["data"]}.get(where)
                if where == "meta":
                    if key == "notices":
                        continue
                    fr["schema"]["meta"] = {key: val}
                else:
                    target[key] = val
                j = _collect(wf, name, bad)
                assert j["status"] == "failed" and j["pending"] == [], (name, where, key)


@pytest.mark.parametrize("name", list(REAL))
@pytest.mark.parametrize("old,new", [
    ("(o.notices !== undefined || ", "(false || "),
    ("hasErr(fr.data)", "false"),
    ("hasErr(fr) ||", "false ||"),
    ("if (hasErr(res) || res.status", "if (res.status"),
    ("ERR_KEYS.some((k) => fr.schema.meta[k] !== undefined)", "false"),
])
def test_mutant_error_keys_at_other_levels_are_caught(name, old, new):
    wf = _mutate(name, old, new)
    with pytest.raises(AssertionError):
        check_frame_errors(wf)


def test_frame_level_error_notices_make_the_source_failed():
    check_frame_errors(_wf())


@pytest.mark.parametrize("name", list(REAL))
def test_mutant_frame_error_check_removed_is_caught(name):
    wf = _wf()
    n = _node(wf, name)
    old = "!['info', 'warning'].includes(String(ntc.severity).toLowerCase())"
    assert old in n["parameters"]["jsCode"]
    n["parameters"]["jsCode"] = n["parameters"]["jsCode"].replace(old, "false")
    with pytest.raises(AssertionError):
        check_frame_errors(wf)


def _named(wf, name, label, label2=None):
    frames = [_frame(_ident(name, label), [(NOW_MS - 60000, 1)])]
    if label2 is not None:
        frames.append(_frame(_ident(name, label2), [(NOW_MS - 60000, 1)]))
    a = _good_answer(name)
    a["body"]["results"]["A"]["frames"] = frames
    return _collect(wf, name, a)


E_ACUTE = chr(0xE9)
E_COMBINING = "e" + chr(0x301)
CYR_A = chr(0x430)
GREEK_ALPHA = chr(0x3B1)


def check_identities(wf):
    for name in REAL:
        assert _named(wf, name, "caf" + E_ACUTE)["status"] == "ok", name
        # canonically equivalent spellings are one identity: two frames collide and fail
        j = _named(wf, name, "caf" + E_ACUTE, "caf" + E_COMBINING)
        assert j["status"] == "failed" and "duplicate" in j["reason"], name
        j = _named(wf, name, "caf" + E_COMBINING)
        assert j["status"] == "ok" and j["pending"][0]["name"].startswith("caf" + E_ACUTE), name
        for bad in ("a" + CYR_A, CYR_A + "b", "x" + GREEK_ALPHA, "bad@name", "bad" + chr(0x202E) + "name",
                    "bad" + chr(0), " pad", "pad ", "a*b", "a" + chr(10) + "b", "a" + chr(0x200B) + "b"):
            j = _named(wf, name, bad)
            assert j["status"] == "failed" and j["pending"] == [], (name, bad)
        assert _named(wf, name, CYR_A * 3 + "-1")["status"] == "ok", name   # one script is fine
        # every letter must be Latin, Cyrillic or Greek, whatever else is present
        for bad in (chr(0x6F22) + chr(0x639), chr(0x6F22), "a" + chr(0x6F22), chr(0x301),
                    "a" + chr(0x639), "A1" + chr(0x5D0)):
            j = _named(wf, name, bad)
            assert j["status"] == "failed" and j["pending"] == [], (name, bad)
        # full-width forms fold to ASCII (NFKC), so they join the plain spelling and collide with it
        j = _named(wf, name, chr(0xFF21) + "p", "Ap")
        assert j["status"] == "failed" and "duplicate" in j["reason"], name
        assert _named(wf, name, chr(0xFF21) + "p")["pending"][0]["name"] == "Ap", name
        # no link-like or room-alias-like punctuation; ASCII digits only
        for bad in ("https://evil.test/#room:server", "a/b", "a:b", "#room", "a#b", "a+b", chr(0x661) + "a", "(a"):
            j = _named(wf, name, bad)
            assert j["status"] == "failed" and j["pending"] == [], (name, bad)
        assert _named(wf, name, "ap-1.example (office)")["status"] == "ok", name


def test_identities_are_nfkc_allowlisted_and_not_mixed_script():
    check_identities(_wf())


# R4-1: invisible characters must not make two names look identical
INVISIBLE_IDENTITIES = [
    "ap️",            # letter + variation selector
    "ap͏",            # letter + combining grapheme joiner
    "ap᠋",            # letter + Mongolian free variation selector
    "ap\U000E0100",        # letter + variation selector supplement
    "ap⁠",            # word joiner
    "ap­",            # soft hyphen
    "apㅤ",            # Hangul filler
    "1́",             # combining acute directly after a digit (also first character)
    "ap1́",           # combining acute after a digit inside a name
    "ap (́",          # combining acute after punctuation
    "ap ́b",          # combining acute after a space
]


@pytest.mark.parametrize("name", list(REAL))
@pytest.mark.parametrize("bad", INVISIBLE_IDENTITIES, ids=lambda s: "+".join("U%04X" % ord(c) for c in s))
def test_invisible_and_misplaced_marks_are_rejected(name, bad):
    j = _named(_wf(), name, bad)
    assert j["status"] == "failed" and j["pending"] == [], (name, bad)
    # the plain spelling beside the invisible one must not become two pending identities
    j = _named(_wf(), name, "ap", bad)
    assert j["status"] == "failed" and j["pending"] == [], (name, bad)


@pytest.mark.parametrize("name", list(REAL))
def test_legitimate_accented_names_are_still_accepted(name):
    wf = _wf()
    for good in ("café", "café", "ap1-café (office)", "буквӑ",
                 "αβ́"):
        j = _named(wf, name, good)
        assert j["status"] == "ok" and len(j["pending"]) == 1, (name, good)


def test_decomposed_name_joins_history_written_precomposed():
    j = _unifi(_wf(), [("caf" + E_COMBINING, 60000, False)], ever=[("caf" + E_ACUTE, 3)])
    assert j["status"] == "ok" and j["applied"] == [{"name": "caf" + E_ACUTE, "from": "upgrade pending", "to": "up to date"}]


@pytest.mark.parametrize("name", list(REAL))
@pytest.mark.parametrize("old,new", [
    ("v.normalize('NFKC')", "v"),
    ("return family.size > 1 ? null : n;", "return n;"),
    ("if (!/^[\\p{L}0-9][\\p{L}\\p{M}0-9 ._()-]*$/u.test(n)) return null;", ""),
    ("if (i < 0) return null;", ""),
])
def test_mutant_identity_check_removed_is_caught(name, old, new):
    wf = _mutate(name, old, new)
    with pytest.raises(AssertionError):
        check_identities(wf)


def test_accepted_names_reach_the_digest_without_link_or_mention_characters():
    wf = _wf()
    for name in REAL:
        j = _named(wf, name, "ap-1.example.com (office)")
        assert j["status"] == "ok", name
        shown = _build(wf, {"UniFi Collector": _src(pending=j["pending"])})
        assert "ap-1.example.com \\(office\\)" in shown["description"] and "ap-1.example.com (office)" in shown["matrixBody"]
        for text in (shown["description"], shown["matrixBody"]):
            line = [ln for ln in text.split("\n") if "ap-1.example.com" in ln][0]
            assert not any(c in line.split("UniFi: ", 1)[1] for c in "@#<>[]/:"), line
        # the rejected link-like form never reaches the digest at all
        bad = _named(wf, name, "https://evil.test/#room:server")
        assert bad["status"] == "failed" and bad["pending"] == [] and "evil.test" not in json.dumps(bad), name
