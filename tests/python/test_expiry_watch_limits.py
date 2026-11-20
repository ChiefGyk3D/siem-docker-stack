"""Ingress limits for the expiry endpoint (issue #157, owner decision Q12).

The watch posts to n8n over loopback, so no reverse proxy sits in the path. The limits therefore live in
two places: the watch (it refuses to send a body over 16 KB and spaces and caps its posts) and the router's
Check Expiry Secret node (it denies a body over 16 KB and a post that arrives too fast).
"""
import json
import re
import subprocess

import pytest

from conftest import REPO_ROOT
from test_expiry_watch import _Recorder, _at, _run, _write_setup, ew, router  # noqa: F401  one module object
from test_router_expiry_secret import CHECK, SECRET, VAR, _by_name, _expiry_body, _item
from test_update_alerting import _ctx_js, _node_bin

MAX_BODY = 16 * 1024
ROUTER_MIN_INTERVAL_MS = 1000
ROUTER_MAX_PER_WINDOW = 30
ROUTER_WINDOW_MS = 600000


# --- the watch: body cap -----------------------------------------------------------------------

def test_the_watch_refuses_to_send_a_body_over_16_kb(router):
    srv, base = router
    with pytest.raises(ew.ExpiryWatchError, match=r"(?i)over the 16384 byte limit") as exc:
        ew.post_json(base + "/h", "tok-value", {"pad": "x" * MAX_BODY}, timeout=3)
    assert "tok-value" not in str(exc.value)
    assert not _Recorder.seen, "an oversized body must not leave the machine"


def test_the_watch_refuses_an_oversized_body_through_an_injected_opener_too():
    class Boom:
        def open(self, *a, **k):
            raise AssertionError("must not be called")
    with pytest.raises(ew.ExpiryWatchError, match="16384"):
        ew.post_json("http://127.0.0.1:1/h", "tok-value", {"pad": "x" * MAX_BODY}, timeout=3, opener=Boom())


def test_a_body_at_the_cap_is_still_sent(router):
    srv, base = router
    overhead = len(json.dumps({"pad": ""}))
    ew.post_json(base + "/h", "tok-value", {"pad": "x" * (MAX_BODY - overhead)}, timeout=3)
    assert len(_Recorder.seen[0][2]) == MAX_BODY


def test_the_run_exits_non_zero_when_the_body_is_too_large(tmp_path, router, monkeypatch):
    srv, base = router
    cfg = _write_setup(tmp_path, base)
    real = ew.build_payload
    monkeypatch.setattr(ew, "build_payload", lambda n, now: dict(real(n, now), pad="x" * MAX_BODY))
    code, out, err = _run(cfg, _at(14))
    assert code == 1 and "16384" in err and not _Recorder.seen
    assert "secret-token-value" not in out + err


# --- the watch: post rate ----------------------------------------------------------------------

def _multi_setup(tmp_path, base, count):
    reg = tmp_path / "registry.toml"
    reg.write_text("".join(
        f'[[item]]\nname = "key-{i}"\nkind = "ssh-key"\nexpires = 2026-03-01\nowner = "ops@example.com"\n'
        f'runbook = "https://wiki.example.com/r"\n' for i in range(count)))
    cfg = tmp_path / "config.toml"
    cfg.write_text(f'[watch]\nstate_file = "state.json"\n\n[router]\nurl = "{base}/h"\n'
                   f'token_env = "EXPIRY_WATCH_TOKEN"\ntimeout_seconds = 3\n\n[routes]\n\n'
                   f'[[providers]]\ntype = "registry"\npath = "registry.toml"\n')
    return cfg


def test_the_watch_spaces_its_router_posts(tmp_path, router, monkeypatch):
    srv, base = router
    pauses = []
    monkeypatch.setattr(ew, "_pause", pauses.append)
    cfg = _multi_setup(tmp_path, base, 3)
    code, _, _ = _run(cfg, _at(14))
    assert code == 0 and len(_Recorder.seen) == 3
    assert len(pauses) == 2, "no pause before the first post, one before each later post"
    assert all(1.5 <= p <= ew.ROUTER_MIN_INTERVAL_SECONDS for p in pauses), pauses


def test_the_watch_caps_the_router_posts_of_one_run_and_keeps_the_rest_due(tmp_path, router, monkeypatch):
    srv, base = router
    monkeypatch.setattr(ew, "_pause", lambda s: None)
    monkeypatch.setattr(ew, "MAX_ROUTER_POSTS_PER_RUN", 2)
    cfg = _multi_setup(tmp_path, base, 5)
    code, _, err = _run(cfg, _at(14))
    assert code == 1 and len(_Recorder.seen) == 2
    assert "router post limit" in err and "3" in err
    code, _, _ = _run(cfg, _at(14, hour=18))
    assert len(_Recorder.seen) == 4, "the notices that were not posted stay due and go out on the next run"


def test_the_pause_never_runs_past_the_delivery_budget(tmp_path, router, monkeypatch):
    srv, base = router
    pauses = []
    monkeypatch.setattr(ew, "_pause", pauses.append)
    monkeypatch.setattr(ew, "ROUTER_MIN_INTERVAL_SECONDS", 1000.0)
    cfg = _multi_setup(tmp_path, base, 2)
    code, _, err = _run(cfg, _at(14))
    assert code == 1 and len(_Recorder.seen) == 1 and not pauses
    assert "delivery budget" in err


def test_the_watch_limits_stay_within_the_router_limits():
    assert ew.ROUTER_MIN_INTERVAL_SECONDS * 1000 >= ROUTER_MIN_INTERVAL_MS
    # two runs inside one router window (a manual re-run after a scheduled one) must also fit
    assert 2 * ew.MAX_ROUTER_POSTS_PER_RUN <= ROUTER_MAX_PER_WINDOW


def test_a_pause_that_overruns_the_budget_does_not_send(tmp_path, router, monkeypatch):
    import time
    srv, base = router
    monkeypatch.setattr(ew, "_pause", lambda s: time.sleep(1.5))
    monkeypatch.setattr(ew, "ROUTER_MIN_INTERVAL_SECONDS", 0.3)
    cfg = _multi_setup(tmp_path, base, 2)
    cfg.write_text(cfg.read_text().replace("[watch]\n", "[watch]\ndelivery_budget_seconds = 1\n", 1))
    code, _, err = _run(cfg, _at(14))
    assert len(_Recorder.seen) == 1, "the second post must not be sent after the pause used up the budget"
    assert code == 1 and "delivery budget" in err


# --- the router: Check Expiry Secret -----------------------------------------------------------

def _calls(items, times, static=None, env=None, static_throws=False):
    """Run the real Check Expiry Secret code once per item in ONE process, with a controlled clock and one
    workflow static data object shared by the calls (what n8n keeps between production executions)."""
    code = _by_name()[CHECK]["parameters"]["jsCode"]
    ctx = {"env": {VAR: SECRET} if env is None else env}
    harness = (_ctx_js(ctx) + f"const __items={json.dumps(items)};const __times={json.dumps(times)};"
               f"const __static={json.dumps(static or {})};const __throws={json.dumps(static_throws)};"
               "let __now=0;Date.now=()=>__now;const __res=[];"
               "const $getWorkflowStaticData=(t)=>{if(__throws||t!=='global'){throw new Error('no static data');}"
               "return __static;};"
               "for(let i=0;i<__items.length;i++){__now=__times[i];"
               "const f=new Function('$input','$','$prevNode','$env','$getWorkflowStaticData'," + json.dumps(code) + ");"
               "const r=f({first:()=>({json:__items[i]})},$,$prevNode,$env,$getWorkflowStaticData);"
               "__res.push(r[0].json.authorized===true);}"
               "console.log(JSON.stringify(__res));")
    r = subprocess.run([_node_bin(), "-"], input=harness, capture_output=True, text=True, timeout=30)
    assert r.returncode == 0, r.stderr[-300:]
    return json.loads(r.stdout)


def test_a_call_inside_the_minimum_interval_is_denied_and_a_later_one_is_accepted():
    t0 = 1_000_000
    res = _calls([_item()] * 3, [t0, t0 + ROUTER_MIN_INTERVAL_MS - 1, t0 + ROUTER_MIN_INTERVAL_MS])
    assert res == [True, False, True]


def test_a_denied_call_does_not_push_the_next_allowed_time():
    t0 = 1_000_000
    assert _calls([_item()] * 4, [t0, t0 + 900, t0 + 950, t0 + 1000]) == [True, False, False, True]


def test_a_call_with_the_wrong_secret_does_not_use_up_the_rate():
    t0 = 1_000_000
    res = _calls([_item("Bearer wrong"), _item(), _item("Bearer wrong"), _item()], [t0, t0 + 1, t0 + 2, t0 + 1500])
    assert res == [False, True, False, True]


def test_more_than_the_window_cap_in_the_window_is_denied_then_allowed_again():
    t0 = 1_000_000
    n = ROUTER_MAX_PER_WINDOW + 3
    times = [t0 + i * ROUTER_MIN_INTERVAL_MS for i in range(n)]
    res = _calls([_item()] * n, times)
    assert res[:ROUTER_MAX_PER_WINDOW] == [True] * ROUTER_MAX_PER_WINDOW
    assert res[ROUTER_MAX_PER_WINDOW:] == [False] * 3
    later = times[:ROUTER_MAX_PER_WINDOW] + [t0 + ROUTER_WINDOW_MS + 60000]
    assert _calls([_item()] * len(later), later)[-1] is True


def test_the_router_fails_closed_when_workflow_static_data_cannot_be_read():
    assert _calls([_item()], [1_000_000], static_throws=True) == [False]


def test_a_garbage_static_data_value_is_replaced_not_trusted():
    res = _calls([_item(), _item()], [1_000_000, 1_005_000],
                 static={"expiryWatchRecent": "junk", "expiryWatchLastMs": {"a": 1}})
    assert res == [True, True]


def test_a_clock_that_goes_backwards_does_not_lock_the_endpoint():
    t0 = 1_000_000
    assert _calls([_item(), _item()], [t0, t0 - 10 * ROUTER_WINDOW_MS]) == [True, True]


# --- the router: body size ---------------------------------------------------------------------

def _big_body():
    body = _expiry_body()
    body["alerts"][0]["annotations"]["description"] = "d" * MAX_BODY
    return body


def test_a_body_over_16_kb_is_denied_even_with_the_right_secret():
    assert _calls([_item(body=_big_body())], [1_000_000]) == [False]


def test_an_oversized_content_length_header_is_denied():
    item = _item()
    item["headers"]["content-length"] = str(MAX_BODY + 1)
    assert _calls([item], [1_000_000]) == [False]
    item["headers"]["content-length"] = str(MAX_BODY)
    assert _calls([item], [1_000_000]) == [True]
    item["headers"]["content-length"] = "not a number"
    assert _calls([item], [1_000_000]) == [False]


def test_an_oversized_body_does_not_use_up_the_rate():
    t0 = 1_000_000
    assert _calls([_item(body=_big_body()), _item()], [t0, t0 + 1]) == [False, True]


def _size_fn(body, headers=None):
    """Run the node's real withinSize() on its own: the shape check would hide it if run end to end."""
    code = _by_name()[CHECK]["parameters"]["jsCode"]
    m = re.search(r"const MAX_BODY = \d+;", code)
    f = re.search(r"function withinSize\(item\) \{.*?\n\}\n", code, re.S)
    assert m and f
    harness = ("const isStr=(v)=>typeof v==='string';" + m.group(0) + f.group(0)
               + f"console.log(JSON.stringify(withinSize({{headers:{json.dumps(headers or {})},"
                 f"body:{json.dumps(body)}}})));")
    r = subprocess.run([_node_bin(), "-"], input=harness, capture_output=True, text=True, timeout=30)
    assert r.returncode == 0, r.stderr[-300:]
    return json.loads(r.stdout)


def test_the_size_function_counts_utf8_bytes_not_characters():
    assert _size_fn({"pad": "x" * 16000}) is True
    assert _size_fn({"pad": "x" * 16400}) is False
    assert _size_fn({"pad": "é" * 9000}) is False, "9000 two-byte characters are 18000 bytes"
    assert _size_fn({"pad": "\U0001F600" * 5000}) is False, "5000 four-byte characters are 20000 bytes"
    assert _size_fn({"pad": "\U0001F600" * 3000}) is True


def test_the_size_function_boundary_and_surrogates_are_exact():
    overhead = len('{"pad":""}')  # JSON.stringify writes no spaces
    assert _size_fn({"pad": "x" * (MAX_BODY - overhead)}) is True, "exactly 16384 bytes is allowed"
    assert _size_fn({"pad": "x" * (MAX_BODY - overhead + 1)}) is False, "16385 bytes is not"
    # 4094 astral characters plus the 14 byte wrapper = 16390 bytes, but 12282+14 if counted as 3 bytes each
    assert _size_fn({"pad": "\U0001F600" * ((MAX_BODY - overhead) // 4 + 1)}) is False
    assert _size_fn({"pad": "\U0001F600" * ((MAX_BODY - overhead) // 4)}) is True
    assert _size_fn({"pad": "\ud800"}) is True and _size_fn({"pad": "\udc00"}) is True


def test_the_size_function_denies_an_unserializable_body():
    code = _by_name()[CHECK]["parameters"]["jsCode"]
    m = re.search(r"const MAX_BODY = \d+;", code)
    f = re.search(r"function withinSize\(item\) \{.*?\n\}\n", code, re.S)
    harness = ("const isStr=(v)=>typeof v==='string';" + m.group(0) + f.group(0)
               + "console.log(JSON.stringify(withinSize({headers:{},body:undefined})));")
    r = subprocess.run([_node_bin(), "-"], input=harness, capture_output=True, text=True, timeout=30)
    assert r.returncode == 0, r.stderr[-300:]
    assert json.loads(r.stdout) is False


def test_the_size_function_checks_the_content_length_header():
    assert _size_fn({}, {"content-length": str(MAX_BODY + 1)}) is False
    assert _size_fn({}, {"content-length": str(MAX_BODY)}) is True
    assert _size_fn({}, {"content-length": "12abc"}) is False


def test_nothing_is_measured_or_counted_before_the_secret_matches():
    """A caller with the wrong secret must not make the node serialize its body (toJSON would run)."""
    code = _by_name()[CHECK]["parameters"]["jsCode"]
    ctx = {"env": {VAR: SECRET}}
    harness = (_ctx_js(ctx) + "let __n=0;const __res=[];"
               "const $getWorkflowStaticData=()=>({});"
               "for(const hdr of ['Bearer wrong','Bearer " + SECRET + "']){"
               "const body={toJSON(){__n++;return {};}};"
               "const f=new Function('$input','$','$prevNode','$env','$getWorkflowStaticData'," + json.dumps(code) + ");"
               "f({first:()=>({json:{headers:{authorization:hdr},body}})},$,$prevNode,$env,$getWorkflowStaticData);"
               "__res.push(__n);}console.log(JSON.stringify(__res));")
    r = subprocess.run([_node_bin(), "-"], input=harness, capture_output=True, text=True, timeout=30)
    assert r.returncode == 0, r.stderr[-300:]
    wrong, right = json.loads(r.stdout)
    assert wrong == 0, "the body was serialized for a caller with the wrong secret"
    assert right >= 1, "the check must still run for a caller with the right secret"


def test_the_endpoint_stays_disabled_with_a_placeholder_and_the_docs_state_the_limits():
    node = _by_name()["Expiry Watch Webhook"]
    assert node.get("disabled") is True and node["parameters"]["path"].startswith("PLACEHOLDER")
    doc = (REPO_ROOT / "docs" / "expiry-watch.md").read_text(encoding="utf-8")
    runbook = (REPO_ROOT / "docs" / "owner-runbook.md").read_text(encoding="utf-8")
    for text in (doc, runbook):
        assert "16 KB" in text and "UNVERIFIED" in text
    assert "ANSWERED" in runbook and "Q12" in runbook
    assert chr(0x2014) not in doc + runbook
