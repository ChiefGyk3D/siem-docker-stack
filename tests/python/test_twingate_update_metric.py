"""Tests for scripts/twingate-update-metric.py (issue #200).

The script is imported and driven with fake transports, so no test touches the
network, a real Twingate account or a real key. The fake key and network name
below are placeholders.
"""
import importlib.util
import io
import json
import re
import subprocess
import sys

import pytest

from conftest import REPO_ROOT

SCRIPT = REPO_ROOT / "scripts" / "twingate-update-metric.py"
KEY = "FAKEKEY-not-a-real-key-0123456789"
ENV = {"TWINGATE_API_KEY": KEY, "TWINGATE_NETWORK_URL": "https://example-net.twingate.com"}


def _load():
    spec = importlib.util.spec_from_file_location("twingate_update_metric", SCRIPT)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


tm = _load()


def tags_page(*names, nxt=None):
    return {"count": len(names), "next": nxt, "results": [{"name": n} for n in names]}


def conn_page(nodes, has_next=False, cursor=None):
    return {"data": {"connectors": {
        "pageInfo": {"hasNextPage": has_next, "endCursor": cursor},
        "edges": [{"node": n} for n in nodes]}}}


def node(name, version, state="ALIVE"):
    return {"name": name, "version": version, "state": state, "lastHeartbeatAt": "2026-11-26T00:00:00Z"}


class Fakes:
    def __init__(self, gql_pages, tag_pages):
        self.gql_pages, self.tag_pages = list(gql_pages), list(tag_pages)
        self.gql_calls, self.get_calls = [], []

    def post(self, url, api_key, query, variables):
        self.gql_calls.append((url, api_key, query, variables))
        page = self.gql_pages.pop(0)
        if isinstance(page, Exception):
            raise page
        return page

    def get(self, url):
        self.get_calls.append(url)
        page = self.tag_pages.pop(0)
        if isinstance(page, Exception):
            raise page
        return page


def run(gql_pages, tag_pages, env=None, extra_env=None):
    f = Fakes(gql_pages, tag_pages)
    e = dict(ENV if env is None else env)
    extra = dict(extra_env or {})
    if "TWINGATE_EXPECTED_CONNECTORS" not in extra and env is None:
        # the expected inventory is required: default to every well-named connector in the pages
        names = []
        for p in gql_pages:
            try:
                names += [e["node"]["name"] for e in p["data"]["connectors"]["edges"]]
            except (TypeError, KeyError):
                pass
        names = [n for n in names if isinstance(n, str) and re.fullmatch(r"[A-Za-z0-9._-]{1,64}", n)]
        extra["TWINGATE_EXPECTED_CONNECTORS"] = json.dumps(list(dict.fromkeys(names)) or ["anchor"])
    e.update(extra)
    for k in [k for k, v in e.items() if v is None]:
        del e[k]
    out, err = io.StringIO(), io.StringIO()
    rc = tm.main(e, post=f.post, get=f.get, stdout=out, stderr=err)
    return rc, out.getvalue(), err.getvalue(), f


def lines(out):
    return out.strip().splitlines()


LATEST = tags_page("latest", "1", "1.96", "1.96.0", "1.95.0", "1.94.0", "1.93.0", "1.89.0", "1.88.0")


def assert_failed_closed(rc, out):
    assert rc != 0
    assert lines(out) == ["twingate_update_check_success value=0i"]


# --- happy paths -------------------------------------------------------------

def test_up_to_date_connector():
    rc, out, _, _ = run([conn_page([node("tg-a", "1.96.0")])], [LATEST])
    assert rc == 0
    assert lines(out) == [
        "twingate_connector_behind,connector=tg-a,managed_by=docker value=0i",
        "twingate_connector_up,connector=tg-a,managed_by=docker value=1i",
        "twingate_unexpected_connector value=0i",
        "twingate_update_check_success value=1i",
    ]


def test_behind_counts_releases_newer_than_the_connector():
    rc, out, _, _ = run([conn_page([node("tg-a", "1.89.0"), node("tg-b", "1.96.0")])], [LATEST])
    assert rc == 0
    assert "twingate_connector_behind,connector=tg-a,managed_by=docker value=4i" in lines(out)
    assert "twingate_connector_behind,connector=tg-b,managed_by=docker value=0i" in lines(out)


def test_versions_compare_numerically_not_as_text():
    # 1.9.0 < 1.10.0 numerically; as text "1.9.0" > "1.10.0"
    tags = tags_page("1.10.0", "1.9.0")
    rc, out, _, _ = run([conn_page([node("tg-a", "1.9.0")])], [tags])
    assert rc == 0
    assert "twingate_connector_behind,connector=tg-a,managed_by=docker value=1i" in lines(out)


def test_connector_ahead_of_latest_is_zero_behind():
    rc, out, _, _ = run([conn_page([node("tg-a", "1.97.0")])], [LATEST])
    assert rc == 0 and "twingate_connector_behind,connector=tg-a,managed_by=docker value=0i" in lines(out)


def test_state_maps_to_up_value():
    rc, out, _, _ = run([conn_page([node("a", "1.96.0", "ALIVE"), node("b", "1.96.0", "DEAD"),
                                    node("c", "1.96.0", "weird state")])], [LATEST])
    assert rc == 0
    up = {m.group(1): m.group(2) for m in re.finditer(r"twingate_connector_up,connector=(\S+?),managed_by=\w+ value=(\d)i", out)}
    assert up == {"a": "1", "b": "0", "c": "0"}


def test_pagination_is_followed_and_capped():
    p1 = conn_page([node("a", "1.96.0")], True, "cur1")
    p2 = conn_page([node("b", "1.96.0")], False, None)
    rc, out, _, f = run([p1, p2], [LATEST])
    assert rc == 0 and "connector=b" in out
    assert f.gql_calls[0][3].get("after") is None and f.gql_calls[1][3]["after"] == "cur1"
    # a server that never stops paging is a failure, not a loop
    endless = [conn_page([node("a", "1.96.0")], True, "cur")] * 50
    rc, out, _, f = run(endless, [LATEST])
    assert_failed_closed(rc, out)
    assert len(f.gql_calls) <= tm.MAX_CONNECTOR_PAGES


def test_latest_version_is_collected_across_tag_pages_with_a_cap():
    t1 = tags_page("1.95.0", nxt="https://hub.docker.com/v2/next")
    t2 = tags_page("1.96.0", "1.94.0")
    rc, out, _, f = run([conn_page([node("a", "1.95.0")])], [t1, t2])
    assert rc == 0 and "twingate_connector_behind,connector=a,managed_by=docker value=1i" in lines(out)
    assert len(f.get_calls) == 2 and all(u.startswith("https://hub.docker.com/v2/repositories/twingate/connector/tags") for u in f.get_calls)
    endless = [tags_page("1.95.0", nxt="x")] * 50
    rc, out, _, f = run([conn_page([node("a", "1.95.0")])], endless)
    assert len(f.get_calls) <= tm.MAX_TAG_PAGES


# --- fail closed ---------------------------------------------------------------

def test_api_error_fails_closed():
    rc, out, err, _ = run([RuntimeError("boom")], [LATEST])
    assert_failed_closed(rc, out)


def test_graphql_errors_array_fails_closed():
    bad = {"errors": [{"message": "denied"}], "data": None}
    rc, out, _, _ = run([bad], [LATEST])
    assert_failed_closed(rc, out)
    # even a well-formed page next to an errors array is not trusted
    partial = dict(conn_page([node("a", "1.96.0")]), errors=[{"message": "partial"}])
    rc, out, _, _ = run([partial], [LATEST])
    assert_failed_closed(rc, out)


@pytest.mark.parametrize("payload", [
    {}, {"data": None}, {"data": {"connectors": None}}, {"data": {"connectors": {"edges": "x"}}},
    conn_page([]),  # zero connectors is suspicious (wrong key scope), never healthy
    "not a dict", [],
])
def test_malformed_or_empty_api_answers_fail_closed(payload):
    rc, out, _, _ = run([payload], [LATEST])
    assert_failed_closed(rc, out)


@pytest.mark.parametrize("version", ["", None, "latest", "1.96", "1.96.0-rc1", "v1.96.0", "1.96.0\n# x",
                                     "99999.1.1", "1.2.3.4", 196, "１.９.０"])
def test_unparsable_connector_version_fails_closed(version):
    rc, out, _, _ = run([conn_page([node("a", version)])], [LATEST])
    assert_failed_closed(rc, out)


def test_latest_source_failure_or_empty_fails_closed():
    for tags in (RuntimeError("down"), tags_page(), tags_page("latest", "1", "1.96"), {"results": "x"}, [],
                 tags_page("1.96.0-rc1", "bogus")):
        rc, out, _, _ = run([conn_page([node("a", "1.96.0")])], [tags])
        assert_failed_closed(rc, out)


@pytest.mark.parametrize("missing", ["TWINGATE_API_KEY", "TWINGATE_NETWORK_URL"])
def test_missing_environment_fails_closed(missing):
    env = {k: v for k, v in ENV.items() if k != missing}
    rc, out, _, f = run([conn_page([node("a", "1.96.0")])], [LATEST], env=env)
    assert_failed_closed(rc, out)
    assert not f.gql_calls and not f.get_calls


@pytest.mark.parametrize("url", [
    "http://example-net.twingate.com", "https://example-net.twingate.com.evil.test",
    "https://evil.test/example-net.twingate.com", "https://user:pw@example-net.twingate.com",
    "https://example-net.twingate.com:8443", "https://twingate.com", "ftp://example-net.twingate.com",
    "https://example-net.twingate.com@evil.test", "", "example-net",
])
def test_network_url_must_be_an_https_twingate_host_so_the_key_is_never_sent_elsewhere(url):
    rc, out, _, f = run([conn_page([node("a", "1.96.0")])], [LATEST], extra_env={"TWINGATE_NETWORK_URL": url})
    assert_failed_closed(rc, out)
    assert not f.gql_calls


def test_graphql_endpoint_and_key_use():
    rc, _, _, f = run([conn_page([node("a", "1.96.0")])], [LATEST],
                      extra_env={"TWINGATE_NETWORK_URL": "https://example-net.twingate.com/"})
    assert rc == 0
    url, key, query, variables = f.gql_calls[0]
    assert url == "https://example-net.twingate.com/api/graphql/" and key == KEY
    assert re.match(r"\s*query\b", query) and "mutation" not in query.lower()
    assert variables.get("first") == 100


def test_redirects_are_refused_by_the_real_transport():
    import urllib.error
    import urllib.request
    h = tm.NoRedirect()
    req = urllib.request.Request("https://example-net.twingate.com/api/graphql/", headers={"X-API-KEY": KEY})
    with pytest.raises(urllib.error.HTTPError):
        h.redirect_request(req, None, 302, "Found", {}, "https://evil.test/")


# --- hostile remote text ---------------------------------------------------------

@pytest.mark.parametrize("name", [
    "evil,connector=x value=1i\ntwingate_update_check_success value=1i",
    "a b", "a=b", 'a"b', "line\nbreak", "tab\there", "a\\b", "🙂", "x" * 500, "", "   ",
])
def test_malicious_names_cannot_inject_line_protocol(name):
    rc, out, _, _ = run([conn_page([node("anchor", "1.96.0"), node(name, "1.96.0")])], [LATEST])
    assert rc == 0
    ls = lines(out)
    assert len(ls) == 6, ls
    assert ls[4] == "twingate_unexpected_connector value=1i"
    for ln in ls[2:4]:
        assert re.fullmatch(r"twingate_connector_(behind|up),connector=[A-Za-z0-9._-]{1,64},managed_by=(docker|systemd|operator) value=\di", ln), ln
    assert ls[5] == "twingate_update_check_success value=1i"


def test_names_that_sanitize_to_the_same_tag_stay_distinct():
    rc, out, _, _ = run([conn_page([node("anchor", "1.96.0"), node("a b", "1.96.0"), node("a,b", "1.89.0")])], [LATEST])
    assert rc == 0
    tagset = [m.group(1) for m in re.finditer(r"twingate_connector_up,connector=(\S+?),", out)]
    assert len(tagset) == 3 and len(set(tagset)) == 3


def test_oversized_or_hostile_state_is_just_down():
    rc, out, _, _ = run([conn_page([node("a", "1.96.0", "ALIVE" * 1000)])], [LATEST])
    assert rc == 0 and "twingate_connector_up,connector=a,managed_by=docker value=0i" in out


# --- secrets ----------------------------------------------------------------------

def test_key_and_network_never_reach_stdout_or_stderr():
    for pages, tags in (([conn_page([node("a", "1.96.0")])], [LATEST]),
                        ([RuntimeError(KEY + " example-net.twingate.com")], [LATEST]),
                        ([conn_page([node("a", "1.96.0")])], [RuntimeError(KEY)])):
        rc, out, err, _ = run(pages, tags)
        for text in (out, err):
            assert KEY not in text and "example-net" not in text


def test_script_reads_key_only_from_the_environment_not_argv(tmp_path):
    # With no environment the real process fails closed, takes no argv, and prints nothing secret.
    r = subprocess.run([sys.executable, "-I", str(SCRIPT)], capture_output=True, text=True,
                       env={"PATH": "/usr/bin:/bin"}, timeout=30)
    assert r.returncode != 0
    assert r.stdout.strip() == "twingate_update_check_success value=0i"
    src = SCRIPT.read_text(encoding="utf-8")
    assert "sys.argv" not in src and "argparse" not in src
    assert not re.search(r"print\([^)]*(api_key|API_KEY)", src)


def test_script_is_stdlib_only_and_read_only():
    src = SCRIPT.read_text(encoding="utf-8")
    imports = set(re.findall(r"(?m)^(?:import|from)\s+([A-Za-z_][A-Za-z0-9_]*)", src))
    stdlib = set(sys.stdlib_module_names)
    assert imports and imports <= stdlib, imports - stdlib
    assert not re.search(r"\bmutation\b", src, re.I)
    assert not re.search(r"os\.system|subprocess|shell=True|eval\(|exec\(", src)


# --- adaptive management mode (owner addition 2026-11-26) -------------------------------

MIX = json.dumps({"tg-docker": "docker", "tg-systemd": "systemd", "tg-operator": "operator"})
ALL = [node("tg-docker", "1.89.0"), node("tg-systemd", "1.89.0"), node("tg-operator", "1.89.0"),
       node("tg-unlisted", "1.89.0")]


def managed(out):
    return {m.group(1): m.group(2) for m in re.finditer(
        r"twingate_connector_behind,connector=(\S+?),managed_by=(\w+) ", out)}


@pytest.mark.parametrize("mode", ["docker", "systemd", "operator"])
def test_each_management_mode_is_tagged_from_the_inline_mapping(mode):
    rc, out, _, _ = run([conn_page([node("c1", "1.89.0")])], [LATEST],
                        extra_env={"TWINGATE_CONNECTOR_MANAGED_BY": json.dumps({"c1": mode})})
    assert rc == 0
    assert f"twingate_connector_behind,connector=c1,managed_by={mode} value=4i" in lines(out)
    assert f"twingate_connector_up,connector=c1,managed_by={mode} value=1i" in lines(out)


def test_unlisted_name_defaults_to_docker_manual_update():
    rc, out, _, _ = run([conn_page(ALL)], [LATEST], extra_env={"TWINGATE_CONNECTOR_MANAGED_BY": MIX})
    assert rc == 0
    assert managed(out) == {"tg-docker": "docker", "tg-systemd": "systemd", "tg-operator": "operator",
                            "tg-unlisted": "docker"}


def test_no_config_at_all_means_every_connector_is_docker():
    rc, out, _, _ = run([conn_page(ALL)], [LATEST])
    assert rc == 0 and set(managed(out).values()) == {"docker"}


def test_mapping_can_come_from_a_file(tmp_path):
    p = tmp_path / "managed.json"
    p.write_text(MIX, encoding="utf-8")
    rc, out, _, _ = run([conn_page(ALL)], [LATEST], extra_env={"TWINGATE_CONNECTOR_MANAGED_BY_FILE": str(p)})
    assert rc == 0 and managed(out)["tg-operator"] == "operator" and managed(out)["tg-unlisted"] == "docker"


def test_file_wins_over_inline_when_both_are_set(tmp_path):
    p = tmp_path / "managed.json"
    p.write_text(json.dumps({"c1": "systemd"}), encoding="utf-8")
    rc, out, _, _ = run([conn_page([node("c1", "1.89.0")])], [LATEST],
                        extra_env={"TWINGATE_CONNECTOR_MANAGED_BY_FILE": str(p),
                                   "TWINGATE_CONNECTOR_MANAGED_BY": json.dumps({"c1": "operator"})})
    assert rc == 0 and managed(out) == {"c1": "systemd"}


def test_mapping_matches_the_raw_name_not_the_sanitized_one():
    rc, out, _, _ = run([conn_page([node("anchor", "1.96.0"), node("my connector", "1.89.0")])], [LATEST],
                        extra_env={"TWINGATE_CONNECTOR_MANAGED_BY": json.dumps({"my connector": "operator"})})
    assert rc == 0 and managed(out) == {"anchor": "docker", "my_connector": "operator"}


@pytest.mark.parametrize("cfg", [
    "not json", "[]", '"docker"', json.dumps({"a": "kubernetes"}), json.dumps({"a": "Docker"}),
    json.dumps({"a": 1}), json.dumps({"a": None}), '{"a": "docker", "a": "operator"}',
    json.dumps({"x" * 300: "docker"}), "{" * 5000,
])
def test_bad_management_config_fails_closed(cfg):
    rc, out, _, f = run([conn_page([node("a", "1.96.0")])], [LATEST],
                        extra_env={"TWINGATE_CONNECTOR_MANAGED_BY": cfg})
    assert_failed_closed(rc, out)
    assert not f.gql_calls


def test_bad_management_file_fails_closed(tmp_path):
    big = tmp_path / "big.json"
    big.write_text("{" + " " * 200000 + "}", encoding="utf-8")
    for path in (tmp_path / "missing.json", big, tmp_path):
        rc, out, _, _ = run([conn_page([node("a", "1.96.0")])], [LATEST],
                            extra_env={"TWINGATE_CONNECTOR_MANAGED_BY_FILE": str(path)})
        assert_failed_closed(rc, out)


# --- Grafana rules, router allowlist, docs --------------------------------------------

import yaml  # noqa: E402  (kept next to the tests that use it)

RULES = REPO_ROOT / "docker" / "grafana" / "provisioning" / "alerting" / "update-alert-rules-twingate.yml"
ROUTER = REPO_ROOT / "n8n" / "grafana-alert-router.json"
DOC = REPO_ROOT / "docs" / "update-alerting.md"
DATASOURCES = REPO_ROOT / "docker" / "grafana" / "provisioning" / "datasources" / "datasources.yml"


def rules():
    data = yaml.safe_load(RULES.read_text(encoding="utf-8"))
    assert data["apiVersion"] == 1
    return {r["uid"]: r for g in data["groups"] for r in g["rules"]}


def refs(rule, ref):
    return next(d for d in rule["data"] if d["refId"] == ref)


def test_rules_ship_paused_with_alerting_error_states():
    rs = rules()
    assert set(rs) == {"update-twingate-pending-7d", "update-twingate-pending-14d",
                       "update-twingate-operator-behind", "update-twingate-check-failing",
                       "update-twingate-connector-down", "update-twingate-unexpected-connector"}
    for uid, r in rs.items():
        assert r["isPaused"] is True, uid
        assert r["noDataState"] == "Alerting" and r["execErrState"] == "Alerting", uid
        lab = r["labels"]
        assert lab["update_alert"] == "true" and lab["alert_group"] == "updates", uid
        assert lab["source"] == "twingate" and lab["severity"] in {"warning", "critical"}, uid
        assert lab["phone"] in {"true", "false"}, uid


def test_manual_rules_page_and_the_operator_rule_does_not():
    rs = rules()
    assert rs["update-twingate-pending-7d"]["labels"]["severity"] == "warning"
    assert rs["update-twingate-pending-14d"]["labels"]["severity"] == "critical"
    for uid in ("update-twingate-pending-7d", "update-twingate-pending-14d",
                "update-twingate-check-failing", "update-twingate-connector-down"):
        assert rs[uid]["labels"]["phone"] == "true", uid
    assert rs["update-twingate-operator-behind"]["labels"]["phone"] == "false"
    assert rs["update-twingate-operator-behind"]["labels"]["severity"] == "warning"


def _query(rule, ref):
    return refs(rule, ref)["model"]["query"]


def test_manual_rules_exclude_operator_connectors_and_the_operator_rule_selects_only_them():
    rs = rules()
    for uid in ("update-twingate-pending-7d", "update-twingate-pending-14d"):
        for ref in ("A", "N", "Q", "M"):
            assert "\"managed_by\" != 'operator'" in _query(rs[uid], ref), (uid, ref)
    op = rs["update-twingate-operator-behind"]
    for ref in ("Q", "M"):
        assert "\"managed_by\" = 'operator'" in _query(op, ref)
        assert "!=" not in _query(op, ref)


def test_seven_and_fourteen_day_rules_have_no_overlap_or_gap():
    rs = rules()
    w, c = rs["update-twingate-pending-7d"], rs["update-twingate-pending-14d"]
    ew = refs(w, "C")["model"]["expression"]
    ec = refs(c, "C")["model"]["expression"]
    mc = re.fullmatch(r"\$Qc > 0 && \$Mc >= (\d+)", ec)
    mw = re.fullmatch(r"\$B > 0 && \$Nc >= (\d+) && !\(\$Qc > 0 && \$Mc >= (\d+)\)", ew)
    assert mc and mw, (ew, ec)
    assert mw.group(2) == mc.group(1)          # the warning excludes exactly what the critical covers
    assert int(mw.group(1)) <= 168 and int(mc.group(1)) <= 336   # hourly samples in 7 and 14 days
    assert refs(w, "A")["relativeTimeRange"]["from"] == 7 * 86400
    assert refs(w, "Q")["relativeTimeRange"]["from"] == 14 * 86400
    assert w["for"] == "0s" and c["for"] == "0s"   # the clock is in the query, not in `for`


def test_rules_read_the_metrics_the_script_writes():
    text = RULES.read_text(encoding="utf-8")
    src = SCRIPT.read_text(encoding="utf-8")
    for metric in ("twingate_connector_behind", "twingate_connector_up", "twingate_update_check_success"):
        assert metric in text and metric in src
    ds = yaml.safe_load(DATASOURCES.read_text(encoding="utf-8"))["datasources"]
    by = {d["uid"]: d for d in ds}
    assert by["influxdb-twingate"]["type"] == "influxdb"
    for r in rules().values():
        for d in r["data"]:
            if d["datasourceUid"] != "__expr__":
                assert d["datasourceUid"] == "influxdb-twingate"


def test_every_rule_title_is_in_the_router_allowlist():
    wf = json.loads(ROUTER.read_text(encoding="utf-8"))
    js = next(n["parameters"]["jsCode"] for n in wf["nodes"] if "ALLOWED_ALERTNAMES" in n.get("parameters", {}).get("jsCode", ""))
    listed = set(re.findall(r"'([^']*)'", re.search(r"const ALLOWED_ALERTNAMES = \[(.*?)\];", js, re.S).group(1)))
    titles = {r["title"] for r in rules().values()}
    assert len(titles) == 6 and titles <= listed


def test_docs_cover_twingate_collector_and_management_modes():
    text = DOC.read_text(encoding="utf-8")
    flat = " ".join(text.split())
    assert "—" not in text
    for needle in ("TWINGATE_API_KEY", "TWINGATE_NETWORK_URL", "TWINGATE_CONNECTOR_MANAGED_BY_FILE",
                   "TWINGATE_CONNECTOR_MANAGED_BY", "managed_by", "Kubernetes Operator", "weekly digest",
                   "scripts/twingate-update-metric.py", "Docker Hub", "update-alert-rules-twingate.yml"):
        assert needle in flat, needle
    for mode in ("docker", "systemd", "operator"):
        assert f"`{mode}`" in text, mode
    assert "unlisted" in flat.lower() or "not listed" in flat.lower()
    # placeholders only: no real key shape or network name
    assert not re.search(r"\b[A-Za-z0-9_-]{40,}\b", text.split("### Twingate data")[1].split("### Label taxonomy")[0])


# --- review round 1 hardening --------------------------------------------------

@pytest.mark.parametrize("info", [None, {}, {"endCursor": "x"}, {"hasNextPage": "false"}, {"hasNextPage": None}, []])
def test_missing_or_malformed_page_info_fails_closed(info):
    page = conn_page([node("only-one", "1.96.0")])
    if info is None:
        del page["data"]["connectors"]["pageInfo"]
    else:
        page["data"]["connectors"]["pageInfo"] = info
    rc, out, _, _ = run([page], [LATEST])
    assert_failed_closed(rc, out)


def test_truncated_release_pagination_fails_closed():
    endless = [tags_page("1.95.0", nxt="still-more")] * 50
    rc, out, _, f = run([conn_page([node("a", "1.95.0")])], endless)
    assert_failed_closed(rc, out)
    assert len(f.get_calls) == tm.MAX_TAG_PAGES


def test_release_pagination_ending_on_the_last_allowed_page_is_accepted():
    pages = [tags_page("1.95.0", nxt="more")] * (tm.MAX_TAG_PAGES - 1) + [tags_page("1.96.0")]
    rc, out, _, _ = run([conn_page([node("a", "1.95.0")])], pages)
    assert rc == 0


def up_lines(out):
    return [ln for ln in lines(out) if ln.startswith("twingate_connector_up")]


def test_an_expected_connector_missing_from_the_inventory_fails_closed_and_reads_as_down():
    two = {"TWINGATE_EXPECTED_CONNECTORS": '["a", "b"]'}
    rc, out, _, _ = run([conn_page([node("a", "1.96.0")])], [LATEST], extra_env=two)
    assert rc != 0
    # no healthy per-connector data; the missing name is written as down so the "not ALIVE" rule fires
    assert lines(out) == ["twingate_connector_up,connector=b,managed_by=docker value=0i",
                          "twingate_update_check_success value=0i"]
    rc, out, _, _ = run([conn_page([node("a", "1.96.0"), node("b", "1.96.0")])], [LATEST], extra_env=two)
    assert rc == 0 and "twingate_update_check_success value=1i" in lines(out)


def test_a_missing_expected_connector_keeps_its_management_mode_and_compares_case_insensitively():
    cfg = {"TWINGATE_EXPECTED_CONNECTORS": '["a", "Bee"]',
           "TWINGATE_CONNECTOR_MANAGED_BY": json.dumps({"Bee": "operator"})}
    rc, out, _, _ = run([conn_page([node("a", "1.96.0")])], [LATEST], extra_env=cfg)
    assert rc != 0 and "connector=Bee,managed_by=operator value=0i" in out
    rc, out, _, _ = run([conn_page([node("A", "1.96.0"), node("bee", "1.96.0")])], [LATEST], extra_env=cfg)
    assert rc == 0


@pytest.mark.parametrize("bad", [None, "", "   ", "[]", " [ ] ", "not json", '{"a": 1}', "[1]", '[""]', '["a","a"]',
                                 '["a","A"]', '["a b"]', '["a,b"]', '["a=b"]', '["a\\nb"]', '["x' + "y" * 70 + '"]',
                                 "null", '"a"', '[["a"]]'])
def test_expected_inventory_is_required_and_strict(bad):
    rc, out, _, f = run([conn_page([node("a", "1.96.0")])], [LATEST], extra_env={"TWINGATE_EXPECTED_CONNECTORS": bad})
    assert_failed_closed(rc, out)
    assert not f.gql_calls


def test_unlisted_connectors_are_counted_not_failed():
    rc, out, _, _ = run([conn_page([node("a", "1.96.0"), node("new-one", "1.96.0"), node("new-two", "1.96.0")])],
                        [LATEST], extra_env={"TWINGATE_EXPECTED_CONNECTORS": '["a"]'})
    assert rc == 0
    assert "twingate_unexpected_connector value=2i" in lines(out)
    assert "twingate_update_check_success value=1i" in lines(out)
    assert len(up_lines(out)) == 3


# --- review round 2 hardening: inventory integrity -----------------------------

def test_duplicate_connector_names_fail_closed_across_pages_and_within_a_page():
    p1 = conn_page([node("a", "1.96.0")], True, "c1")
    p2 = conn_page([node("a", "1.96.0")], False)
    rc, out, _, _ = run([p1, p2], [LATEST])
    assert_failed_closed(rc, out)
    rc, out, _, _ = run([conn_page([node("a", "1.96.0"), node("a", "1.96.0")])], [LATEST])
    assert_failed_closed(rc, out)
    rc, out, _, _ = run([conn_page([node("a", "1.96.0"), node("A", "1.96.0")])], [LATEST],
                        extra_env={"TWINGATE_EXPECTED_CONNECTORS": '["a"]'})
    assert_failed_closed(rc, out)


def test_duplicate_connector_ids_fail_closed():
    one, two = dict(node("a", "1.96.0"), id="id-1"), dict(node("b", "1.96.0"), id="id-1")
    rc, out, _, _ = run([conn_page([one, two])], [LATEST])
    assert_failed_closed(rc, out)
    two["id"] = "id-2"
    rc, out, _, _ = run([conn_page([one, two])], [LATEST])
    assert rc == 0


def test_a_repeated_cursor_fails_closed():
    p1 = conn_page([node("a", "1.96.0")], True, "same")
    p2 = conn_page([node("b", "1.96.0")], True, "same")
    p3 = conn_page([node("c", "1.96.0")], False)
    rc, out, _, _ = run([p1, p2, p3], [LATEST], extra_env={"TWINGATE_EXPECTED_CONNECTORS": '["a","b","c"]'})
    assert_failed_closed(rc, out)


def test_a_page_that_adds_nothing_while_more_pages_are_promised_fails_closed():
    p1 = conn_page([node("a", "1.96.0")], True, "c1")
    p2 = conn_page([], True, "c2")
    p3 = conn_page([node("b", "1.96.0")], False)
    rc, out, _, _ = run([p1, p2, p3], [LATEST], extra_env={"TWINGATE_EXPECTED_CONNECTORS": '["a","b"]'})
    assert_failed_closed(rc, out)


def test_a_repeated_final_page_is_not_accepted():
    p1 = conn_page([node("a", "1.96.0")], True, "c1")
    p2 = conn_page([node("a", "1.96.0")], False)
    rc, out, _, _ = run([p1, p2], [LATEST], extra_env={"TWINGATE_EXPECTED_CONNECTORS": '["a"]'})
    assert_failed_closed(rc, out)
