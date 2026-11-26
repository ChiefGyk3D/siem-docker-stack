#!/usr/bin/env python3
"""twingate-update-metric.py - print Twingate Connector update state as Telegraf
exec input (InfluxDB line protocol). Issue #200.

READ-ONLY and stdlib only. It sends one GraphQL read query to the
Twingate Admin API and one GET to the public Docker Hub tags API, and prints
metrics on stdout. It never changes a Connector.

Environment (never argv, never printed, never logged):
  TWINGATE_API_KEY      read-only Admin API key
  TWINGATE_NETWORK_URL  https://<network>.twingate.com
  TWINGATE_CONNECTOR_MANAGED_BY_FILE   optional path to a JSON object
  TWINGATE_CONNECTOR_MANAGED_BY        optional inline JSON object (used only
                                       when no file is set)
  TWINGATE_EXPECTED_CONNECTORS         optional JSON array of Connector names that
                                       must all be present; a missing one fails
                                       the check (a deleted Connector must not
                                       just vanish from the metrics)
The JSON object maps a Connector name to how it is updated: "docker",
"systemd" (both manual, so they page) or "operator" (the Kubernetes Operator
updates it, so it never pages). A name that is not listed is "docker".

Success (exit 0), per Connector, then the health metric:
  twingate_connector_behind,connector=<n>,managed_by=<m> value=<releases behind>i
  twingate_connector_up,connector=<n>,managed_by=<m> value=1i|0i
  twingate_update_check_success value=1i
"Releases behind" is the number of released versions newer than the Connector.

Failure (any API error, empty answer, unparsable version, bad configuration or
unreachable latest-version source): prints only
`twingate_update_check_success value=0i` and exits 1. It never prints
per-Connector metrics after a failure, so a broken check cannot look healthy.

Latest-version source: the Docker Hub tags API for twingate/connector (JSON,
one version per tag). Every remote value is untrusted: strict version regex,
size and page caps, and Connector names are reduced to [A-Za-z0-9._-] before
they become a tag.
"""
import json
import os
import re
import stat
import sys
import urllib.error
import urllib.request

MAX_CONNECTOR_PAGES = 10
MAX_CONNECTORS = 1000
MAX_TAG_PAGES = 5
MAX_BODY_BYTES = 4 * 1024 * 1024
MAX_CONFIG_BYTES = 64 * 1024
MAX_CONFIG_ENTRIES = 1000
TIMEOUT_SECONDS = 20
MODES = ("docker", "systemd", "operator")
DEFAULT_MODE = "docker"
TAGS_URL = "https://hub.docker.com/v2/repositories/twingate/connector/tags"
HOST_RE = re.compile(r"[a-z0-9][a-z0-9-]{0,62}\.twingate\.com")
VERSION_RE = re.compile(r"[0-9]{1,4}\.[0-9]{1,4}\.[0-9]{1,4}")
QUERY = ("query Connectors($first: Int!, $after: String) { "
         "connectors(first: $first, after: $after) { "
         "pageInfo { hasNextPage endCursor } "
         "edges { node { name version state } } } }")


class CheckError(Exception):
    """A check failure. The text is fixed and never carries remote data or a secret."""


class NoRedirect(urllib.request.HTTPRedirectHandler):
    """Refuse every redirect: the API key header must never follow one."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise urllib.error.HTTPError(req.full_url, code, "redirect refused", headers, fp)


def _read_json(req):
    opener = urllib.request.build_opener(NoRedirect)
    with opener.open(req, timeout=TIMEOUT_SECONDS) as resp:
        body = resp.read(MAX_BODY_BYTES + 1)
    if len(body) > MAX_BODY_BYTES:
        raise CheckError("answer too large")
    return json.loads(body.decode("utf-8"))


def post_graphql(url, api_key, query, variables):
    data = json.dumps({"query": query, "variables": variables}).encode("utf-8")
    req = urllib.request.Request(url, data=data, method="POST", headers={
        "X-API-KEY": api_key, "Content-Type": "application/json", "Accept": "application/json"})
    return _read_json(req)


def get_json(url):
    if not url.startswith(TAGS_URL + "?"):
        raise CheckError("unexpected url")
    req = urllib.request.Request(url, method="GET", headers={
        "Accept": "application/json", "User-Agent": "siem-twingate-update-metric"})
    return _read_json(req)


def parse_version(value):
    if not isinstance(value, str) or not VERSION_RE.fullmatch(value):
        raise CheckError("unparsable version")
    return tuple(int(p) for p in value.split("."))


def api_url(network_url):
    """https://<name>.twingate.com only: the key is never sent to any other host."""
    if not isinstance(network_url, str) or not network_url.isascii():
        raise CheckError("bad network url")
    m = re.fullmatch(r"https://([^/?#@:\s]+)/?", network_url)
    if not m or not HOST_RE.fullmatch(m.group(1)):
        raise CheckError("bad network url")
    return "https://" + m.group(1) + "/api/graphql/"


def _no_duplicates(pairs):
    out = {}
    for k, v in pairs:
        if k in out:
            raise CheckError("duplicate key in management config")
        out[k] = v
    return out


def load_management(env):
    """Connector name -> mode. Empty when nothing is configured."""
    path = env.get("TWINGATE_CONNECTOR_MANAGED_BY_FILE")
    if path:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        try:
            if not stat.S_ISREG(os.fstat(fd).st_mode):
                raise CheckError("management config is not a regular file")
            raw = os.read(fd, MAX_CONFIG_BYTES + 1)
        finally:
            os.close(fd)
    else:
        raw = (env.get("TWINGATE_CONNECTOR_MANAGED_BY") or "").encode("utf-8")
        if not raw:
            return {}
    if len(raw) > MAX_CONFIG_BYTES:
        raise CheckError("management config too large")
    cfg = json.loads(raw.decode("utf-8"), object_pairs_hook=_no_duplicates)
    if not isinstance(cfg, dict) or len(cfg) > MAX_CONFIG_ENTRIES:
        raise CheckError("management config must be a small JSON object")
    for k, v in cfg.items():
        if not isinstance(k, str) or not 0 < len(k) <= 128 or v not in MODES or not isinstance(v, str):
            raise CheckError("bad management config entry")
    return cfg


def load_expected(env):
    """Names that must appear in the inventory. Empty when nothing is configured."""
    raw = env.get("TWINGATE_EXPECTED_CONNECTORS")
    if not raw:
        return set()
    if not isinstance(raw, str) or len(raw.encode("utf-8")) > MAX_CONFIG_BYTES:
        raise CheckError("bad expected connectors")
    val = json.loads(raw)
    if (not isinstance(val, list) or len(val) > MAX_CONFIG_ENTRIES
            or not all(isinstance(x, str) and 0 < len(x) <= 128 for x in val)):
        raise CheckError("bad expected connectors")
    return set(val)


def latest_releases(get):
    """Every released x.y.z version Docker Hub lists (floating tags are ignored)."""
    versions = set()
    for page in range(1, MAX_TAG_PAGES + 1):
        data = get(f"{TAGS_URL}?page_size=100&ordering=last_updated&page={page}")
        if not isinstance(data, dict) or not isinstance(data.get("results"), list):
            raise CheckError("bad tags answer")
        for item in data["results"]:
            name = item.get("name") if isinstance(item, dict) else None
            if isinstance(name, str) and VERSION_RE.fullmatch(name):
                versions.add(parse_version(name))
        if not data.get("next"):
            break
    else:
        raise CheckError("release list truncated")
    if not versions:
        raise CheckError("no release versions found")
    return versions


def fetch_connectors(post, url, api_key):
    nodes, after = [], None
    for _ in range(MAX_CONNECTOR_PAGES):
        data = post(url, api_key, QUERY, {"first": 100, "after": after})
        if not isinstance(data, dict) or data.get("errors"):
            raise CheckError("api error")
        conns = (data.get("data") or {}).get("connectors") if isinstance(data.get("data"), dict) else None
        if not isinstance(conns, dict) or not isinstance(conns.get("edges"), list):
            raise CheckError("bad api answer")
        for edge in conns["edges"]:
            n = edge.get("node") if isinstance(edge, dict) else None
            if not isinstance(n, dict):
                raise CheckError("bad connector")
            nodes.append(n)
        if len(nodes) > MAX_CONNECTORS:
            raise CheckError("too many connectors")
        info = conns.get("pageInfo")
        if not isinstance(info, dict) or not isinstance(info.get("hasNextPage"), bool):
            raise CheckError("bad page info")
        if not info["hasNextPage"]:
            if not nodes:
                raise CheckError("no connectors returned")
            return nodes
        after = info.get("endCursor")
        if not isinstance(after, str) or not 0 < len(after) <= 512:
            raise CheckError("bad cursor")
    raise CheckError("too many pages")


def safe_tag(name, seen):
    base = re.sub(r"[^A-Za-z0-9._-]", "_", name)[:64] or "_"
    tag, n = base, 1
    while tag in seen:
        n += 1
        tag = base[:60] + "_" + str(n)
    seen.add(tag)
    return tag


def collect(env, post, get):
    management = load_management(env)
    expected = load_expected(env)
    api_key = env.get("TWINGATE_API_KEY")
    if not api_key or not isinstance(api_key, str):
        raise CheckError("missing key")
    url = api_url(env.get("TWINGATE_NETWORK_URL"))
    nodes = fetch_connectors(post, url, api_key)
    if not expected <= {n.get("name") for n in nodes}:
        raise CheckError("expected connector missing")
    releases = latest_releases(get)
    out, seen = [], set()
    for n in nodes:
        name = n.get("name")
        if not isinstance(name, str):
            raise CheckError("bad connector name")
        have = parse_version(n.get("version"))
        behind = sum(1 for v in releases if v > have)
        state = n.get("state")
        up = 1 if isinstance(state, str) and state == "ALIVE" else 0
        tags = f"connector={safe_tag(name, seen)},managed_by={management.get(name, DEFAULT_MODE)}"
        out.append(f"twingate_connector_behind,{tags} value={behind}i")
        out.append(f"twingate_connector_up,{tags} value={up}i")
    out.append("twingate_update_check_success value=1i")
    return out


def main(env=None, post=post_graphql, get=get_json, stdout=None, stderr=None):
    env = os.environ if env is None else env
    stdout = stdout or sys.stdout
    stderr = stderr or sys.stderr
    try:
        lines = collect(env, post, get)
    except CheckError as e:
        reason = str(e)
    except Exception:  # any other failure: fixed text only, never the exception (it may echo a secret)
        reason = "check failed"
    else:
        stdout.write("\n".join(lines) + "\n")
        return 0
    stderr.write(f"twingate-update-metric: {reason}\n")
    stdout.write("twingate_update_check_success value=0i\n")
    return 1


if __name__ == "__main__":
    sys.exit(main())
