#!/usr/bin/env python3
"""Game-day failure tests for the alert path (issue #84, epic #62).

Break one link of Grafana -> n8n router -> Discord / phone on purpose, and
check that a failure alert still arrives through another path. One subcommand
per scenario. See docs/game-day.md for the checklist and the rollback section.

SAFETY MODEL
  Dry-run is the default: a scenario prints what it would do, what you should
  observe and how to revert, and changes nothing. Changes run only with BOTH
  --apply and --confirm-live. --apply alone is refused (exit 2) and nothing is
  run. Every change goes through an injectable runner, so the tests never touch
  a live system. Nothing in this file is a hostname or a secret.

Usage:
  gameday.py list
  gameday.py SCENARIO                          dry-run: print the plan
  gameday.py SCENARIO --apply --confirm-live   run the steps
  gameday.py SCENARIO --revert                 dry-run: print only the revert
  gameday.py SCENARIO --revert --apply --confirm-live
  Options: --config FILE (TOML), --log FILE (append one JSON line per run)

Configuration: environment variables GAMEDAY_<KEY> win over the TOML file
(env name = GAMEDAY_ + upper-case key). Keys:
  n8n_container       default n8n
  grafana_container   default grafana
  docker              default docker (the container CLI)
  discord_host        default discord.com (blocked inside n8n by discord-unreachable)
  pushover_host       default api.pushover.net (phone-unreachable)
  heartbeat_host      no default; the host of your heartbeat observer's ping URL
  router_workflow_id  no default; the n8n id of the router workflow (router-inactive)
  router_path         no default; the router's private webhook path (wrong-header)
  n8n_base            optional full base URL; else looked up at run time
The Grafana webhook secret is never read or sent: wrong-header sends a made-up value.
"""
import argparse
import datetime
import ipaddress
import json
import os
import re
import stat
import subprocess
import sys
import urllib.error
import urllib.parse
import urllib.request

sys.path.insert(0, os.path.dirname(os.path.realpath(__file__)))
import container_engine  # noqa: E402  (the one shared engine setting and trusted-binary resolver, issue #130)

MARKER = "# gameday-84"  # the line marker is MARKER + "-" + the run id
CLI_ALLOWED = container_engine.ENGINES
RUN_ID_RE = re.compile(r"[0-9a-f]{8,32}")
TRUSTED_DIRS = container_engine.TRUSTED_DIRS
TRUSTED_UID = container_engine.TRUSTED_UID  # the owner a trusted binary and every directory above it must have
TRUSTED_ROOT = container_engine.TRUSTED_ROOT  # ownership is checked on every directory from here down
SAFE_BIN_PATH = "/usr/sbin:/usr/bin:/sbin:/bin"  # PATH inside the container for the hosts scripts
BIN_PATH_RE = re.compile(r"[A-Za-z0-9_./:-]{1,512}")
PLACEHOLDER_ID = "<RUN_ID>"  # shown in a dry-run revert when no --run-id was given
DEFAULTS = {
    "n8n_container": "n8n",
    "grafana_container": "grafana",
    "docker": "docker",
    "discord_host": "discord.com",
    "pushover_host": "api.pushover.net",
}
KEYS = (
    "n8n_container", "grafana_container", "docker", "discord_host", "pushover_host",
    "heartbeat_host", "router_workflow_id", "router_path", "n8n_base",
)
NAME_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,127}")
HOST_RE = re.compile(r"[A-Za-z0-9]([A-Za-z0-9.-]{0,251}[A-Za-z0-9])?")
PATH_RE = re.compile(r"[A-Za-z0-9_-]{1,128}")
ID_RE = re.compile(r"[A-Za-z0-9]{1,64}")


class GamedayError(Exception):
    """Bad configuration or a refused action; the message says what to do."""


# ---------------------------------------------------------------- configuration

def load_config(env=None, config_path=None):
    """Merge defaults, the TOML file and the environment (environment wins)."""
    env = os.environ if env is None else env
    cfg = dict(DEFAULTS)
    try:
        cfg["docker"] = container_engine.engine_name(env)  # CONTAINER_ENGINE; GAMEDAY_DOCKER below still wins
    except container_engine.ContainerEngineError as err:
        raise GamedayError(str(err))
    path = config_path or env.get("GAMEDAY_CONFIG")
    if path:
        try:
            import tomllib
        except ImportError:  # pragma: no cover - python < 3.11
            raise GamedayError("a TOML config needs Python 3.11 or newer; use GAMEDAY_* variables instead")
        try:
            with open(path, "rb") as fh:
                data = tomllib.load(fh)
        except OSError as err:
            raise GamedayError(f"cannot read config file: {err.strerror}")
        except tomllib.TOMLDecodeError as err:
            raise GamedayError(f"config file is not valid TOML: {err}")
        for key, value in data.items():
            if key not in KEYS:
                raise GamedayError(f"unknown config key '{key}' (allowed: {', '.join(KEYS)})")
            if not isinstance(value, str):
                raise GamedayError(f"config key '{key}' must be a string")
            cfg[key] = value
    for key in KEYS:
        value = env.get("GAMEDAY_" + key.upper())
        if value is not None and value.strip():
            cfg[key] = value.strip()
    if cfg["docker"] not in CLI_ALLOWED:
        raise GamedayError(f"'docker' must be one of: {', '.join(CLI_ALLOWED)}")
    return cfg


def _need(cfg, key, scenario):
    value = cfg.get(key)
    if not value:
        raise GamedayError(
            f"scenario '{scenario}' needs '{key}': set GAMEDAY_{key.upper()} or put it in the TOML config")
    return value


def _check(value, regex, what):
    if not regex.fullmatch(value):
        raise GamedayError(f"{what} has characters that are not allowed")
    return value


# ------------------------------------------------------------------- the plan

class Step:
    """One action. kind 'exec' runs argv; kind 'http' posts to the router."""

    def __init__(self, text, argv=None, http=None, needs_id=False):
        self.text = text
        self.argv = argv
        self.http = http
        self.needs_id = needs_id  # the argv carries the run id

    def describe(self):
        if self.argv:
            return self.text + "\n        $ " + " ".join(_quote(a) for a in self.argv)
        return self.text


def _quote(arg):
    return arg if re.fullmatch(r"[A-Za-z0-9_@%+=:,./-]+", arg) else "'" + arg.replace("'", "'\\''") + "'"


class Scenario:
    def __init__(self, name, title, steps, observe, revert, note=""):
        self.name, self.title, self.steps = name, title, steps
        self.observe, self.revert, self.note = observe, revert, note


def _docker(cfg, *args):
    return [cfg["docker"], *args]


def hosts_line(host, run_id):
    """The one line this run adds. The run id makes it exact and unique."""
    return f"0.0.0.0 {host} {MARKER}-{run_id}"


_SH_HEAD = r"""PATH='@P@'
export PATH
set -eu
H='@H@'
L='@L@'
LK="$H.gameday-lock"
D=''
ok=0
locked=0
cleanup() {
  if [ -n "$D" ]; then
    if [ "$ok" = 1 ]; then rm -rf "$D"; else echo "backup kept in $D" >&2; fi
  fi
  if [ "$locked" = 1 ]; then rm -rf "$LK"; fi
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM HUP
chk() { [ -f "$H" ] && [ ! -L "$H" ]; }
chk || { echo 'hosts file missing or a symlink' >&2; exit 1; }
if echo x | grep -a x >/dev/null 2>&1; then G='grep -a'; else G=grep; fi
tries=0
while ! mkdir "$LK" 2>/dev/null; do
  pid=$(cat "$LK/pid" 2>/dev/null || true)
  if [ -n "$pid" ] && ! kill -0 "$pid" 2>/dev/null; then
    if mv "$LK" "$LK.stale.$$" 2>/dev/null; then
      got=$(cat "$LK.stale.$$/pid" 2>/dev/null || true)
      if [ "$got" = "$pid" ]; then rm -rf "$LK.stale.$$"; else mv "$LK.stale.$$" "$LK" 2>/dev/null || rm -rf "$LK.stale.$$"; fi
    fi
    continue
  fi
  tries=$((tries + 1))
  [ "$tries" -le @TRIES@ ] || { echo "another hosts edit holds the lock $LK (remove it if no game-day script is running)" >&2; exit 1; }
  sleep @SLEEP@
done
locked=1
printf '%s\n' "$$" > "$LK/pid"
printf '%s\n' "$L" > "$LK/run"
"""

_SH_ADD = r"""rc=0; $G -qxF -- "$L" "$H" || rc=$?
if [ "$rc" -eq 0 ]; then exit 0; fi
[ "$rc" -eq 1 ]
chk || { echo 'hosts file changed under us' >&2; exit 1; }
if [ -s "$H" ] && [ "$(tail -c 1 "$H" | od -An -tx1 | tr -d ' \n')" != 0a ]; then printf '\n' >> "$H"; fi
printf '%s\n' "$L" >> "$H"
rc=0; $G -qxF -- "$L" "$H" || rc=$?
[ "$rc" -eq 0 ]
"""

_SH_REMOVE = r"""rc=0; $G -qxF -- "$L" "$H" || rc=$?
if [ "$rc" -eq 1 ]; then echo 'line already absent'; exit 0; fi
[ "$rc" -eq 0 ]
D=$(mktemp -d "${TMPDIR:-/tmp}/gameday.XXXXXX")
chk || { echo 'hosts file changed under us' >&2; exit 1; }
cat "$H" > "$D/orig"
cmp -s "$D/orig" "$H"
total=$($G -c '' "$H" || [ $? -eq 1 ])
gone=$($G -cxF -- "$L" "$H" || [ $? -eq 1 ])
$G -vxF -- "$L" "$H" > "$D/new" || [ $? -eq 1 ]
[ -s "$D/new" ] || { echo 'refusing to leave an empty hosts file' >&2; exit 1; }
rc=0; $G -qxF -- "$L" "$D/new" || rc=$?
[ "$rc" -eq 1 ] || { echo 'marker still present in the new content' >&2; exit 1; }
have=$($G -c '' "$D/new" || [ $? -eq 1 ])
[ "$have" -eq $((total - gone)) ] || { echo 'line count check failed' >&2; exit 1; }
if [ "$(tail -c 1 "$D/orig" | od -An -tx1 | tr -d ' \n')" != 0a ] && [ "$(tail -n 1 "$D/orig")" != "$L" ]; then
  n=$(wc -c < "$D/new")
  head -c $((n - 1)) "$D/new" > "$D/new2"
  mv "$D/new2" "$D/new"
fi
chk || { echo 'hosts file changed under us' >&2; exit 1; }
cmp -s "$D/orig" "$H" || { echo 'hosts file changed since the backup was taken; nothing written' >&2; exit 1; }
if cat "$D/new" > "$H" && cmp -s "$D/new" "$H"; then ok=1; exit 0; fi
echo 'write failed; restoring the original' >&2
chk || { echo 'RESTORE FAILED: hosts file replaced; original kept in '"$D"'/orig' >&2; exit 1; }
if cmp -s "$D/orig" "$H"; then echo 'original is intact' >&2; ok=1; exit 1; fi
sz=$(wc -c < "$H")
nsz=$(wc -c < "$D/new")
if [ "$sz" -le "$nsz" ] && head -c "$sz" "$D/new" | cmp -s - "$H"; then
  if cat "$D/orig" > "$H" && cmp -s "$D/orig" "$H"; then echo 'original restored' >&2; ok=1; exit 1; fi
  echo 'RESTORE FAILED: original kept in '"$D"'/orig' >&2
  exit 1
fi
echo 'RESTORE SKIPPED: the hosts file was changed by another writer; original kept in '"$D"'/orig' >&2
exit 1
"""


def _sh(body, line, path, bin_path, lock_tries, lock_sleep):
    bin_path = SAFE_BIN_PATH if bin_path is None else bin_path
    if not BIN_PATH_RE.fullmatch(bin_path):
        raise GamedayError("container PATH text has characters that are not allowed")
    if not re.fullmatch(r"[0-9]{1,4}", str(lock_tries)) or not re.fullmatch(r"[0-9]{1,2}(\.[0-9]{1,3})?", str(lock_sleep)):
        raise GamedayError("lock settings are not valid")
    return ((_SH_HEAD + body).replace("@P@", bin_path).replace("@H@", path).replace("@L@", line)
            .replace("@TRIES@", str(lock_tries)).replace("@SLEEP@", str(lock_sleep)))


def hosts_add_script(line, path="/etc/hosts", bin_path=None, lock_tries=30, lock_sleep="1"):
    """Shell text that appends exactly `line` under the hosts lock. Any failed step is a nonzero exit.

    The script sets its own PATH first (SAFE_BIN_PATH), so a writable directory in the container's
    PATH is never searched. It needs these utilities in those directories: sh, grep, cat, cmp,
    mktemp, tail, od, tr, wc, head, mv, rm, kill, sleep, mkdir (BusyBox provides all of them).
    """
    return _sh(_SH_ADD, line, path, bin_path, lock_tries, lock_sleep)


def hosts_remove_script(line, path="/etc/hosts", bin_path=None, lock_tries=30, lock_sleep="1"):
    """Shell text that removes every copy of exactly `line` and nothing else.

    Same PATH and utility rules as hosts_add_script. One lock (a mkdir lock next to the file, with
    pid metadata, bounded wait and stale-owner handling) serializes every add and remove. The file
    is never held in a shell variable. The new content goes to a private mktemp -d directory
    (removed by a trap on success; kept with a message on failure) next to a backup of the original.
    Just before the write the live file is compared with the backup and nothing is written if it
    changed. The target is rewritten in place (it may be a bind mount that cannot be renamed over),
    compared with cmp, and restored from the backup only if what is there is a prefix of the new
    content (our own partial write); anything else means another writer changed it and the restore
    is skipped. The symlink check runs before the copy, before the write and before a restore.
    Residual: a root-equivalent actor inside the container can still swap the path between the last
    check and the write; see docs/game-day.md.
    """
    return _sh(_SH_REMOVE, line, path, bin_path, lock_tries, lock_sleep)


def _hosts_block(cfg, container, host, rid):
    _check(container, NAME_RE, "container name")
    _check(host, HOST_RE, "host name")
    if rid != PLACEHOLDER_ID:
        _check(rid, RUN_ID_RE, "run id")
    return Step(f"Make '{host}' unresolvable inside '{container}' (one exact line in /etc/hosts, run {rid})",
                _docker(cfg, "exec", "-u", "root", container, "sh", "-c", hosts_add_script(hosts_line(host, rid))),
                needs_id=True)


def _hosts_unblock(cfg, container, host, rid):
    _check(container, NAME_RE, "container name")
    _check(host, HOST_RE, "host name")
    if rid != PLACEHOLDER_ID:
        _check(rid, RUN_ID_RE, "run id")
    return Step(f"Remove only this run's line ({rid}) from /etc/hosts in '{container}'",
                _docker(cfg, "exec", "-u", "root", container, "sh", "-c",
                        hosts_remove_script(hosts_line(host, rid))),
                needs_id=True)


def _stop(cfg, container):
    _check(container, NAME_RE, "container name")
    return Step(f"Stop container '{container}'", _docker(cfg, "stop", container))


def _start(cfg, container):
    _check(container, NAME_RE, "container name")
    return Step(f"Start container '{container}'", _docker(cfg, "start", container))


def build_scenarios(cfg, rid=PLACEHOLDER_ID):
    """Return {name: Scenario}. A scenario whose config is missing raises on use."""
    n8n, grafana = cfg["n8n_container"], cfg["grafana_container"]

    def discord():
        return Scenario(
            "discord-unreachable",
            "Discord webhook unreachable from n8n",
            [_hosts_block(cfg, n8n, cfg["discord_host"], rid)],
            ["Send a test alert (n8n-test-router.py case 5 or a Grafana contact point test). "
             "The router answers HTTP 502 {\"status\": \"delivery failed\"}.",
             "The error handler sends ONE Pushover message (priority 1) naming the workflow, the failed node and the execution id.",
             "Grafana logs a failed notification; the delivery-failure alert (#81) fires if its rule is loaded.",
             "No Discord message arrives. The phone path still works for alerts labeled phone=true."],
            [_hosts_unblock(cfg, n8n, cfg["discord_host"], rid)])

    def phone():
        return Scenario(
            "phone-unreachable",
            "Phone channel (Pushover) unreachable from n8n",
            [_hosts_block(cfg, n8n, cfg["pushover_host"], rid)],
            ["Send a test alert labeled phone=true (n8n-test-router.py --phone).",
             "Discord still receives the alert and then a notice: \"phone delivery failed: Pushover Notify ...\".",
             "The router answers 200 (a phone failure never fails the run)."],
            [_hosts_unblock(cfg, n8n, cfg["pushover_host"], rid)],
            "Only meaningful when PUSHOVER_ENABLED is true in the router. With it false there is no phone step to fail.")

    def heartbeat():
        host = _need(cfg, "heartbeat_host", "heartbeat-silent")
        return Scenario(
            "heartbeat-silent",
            "Heartbeat pings cannot reach the observer",
            [_hosts_block(cfg, n8n, host, rid)],
            ["The router keeps answering and Discord keeps working; only the ping to the observer fails.",
             "After the observer's period plus grace (10 to 15 minutes with the documented settings) the observer "
             "alerts through its own channels. That is the pass condition.",
             "A ping failure shows in the n8n log, not as a Discord message."],
            [_hosts_unblock(cfg, n8n, host, rid)])

    def n8n_down():
        return Scenario(
            "n8n-down",
            "n8n stopped",
            [_stop(cfg, n8n)],
            ["Grafana cannot deliver: its notification-failure alert (#81) fires and its log shows the error.",
             "Heartbeat pings stop; the observer alerts after period plus grace.",
             "Nothing reaches Discord or the phone through the router while n8n is down; the alerts you see "
             "come from Grafana's own failure path and the observer."],
            [_start(cfg, n8n)])

    def grafana_down():
        return Scenario(
            "grafana-down",
            "Grafana stopped",
            [_stop(cfg, grafana)],
            ["No rule is evaluated, so no heartbeat is sent. The observer alerts after period plus grace.",
             "This is the case only the external observer can catch."],
            [_start(cfg, grafana)])

    def router_inactive():
        wid = _need(cfg, "router_workflow_id", "router-inactive")
        _check(wid, ID_RE, "router workflow id")
        return Scenario(
            "router-inactive",
            "Router workflow deactivated (webhook answers an error, not 200)",
            [Step("Deactivate the router workflow with the n8n CLI",
                  _docker(cfg, "exec", n8n, "n8n", "update:workflow", f"--id={wid}", "--active=false")),
             _restart(cfg, n8n, "so the deactivation takes effect")],
            ["Grafana gets a non-2xx from the contact point, logs a failed notification, and the "
             "delivery-failure alert (#81) fires if loaded.",
             "Heartbeat pings stop; the observer alerts after period plus grace.",
             "No Discord message arrives for the test alert."],
            [Step("Activate the router workflow again",
                  _docker(cfg, "exec", n8n, "n8n", "update:workflow", f"--id={wid}", "--active=true")),
             _restart(cfg, n8n, "so the activation takes effect")],
            "UNVERIFIED against a live n8n: the CLI command name differs between n8n versions "
            "(newer ones use publish:workflow / unpublish:workflow). Check `n8n --help` first.")

    def wrong_header():
        path = _need(cfg, "router_path", "wrong-header")
        _check(path, PATH_RE, "router path")
        return Scenario(
            "wrong-header",
            "Webhook call with a wrong Authorization header",
            [Step("POST a harmless test body to the router with a made-up Bearer value "
                  "(the real secret is never read)",
                  http={"path": path, "headers": {"Authorization": "Bearer gameday-wrong-value"},
                        "body": '{"status":"firing","alerts":[]}'})],
            ["The router answers 401 or 403. Anything else (especially 200) is a defect: the webhook is open.",
             "No Discord or phone message is sent; n8n logs a rejected call."],
            [],
            "Nothing to revert: the call changes no state.")

    return {
        "discord-unreachable": discord, "phone-unreachable": phone, "heartbeat-silent": heartbeat,
        "n8n-down": n8n_down, "grafana-down": grafana_down, "router-inactive": router_inactive,
        "wrong-header": wrong_header,
    }  # factories, so one missing config key does not block the other scenarios


def _restart(cfg, container, why):
    _check(container, NAME_RE, "container name")
    return Step(f"Restart container '{container}' {why}", _docker(cfg, "restart", container))


SCENARIO_NAMES = ("discord-unreachable", "phone-unreachable", "heartbeat-silent",
                  "n8n-down", "grafana-down", "router-inactive", "wrong-header")


def get_scenario(cfg, name, rid=PLACEHOLDER_ID):
    factories = build_scenarios(cfg, rid)
    if name not in factories:
        raise GamedayError(f"unknown scenario '{name}' (try: list)")
    return factories[name]()


# ------------------------------------------------------------ real runners

def _dirs_ok(path, owner_uid, root):
    return container_engine._dirs_ok(path, owner_uid, root)


def resolve_cli(name, dirs=None, owner_uid=None, root=None):
    """The shared resolver (container_engine.resolve_cli), defaulting to this module's trusted settings."""
    return container_engine.resolve_cli(
        name,
        TRUSTED_DIRS if dirs is None else dirs,
        TRUSTED_UID if owner_uid is None else owner_uid,
        TRUSTED_ROOT if root is None else root,
    )


def real_runner(argv):
    """Run a command; returns (returncode, short text). Output beyond 300 characters is cut."""
    exe = resolve_cli(argv[0])
    if exe is None:
        return 127, f"no trusted '{argv[0]}' found in {', '.join(TRUSTED_DIRS)} (root-owned, not writable by others)"
    good = [d for d in TRUSTED_DIRS if os.path.isdir(d) and _dirs_ok(os.path.realpath(d), TRUSTED_UID, TRUSTED_ROOT)]
    env = container_engine.engine_env(path=":".join(good))  # no DOCKER_HOST, LD_*, config or helper variables
    try:
        proc = subprocess.run([argv[0], *argv[1:]], executable=exe, capture_output=True, text=True,
                              timeout=120, env=env)
    except FileNotFoundError:
        return 127, f"command not found: {argv[0]}"
    except subprocess.TimeoutExpired:
        return 124, "timed out after 120 seconds"
    return proc.returncode, ((proc.stdout or "") + (proc.stderr or "")).strip()[:300]


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    """Never follow a redirect: the request would carry the Authorization header along."""

    def redirect_request(self, *args, **kwargs):
        return None


_OPENER = urllib.request.build_opener(urllib.request.ProxyHandler({}), _NoRedirect)


def validate_base(base):
    """Accept only http(s)://<loopback or private IP>[:port][/]. Returns the base without a trailing slash."""
    try:
        parts = urllib.parse.urlsplit(base)
        host, port = parts.hostname, parts.port  # port raises ValueError when out of range
        ip = ipaddress.ip_address(host) if host else None
    except ValueError:
        raise GamedayError("n8n base URL is not valid (use http://<private IP>:<port>)")
    if parts.scheme not in ("http", "https") or ip is None or parts.username is not None or parts.password is not None:
        raise GamedayError("n8n base URL must be http(s)://<private IP>[:port] with no user info")
    if parts.path not in ("", "/") or parts.query or parts.fragment:
        raise GamedayError("n8n base URL must have no path, query or fragment")
    if ip.is_unspecified or ip.is_multicast or ip.is_link_local or not (ip.is_loopback or ip.is_private):
        raise GamedayError("n8n base URL must be a loopback or private address (not link-local or public)")
    return base.rstrip("/")


def real_poster(url, headers, body):
    """POST and return the status code (or 'error:<Type>'). Redirects are not followed."""
    req = urllib.request.Request(url, data=body.encode(), method="POST",
                                 headers=dict({"Content-Type": "application/json"}, **headers))
    try:
        with _OPENER.open(req, timeout=20) as resp:
            return resp.status
    except urllib.error.HTTPError as err:
        return err.code
    except Exception as err:
        return "error:" + type(err).__name__


def real_resolver(cfg):
    sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
    import n8n_address
    env = dict(os.environ)
    env["CONTAINER_ENGINE"] = cfg["docker"]  # the one engine this run chose, never re-read from the environment
    if cfg.get("n8n_base"):
        env["N8N_BASE"] = cfg["n8n_base"]
    env.setdefault("N8N_CONTAINER", cfg["n8n_container"])
    return n8n_address.resolve_n8n_base(env)


# ------------------------------------------------------------------ execution

def render(sc, revert_only):
    lines = [f"SCENARIO: {sc.name} - {sc.title}", f"MODE: {'revert only' if revert_only else 'inject'}"]
    steps = sc.revert if revert_only else sc.steps
    lines.append("WOULD DO:" if steps else "WOULD DO: nothing (no state change)")
    for i, step in enumerate(steps, 1):
        lines.append(f"  {i}. {step.describe()}")
    if not revert_only:
        lines.append("OBSERVE:")
        lines += [f"  - {o}" for o in sc.observe]
    lines.append("REVERT:" if sc.revert else "REVERT: none needed")
    for i, step in enumerate(sc.revert, 1):
        lines.append(f"  {i}. {step.describe()}")
    if sc.note:
        lines.append(f"NOTE: {sc.note}")
    return "\n".join(lines)


def run_steps(steps, cfg, run, post, resolve, results=None):
    """Run steps in order; stop at the first failure. `results` (a list) is filled as steps start,
    so a caller still sees what began when an exception escapes. Each entry: [text, ok, detail]."""
    results = [] if results is None else results
    for step in steps:
        entry = [step.text, False, "started, outcome unknown"]
        results.append(entry)  # recorded BEFORE the call: an interrupted step may have applied
        if step.argv:
            rc, detail = run(step.argv)
            ok = rc == 0
            detail = f"exit {rc}" + (f": {detail}" if detail and not ok else "")
        else:
            try:
                base = validate_base(resolve(cfg))
            except GamedayError as err:
                entry[1:] = [False, f"refused: {err}"]
                break
            status = post(f"{base}/webhook/{step.http['path']}", step.http["headers"], step.http["body"])
            ok = status in (401, 403)
            detail = f"HTTP {status} (expected 401 or 403)"
        entry[1:] = [ok, detail]
        if not ok:
            break
    return [tuple(e) for e in results]


def write_log(path, rec, write=os.write):
    """Append one JSON line, private and without following symlinks. Returns an error text or ''.

    An existing file must be a regular file we own, with no group or world permission bits and a
    single link. The whole record is written (short writes are completed; a zero write is a failure).
    """
    flags = os.O_APPEND | os.O_CREAT | os.O_WRONLY | os.O_NOFOLLOW | os.O_NONBLOCK
    try:
        fd = os.open(path, flags, 0o600)
    except OSError as err:
        return f"cannot open log ({err.strerror})"
    try:
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode):
            return "log path is not a regular file"
        if st.st_uid != os.geteuid():
            return "log file is owned by another user"
        if st.st_mode & 0o077:
            return "log file must be private (mode 0600); it has group or world permissions"
        if st.st_nlink != 1:
            return "log file has more than one hard link"
        data = (json.dumps(rec) + "\n").encode()
        while data:
            n = write(fd, data)
            if not n or n < 0:
                return "cannot write log (write made no progress)"
            data = data[n:]
    except OSError as err:
        return f"cannot write log ({err.strerror})"
    finally:
        os.close(fd)
    return ""


def execute(argv, env=None, run=real_runner, post=real_poster, resolve=real_resolver, out=sys.stdout, clock=None):
    """Entry point with injectable collaborators. Returns the process exit code."""
    parser = argparse.ArgumentParser(prog="gameday.py", description=__doc__.split("\n\n")[0],
                                     allow_abbrev=False)
    parser.add_argument("scenario", help="a scenario name, or 'list'")
    parser.add_argument("--apply", action="store_true", help="run the steps (also needs --confirm-live)")
    parser.add_argument("--confirm-live", action="store_true",
                        help="state that you mean to change the live system")
    parser.add_argument("--revert", action="store_true", help="print or run only the revert steps")
    parser.add_argument("--run-id", help="hex id of the injection to revert (printed when you inject)")
    parser.add_argument("--config", help="TOML config file")
    parser.add_argument("--log", help="append one JSON line describing this run")
    try:
        args = parser.parse_args(argv)
    except SystemExit as err:
        return err.code if isinstance(err.code, int) else 2

    def say(text):
        print(text, file=out)

    if args.apply and not args.confirm_live:
        say("REFUSED: --apply changes the live system and needs --confirm-live as well. Nothing was run.")
        return 2

    try:
        cfg = load_config(env, args.config)
        if args.scenario == "list":
            for name in SCENARIO_NAMES:
                say(name)
            return 0
        if args.run_id is not None and not RUN_ID_RE.fullmatch(args.run_id):
            raise GamedayError("--run-id must be 8 to 32 lower-case hex characters")
        rid = args.run_id or (PLACEHOLDER_ID if args.revert else os.urandom(6).hex())
        sc = get_scenario(cfg, args.scenario, rid)
        if args.apply and args.revert and rid == PLACEHOLDER_ID and any(s.needs_id for s in sc.revert):
            raise GamedayError("reverting this scenario needs --run-id (printed when it was injected)")
        say(render(sc, args.revert))
        if not args.revert and any(s.needs_id for s in sc.steps):
            say(f"RUN ID: {rid}  (revert with: gameday.py {sc.name} --revert --run-id {rid} --apply --confirm-live)")
    except GamedayError as err:
        say(f"ERROR: {err}")
        return 2

    if not args.apply:
        say("DRY-RUN: nothing was changed. Add --apply --confirm-live to run the steps above.")
        return 0

    steps = sc.revert if args.revert else sc.steps
    say("APPLYING (live):")
    results, reverted, pending = [], [], None
    try:
        run_steps(steps, cfg, run, post, resolve, results)
    except BaseException as exc:  # includes KeyboardInterrupt: a started step may have applied
        pending = exc
    for text, ok, detail in results:
        say(f"  [{'ok' if ok else 'FAILED'}] {text} - {detail}")
    failed = pending is not None or any(not e[1] for e in results)
    if pending is not None:
        say(f"INTERRUPTED by {type(pending).__name__}; the last step may have been applied.")
    if failed and not args.revert and sc.revert:
        say("A step failed or was interrupted. Running the revert steps now.")
        try:
            run_steps(sc.revert, cfg, run, post, resolve, reverted)
        except BaseException as exc:  # never mask the original problem
            say(f"REVERT INTERRUPTED by {type(exc).__name__}.")
            reverted.append(["revert", False, "interrupted"])
        for text, ok, detail in reverted:
            say(f"  [revert {'ok' if ok else 'FAILED'}] {text} - {detail}")
        if any(not e[1] for e in reverted):
            say("REVERT FAILED. Run the REVERT commands printed above by hand now.")
    elif not failed and not args.revert and sc.revert:
        say("Injected. Observe the points above, then revert with: "
            f"gameday.py {sc.name} --revert{' --run-id ' + rid if any(s.needs_id for s in sc.steps) else ''} "
            "--apply --confirm-live")
    if args.log:
        now = (clock or (lambda: datetime.datetime.now(datetime.timezone.utc)))()
        rec = {"time": now.isoformat(), "scenario": sc.name, "mode": "revert" if args.revert else "inject",
               "ok": not failed, "steps": [{"step": e[0], "ok": e[1]} for e in results],
               "auto_reverted": bool(reverted)}
        if any(s.needs_id for s in sc.steps) and not args.revert:
            rec["run_id"] = rid
        problem = write_log(args.log, rec)
        if problem:
            say(f"WARNING: log not written: {problem}. The result above still stands.")
    if pending is not None:
        raise pending
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(execute(sys.argv[1:]))
