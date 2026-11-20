#!/usr/bin/env python3
"""Weekly status digest by email (issue #69, epic #62; the P3 tier of docs/design/channel-redundancy.md).

One plain text email per run: what was patched automatically, what needs action, which alerts
fired this week, and what is stale. Standard library only. Every data source is a small provider
function that run() takes as an argument, so tests (and other sources later) swap it.

Safe by default: a run is a dry run that prints the rendered email and makes NO network call
(not even a read). Sending needs --send. The SMTP sender is the expiry watch's own (imported, not
copied): TLS verified, STARTTLS required, one overall delivery deadline, login from environment
variables named in the config. Secrets are only ever environment variable NAMES in the config.

Exit codes: 0 done; 1 done, but a data source failed (named in the email); 2 config error;
3 the email was not delivered.
"""
import argparse
import datetime as dt
import email.message
import email.utils
import hashlib
import os
import re
import sys
import urllib.parse
from dataclasses import dataclass
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import expiry_watch as ew  # noqa: E402  the one hardened sender and config toolkit

DigestError = ew.ExpiryWatchError
UTC = dt.timezone.utc

MAX_BODY_BYTES_LIMIT = 200_000
MAX_ENTRY_CHARS = 200
MAX_EVENTS = 1000
_LINE_BREAKS = re.compile("[\u0000-\u001f\u007f-\u009f  \u0085]")
_SPACES = re.compile(r" {2,}")


def clean(text, limit=MAX_ENTRY_CHARS):
    """One line of text from a provider: control characters and line breaks become spaces, runs of
    spaces collapse, length is capped. Applied to EVERY provider string at render time."""
    return _SPACES.sub(" ", _LINE_BREAKS.sub(" ", str(text))).strip()[:limit]


# --- config ---------------------------------------------------------------------------------

@dataclass(frozen=True)
class GrafanaConfig:
    url: str
    token_env: str
    timeout_seconds: float
    limit: int
    needs_action_words: tuple


@dataclass(frozen=True)
class DigestConfig:
    window_days: int
    max_body_bytes: int
    max_entries: int
    delivery_budget_seconds: float
    state_file: str
    warn_days: int
    stale_run_days: int
    email: object
    grafana: GrafanaConfig = None


def parse_grafana(table):
    if not isinstance(table, dict):
        raise DigestError("[grafana] must be a table")
    ew._only_keys("[grafana]", table, ("url", "token_env", "timeout_seconds", "limit", "needs_action_words"))
    url = ew._check_url("grafana.url", table.get("url"), plain=False).rstrip("/")
    words = table.get("needs_action_words", ["update", "reboot"])
    if not isinstance(words, list) or not 1 <= len(words) <= 20:
        raise DigestError("grafana.needs_action_words must be a list of 1 to 20 words")
    words = tuple(ew._text("grafana.needs_action_words entry", w, 40).lower() for w in words)
    return GrafanaConfig(url, ew._env_name("grafana.token_env", table.get("token_env")),
                         ew._timeout("grafana.timeout_seconds", table.get("timeout_seconds"), 10),
                         ew._int("grafana.limit", table.get("limit", 500), 1, MAX_EVENTS), words)


def parse_config(raw):
    if not isinstance(raw, dict):
        raise DigestError("config must be a table")
    ew._only_keys("config", raw, ("digest", "expiry", "email", "grafana"))
    digest = raw.get("digest", {})
    expiry = raw.get("expiry", {})
    for label, t in (("[digest]", digest), ("[expiry]", expiry)):
        if not isinstance(t, dict):
            raise DigestError(f"{label} must be a table")
    ew._only_keys("[digest]", digest, ("window_days", "max_body_bytes", "max_entries_per_section",
                                       "delivery_budget_seconds"))
    ew._only_keys("[expiry]", expiry, ("state_file", "warn_days", "stale_run_days"))
    budget = digest.get("delivery_budget_seconds", 60)
    if isinstance(budget, bool) or not isinstance(budget, (int, float)) or not 0 < budget <= 3600:
        raise DigestError("delivery_budget_seconds must be above 0 and at most 3600")
    if "email" not in raw:
        raise DigestError("the config needs an [email] table (same settings as the expiry watch)")
    return DigestConfig(
        window_days=ew._int("window_days", digest.get("window_days", 7), 1, 31),
        max_body_bytes=ew._int("max_body_bytes", digest.get("max_body_bytes", 32768), 1024, MAX_BODY_BYTES_LIMIT),
        max_entries=ew._int("max_entries_per_section", digest.get("max_entries_per_section", 40), 1, 200),
        delivery_budget_seconds=float(budget),
        state_file=ew._text("expiry.state_file", expiry.get("state_file", "expiry-watch-state.json"), 256),
        warn_days=ew._int("warn_days", expiry.get("warn_days", 30), 1, ew.MAX_DAYS),
        stale_run_days=ew._int("stale_run_days", expiry.get("stale_run_days", 3), 1, 365),
        email=ew.parse_email(raw["email"]),
        grafana=parse_grafana(raw["grafana"]) if "grafana" in raw else None)


# --- providers (each returns a Section; they may raise DigestError) --------------------------

@dataclass(frozen=True)
class Section:
    title: str
    lines: tuple = ()
    note: str = ""  # shown when there are no lines, or as a label above them


def patched_provider(ctx):
    """What Patch Gremlin applied automatically. The repo does not document a Patch Gremlin state
    format, so this is a labeled placeholder until one is defined (docs/weekly-digest.md)."""
    return Section("Patched automatically",
                   note="PLACEHOLDER: no Patch Gremlin state source is defined in this repo yet, so nothing is reported here.")


def expiry_provider(ctx):
    """Stale things, from the expiry watch state file, read-only (never written)."""
    cfg, today = ctx["config"], ctx["now"].date()
    root = ctx["root"]
    try:
        ew.read_capped(cfg.state_file, "state", root)  # a missing file is empty to load_state, so look first
        state = ew.load_state(cfg.state_file, root)
    except ew.FileMissing:
        state = None
    lines = []
    if state is None:
        return Section("Stale", note=f"The expiry watch state file {clean(cfg.state_file, 80)} was not found: "
                                     "the watch may never have run.")
    for name, st in sorted(state.items()):
        left = (dt.date.fromisoformat(st["expires"]) - today).days
        if st["expired"] or left < 0:
            lines.append(f"{name}: EXPIRED {-left} days ago ({st['expires']})")
        elif left <= cfg.warn_days:
            lines.append(f"{name}: expires in {left} days ({st['expires']})")
    age = ctx["state_age_days"]
    if age is not None and age > cfg.stale_run_days:
        lines.append(f"the expiry watch itself has not saved its state for {age} days")
    return Section("Stale", tuple(lines), note="Nothing stale." if not lines else "")


def _grafana_events(ctx):
    """Alert state changes of the window, read through the Grafana annotations API (read-only
    token from an environment variable). Returns a list of (time_ms, name, new_state)."""
    g = ctx["config"].grafana
    token = ctx["env"].get(g.token_env)
    if not token:
        raise DigestError(f"set the environment variable {g.token_env} (the read-only Grafana token)")
    end = int(ctx["now"].timestamp() * 1000)
    start = end - ctx["config"].window_days * 86_400_000
    query = urllib.parse.urlencode({"type": "alert", "from": start, "to": end, "limit": g.limit})
    data = ew.http_get_json(f"{g.url}/api/annotations?{query}", token, g.timeout_seconds)
    if not isinstance(data, list):
        raise DigestError("grafana: the annotations answer is not a list")
    events = []
    for rec in data[:MAX_EVENTS]:
        if not isinstance(rec, dict):
            continue
        t, name, state = rec.get("time"), rec.get("alertName"), rec.get("newState")
        if (isinstance(t, int) and not isinstance(t, bool) and isinstance(name, str) and name
                and isinstance(state, str)):
            events.append((t, name, state))
    return sorted(events)


def grafana_provider(ctx):
    """(alerts that fired, needs action) from one read of the Grafana alert state history. A
    provider that returns two sections keeps the network read to one call."""
    g = ctx["config"].grafana
    if g is None:
        note = "Not configured: add a [grafana] table (docs/weekly-digest.md)."
        return (Section("Alerts that fired this week", note=note), Section("Needs action", note=note))
    events = _grafana_events(ctx)
    fired, latest = {}, {}
    for t, name, state in events:
        latest[name] = (t, state)
        if state.lower().startswith(("alerting", "error")):
            fired[name] = fired.get(name, 0) + 1
    fired_lines = tuple(f"{name}: fired {n} time{'s' if n != 1 else ''}" for name, n in sorted(fired.items()))
    action = tuple(f"{name}: still {state} (last change {dt.datetime.fromtimestamp(t / 1000, UTC):%Y-%m-%d %H:%M} UTC)"
                   for name, (t, state) in sorted(latest.items())
                   if any(w in name.lower() for w in g.needs_action_words) and not state.lower().startswith("normal"))
    return (Section("Alerts that fired this week", fired_lines, "None fired." if not fired_lines else ""),
            Section("Needs action", action,
                    "Reboots: no source is defined in this repo yet." + ("" if action else " No update alert is open.")))


def default_providers():
    return {"patched": patched_provider, "expiry": expiry_provider, "grafana": grafana_provider}


# --- rendering ------------------------------------------------------------------------------

def render(sections, now, cfg, failures=()):
    """(subject, body). The subject is built from counts only, never from provider text. Every
    provider string is cleaned here, the entries per section and the body size are capped."""
    out = [f"Weekly digest, week ending {now:%Y-%m-%d} (UTC)", ""]
    for sec in sections:
        out.append(clean(sec.title, 80).upper())
        if sec.note:
            out.append(clean(sec.note, 300))
        for line in sec.lines[:cfg.max_entries]:
            out.append("- " + clean(line))
        if len(sec.lines) > cfg.max_entries:
            out.append(f"... and {len(sec.lines) - cfg.max_entries} more not shown")
        out.append("")
    for f in failures:
        out.append("SOURCE FAILED: " + clean(f, 300))
    body = "\n".join(out).rstrip() + "\n"
    raw = body.encode("utf-8")
    if len(raw) > cfg.max_body_bytes:
        mark = "\n[digest truncated at the size limit]\n"
        cut = raw[:cfg.max_body_bytes - len(mark.encode())].decode("utf-8", "ignore")
        body = cut.rsplit("\n", 1)[0] + mark
    counts = {s.title: len(s.lines) for s in sections}
    subject = (f"Weekly digest: {counts.get('Needs action', 0)} need action, "
               f"{counts.get('Alerts that fired this week', 0)} alerts, {counts.get('Stale', 0)} stale")
    if failures:
        subject += f", {len(failures)} source failed"
    return subject, body


def build_message(cfg, subject, body, now):
    msg = email.message.EmailMessage()
    msg["From"], msg["To"] = cfg.email.sender, ", ".join(cfg.email.to)
    msg["Subject"] = subject
    msg["Date"] = email.utils.format_datetime(now.astimezone(UTC))
    digest = hashlib.sha256(f"{now:%G-%V}|{subject}|{body}".encode()).hexdigest()[:32]
    msg["Message-ID"] = f"<digest-{digest}@{cfg.email.sender.rsplit('@', 1)[1]}>"
    msg["Auto-Submitted"] = "auto-generated"
    msg.set_content(body)
    return msg


# --- the runner -----------------------------------------------------------------------------

def _state_age_days(path, root, now):
    """Whole days since the expiry watch state file was last written (read-only stat, no links)."""
    dirfd, leaf = ew._open_parent(path, root)
    try:
        mtime = os.stat(leaf, dir_fd=dirfd, follow_symlinks=False).st_mtime
    finally:
        os.close(dirfd)
    return max(0, int((now.timestamp() - mtime) // 86400))


def _gather(ctx, providers):
    sections, failures = [], []

    def call(key, fallback_titles):
        try:
            res = providers[key](ctx)
            return list(res) if isinstance(res, (tuple, list)) else [res]
        except DigestError as e:
            failures.append(f"{key}: {e}")
        except Exception as e:  # a provider bug must not cost the whole digest
            failures.append(f"{key}: {type(e).__name__}")
        return [Section(t, note="unavailable (see the failure line below)") for t in fallback_titles]

    patched = call("patched", ["Patched automatically"])
    if ctx["dry_run"]:
        note = "Not fetched: a dry run makes no network call. Run with --send to read Grafana."
        graf = [Section("Needs action", note=note), Section("Alerts that fired this week", note=note)]
    else:
        g = call("grafana", ["Alerts that fired this week", "Needs action"])
        by = {s.title: s for s in g}
        graf = [by.get("Needs action") or g[-1], by.get("Alerts that fired this week") or g[0]]
    stale = call("expiry", ["Stale"])
    return patched + graf + stale, failures


def run(config_path, now, env=None, out=print, err=None, send=False, providers=None):
    err = err or (lambda m: print(m, file=sys.stderr))
    env = os.environ if env is None else env
    folder, leaf = os.path.split(str(config_path))
    try:
        root = ew.Root(folder or ".")
    except DigestError as e:
        err(f"config error: {e}")
        return 2
    try:
        try:
            cfg = parse_config(ew.read_toml(leaf, "config", root))
            if send:
                ew.email_secrets(cfg.email, env)  # a missing login is a config error, before any read
        except DigestError as e:
            err(f"config error: {e}")
            return 2
        age = None
        try:
            age = _state_age_days(cfg.state_file, root, now)
        except (DigestError, OSError):
            pass
        ctx = {"config": cfg, "now": now, "env": env, "root": root, "dry_run": not send, "state_age_days": age}
        sections, failures = _gather(ctx, {**default_providers(), **(providers or {})})
        subject, body = render(sections, now, cfg, failures)
        if not send:
            out(f"Subject: {subject}\nTo: {', '.join(cfg.email.to)}\n\n{body}")
            err("dry run: nothing was sent (use --send to send)")
        else:
            try:
                ew.smtp_deliver(cfg.email, env, build_message(cfg, subject, body, now), root=root,
                                budget=cfg.delivery_budget_seconds)
            except DigestError as e:
                err(f"delivery failed: {e}")
                return 3
            out(f"sent one digest to {len(cfg.email.to)} recipient(s)")
        for f in failures:
            err(f"source failed: {clean(f, 300)}")
        return 1 if failures else 0
    finally:
        root.close()


def main(argv=None):
    ap = argparse.ArgumentParser(description="Weekly status digest by email (dry run unless --send)")
    ap.add_argument("--config", required=True, help="path to the TOML config (docs/weekly-digest.example.toml)")
    ap.add_argument("--send", action="store_true", help="read Grafana and send the email (default: dry run, no network)")
    args = ap.parse_args(argv)
    return run(args.config, dt.datetime.now(UTC), send=args.send)


if __name__ == "__main__":
    sys.exit(main())
