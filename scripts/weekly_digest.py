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
3 delivery failed, or its outcome is uncertain (the server may have accepted it, so `pending` is kept); 4 not sent on purpose (lock held, already sent this week, damaged
marker, or an earlier send that was not recorded: see docs/weekly-digest.md). Exit 1 also covers a
sent digest whose state could not be recorded.
"""
import argparse
import datetime as dt
import email.message
import email.policy
import email.utils
import fcntl
import hashlib
import os
import re
import stat
import sys
import unicodedata
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
_SPACES = re.compile(r" {2,}")
# Unicode categories removed from provider text: Cc control characters (including C0, C1 and
# line breaks), Cf format characters (bidi overrides and isolates, zero-width characters, the
# byte order mark, soft hyphen), Zl and Zp line and paragraph separators.
_DROP_CATEGORIES = frozenset(("Cc", "Cf", "Cs", "Zl", "Zp"))  # Cs: lone surrogates, which cannot be encoded
_WEEK = re.compile(r"([0-9]{4})-W([0-9]{2})")
_STATE_DIR = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,63}")
CLOCK_SKEW_MS = 5 * 60 * 1000


def clean(text, limit=MAX_ENTRY_CHARS):
    """One line of text from a provider: control, format (bidi, zero-width) and line or paragraph
    separator characters become spaces, runs of spaces collapse, length is capped. Ordinary
    printable text in any script is kept. Applied to EVERY provider string at render time."""
    text = "".join(" " if unicodedata.category(c) in _DROP_CATEGORIES else c for c in str(text))
    text = _SPACES.sub(" ", text).strip()[:limit]
    return text.encode("utf-8", "replace").decode("utf-8")  # final safety: never hand on unencodable text


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
    max_message_bytes: int
    state_dir: str
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
    ew._only_keys("[digest]", digest, ("window_days", "max_body_bytes", "max_message_bytes", "state_dir",
                                       "max_entries_per_section", "delivery_budget_seconds"))
    state_dir = digest.get("state_dir", "weekly-digest-state")
    if not isinstance(state_dir, str) or not _STATE_DIR.fullmatch(state_dir) or state_dir in (".", ".."):
        raise DigestError("state_dir must be one folder name (letters, digits, . _ -) next to the config file")
    ew._only_keys("[expiry]", expiry, ("state_file", "warn_days", "stale_run_days"))
    budget = digest.get("delivery_budget_seconds", 60)
    if isinstance(budget, bool) or not isinstance(budget, (int, float)) or not 0 < budget <= 3600:
        raise DigestError("delivery_budget_seconds must be above 0 and at most 3600")
    if "email" not in raw:
        raise DigestError("the config needs an [email] table (same settings as the expiry watch)")
    return DigestConfig(
        window_days=ew._int("window_days", digest.get("window_days", 7), 1, 31),
        max_body_bytes=ew._int("max_body_bytes", digest.get("max_body_bytes", 32768), 1024, MAX_BODY_BYTES_LIMIT),
        max_message_bytes=ew._int("max_message_bytes", digest.get("max_message_bytes", 100_000), 4096,
                                  MAX_BODY_BYTES_LIMIT * 2),
        state_dir=state_dir,
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
    events, skipped = [], 0
    for rec in data[:MAX_EVENTS]:
        if not isinstance(rec, dict):
            continue
        t, name, state = rec.get("time"), rec.get("alertName"), rec.get("newState")
        if not (isinstance(name, str) and name and isinstance(state, str)):
            continue
        # The range is checked as a number before anything converts it to a date: one absurd
        # value costs that record only, never the other results.
        if (isinstance(t, int) and not isinstance(t, bool) and start - CLOCK_SKEW_MS <= t <= end + CLOCK_SKEW_MS):
            events.append((t, name, state))
        else:
            skipped += 1
    if skipped:
        ctx.setdefault("notes", []).append(
            f"grafana: {skipped} record(s) skipped because the time is outside the requested window")
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

TRUNCATED = "\n[digest truncated at the size limit]\n"


def _truncate(body, limit):
    raw = body.encode("utf-8")
    if len(raw) <= limit:
        return body
    cut = raw[:max(0, limit - len(TRUNCATED.encode()))].decode("utf-8", "ignore")
    return cut.rsplit("\n", 1)[0] + TRUNCATED


def render(sections, now, cfg, failures=(), notes=()):
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
    for n in notes:
        out.append("SOURCE NOTE: " + clean(n, 300))
    body = _truncate("\n".join(out).rstrip() + "\n", cfg.max_body_bytes)
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


def wire_size(msg):
    """Bytes of the complete DATA section as SMTP transmits it: headers, MIME framing, the
    transfer encoding (which can expand non-ASCII text), dot-stuffing and the final CRLF.CRLF
    terminator, not just the body text."""
    raw = msg.as_bytes(policy=email.policy.SMTP)
    stuffed = re.sub(rb"(?m)^\.", b"..", raw)  # what smtplib does to every line that starts with a dot
    if not stuffed.endswith(b"\r\n"):
        stuffed += b"\r\n"
    return len(stuffed) + len(b".\r\n")  # and the DATA terminator


def fit_message(cfg, subject, body, now):
    """The message whose whole encoded size is within max_message_bytes: the body is cut further
    (with the truncation marker) until it fits. Refuses if even a tiny body cannot fit."""
    limit = len(body.encode("utf-8"))
    for _ in range(40):
        msg = build_message(cfg, subject, body, now)
        size = wire_size(msg)
        if size <= cfg.max_message_bytes:
            return msg, body
        limit = max(0, limit - max(256, size - cfg.max_message_bytes))
        body = _truncate(body, limit)
    raise DigestError("the message cannot be made to fit max_message_bytes")


# --- one send per week: lock and marker --------------------------------------------------------

class _Refused(DigestError):
    """The send was refused on purpose (lock held, or already sent this week): exit code 4."""


def _open_state_dir(root, name):
    """The private state folder next to the config (created 0700, never followed through a link)."""
    try:
        os.mkdir(name, 0o700, dir_fd=root.fd)
    except FileExistsError:
        pass
    try:
        fd = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=root.fd)
    except OSError as e:
        raise DigestError(f"state_dir {name}: cannot open ({e.strerror}); a link is refused") from None
    st = os.fstat(fd)
    if st.st_uid != os.geteuid() or st.st_mode & 0o077:
        os.close(fd)
        raise DigestError(f"state_dir {name}: must be owned by you and private (mode 0700); "
                          "fix it with chmod 700 and re-run")
    return fd


def _valid_week(value):
    """True only for a real ISO week written canonically as YYYY-Www (week 53 only in a year that
    has one, year 1 to 9999): the value must survive a round trip through the calendar."""
    m = _WEEK.fullmatch(value)
    if not m:
        return False
    year, week = int(m.group(1)), int(m.group(2))
    try:
        iso = dt.date.fromisocalendar(year, week, 1).isocalendar()
    except ValueError:
        return False
    return (iso[0], iso[1]) == (year, week)


class SendGuard:
    """Holds the lock for one whole gather-and-send and knows what was already sent.

    Lock: an flock on a file held open for the whole run, so ownership is the open descriptor, not a
    pathname. The kernel drops it when the run ends or dies, so there is no stale lock to clear by
    hand. The file `lock` stays on disk and is never unlinked (no pathname race, no inode reuse).
    After locking, the path is checked to still name the locked file; if not, the run is refused.
    The state folder must be on a local filesystem (flock is not dependable over NFS).

    Sent state, in two phases: begin_send() durably writes a `pending` file BEFORE the message is
    handed to the server; mark_sent() durably writes `last-sent` (the ISO week) after the server
    accepted it and only then removes `pending`. Whatever goes wrong in between (an exception, an
    interrupt, a failed write, a crash) leaves `pending` behind, and the next run refuses until the
    owner has checked the inbox and removed it (or uses --force)."""

    def __init__(self, root, name, now, force):
        self.fd, self.week, self.force = _open_state_dir(root, name), f"{now:%G-W%V}", force
        self.lockfd = None
        self.closed = False

    def __enter__(self):
        refused = _Refused("another digest run holds the lock (state folder file 'lock')")
        try:
            for _ in range(3):
                fd = os.open("lock", os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600, dir_fd=self.fd)
                try:
                    fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                except OSError:
                    os.close(fd)
                    raise refused from None
                try:
                    now_path = os.stat("lock", dir_fd=self.fd, follow_symlinks=False)
                    mine = os.fstat(fd)
                    same = (now_path.st_dev, now_path.st_ino) == (mine.st_dev, mine.st_ino)
                except OSError:
                    same = False
                if same:
                    self.lockfd = fd
                    break
                os.close(fd)  # the file was replaced between open and lock: try the new one
            else:
                raise _Refused("the lock file keeps being replaced; another digest run is starting")
        except BaseException:
            self.__exit__()
            raise
        try:  # __exit__ does not run when __enter__ raises: release here
            self.check_state()
        except BaseException:
            self.__exit__()
            raise
        return self

    def check_state(self):
        if self.force:
            return
        if self.last_sent() == self.week:
            raise _Refused(f"a digest was already sent for {self.week}; use --force to send again")
        try:
            os.stat("pending", dir_fd=self.fd, follow_symlinks=False)
        except FileNotFoundError:
            return
        except OSError:
            pass
        raise _Refused("an earlier send may have been accepted by the server without being recorded (state "
                       "folder file 'pending'): check the inbox, then remove 'pending' (or write the week "
                       "into 'last-sent'), or use --force")

    def last_sent(self):
        """The ISO week of the last send, or None ONLY when the marker file does not exist. A marker
        that exists but cannot be read, is not a regular file, or does not hold a real ISO week is a
        state error: the run is refused (exit 4) until the owner repairs it or uses --force."""
        bad = _Refused("the last-sent marker is damaged or unreadable; fix or remove the file "
                       "'last-sent' in the state folder, or use --force")
        try:
            fd = os.open("last-sent", os.O_RDONLY | os.O_NOFOLLOW | getattr(os, "O_NONBLOCK", 0), dir_fd=self.fd)
        except FileNotFoundError:
            return None
        except OSError:
            raise bad from None
        try:
            if not stat.S_ISREG(os.fstat(fd).st_mode):
                raise bad
            raw = os.read(fd, 33)
        except OSError:
            raise bad from None
        finally:
            os.close(fd)
        value = raw.decode("ascii", "replace").strip() if len(raw) <= 32 else ""
        if not _valid_week(value):
            raise bad
        return value

    def _write_durable(self, name, text):
        """Write name atomically and durably: temp file, fsync, rename, fsync of the folder. The
        temp file (named for this run only) is removed again if anything fails."""
        tmp = f".tmp-{os.getpid()}-{os.urandom(6).hex()}"
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=self.fd)
        try:
            try:
                os.write(fd, text.encode("ascii"))
                os.fsync(fd)
            finally:
                os.close(fd)
            os.replace(tmp, name, src_dir_fd=self.fd, dst_dir_fd=self.fd)
        except BaseException:
            try:
                os.unlink(tmp, dir_fd=self.fd)
            except OSError:
                pass
            raise
        os.fsync(self.fd)

    def begin_send(self):
        """Before the message goes out: record that a send is in flight (fail closed if it dies)."""
        self._write_durable("pending", f"send started for {self.week}\n")

    def clear_pending(self):
        """The server did not take the message: nothing to remember."""
        try:
            os.unlink("pending", dir_fd=self.fd)
            os.fsync(self.fd)
        except OSError:
            pass

    def mark_sent(self):
        """After acceptance: the week is recorded durably first, then the pending note is removed."""
        self._write_durable("last-sent", self.week + "\n")
        try:
            os.unlink("pending", dir_fd=self.fd)
        except FileNotFoundError:
            pass
        os.fsync(self.fd)

    def __exit__(self, *exc):
        """Release. Idempotent, and never raises over an exception already in flight."""
        if self.closed:
            return
        self.closed = True
        try:
            if self.lockfd is not None:
                os.close(self.lockfd)  # closing the descriptor releases the flock
        except OSError:
            pass
        finally:
            try:
                os.close(self.fd)
            except OSError:
                pass


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


def run(config_path, now, env=None, out=print, err=None, send=False, providers=None, force=False):
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
        if not send:
            return _once(cfg, root, now, env, out, err, False, providers, None)
        try:
            with SendGuard(root, cfg.state_dir, now, force) as guard:
                return _once(cfg, root, now, env, out, err, True, providers, guard)
        except _Refused as e:
            err(f"not sent: {e}")
            return 4
        except DigestError as e:
            err(f"config error: {e}")
            return 2
    finally:
        root.close()


def _once(cfg, root, now, env, out, err, send, providers, guard):
    age = None
    try:
        age = _state_age_days(cfg.state_file, root, now)
    except (DigestError, OSError):
        pass
    ctx = {"config": cfg, "now": now, "env": env, "root": root, "dry_run": not send, "state_age_days": age,
           "notes": []}
    sections, failures = _gather(ctx, {**default_providers(), **(providers or {})})
    subject, body = render(sections, now, cfg, failures, ctx["notes"])
    try:
        msg, body = fit_message(cfg, subject, body, now)
    except DigestError as e:
        err(f"not sent: {e}")
        return 3
    if not send:
        out(f"Subject: {subject}\nTo: {', '.join(cfg.email.to)}\n\n{body}")
        err("dry run: nothing was sent (use --send to send)")
    else:
        try:
            guard.begin_send()
        except OSError as e:
            err(f"not sent: the state folder cannot be written ({e.strerror})")
            return 3
        # From here until mark_sent() finishes, `pending` stays on disk. Only a plain refusal by the
        # server (a DigestError: nothing was accepted) removes it; an interrupt, a crash or a failed
        # write leaves it, so the next run refuses instead of sending a duplicate.
        try:
            ew.smtp_deliver(cfg.email, env, msg, root=root, budget=cfg.delivery_budget_seconds)
        except DigestError as e:
            if getattr(e, "uncertain", False):
                # The server may have accepted it (no reply, lost connection, timeout, TLS error after
                # the data went out): `pending` stays, so the next run refuses instead of duplicating.
                err(f"delivery outcome uncertain: {e}; the state folder file 'pending' stays, so the next "
                    "run refuses until you have checked the inbox and removed it")
                return 3
            guard.clear_pending()  # an explicit rejection, or a failure before any data went out
            err(f"delivery failed: {e}")
            return 3
        out(f"sent one digest to {len(cfg.email.to)} recipient(s)")
        try:
            guard.mark_sent()
        except OSError as e:
            err(f"the digest was sent but could not be recorded ({e.strerror}); the state folder file "
                "'pending' stays, so the next run refuses until you remove it")
            return 1
    for f in failures:
        err(f"source failed: {clean(f, 300)}")
    return 1 if failures else 0


def main(argv=None):
    ap = argparse.ArgumentParser(description="Weekly status digest by email (dry run unless --send)")
    ap.add_argument("--config", required=True, help="path to the TOML config (docs/weekly-digest.example.toml)")
    ap.add_argument("--send", action="store_true", help="read Grafana and send the email (default: dry run, no network)")
    ap.add_argument("--force", action="store_true", help="with --send: send even if this ISO week was already sent")
    args = ap.parse_args(argv)
    if args.force and not args.send:
        ap.error("--force only applies with --send")
    return run(args.config, dt.datetime.now(UTC), send=args.send, force=args.force)


if __name__ == "__main__":
    sys.exit(main())
