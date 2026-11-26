#!/usr/bin/env python3
"""Deploys the Grafana alerting provisioning files of this repo to the SIEM host. Run
it under siem-run on the host. It only writes files. It never starts docker and
never reads the compose file: the compose pass-through line and the Grafana
restart are manual steps (docs/live-deploy-runbook.md, section 5, steps 4 and 5).
It prints only file names, line counts, backup names, variable names, the length
of the router path and the INFLUX_URL in effect (a validated plain http(s) URL, no
credentials). It never prints file content, hashes or other environment values.

What it deploys (existing files are replaced only after a backup):
  1. Folder grafana/provisioning/alerting with the contact point, the UniFi
     rules, the (paused) pfSense rules, the heartbeat rule, the notification
     failure rule and, when it is staged, the Twingate rules (OPTIONAL_FILES). The contact point URL gets the private webhook path of the
     authenticated n8n router.
  2. One datasource file with two extra InfluxDB datasources carrying the ids the
     rules expect (same databases, no change to the existing datasources). A live
     "influxdb-twingate" datasource in that file is kept as it is.

Usage: siem-run python3 -I grafana-deploy.py [--dry-run | --stage | --apply]
                                              [--include-example NAME ...]
  (no flag)  dry run, the default: validates everything, prints the plan (no file
             content, no hash, only line counts) and writes nothing.
  --dry-run  the same as no flag.
  --stage    validate only and print one line.
  --apply    write the files one at a time.
  --include-example NAME
             also deploy one allowlisted example file, email-contact-point.yml.example
             or email-notification-policy.yml.example, under its name without
             ".example". Without this option the examples stay inactive.
             Repeatable. The policy example replaces the whole notification
             policy tree once deployed.

Environment (all optional, the current values are the defaults):
  SIEM_DIR            directory of the live stack (default: /opt/siem); the script
                      writes under SIEM_DIR/grafana/provisioning
  SIEM_STAGE_DIR      directory holding the staged alerting files, copied from
                      docker/grafana/provisioning/alerting in this repo
                      (default: $HOME/bin/alerting)
  SIEM_CONFIG_DIR     private config directory with the file "router-path"
                      (default: $HOME/.config/doppler-siem)
  N8N_WEBHOOK_BASE    base of the contact point URL, up to /webhook/ (default: http://n8n)
  INFLUX_URL          URL the two added datasources use (default: http://influxdb:8086).
                      Set it to the real InfluxDB container address if another stack's
                      service named influxdb makes the name ambiguous (see the runbook).
                      Every run prints "INFLUX_URL in effect". --apply refuses when it is
                      unset but the live datasource file has another URL (set it to keep
                      that URL, or to the default on purpose).
  GRAFANA_CONTAINER   container name used in the printed restart step (default: grafana)

What this script guarantees:
  - Files come from an explicit allowlist (no globbing).
  - Output is limited to what the top of this text lists. An overwrite shows only
    how many lines change. Variable names are listed for example files. Error
    messages do not echo path components or arguments you supplied.
  - The router path must be "grafana-alerts-" plus 8 to 128 letters, digits, "_" or
    "-", and N8N_WEBHOOK_BASE and INFLUX_URL must be plain http(s) URLs, because
    they are written into YAML as is.
  - Every directory is opened component by component with O_NOFOLLOW, and every
    component must be owned by root or the running user and not writable by group
    or others (a sticky world-writable directory such as /tmp is accepted). Reads,
    backups, temp files and renames go through the directory descriptor. Symlinked
    files, files that are not regular, oversized and non-UTF-8 files and names off
    the allowlist are refused. Bind mounts are outside this guarantee.
  - Before anything is replaced, every existing target is re-read and backed up as
    NAME.bak-<UTC timestamp> (mode 600, written under a temp name, fsynced and
    linked into place, never overwriting another backup). A target that changed
    since planning stops the run before any file is replaced.
  - Files are then replaced one at a time (temp file, fsync, rename), each one
    compared with the planned content right before its rename. One "manifest:" line
    is printed per file as it is done, and a list of the files replaced at the end.
  - Any error exits nonzero.

Concurrent edits are not supported: a process running as the same user, or root,
can still change a file in the window of a few microseconds between the final
comparison and the rename (the standard library has no atomic compare-and-rename).
That edit would be replaced and is not in the backup. Directory permissions, not
this script, keep other users out.

What it does NOT guarantee: there is no atomicity across files and no crash
safety. A failure, a kill or a power loss in the middle of an apply can leave a
partial set: some files new, some old. Nothing is rolled back automatically and no
journal is kept. When a run stops on an error it prints which files it had already
replaced and which backup restores each one. To recover by hand, copy each backup
over its file in the same folder, for example
  cp -p contact-points.yml.bak-<UTC timestamp> contact-points.yml
and delete the files marked "created". After a kill with no report, look for
NAME.bak-* files and for leftover .NAME.new-* temp files in the alerting folder
and the datasources folder.
"""
import datetime
import difflib
import os
import re
import stat
import sys

SIEM = os.environ.get("SIEM_DIR", "/opt/siem")
STAGE = os.environ.get("SIEM_STAGE_DIR") or os.path.join(os.path.expanduser("~"), "bin", "alerting")
CONFIG_DIR = os.environ.get("SIEM_CONFIG_DIR") or os.path.join(os.path.expanduser("~"), ".config", "doppler-siem")
PATH_FILE = os.path.join(CONFIG_DIR, "router-path")
WEBHOOK_BASE = os.environ.get("N8N_WEBHOOK_BASE", "http://n8n").rstrip("/")
DEFAULT_INFLUX_URL = "http://influxdb:8086"
INFLUX_URL = os.environ.get("INFLUX_URL") or DEFAULT_INFLUX_URL
INFLUX_URL_SET = bool(os.environ.get("INFLUX_URL"))
_CONTAINER = os.environ.get("GRAFANA_CONTAINER", "")
GRAFANA_CONTAINER = _CONTAINER if re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,63}", _CONTAINER) else "grafana"
ALERT_DIR = SIEM + "/grafana/provisioning/alerting"
DS_FILE = SIEM + "/grafana/provisioning/datasources/alerting-influx.yml"
FILES = ("contact-points.yml", "update-alert-rules-unifi.yml", "update-alert-rules-pfsense.yml",
         "heartbeat-alert-rule.yml", "notification-failure-alert-rule.yml")
# Deployed only when staged (a missing one is skipped, not an error). Adding a rule
# file the live box needs is a one-line add here.
OPTIONAL_FILES = ("update-alert-rules-twingate.yml", "infra-alerts.yml")
KEEP_DATASOURCE_UIDS = ("influxdb-twingate",)
# Examples stay inactive unless named with --include-example. Maps the staged
# example name to the name it gets in the alerting folder.
EXAMPLE_FILES = {
    "email-contact-point.yml.example": "email-contact-point.yml",
    "email-notification-policy.yml.example": "email-notification-policy.yml",
}
POLICY_EXAMPLES = ("email-notification-policy.yml.example",)
MAX_BYTES = 1024 * 1024
OLD_URL = "http://n8n/webhook/grafana-alerts"
ROUTER_PATH = re.compile(r"grafana-alerts-[A-Za-z0-9_-]{8,128}")
SAFE_URL = re.compile(r"https?://[A-Za-z0-9._-]+(?::([0-9]{1,5}))?(?:/[A-Za-z0-9._~/-]*)?")
PORT = re.compile(r"[1-9][0-9]{0,4}")

DATASOURCES = """apiVersion: 1

# Extra InfluxDB datasources for the update alert rules. They carry fixed ids so
# the provisioned rules can find them. The existing datasources are untouched.
datasources:
  - name: InfluxDB-pfSense-alerts
    uid: influxdb-pfsense
    type: influxdb
    access: proxy
    url: {url}
    database: pfsense
    jsonData:
      httpMode: GET

  - name: InfluxDB-UniFi-alerts
    uid: influxdb-unifi
    type: influxdb
    access: proxy
    url: {url}
    database: unpoller
    jsonData:
      httpMode: GET
"""

class GuardError(Exception):
    """A safety rule or a validation refused the request. The message is safe to print."""

# ---- pure logic (importable) -----------------------------------------

def valid_url(url):
    hit = SAFE_URL.fullmatch(url or "")
    if not hit:
        return False
    port = hit.group(1)
    return port is None or (PORT.fullmatch(port) is not None and int(port) <= 65535)

def datasources_yaml(url=None, keep=""):
    """Content of the extra-datasources provisioning file. The URL goes into YAML
    unquoted, so only a plain http(s) URL is accepted (ValueError otherwise). keep is
    the verbatim text of live datasources to carry over (see kept_datasources)."""
    url = url or INFLUX_URL
    if not valid_url(url):
        raise ValueError("INFLUX_URL is not a plain http(s) URL")
    text = DATASOURCES.format(url=url)
    if keep:
        text += "\n" + keep
    return text

def datasource_blocks(text):
    """Split a datasource provisioning file into (uid, block text) pairs, one per
    "  - " list item. The uid is "" when a block has none."""
    blocks, cur = [], None
    for line in (text or "").split("\n"):
        if line.startswith("  - "):
            cur = [line]
            blocks.append(cur)
        elif cur is not None and (line.startswith("    ") or not line.strip()):
            cur.append(line)
        else:
            cur = None
    out = []
    for blk in blocks:
        body = "\n".join(blk).rstrip("\n") + "\n"
        hit = re.search(r"^\s+uid:\s*([A-Za-z0-9_.-]+)\s*$", body, re.M)
        out.append((hit.group(1) if hit else "", body))
    return out

def live_influx_urls(text):
    """URLs the live file gives the two datasources this script writes."""
    urls = []
    for uid, body in datasource_blocks(text):
        if uid in ("influxdb-pfsense", "influxdb-unifi"):
            hit = re.search(r"^\s+url:\s*(\S+)\s*$", body, re.M)
            if hit:
                urls.append(hit.group(1))
    return urls

def kept_datasources(old_text):
    """Live datasources this script must not drop (KEEP_DATASOURCE_UIDS), verbatim."""
    return "\n".join(body for uid, body in datasource_blocks(old_text) if uid in KEEP_DATASOURCE_UIDS)

def influx_url_problem(old_text):
    """Message when INFLUX_URL is unset but the live file uses another URL, else ""."""
    if INFLUX_URL_SET:
        return ""
    if any(u != DEFAULT_INFLUX_URL for u in live_influx_urls(old_text)):
        return ("INFLUX_URL is not set but the live datasource file uses a different URL for the "
                "InfluxDB datasources; this would reset it to the default")
    return ""

def valid_router_path(path):
    return bool(ROUTER_PATH.fullmatch(path or ""))

def contact_with_path(contact_text, path, base=None):
    """Point the staged contact point at the private webhook path."""
    if not valid_router_path(path):
        raise ValueError("router path has characters outside letters, digits, _ and -")
    base = (base or WEBHOOK_BASE).rstrip("/")
    if not valid_url(base):
        raise ValueError("N8N_WEBHOOK_BASE is not a plain http(s) URL")
    if OLD_URL not in contact_text:
        raise ValueError("contact point URL not found in the staged file")
    return contact_text.replace(OLD_URL, base + "/webhook/" + path)

def timestamp():
    return datetime.datetime.now(datetime.timezone.utc).strftime("%Y%m%dT%H%M%SZ")

VAR_NAME = re.compile(r"\$\{?([A-Z][A-Z0-9_]{2,})\}?")

def variable_names(text):
    """Names (never values) of the environment variables a file refers to."""
    return sorted(set(VAR_NAME.findall(text)))

def line_changes(old, new):
    """(added, removed) line counts. Content is never returned."""
    a, b = old.split("\n"), new.split("\n")
    added = removed = 0
    for tag, i1, i2, j1, j2 in difflib.SequenceMatcher(None, a, b, autojunk=False).get_opcodes():
        if tag in ("replace", "delete"):
            removed += i2 - i1
        if tag in ("replace", "insert"):
            added += j2 - j1
    return added, removed

# ---- directory descriptors --------------------------------------------------------

DIR_FLAGS = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC

def _trusted(fd, final):
    """Owned by root or us, and not writable by group or others. A sticky directory such
    as /tmp is accepted only as an ancestor, never as the final directory the script reads
    from or writes into (sticky does not stop the directory owner from supplying files)."""
    info = os.fstat(fd)
    if info.st_uid not in (0, os.geteuid()):
        raise GuardError("a directory in the path is owned by another user")
    if info.st_mode & 0o022 and (final or not info.st_mode & stat.S_ISVTX):
        raise GuardError("a directory in the path is writable by others or its group")

def open_dir(path, create=False):
    """Descriptor of a directory, opened one component at a time with O_NOFOLLOW so no
    ancestor can be a symlink; every component must pass _trusted. Returns None when it
    does not exist (and create is false). With create, missing components are made
    (mode 755) through the descriptor. The caller closes it."""
    fd = os.open("/", DIR_FLAGS)
    try:
        parts = [p for p in os.path.abspath(path).split("/") if p]
        _trusted(fd, not parts)
        for index, part in enumerate(parts):
            try:
                nfd = os.open(part, DIR_FLAGS, dir_fd=fd)
            except FileNotFoundError:
                if not create:
                    os.close(fd)
                    return None
                os.mkdir(part, 0o755, dir_fd=fd)
                nfd = os.open(part, DIR_FLAGS, dir_fd=fd)
            except OSError:
                raise GuardError("refusing a symlink or non-directory in a path")
            os.close(fd)
            fd = nfd
            _trusted(fd, index == len(parts) - 1)
        return fd
    except BaseException:
        os.close(fd)
        raise

def _read_file(dfd, name, strict=False):
    """(text, mode) of dfd/name, or None when it does not exist. Refuses symlinks,
    non-regular files (a FIFO would hang a plain open), oversized and non-UTF-8 files."""
    try:
        fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC, dir_fd=dfd)
    except FileNotFoundError:
        return None
    except OSError:
        try:
            if stat.S_ISLNK(os.lstat(name, dir_fd=dfd).st_mode):
                raise GuardError("refusing symlink: " + name)
        except FileNotFoundError:
            return None
        raise GuardError("cannot open: " + name)
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode):
            raise GuardError("not a regular file: " + name)
        if strict and info.st_uid not in (0, os.geteuid()):
            raise GuardError("input file is owned by another user: " + name)
        if strict and info.st_mode & 0o022:
            raise GuardError("input file is writable by group or others (chmod 644 it): " + name)
        if info.st_size > MAX_BYTES:
            raise GuardError("file too large: " + name)
        data = b""
        while len(data) <= MAX_BYTES:
            chunk = os.read(fd, 65536)
            if not chunk:
                break
            data += chunk
        if len(data) > MAX_BYTES:
            raise GuardError("file too large: " + name)
    finally:
        os.close(fd)
    try:
        return data.decode("utf-8"), stat.S_IMODE(info.st_mode)
    except UnicodeDecodeError:
        raise GuardError("not valid UTF-8: " + name)

def read_in(path, name, strict=False):
    """Read one file from a directory given by path. None if directory or file is missing."""
    dfd = open_dir(path)
    if dfd is None:
        return None
    try:
        return _read_file(dfd, name, strict)
    finally:
        os.close(dfd)

def read_staged(stage_dir, name):
    """Read one allowlisted staged file. Names off the allowlist are refused."""
    if name not in FILES and name not in OPTIONAL_FILES and name not in EXAMPLE_FILES:
        raise GuardError("unexpected file name (not on the allowlist)")
    got = read_in(stage_dir, name, strict=True)
    if got is None:
        raise GuardError("missing staged file: " + name)
    return got[0]

def plan_files(stage_dir, alert_dir, router_path, examples=()):
    """Read and check everything, write nothing. Returns a list of item dicts."""
    items = []
    dfd = open_dir(alert_dir)
    try:
        optional = [n for n in OPTIONAL_FILES if read_in(stage_dir, n, strict=True) is not None]
        for name in tuple(FILES) + tuple(optional) + tuple(examples):
            text = read_staged(stage_dir, name)
            if name == "contact-points.yml":
                try:
                    text = contact_with_path(text, router_path)
                except ValueError as err:
                    raise GuardError(str(err))
            target = EXAMPLE_FILES.get(name, name)
            got = _read_file(dfd, target) if dfd is not None else None
            old = got[0] if got else None
            action = "create" if old is None else ("unchanged" if old == text else "overwrite")
            items.append({"source": name, "target": target, "new": text, "old": old, "action": action,
                          "example": name in EXAMPLE_FILES})
    finally:
        if dfd is not None:
            os.close(dfd)
    return items

def describe(items, applying, stamp):
    """Plan text for the operator. Never contains file content, a hash or a secret value."""
    lines = []
    for it in items:
        label = it["target"]
        if it["action"] == "overwrite":
            lines.append("file %s: overwrite (%s %s.bak-%s)" % (
                label, "backup" if applying else "backup on apply:", label, stamp))
            added, removed = line_changes(it["old"], it["new"])
            lines.append("    changed: +%d -%d lines" % (added, removed))
        else:
            lines.append("file %s: %s" % (label, it["action"]))
        if it["example"]:
            names = variable_names(it["new"])
            if names:
                lines.append("    needs in the grafana container environment: " + ", ".join(names))
            if it["source"] in POLICY_EXAMPLES:
                lines.append("    WARNING: a provisioned policy file replaces the whole notification policy "
                             "tree (Grafana loads one tree per organization)")
    return lines

# ---- writing ------------------------------------------------------------------------

def _unlink(dfd, name):
    try:
        os.unlink(name, dir_fd=dfd)
    except OSError:
        pass

def write_backup(dfd, target, old_text, stamp):
    """Save the live file before it is replaced. The content is written and synced under
    a temp name and linked to the final name only when complete, so a failed write never
    leaves a valid-looking backup. Never overwrites an existing backup."""
    base = "%s.bak-%s" % (target, stamp)
    part = ".%s.part-%d" % (base, os.getpid())
    try:
        fd = os.open(part, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600, dir_fd=dfd)
    except OSError:
        raise GuardError("cannot write backup for " + target)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            handle.write(old_text)
            handle.flush()
            os.fsync(handle.fileno())
        for n in range(100):
            name = base if n == 0 else "%s-%d" % (base, n)
            try:
                os.link(part, name, src_dir_fd=dfd, dst_dir_fd=dfd, follow_symlinks=False)
            except FileExistsError:
                continue
            try:
                os.fsync(dfd)
            except OSError:
                _unlink(dfd, name)
                try:
                    os.fsync(dfd)
                except OSError:
                    pass
                raise
            return name
        raise GuardError("no free backup name for " + target)
    except OSError:
        raise GuardError("cannot write backup for " + target)
    finally:
        _unlink(dfd, part)

def stage_temp(dfd, name, text, mode):
    """Write and sync the new content under a temp name in the same directory.
    Returns the temp name."""
    tmp = ".%s.new-%d" % (name, os.getpid())
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600, dir_fd=dfd)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            handle.write(text)
            handle.flush()
            os.fchmod(handle.fileno(), mode)
            os.fsync(handle.fileno())
    except BaseException:
        _unlink(dfd, tmp)
        raise
    return tmp

def commit_rename(dfd, tmp, name):
    os.rename(tmp, name, src_dir_fd=dfd, dst_dir_fd=dfd)

def _current(w):
    cur = _read_file(w["dfd"], w["name"])
    return cur

def apply_writes(writes, stamp):
    """Back up every existing target, then replace the files one at a time.

    Each write: dfd, name, new (text), old (planned text or None), mode. Not atomic
    across files and not crash safe (see the module docstring). On any error it
    raises GuardError saying which files were already replaced and which backups
    restore them. Returns the list of replaced writes."""
    backups, done = [], []
    try:
        for w in writes:
            cur = _current(w)
            if (cur[0] if cur else None) != w["old"]:
                raise GuardError("changed since planning: " + w["name"])
            w["backup"] = None
            if cur is not None:
                w["backup"] = write_backup(w["dfd"], w["name"], cur[0], stamp)
                backups.append(w)
    except BaseException as err:
        for w in backups:
            _unlink(w["dfd"], w["backup"])
        raise GuardError("apply stopped before replacing anything (%s); nothing was replaced"
                         % (str(err) if isinstance(err, GuardError) else err.__class__.__name__))
    try:
        for w in writes:
            w["tmp"] = stage_temp(w["dfd"], w["name"], w["new"], w["mode"])
            try:
                cur = _current(w)
                if (cur[0] if cur else None) != w["old"]:
                    raise GuardError("changed since planning: " + w["name"])
                commit_rename(w["dfd"], w["tmp"], w["name"])
            except BaseException:
                _unlink(w["dfd"], w["tmp"])
                raise
            done.append(w)
            os.fsync(w["dfd"])
            print(manifest_line(w), flush=True)
    except BaseException as err:
        raise GuardError(failure_report(err, done))
    return done

def manifest_line(w):
    if w["backup"]:
        return "manifest: replaced %s (backup %s)" % (w["name"], w["backup"])
    return "manifest: created " + w["name"]

def failure_report(err, done):
    why = str(err) if isinstance(err, GuardError) else err.__class__.__name__
    if not done:
        return "apply stopped (%s); nothing was replaced" % why
    lines = ["apply stopped (%s); the set is now partial. Already replaced:" % why]
    for w in done:
        if w["backup"]:
            lines.append("  %s (restore: cp -p %s %s in the same folder)" % (w["name"], w["backup"], w["name"]))
        else:
            lines.append("  %s (created by this run; delete it to undo)" % w["name"])
    lines.append("Files not listed were not touched.")
    return "\n".join(lines)

def parse_args(argv):
    mode, examples, args = None, [], list(argv)
    modes = {"--dry-run": "dry", "--stage": "stage", "--apply": "apply"}
    while args:
        arg = args.pop(0)
        if arg in modes:
            if mode is not None:
                raise GuardError("give only one of --dry-run, --stage, --apply")
            mode = modes[arg]
        elif arg == "--include-example" or arg.startswith("--include-example="):
            if "=" in arg:
                value = arg.split("=", 1)[1]
            elif args:
                value = args.pop(0)
            else:
                raise GuardError("--include-example needs a file name")
            if value not in EXAMPLE_FILES:
                raise GuardError("not an allowlisted example (allowed: %s)" % ", ".join(sorted(EXAMPLE_FILES)))
            if value not in examples:
                examples.append(value)
        else:
            raise GuardError("unknown argument\n%s" % __doc__)
    return mode or "dry", examples

# ---- command line ----------------------------------------------------------------

def router_path():
    got = read_in(os.path.dirname(PATH_FILE), os.path.basename(PATH_FILE), strict=True)
    if got is None:
        raise GuardError("router path file missing")
    path = got[0].strip()
    if not valid_router_path(path):
        raise GuardError("router path file looks wrong")
    return path

def print_restart_step():
    """Tell the owner how to make Grafana read the files. This script never runs it."""
    print("Grafana loads provisioning files only at startup. `docker compose up -d grafana` may not re-read "
          "them: it does nothing when the service definition is unchanged.")
    print("Restart step for the owner (this script never runs it): docker restart %s" % GRAFANA_CONTAINER)
    print("If the compose file or its environment changed too, recreate instead: see "
          "docs/live-deploy-runbook.md, section 5, step 5.")

def run(argv):
    mode, examples = parse_args(argv)
    path = router_path()
    items = plan_files(STAGE, ALERT_DIR, path, examples)
    print("staged files ok; router path length %d" % len(path))
    ds_name = os.path.basename(DS_FILE)
    ds_got = read_in(os.path.dirname(DS_FILE), ds_name)
    ds_old = ds_got[0] if ds_got else None
    print("INFLUX_URL in effect: %s (%s)" % (
        INFLUX_URL, "from the environment" if INFLUX_URL_SET else "default; INFLUX_URL is not set"))
    problem = influx_url_problem(ds_old)
    if problem:
        print("WARNING: " + problem + " (--apply refuses until INFLUX_URL is set)")
        if mode == "apply":
            raise GuardError("refusing to apply: " + problem + ". Set INFLUX_URL to the URL you want "
                             "(the live one to keep it) and run again; nothing was changed")
    if mode == "stage":
        return 0
    try:
        ds_new = datasources_yaml(keep=kept_datasources(ds_old))
    except ValueError as err:
        raise GuardError(str(err))
    stamp = timestamp()
    if mode == "dry":
        print("dry run: nothing is changed; add --apply to write these files")
    for ln in describe(items, mode == "apply", stamp):
        print(ln)
    print("file %s: %s" % (ds_name, "create" if ds_old is None else ("unchanged" if ds_old == ds_new else "overwrite")))
    for name in sorted(EXAMPLE_FILES):
        if name not in examples:
            print("file %s: skipped (inactive; name it with --include-example to deploy it)" % name)
    print_restart_step()
    if mode == "dry":
        return 0

    fds = []
    try:
        alert_fd = open_dir(ALERT_DIR, create=True)
        fds.append(alert_fd)
        ds_fd = open_dir(os.path.dirname(DS_FILE), create=True)
        fds.append(ds_fd)
        writes = [{"dfd": alert_fd, "name": it["target"], "new": it["new"], "old": it["old"], "mode": 0o644}
                  for it in items if it["action"] != "unchanged"]
        if ds_old != ds_new:
            writes.append({"dfd": ds_fd, "name": ds_name, "new": ds_new, "old": ds_old, "mode": 0o644})
        done = apply_writes(writes, stamp) if writes else []
    finally:
        for fd in fds:
            os.close(fd)
    if not done:
        print("nothing was replaced: every file already matches")
        return 0
    print("files replaced:")
    for w in done:
        print("  " + w["name"])
    print("The remaining steps (a pass-through line in the grafana service environment, then a restart) "
          "are done by hand: follow docs/live-deploy-runbook.md, section 5, steps 4 and 5. "
          "The restart step is printed above (Restart step for the owner).")
    return 0


def main(argv):
    try:
        return run(argv)
    except GuardError as err:
        print(str(err), file=sys.stderr)
        return 1
    except OSError as err:
        print("error: " + err.__class__.__name__, file=sys.stderr)
        return 1

if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
