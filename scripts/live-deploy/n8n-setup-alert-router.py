#!/usr/bin/env python3
"""Create the two n8n credentials and import the authenticated alert router.

Runs on the SIEM host under siem-run, so the three values arrive in the
environment: GRAFANA_WEBHOOK_SECRET, PUSHOVER_API_KEY (app token) and
PUSHOVER_USER_KEY. It never prints a value. Credentials go to n8n over stdin to
`n8n import:credentials` inside the container (n8n encrypts them), so no file
with a value is left on the host.

Usage:
  siem-run python3 -I n8n-setup-alert-router.py --check
  siem-run python3 -I n8n-setup-alert-router.py --credentials
  siem-run python3 -I n8n-setup-alert-router.py --error-workflow handler.json [HANDLER_ID]
  siem-run python3 -I n8n-setup-alert-router.py --check --with-matrix
  siem-run python3 -I n8n-setup-alert-router.py --credentials --with-matrix
  siem-run python3 -I n8n-setup-alert-router.py --credentials --with-grafana-viewer
  siem-run python3 -I n8n-setup-alert-router.py --digest-workflow weekly-update-digest.json [WORKFLOW_ID] [--error-workflow-id HANDLER_ID]
  siem-run python3 -I n8n-setup-alert-router.py --workflow router.json [WORKFLOW_ID] [--pushover-on] [--error-workflow-id HANDLER_ID]

--credentials --with-matrix (the flag adds, it does not replace) also creates the
Custom Auth credential matrix-bot-auth: the bearer token comes from the environment value
MATRIX_BOT_TOKEN and goes to n8n over stdin like the other secrets (never argv, never
printed). --digest-workflow imports n8n/weekly-update-digest.json inactive with its
credential ids mapped; import the error handler first and pass its id, as for the router.
--with-grafana-viewer works the same way for the Custom Auth credential grafana-viewer-auth
(the weekly digest collectors read Grafana with it): the token of a Grafana Viewer service
account comes from the environment value GRAFANA_VIEWER_TOKEN, over stdin, never argv, never
printed. After a successful viewer import the command exits 40 (imported, Allowed HTTP Request
Domains lock not verified; 0 is never returned for it, 1 and above otherwise mean the import failed).
The flags can be combined; every needed value and id is checked BEFORE n8n is changed,
so a bad value leaves nothing half done. Tokens lose surrounding whitespace; an empty or
multi-line token stops the run. GRAFANA_BASE_URL is not a secret: a pass-through line
(name only) in the n8n container environment.
MATRIX_HOMESERVER and MATRIX_ROOM_ID are not secrets and not handled here: they are
pass-through lines (names only) in the n8n container environment of the compose file.

Import order: the error handler first (--error-workflow prints its id), then the
router with that id (--workflow ... --error-workflow-id ID), so the router's
errorWorkflow setting points at a real workflow. Both import inactive. A re-run
with the same id overwrites. Without --error-workflow-id the router keeps no
errorWorkflow setting (a placeholder id would be rejected by n8n).

Environment (all optional, the current values are the defaults):
  SIEM_CONFIG_DIR         private config directory (default: $HOME/.config/doppler-siem);
                          holds the file "router-path" with the private Grafana webhook path
                          and the file "expiry-path" with the private expiry watch path
  N8N_CONTAINER           n8n container name (default: n8n)
  GRAFANA_CONTAINER       Grafana container name, read for the dashboard origin
                          (default: grafana)
  N8N_CRED_HEADER_ID      id for the grafana-webhook-auth credential (default: gfwebhookauth01)
  N8N_CRED_PUSHOVER_ID    id for the pushover-api credential (default: pushoverapi0001)
  N8N_CRED_MATRIX_ID      id for the matrix-bot-auth credential (default: matrixbotauth01)
  MATRIX_BOT_TOKEN        only with --with-matrix: the Matrix bot's access token (secret)
  N8N_CRED_GRAFANA_VIEWER_ID  id for the grafana-viewer-auth credential (default: grafanaviewer01)
                          (every credential id is 8 to 32 letters or digits, and no two are equal)
  GRAFANA_VIEWER_TOKEN    only with --with-grafana-viewer: a Grafana Viewer service account token (secret)
  N8N_CRED_DISCORD_ID     id of the existing Discord webhook credential in n8n
                          (default: dscwhk1479574998; an n8n internal id, not a secret)
  N8N_DISCORD_CRED_NAME   name of that credential (default: Discord Webhook Alerts)
  N8N_ROUTER_NAME         name given to the imported router workflow
  N8N_HANDLER_NAME        name given to the imported error handler workflow
"""
import json
import os
import re
import secrets
import stat
import subprocess
import sys
import uuid

sys.path.insert(0, os.path.join(os.path.dirname(os.path.realpath(__file__)), ".."))
import container_engine  # noqa: E402  (the shared CONTAINER_ENGINE setting and trusted-binary resolver)

CONTAINER = os.environ.get("N8N_CONTAINER", "n8n")
GRAFANA_CONTAINER = os.environ.get("GRAFANA_CONTAINER", "grafana")
CONFIG_DIR = os.environ.get("SIEM_CONFIG_DIR") or os.path.join(os.path.expanduser("~"), ".config", "doppler-siem")
PATH_FILE = os.path.join(CONFIG_DIR, "router-path")
EXPIRY_PATH_FILE = os.path.join(CONFIG_DIR, "expiry-path")
CRED_HEADER_ID = os.environ.get("N8N_CRED_HEADER_ID", "gfwebhookauth01")
CRED_PUSHOVER_ID = os.environ.get("N8N_CRED_PUSHOVER_ID", "pushoverapi0001")
CRED_MATRIX_ID = os.environ.get("N8N_CRED_MATRIX_ID", "matrixbotauth01")
CRED_GRAFANA_VIEWER_ID = os.environ.get("N8N_CRED_GRAFANA_VIEWER_ID", "grafanaviewer01")
CRED_DISCORD_ID = os.environ.get("N8N_CRED_DISCORD_ID", "dscwhk1479574998")
DISCORD_NAME = os.environ.get("N8N_DISCORD_CRED_NAME", "Discord Webhook Alerts")
NEW_NAME = os.environ.get("N8N_ROUTER_NAME", "Grafana SOAR — Alert Router (authenticated)")
NEEDED = ("GRAFANA_WEBHOOK_SECRET", "PUSHOVER_API_KEY", "PUSHOVER_USER_KEY")
HANDLER_NAME = os.environ.get("N8N_HANDLER_NAME", "Alert Router Error Handler")
ERROR_PLACEHOLDER = "ERROR_WORKFLOW_ID"
PATH_PREFIX = "grafana-alerts-"
EXPIRY_PATH_PREFIX = "expiry-watch-alerts-"
STRIP_KEYS = ("activeVersionId", "shared", "versionMetadata", "versionCounter",
              "createdAt", "updatedAt", "triggerCount", "pinData", "isArchived")


def need(name):
    value = os.environ.get(name, "")
    if not value:
        sys.exit("missing environment value: " + name)
    return value


def bearer_token(name):
    """A secret from the environment for a Bearer header: surrounding whitespace is stripped; empty, or
    anything with a line break or other control character inside, stops the run (it would corrupt the header)."""
    value = os.environ.get(name, "").strip()
    if not value:
        sys.exit("missing environment value: " + name)
    if any(ord(ch) < 32 or ord(ch) == 127 for ch in value):
        sys.exit(name + " must be one line without control characters")
    return value


def credential_ids():
    """Every credential id this tooling creates or expects, by credential name."""
    return {
        "grafana-webhook-auth": CRED_HEADER_ID,
        "pushover-api": CRED_PUSHOVER_ID,
        DISCORD_NAME: CRED_DISCORD_ID,
        "matrix-bot-auth": CRED_MATRIX_ID,
        "grafana-viewer-auth": CRED_GRAFANA_VIEWER_ID,
    }


def check_credential_ids():
    """Each credential id is 8 to 32 letters or digits and no two credentials share one."""
    seen = {}
    for name, value in credential_ids().items():
        if not re.match(r"^[A-Za-z0-9]{8,32}$", value or ""):
            sys.exit("credential id for %s must be 8 to 32 letters or digits" % name)
        if value in seen:
            sys.exit("credential id for %s equals the id for %s: every credential needs its own id" % (name, seen[value]))
        seen[value] = name


def preflight(with_matrix=False, with_viewer=False):
    """Check everything a credential run needs BEFORE n8n is changed, so a bad value never leaves a partial result."""
    check_credential_ids()
    for name in NEEDED:
        need(name)
    if with_matrix:
        bearer_token("MATRIX_BOT_TOKEN")
    if with_viewer:
        bearer_token("GRAFANA_VIEWER_TOKEN")


def engine():
    """The container engine name (docker unless CONTAINER_ENGINE says podman); a bad value stops the run."""
    try:
        return container_engine.engine_name()
    except container_engine.ContainerEngineError as err:
        sys.exit(str(err))


def engine_run(args, **kwargs):
    """Run the selected engine as the trusted binary (never through PATH); no shell is involved."""
    try:
        return container_engine.engine_run([engine(), *args], capture_output=True, check=False, **kwargs)
    except container_engine.ContainerEngineError as err:
        sys.exit(str(err))


def docker_in(script, payload):
    """Feed payload to a shell script inside the n8n container over stdin."""
    proc = engine_run(["exec", "-i", CONTAINER, "sh", "-c", script], input=payload.encode())
    out = (proc.stdout + proc.stderr).decode(errors="replace")
    # Never echo anything that could contain a value; keep only plain status lines.
    lines = [ln for ln in out.splitlines() if ln.strip() and "Error tracking" not in ln]
    rc = proc.returncode
    if rc == EXIT_DOMAIN_LOCK_UNVERIFIED:
        rc = 1   # a child must never look like "imported, lock not verified"
    return rc, lines


# Secret-bearing imports. The plaintext JSON arrives over stdin and is written inside the container
# into a private directory (mktemp -d is mode 700, umask 077 makes the file mode 600 from creation)
# with an unpredictable name; the trap removes both on exit or on a signal. The n8n CLI is documented
# with --input=<file> only (no stdin form), so a file is used. The n8n output is thrown away inside the
# container and never printed here: it is not needed to judge success (the exit code is), and a CLI
# error could echo its input.
# The directory is under /dev/shm when that is a memory-backed mount (the filesystem type is read with
# stat and must be tmpfs), so a SIGKILL or crash, which skips the trap, leaves the plaintext in RAM only
# and not in the container's writable layer. Otherwise /tmp is used and WARN_NOT_TMPFS is printed by the
# caller (it is a fixed line; no other child output is ever shown).
SHM_DIR = "/dev/shm"
FALLBACK_DIR = "/tmp"
WARN_NOT_TMPFS = "warning: /dev/shm is not a memory-backed mount; the credential file uses /tmp (it survives a SIGKILL)"
CRED_IMPORT_SCRIPT = (
    "umask 077; shm=" + SHM_DIR + "; base=" + FALLBACK_DIR + "; "
    "if [ -d \"$shm\" ] && [ -w \"$shm\" ] && [ \"$(stat -f -c %T \"$shm\" 2>/dev/null)\" = tmpfs ]; then base=$shm; "
    "else echo '" + WARN_NOT_TMPFS + "'; fi; "
    "d=$(mktemp -d \"$base/n8n-cred.XXXXXXXXXX\") || exit 70; "
    "trap 'rm -f \"$d/c.json\"; rmdir \"$d\"' EXIT HUP INT TERM; "
    "cat > \"$d/c.json\" && n8n import:credentials --input=\"$d/c.json\" >/dev/null 2>&1"
)

# Exit code of the viewer flow when the import itself worked: the credential exists but nothing proves
# its Allowed HTTP Request Domains lock, so automation must not treat the run as fully done.
EXIT_DOMAIN_LOCK_UNVERIFIED = 40


def failure_code(rc):
    """A failed child never reports the 'imported, lock not verified' code (or 0): it becomes 1."""
    return 1 if rc in (0, EXIT_DOMAIN_LOCK_UNVERIFIED) else rc

VIEWER_REMINDER = (
    "REQUIRED NEXT STEP: an import file cannot lock a credential to a host. In the n8n editor open\n"
    "credential grafana-viewer-auth and set Allowed HTTP Request Domains to the Grafana host only,\n"
    "then run the post-import check in docs/live-deploy-runbook.md. Until then the Viewer token can be\n"
    "sent to any https host that GRAFANA_BASE_URL names."
)


def import_credential_records(records):
    """Import credential records through the private-file script. Returns only the exit code: child
    output is never shown, so no error path can print the token or the credential JSON."""
    rc, lines = docker_in(CRED_IMPORT_SCRIPT, json.dumps(records))
    if WARN_NOT_TMPFS in lines:
        print(WARN_NOT_TMPFS)   # the one fixed line the script itself prints; nothing else from the child
    return rc


def docker_out(*args):
    proc = engine_run(list(args))
    return proc.returncode, proc.stdout.decode(errors="replace").strip()


# ---- pure logic (importable, no docker, no files) -------------------------------

def build_credentials(secret, token, user):
    """The two n8n credential records, as `n8n import:credentials` takes them."""
    return [
        {
            "id": CRED_HEADER_ID,
            "name": "grafana-webhook-auth",
            "type": "httpHeaderAuth",
            "data": {"name": "Authorization", "value": "Bearer " + secret},
        },
        {
            "id": CRED_PUSHOVER_ID,
            "name": "pushover-api",
            "type": "httpCustomAuth",
            "data": {"json": json.dumps({"body": {"token": token, "user": user}})},
        },
    ]


def build_matrix_credential(token):
    """The Custom Auth credential the weekly digest's Matrix node uses: one Authorization header."""
    return {
        "id": CRED_MATRIX_ID,
        "name": "matrix-bot-auth",
        "type": "httpCustomAuth",
        "data": {"json": json.dumps({"headers": {"Authorization": "Bearer " + token}})},
    }


def build_grafana_viewer_credential(token):
    """The Custom Auth credential the weekly digest's Grafana query nodes use: one Authorization header."""
    return {
        "id": CRED_GRAFANA_VIEWER_ID,
        "name": "grafana-viewer-auth",
        "type": "httpCustomAuth",
        "data": {"json": json.dumps({"headers": {"Authorization": "Bearer " + token}})},
    }


def credential_id_map():
    """Credential name -> the n8n credential id this tooling creates or expects."""
    return credential_ids()


def choose_webhook_path(existing, token_fn=None, prefix=PATH_PREFIX, token_len=None):
    """Reuse the saved private path when it looks right, else make a new one.

    With token_len the saved path must be the prefix plus exactly that many URL-safe characters (the
    shape token_urlsafe(18) makes, 24), so a known or short suffix is never reused."""
    existing = (existing or "").strip()
    if token_len is not None:
        ok = re.fullmatch(re.escape(prefix) + "[A-Za-z0-9_-]{%d}" % token_len, existing) is not None
    else:
        ok = existing.startswith(prefix) and len(existing) >= 20
    if ok:
        return existing
    return prefix + (token_fn or (lambda: secrets.token_urlsafe(18)))()


EXPIRY_TOKEN_LEN = 24


def valid_expiry_path(path):
    return re.fullmatch(re.escape(EXPIRY_PATH_PREFIX) + "[A-Za-z0-9_-]{%d}" % EXPIRY_TOKEN_LEN, path or "") is not None


def _open_private(path, flags):
    """Open path without following a symlink; refuse anything but a regular file we own."""
    try:
        fd = os.open(path, flags | os.O_NOFOLLOW | os.O_NONBLOCK, 0o600)
    except OSError as err:
        sys.exit("cannot open %s safely (%s): refusing" % (path, err.strerror))
    st = os.fstat(fd)
    if not stat.S_ISREG(st.st_mode):
        os.close(fd)
        sys.exit("%s is not a regular file: refusing" % path)
    if st.st_uid != os.geteuid():
        os.close(fd)
        sys.exit("%s has the wrong owner: refusing" % path)
    return fd, st


def read_private_file(path):
    """Contents of a private file, or "" when it does not exist. Refuses a symlink, a file that is not a
    regular file owned by this user, and any group or other permission bit (the path inside may have been
    read by others: rotate it by deleting the file)."""
    if not os.path.lexists(path):
        return ""
    fd, st = _open_private(path, os.O_RDONLY)
    try:
        if st.st_mode & 0o077:
            sys.exit("%s has mode %o, looser than 600: refusing to trust it; delete it to make a new path"
                     % (path, st.st_mode & 0o777))
        with os.fdopen(fd, "r", encoding="utf-8") as handle:
            fd = -1
            return handle.read()
    finally:
        if fd >= 0:
            os.close(fd)


def write_private_file(path, value):
    """Replace path atomically and durably with mode 600: write a temp file in the same folder (created
    exclusively, no symlink followed, mode 600 requested at creation), write until every byte is out,
    fsync it, rename it over the final name, fsync the folder. The temp file is removed on any failure and
    the old file stays untouched. A symlink or non-regular final path is refused."""
    if os.path.lexists(path):
        os.close(_open_private(path, os.O_RDONLY)[0])  # refuses a symlink, non-regular file, foreign owner
    folder = os.path.dirname(path) or "."
    tmp = os.path.join(folder, ".%s.tmp-%d-%s" % (os.path.basename(path), os.getpid(), secrets.token_hex(6)))
    data = value.encode("utf-8")
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, stat.S_IRUSR | stat.S_IWUSR)
    try:
        try:
            view = memoryview(data)
            while view:
                try:
                    written = os.write(fd, view)
                except InterruptedError:
                    continue
                if written <= 0:
                    raise OSError("short write to %s made no progress" % tmp)
                view = view[written:]
            os.fsync(fd)
        finally:
            os.close(fd)
        os.replace(tmp, path)
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise
    dir_fd = os.open(folder, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(dir_fd)
    finally:
        os.close(dir_fd)


def valid_origin(text):
    """A plain http(s) origin (host and optional port, no path), else empty."""
    if re.match(r"^https?://[A-Za-z0-9.\-]+(:[0-9]+)?/?$", text or ""):
        return text.rstrip("/")
    return ""


def check_id(value, what="workflow id"):
    if value and not re.match(r"^[0-9a-f]{16}$", value):
        raise ValueError(what + " must be 16 hex characters")


def patch_error_workflow(wf, reuse_id="", new_id=None):
    """Return the error handler workflow patched for import (inactive, ids mapped)."""
    check_id(reuse_id)
    for key in STRIP_KEYS:
        wf.pop(key, None)
    wf["id"] = reuse_id or new_id or secrets.token_hex(8)
    wf["name"] = HANDLER_NAME
    wf["active"] = False
    ids = credential_id_map()
    for node in wf["nodes"]:
        for cred in (node.get("credentials") or {}).values():
            if cred.get("name") in ids:
                cred["id"] = ids[cred["name"]]
    return wf


def patch_digest_workflow(wf, reuse_id="", error_workflow_id="", new_id=None):
    """Return the weekly update digest workflow patched for import (inactive, credential ids mapped).
    The committed placeholder errorWorkflow id is dropped unless a real handler id is given."""
    check_id(reuse_id)
    check_id(error_workflow_id, "error workflow id")
    for key in STRIP_KEYS:
        wf.pop(key, None)
    wf["id"] = reuse_id or new_id or secrets.token_hex(8)
    wf["active"] = False
    settings = wf.setdefault("settings", {})
    if error_workflow_id:
        settings["errorWorkflow"] = error_workflow_id
    else:
        settings.pop("errorWorkflow", None)
    ids = credential_id_map()
    for node in wf["nodes"]:
        for cred in (node.get("credentials") or {}).values():
            if cred.get("name") in ids:
                cred["id"] = ids[cred["name"]]
    return wf


def parse_workflow_args(rest):
    """Parse the arguments after the workflow file: (reuse_id, pushover_on, error_workflow_id)."""
    reuse_id, error_id, pushover_on, i = "", "", False, 0
    while i < len(rest):
        arg = rest[i]
        if arg == "--pushover-on":
            pushover_on = True
        elif arg == "--error-workflow-id":
            if i + 1 >= len(rest):
                raise ValueError("--error-workflow-id needs an id")
            error_id = rest[i + 1]
            i += 1
        elif not reuse_id:
            reuse_id = arg
        else:
            raise ValueError("unexpected argument: " + arg)
        i += 1
    return reuse_id, pushover_on, error_id


def patch_workflow(wf, reuse_id="", pushover_on=False, origin="", webhook_path="",
                   webhook_id=None, new_id=None, error_workflow_id="", expiry_path=None):
    """Return the workflow patched for import. Mutates and returns wf."""
    check_id(reuse_id)
    check_id(error_workflow_id, "error workflow id")
    for key in STRIP_KEYS:
        wf.pop(key, None)
    # n8n requires an id. Reuse the id of an earlier import of THIS workflow so a re-run
    # overwrites it; otherwise make a fresh one, which can never overwrite another workflow.
    wf["id"] = reuse_id or new_id or secrets.token_hex(8)
    wf["name"] = NEW_NAME
    wf["active"] = False
    settings = wf.setdefault("settings", {})
    if error_workflow_id:
        settings["errorWorkflow"] = error_workflow_id
    else:
        settings.pop("errorWorkflow", None)
    ids = credential_id_map()
    for node in wf["nodes"]:
        for cred in (node.get("credentials") or {}).values():
            if cred.get("name") in ids:
                cred["id"] = ids[cred["name"]]
        if node["type"].endswith(".webhook") and node["name"] == "Expiry Watch Webhook":
            # the expiry watch's entry gets its own private path (never the committed placeholder),
            # so an anonymous caller cannot find it and start executions
            path = expiry_path or choose_webhook_path("", prefix=EXPIRY_PATH_PREFIX, token_len=EXPIRY_TOKEN_LEN)
            if not valid_expiry_path(path):
                raise ValueError("the expiry webhook path must be %s plus %d URL-safe characters"
                                 % (EXPIRY_PATH_PREFIX, EXPIRY_TOKEN_LEN))
            node["parameters"]["path"] = path
            node["webhookId"] = str(uuid.uuid4())
            node.pop("disabled", None)  # the committed node ships disabled; only a private path enables it
        elif node["type"].endswith(".webhook"):
            node["parameters"]["path"] = webhook_path
            # With a webhookId the production URL is /webhook/<path>; without one n8n
            # serves it under /webhook/<workflowId>/<node name>/<path>.
            node["webhookId"] = webhook_id or str(uuid.uuid4())
        code = node.get("parameters", {}).get("jsCode")
        if code and "PUSHOVER_ENABLED" in code and pushover_on:
            code = re.sub(r"const PUSHOVER_ENABLED = (false|true);",
                          "const PUSHOVER_ENABLED = true;", code, count=1)
            node["parameters"]["jsCode"] = code
        if code and "ALLOWED_DASHBOARD_ORIGIN" in code and origin:
            code = re.sub(r"const ALLOWED_DASHBOARD_ORIGIN = '[^']*';",
                          "const ALLOWED_DASHBOARD_ORIGIN = '%s';" % origin, code, count=1)
            node["parameters"]["jsCode"] = code
    return wf


# ---- command line ----------------------------------------------------------------

def check(with_matrix=False, with_viewer=False):
    names = NEEDED + (("MATRIX_BOT_TOKEN",) if with_matrix else ()) + (("GRAFANA_VIEWER_TOKEN",) if with_viewer else ())
    for name in names:
        print("%s: %s" % (name, "present" if os.environ.get(name) else "MISSING"))
    return 0 if all(os.environ.get(n) for n in names) else 1


def credentials():
    creds = build_credentials(need("GRAFANA_WEBHOOK_SECRET"), need("PUSHOVER_API_KEY"),
                              need("PUSHOVER_USER_KEY"))
    rc = import_credential_records(creds)
    print("credentials import exit code:", rc)
    return rc


def matrix_credentials():
    """Create only matrix-bot-auth. The token is read from the environment and sent over stdin."""
    cred = build_matrix_credential(bearer_token("MATRIX_BOT_TOKEN"))
    rc = import_credential_records([cred])
    print("matrix credential import exit code:", rc)
    return rc


def grafana_viewer_credentials():
    """Create only grafana-viewer-auth. The token is read from the environment and sent over stdin."""
    check_credential_ids()
    cred = build_grafana_viewer_credential(bearer_token("GRAFANA_VIEWER_TOKEN"))
    rc = import_credential_records([cred])
    print("grafana viewer credential import exit code:", rc)
    if rc == 0:
        print(VIEWER_REMINDER)
        print("exit code %d: imported, domain lock not verified (see docs/live-deploy-runbook.md)" % EXIT_DOMAIN_LOCK_UNVERIFIED)
        return EXIT_DOMAIN_LOCK_UNVERIFIED
    return failure_code(rc)


def digest_workflow(path, reuse_id="", error_workflow_id=""):
    try:
        check_id(reuse_id)
        check_id(error_workflow_id, "error workflow id")
    except ValueError as err:
        sys.exit(str(err))
    with open(path, encoding="utf-8") as handle:
        wf = json.load(handle)
    wf = patch_digest_workflow(wf, reuse_id, error_workflow_id)
    script = "cat > /tmp/dg.json && n8n import:workflow --input=/tmp/dg.json; rc=$?; rm -f /tmp/dg.json; exit $rc"
    rc, lines = docker_in(script, json.dumps([wf]))
    for ln in lines[:6]:
        print(ln[:160])
    print("digest workflow import exit code:", rc)
    print("digest workflow id:", wf["id"])
    print("digest workflow active: False (activate it in n8n after you check it)")
    return rc


def grafana_origin():
    rc, out = docker_out("exec", GRAFANA_CONTAINER, "printenv", "GF_SERVER_ROOT_URL")
    return valid_origin(out) if rc == 0 else ""


def error_workflow(path, reuse_id=""):
    try:
        check_id(reuse_id)
    except ValueError as err:
        sys.exit(str(err))
    with open(path, encoding="utf-8") as handle:
        wf = json.load(handle)
    wf = patch_error_workflow(wf, reuse_id)
    script = "cat > /tmp/eh.json && n8n import:workflow --input=/tmp/eh.json; rc=$?; rm -f /tmp/eh.json; exit $rc"
    rc, lines = docker_in(script, json.dumps([wf]))
    for ln in lines[:6]:
        print(ln[:160])
    print("error workflow import exit code:", rc)
    print("error workflow id:", wf["id"])
    return rc


def workflow(path, reuse_id="", pushover_on=False, error_workflow_id=""):
    try:
        check_id(reuse_id)
        check_id(error_workflow_id, "error workflow id")
    except ValueError as err:
        sys.exit(str(err))
    with open(path, encoding="utf-8") as handle:
        wf = json.load(handle)
    # Reuse the private path from an earlier run (Grafana's contact point already
    # points at it); only make a new one the first time.
    existing = ""
    if os.path.isfile(PATH_FILE):
        with open(PATH_FILE, encoding="utf-8") as handle:
            existing = handle.read()
    new_path = choose_webhook_path(existing)
    expiry_existing = read_private_file(EXPIRY_PATH_FILE)
    expiry_path = choose_webhook_path(expiry_existing, prefix=EXPIRY_PATH_PREFIX, token_len=EXPIRY_TOKEN_LEN)
    origin = grafana_origin()
    wf = patch_workflow(wf, reuse_id, pushover_on, origin, new_path, error_workflow_id=error_workflow_id,
                        expiry_path=expiry_path)
    old = os.umask(0o077)
    try:
        with open(PATH_FILE, "w", encoding="utf-8") as handle:
            handle.write(new_path)
        write_private_file(EXPIRY_PATH_FILE, expiry_path)
    finally:
        os.umask(old)
    script = "cat > /tmp/wf.json && n8n import:workflow --input=/tmp/wf.json; rc=$?; rm -f /tmp/wf.json; exit $rc"
    rc, lines = docker_in(script, json.dumps([wf]))
    for ln in lines[:6]:
        print(ln[:160])
    print("workflow import exit code:", rc)
    print("new webhook path saved (mode 600):", PATH_FILE)
    print("expiry watch webhook path saved (mode 600):", EXPIRY_PATH_FILE)
    print("dashboard origin constant set:", bool(origin))
    print("error workflow set:", bool(error_workflow_id))
    return rc


def main(argv):
    flags = argv[1:]
    known = {"--with-matrix", "--with-grafana-viewer"}
    if argv[:1] in (["--check"], ["--credentials"]) and len(set(flags)) == len(flags) and set(flags) <= known:
        if argv[0] == "--check":
            return check("--with-matrix" in flags, "--with-grafana-viewer" in flags)
        preflight("--with-matrix" in flags, "--with-grafana-viewer" in flags)
        rc = credentials()
        if rc:
            return rc
        if "--with-matrix" in flags:
            rc = matrix_credentials()
        if not rc and "--with-grafana-viewer" in flags:
            rc = grafana_viewer_credentials()
        return rc
    if argv[:1] == ["--digest-workflow"] and len(argv) >= 2:
        try:
            reuse_id, _unused, error_id = parse_workflow_args(argv[2:])
        except ValueError as err:
            sys.exit(str(err))
        if _unused:
            sys.exit("--pushover-on does not apply to the digest workflow")
        return digest_workflow(argv[1], reuse_id, error_id)
    if argv[:1] == ["--error-workflow"] and len(argv) >= 2:
        return error_workflow(argv[1], argv[2] if len(argv) > 2 else "")
    if argv[:1] == ["--workflow"] and len(argv) >= 2:
        try:
            reuse_id, pushover_on, error_id = parse_workflow_args(argv[2:])
        except ValueError as err:
            sys.exit(str(err))
        return workflow(argv[1], reuse_id, pushover_on, error_id)
    sys.exit(__doc__)


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
