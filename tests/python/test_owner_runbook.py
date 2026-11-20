"""Checks on docs/owner-runbook.md that a machine can make (issue #174).

The runbook is what the owner pastes into a terminal on the live box. These tests catch the
mistakes that cost a live step: a script path that does not exist, a flag the script does not
take, a hardened script run with bash, a secret on a command line, a sudo step over an ssh
without a terminal, a placeholder nobody defined, and the steps whose order matters.
They read files only. Nothing here talks to a live system.
"""
import re

import pytest

from conftest import REPO_ROOT

RUNBOOK = (REPO_ROOT / "docs" / "owner-runbook.md").read_text(encoding="utf-8")
FLAT = " ".join(RUNBOOK.split())


def fences(text=RUNBOOK):
    return re.findall(r"```[^\n]*\n(.*?)```", text, flags=re.S)


CODE = "\n".join(fences())
CODE_LINES = CODE.splitlines()


def section(start, end):
    """Text from the heading that starts with `start` up to the heading that starts with `end`."""
    i = RUNBOOK.index(start)
    j = RUNBOOK.index(end, i + len(start))
    return RUNBOOK[i:j]


# ---- paths -----------------------------------------------------------------------

PATH_RE = re.compile(r"(?:(?<![\w./-])|(?<=REPO_DIR/))((?:scripts|docs|docker|n8n|tests)/[\w./-]*\w)")


def test_every_repo_path_the_runbook_names_exists():
    missing = []
    for raw in PATH_RE.findall(RUNBOOK):
        if "bak-" in raw or raw.endswith("-"):
            continue
        if not (REPO_ROOT / raw).exists():
            missing.append(raw)
    assert not missing, sorted(set(missing))


# ---- hardened scripts, secrets, terminals -----------------------------------------

def test_no_shell_script_of_the_repo_is_run_with_bash_or_sh():
    # a hardened script checks its own privileges: it is run as `sudo scripts/NAME.sh`, never `bash scripts/...`
    assert not re.search(r"\b(?:ba)?sh\s+(?:\./)?(?:REPO_DIR/)?scripts/", RUNBOOK)
    for m in re.finditer(r"(?<![\w./-])(?:\./)?(?:REPO_DIR/)?scripts/[\w.-]+\.sh\b", CODE):
        line = CODE[CODE.rfind("\n", 0, m.start()) + 1:CODE.find("\n", m.end())]
        assert "sudo" in line, line


def test_no_secret_on_a_command_line():
    for line in CODE_LINES:
        assert not re.search(r"\bcurl\b[^\n]*(?:\s-u\s|--user\b)", line), line
        if "curl" in line and "Authorization" in line and "-H @-" not in line:
            raise AssertionError("a curl line carries an Authorization header on its command line: " + line)
        if "doppler secrets set" in line:
            assert "--silent" in line and line.rstrip().endswith("> /dev/null"), line
            assert not re.search(r"doppler secrets set \S+ \S", line.split("--project")[0]), line  # no value argument


def test_every_ssh_line_names_the_key_and_every_sudo_over_ssh_has_a_terminal():
    for line in CODE_LINES:
        if re.match(r"\s*ssh\s", line):
            assert "-i KEY_FILE -o IdentitiesOnly=yes" in line, line
            if "sudo" in line:
                assert re.search(r"\s-t\s", line), "sudo over ssh needs a terminal (-t): " + line


# ---- flags and names exist in the code ----------------------------------------------

def doc_flags(path):
    text = (REPO_ROOT / path).read_text(encoding="utf-8")
    return set(re.findall(r"--[a-z][a-z0-9-]+", text))


def flags_on_lines(marker):
    out = set()
    for line in CODE_LINES:
        if marker in line:
            after = re.split(r"&&|;|\|", line.split(marker, 1)[1])[0]  # only the script's own arguments
            out |= set(re.findall(r"\s(--[a-z][a-z0-9-]+)", after))
    return out


@pytest.mark.parametrize("marker,source", [
    ("n8n-setup-alert-router.py", "scripts/live-deploy/n8n-setup-alert-router.py"),
    ("grafana-deploy.py", "scripts/live-deploy/grafana-deploy.py"),
    ("n8n-test-router.py", "scripts/live-deploy/n8n-test-router.py"),
    ("expiry_watch.py", "scripts/expiry_watch.py"),
    ("backup-state.py", "scripts/backup-state.py"),
    ("restore-state.py", "scripts/restore-state.py"),
    ("gameday.py", "scripts/gameday.py"),
])
def test_flags_in_the_runbook_exist_in_the_script(marker, source):
    text = (REPO_ROOT / source).read_text(encoding="utf-8")
    for flag in flags_on_lines(marker):
        assert flag in text, "%s is not in %s" % (flag, source)


def test_names_the_runbook_uses_exist_in_the_code():
    setup = (REPO_ROOT / "scripts" / "live-deploy" / "n8n-setup-alert-router.py").read_text(encoding="utf-8")
    for name in ("router-path", "expiry-path", "SIEM_CONFIG_DIR"):
        assert name in setup and name in RUNBOOK, name
    router = (REPO_ROOT / "n8n" / "grafana-alert-router.json").read_text(encoding="utf-8")
    for name in ("EXPIRY_WATCH_ROUTER_SECRET", "HEARTBEAT_PING_URL", "HEARTBEAT_KIND"):
        assert name in router and name in RUNBOOK, name
    watch = (REPO_ROOT / "scripts" / "expiry_watch.py").read_text(encoding="utf-8")
    assert "EXPIRY_WATCH_ROUTER_TOKEN" in (REPO_ROOT / "docs" / "expiry-watch.example.toml").read_text(encoding="utf-8")
    assert "token_env" in watch
    assert "N8N_PAYLOAD_SIZE_MAX" in (REPO_ROOT / "docs" / "expiry-watch.md").read_text(encoding="utf-8")


# ---- placeholders ---------------------------------------------------------------------

TOKEN_RE = re.compile(r"\b[A-Z][A-Z0-9]*(?:_[A-Z0-9]+)+\b")


def placeholder_table():
    block = section("## Placeholders and conventions", "Rules every step follows")
    names = set()
    for line in block.splitlines():
        if line.startswith("| `"):
            names |= set(re.findall(r"`([A-Za-z0-9_]+)`", line.split("|")[1]))
    return names


def repo_text_outside_runbook():
    chunks = []
    for path in REPO_ROOT.rglob("*"):
        if not path.is_file() or ".git" in path.parts or "tests" in path.parts or path.name == "owner-runbook.md":
            continue
        if path.suffix in (".md", ".py", ".sh", ".yml", ".yaml", ".json", ".toml", ".example", ".service", ".timer", ".env") \
                or path.name.startswith(".env"):
            try:
                chunks.append(path.read_text(encoding="utf-8"))
            except (UnicodeDecodeError, OSError):
                pass
    return "\n".join(chunks)


def test_every_placeholder_is_defined_once_in_the_table():
    defined = placeholder_table()
    for name in ("KEY_FILE", "LOGGING_BOX", "REPO_DIR", "ROUTER_ID", "HANDLER_ID", "OLD_ROUTER_ID", "SERVICE_ACCOUNT",
                 "DEV_CONFIG", "N8N_COMPOSE_FILE", "N8N_COMPOSE_DIR", "HOST_PORT", "CONTAINER_PORT", "SIEM_NETWORK",
                 "EXPIRY_WATCH_PRIVATE_PATH", "PRIVATE_WEBHOOK_PATH", "ARCHIVE_FILE", "OBSERVER_HOSTNAME", "VARIABLE_NAME"):
        assert name in defined, name + " is used but not defined in the placeholder table"
    elsewhere = repo_text_outside_runbook()
    undefined = set()
    for token in TOKEN_RE.findall(CODE):
        if token in defined or token in ("EOF", "HOME", "UTC"):
            continue
        if token not in elsewhere:
            undefined.add(token)  # not an environment name the repo knows, so it can only be a placeholder
    assert not undefined, sorted(undefined)


def test_the_live_deploy_runbook_pointer_to_q1_resolves():
    # docs/live-deploy-runbook.md says "see docs/owner-runbook.md, Q1" for DEV_CONFIG
    assert re.search(r"^\| Q1 \|", RUNBOOK, flags=re.M)
    assert "DEV_CONFIG" in section("## Open questions", "## Order and why")


# ---- the repo on the box ---------------------------------------------------------------

def test_a_step_says_how_the_repo_gets_onto_the_box():
    step = section("## Step 0a.", "## Step 0b.")
    assert "git archive" in step and "scp" in step and "tar -xzf" in step
    assert "/opt/siem" in step and "container_engine.py" in step
    assert "REPO_DIR" in step
    assert "step 0a" in section("## Step 0. Preflight", "## Step 0a.")


# ---- order and state of the router re-import (6.1 item 3) -------------------------------

def item3():
    return section("**3. Re-import the router", "**4. Post-import checks.")


def test_router_reimport_states_inactive_gap_and_handler_order():
    text = " ".join(item3().split())
    assert "INACTIVE" in text
    assert "alert gap" in text.lower()
    assert "error handler" in text.lower() and "first" in text.lower()
    assert "router-path" in text  # the saved Grafana path must exist or a new one is made
    assert "n8n --help" in text  # the publish subcommand name differs between n8n versions
    assert "export:workflow" in text  # a copy of the live workflow before the in-place overwrite
    assert "Whether a re-import leaves the workflow active is not documented" not in text


def test_router_id_is_not_said_to_be_printed_by_the_router_import():
    block = section("## Placeholders and conventions", "Rules every step follows")
    row = next(l for l in block.splitlines() if l.startswith("| `ROUTER_ID`"))
    assert "printed by the router import" not in row
    assert "error workflow id:" in row or "list:workflow" in row


# ---- statements that were false against the merged code ----------------------------------

def test_the_dry_run_is_not_said_to_check_the_router_secret():
    # scripts/expiry_watch.py reads the router token only when it posts (not dry_run)
    assert "the dry run in 6c confirms" not in FLAT
    assert "never reads the secret" in FLAT.lower() or "never reads the router secret" in FLAT.lower()


def test_the_secret_is_stored_without_a_trailing_newline():
    # the watch rejects a token with a newline (its pattern allows only printable characters)
    line = next(l for l in CODE_LINES if "doppler secrets set EXPIRY_WATCH_ROUTER_TOKEN" in l)
    assert "openssl rand -base64 32" in line and "tr -d '\\n'" in line


def test_router_limit_test_does_not_read_denials_from_the_executions_list():
    text = " ".join(section("### 6.3 Test the router limits", "### 6a.").split())
    assert "saveDataErrorExecution" in text or "stored" in text  # says why nothing is listed
    assert "read the 403 results" not in text
    assert "-H @-" in section("### 6.3 Test the router limits", "### 6a.")  # header from stdin, not argv


def test_the_expiry_watch_runs_as_the_service_account():
    lines = [l for l in CODE_LINES if "scripts/expiry_watch.py" in l and "ssh" in l]
    assert lines
    for line in lines:
        assert "sudo -u SERVICE_ACCOUNT" in line, line


def test_first_backup_run_matches_who_owns_the_destination():
    text = " ".join(section("### 2c. First run, by hand", "### 2d.").split())
    assert "not owned by the user running it" in text


def test_n8n_recreates_are_followed_by_a_read_back_of_the_variables():
    text = " ".join(section("### 6.2 Cap request bodies", "### 6.3 Test the router limits").split())
    assert "HEARTBEAT_PING_URL" in text and "docker network inspect" in text
    assert "OWNER DECISION" in RUNBOOK


def test_stale_pr_126_wording_is_gone():
    assert "Use this only after PR #126 is merged" not in FLAT
    assert "Until the PR is merged and the script is on the host" not in FLAT


def test_no_em_dash():
    assert chr(0x2014) not in RUNBOOK
