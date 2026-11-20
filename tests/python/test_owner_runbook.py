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
        if re.search(r"(?<![\w$])" + re.escape(token) + r"=", CODE):
            continue  # a shell variable the runbook assigns itself
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


# ---- Daybreak round 1 on PR #176: one pin per finding, so none can be silently removed ----

def test_round1_f1_every_n8n_recreate_goes_through_the_safe_wrapper():
    # (1) no plain `docker compose up -d n8n` anywhere except the recorded 2026-11-20 command
    plain = [l for l in CODE_LINES if "compose up -d n8n" in l]
    assert plain, "the safe recreate block must exist"
    safe = [l for l in plain if "doppler run" in l and "REFUSING" in l and "--preserve-env" in l]
    assert len(safe) == 1, plain
    recorded = [l for l in plain if l not in safe]
    assert all("bak-payload" in l or "sleep 15" in l for l in recorded), recorded
    block = section("SAFE N8N RECREATE", "Compare the `$HOME/n8n-env-before.txt`")
    assert "n8n-env-before.txt" in block  # names-only capture before the recreate
    assert "NOT recreated" in block and "RECOVERY:" in block  # fails closed, prints the recovery
    assert "HEARTBEAT_PING_URL" in block and "EXPIRY_WATCH_ROUTER_TOKEN" in block
    assert "OWNER DECISION" in RUNBOOK
    for name in ("### 6.0", "### 6.1", "### 6.2"):
        pass
    assert FLAT.count("SAFE N8N RECREATE") >= 4  # 6.0 rollback, 6.1, 6.2 repeat and 6.2 rollback


def test_round1_f2_router_chain_has_a_failure_branch_per_stage_and_a_rollback():
    text = item3()
    flat = " ".join(text.split())
    for stage in ("FAILED stage 1 of 3 (import)", "FAILED stage 2 of 3 (publish)", "FAILED stage 3 of 3 (restart)"):
        assert stage in flat, stage
    assert "chain exit code" in flat and "MAXIMUM GAP" in flat and "5 minutes" in flat
    assert "ROLLBACK" in flat and "import:workflow --input=/tmp/router-before.json" in flat
    assert 'publish:workflow --id="$ROUTER_ID"' in flat and "docker restart n8n" in flat  # the rollback publishes and restarts
    # the old one-line ssh with a trailing echo (which turned a failure into exit 0) is gone
    assert not any("n8n-setup-alert-router.py --workflow" in l and l.lstrip().startswith("ssh") for l in CODE_LINES)


def test_round1_f3_grafana_prerequisites_have_names_only_commands():
    text = section("4. Find out which other variables", "Watch: the output of item 2")
    assert "sudo sed -n -E" in text and "comm -23" in text and "doppler secrets --only-names" in text
    assert "OWNER DECISION" in text
    # the `.env` reader never prints a value: every line is replaced by its key
    assert r"\2/p" in text


def test_round1_f4_the_extracted_repo_is_made_non_writable_and_checked():
    step = section("## Step 0a.", "## Step 0b.")
    assert "sha256sum" in step and "chmod -R go-w" in step
    assert "-perm /022" in step and "-type l" in step
    assert "/opt/siem-repo.new" in step and "mv /opt/siem-repo.new /opt/siem-repo" in step
    assert "--no-same-permissions" in step


def test_round1_f5_the_router_export_gets_an_explicit_private_mode():
    text = " ".join(item3().split())
    assert "mktemp -d" in text and "install -m 600" in text
    assert 'stat -c %a "$HOME/router-before.json")" = 600' in text
    assert '[ ! -L "$HOME/router-before.json" ]' in text
    assert 'rm -f "$HOME/router-before.json"' in text  # says to delete it afterwards


def test_round1_f6_every_compose_edit_is_gated_on_this_runs_backup():
    for line in CODE_LINES:
        if "sed -i" in line and "compose" in line.lower() and "docker-compose.yml" in line:
            if line.count("bak-payload ") and "sleep 15" in line:
                continue  # the command as run on 2026-11-20, kept as the record and marked do-not-reuse
            assert "cmp " in line and "ok" in line, line
            assert "! -e" in line or "test ! -e" in line, line
    assert "cp --no-clobber" not in CODE
    sudoedits = [l for l in CODE_LINES if "sudoedit N8N_COMPOSE_FILE" in l]
    assert sudoedits and all("cmp N8N_COMPOSE_FILE" in l for l in sudoedits), sudoedits
    assert "bak-payload-$(date" in CODE  # the repeat form no longer overwrites a fixed name


# ---- Daybreak round 2 on PR #176: structural tests that run the documented functions with stubs ----

import os
import subprocess

VARS = {"REPO_DIR": "/tmp", "N8N_COMPOSE_DIR": "/tmp", "SIEM_NETWORK": "net",
        "ROUTER_ID": "aaaaaaaaaaaaaaaa", "HANDLER_ID": "bbbbbbbbbbbbbbbb"}


def func(name):
    m = re.search(r"^" + name + r"\(\) \{\n(.*?)\n\}$", CODE, flags=re.M | re.S)
    assert m, name + " is not defined in a fenced block"
    return "%s() {\n%s\n}" % (name, m.group(1))


def chk_vars_def():
    m = re.search(r"^chk_vars\(\) \{.*\}$", CODE, flags=re.M)
    assert m
    return m.group(0)


STUBS = r'''
docker() {
  echo "docker $*" >> "$LOG"
  if [ -n "$FAIL" ] && [[ "$*" == *"$FAIL"* ]]; then return 7; fi
  case "$*" in
    *list:workflow*) echo "aaaaaaaaaaaaaaaa Router" ;;
    *"grep -o"*) printf 'x\nx\n' ;;
  esac
  return 0
}
doppler() { echo "doppler" >> "$LOG"; [ "$FAIL" = doppler ] && return 7; return 0; }
sleep() { :; }
'''


def run_function(tmp_path, name, call, fail="", extra=""):
    home = tmp_path / "home"
    (home / "bin").mkdir(parents=True, exist_ok=True)
    stub = home / "bin" / "siem-run"
    stub.write_text("#!/bin/sh\n[ \"$FAIL\" = import ] && exit 7\necho import ok\nexit 0\n")
    stub.chmod(0o755)
    saved = home / "router-before.json"
    saved.write_text('{"typeVersion":1,\n"typeVersion":2}')
    saved.chmod(0o600)
    log = tmp_path / "log"
    log.write_text("")
    script = "\n".join(["set -u"] + ["%s=%s" % kv for kv in VARS.items()] +
                       [chk_vars_def(), STUBS, extra, func(name), call, 'echo "STATUS=$?"'])
    env = dict(os.environ, HOME=str(home), LOG=str(log), FAIL=fail)
    out = subprocess.run(["bash", "-c", script], capture_output=True, text=True, env=env, timeout=60)
    status = int(re.search(r"STATUS=(\d+)", out.stdout).group(1))
    return status, out.stdout, log.read_text()


PRE = 'recreate_n8n "HEARTBEAT_PING_URL" "HEARTBEAT_PING_URL,HEARTBEAT_KIND"'
POST = 'recreate_n8n "HEARTBEAT_PING_URL EXPIRY_WATCH_ROUTER_TOKEN" "HEARTBEAT_PING_URL,HEARTBEAT_KIND,EXPIRY_WATCH_ROUTER_TOKEN"'


def test_round2_f1_the_first_call_does_not_require_the_expiry_token():
    assert PRE in CODE and POST in CODE
    body = func("recreate_n8n")
    assert "EXPIRY_WATCH_ROUTER_TOKEN" not in body.replace("EXPIRY_WATCH_ROUTER_SECRET", "")  # the list is an argument
    assert 'for V in $REQ_VARS' in body and '--preserve-env="$PRESERVE"' in body
    assert "EXPIRY" not in PRE


def test_round2_f4_recreate_returns_the_real_status(tmp_path):
    ok, out, _ = run_function(tmp_path, "recreate_n8n", PRE)
    assert ok == 0 and "recreate exit code: 0" in out
    for fail in ("doppler", "port n8n", "network inspect"):
        status, out, _ = run_function(tmp_path, "recreate_n8n", POST, fail=fail)
        assert status != 0, fail
        assert "recreate exit code: %d" % status in out and "RECOVERY:" in out


def test_round2_f6_a_missing_container_stops_before_recording_or_recreating(tmp_path):
    status, out, log = run_function(tmp_path, "recreate_n8n", PRE, fail="exec n8n true")
    assert status == 1 and "STOP:" in out and "recreate exit code: 1" in out
    assert "doppler" not in log
    assert not (tmp_path / "home" / "n8n-env-before.txt").exists()


def test_round2_f4_the_before_file_is_private(tmp_path):
    run_function(tmp_path, "recreate_n8n", PRE)
    before = tmp_path / "home" / "n8n-env-before.txt"
    assert before.exists() and (before.stat().st_mode & 0o077) == 0


@pytest.mark.parametrize("fail,stage", [("import", "stage 1 of 3"), ("publish:workflow", "stage 2 of 3"),
                                        ("restart n8n", "stage 3 of 3")])
def test_round2_f5_router_chain_propagates_its_status(tmp_path, fail, stage):
    status, out, log = run_function(tmp_path, "router_chain", "router_chain", fail=fail)
    assert status == 7 and "FAILED " + stage in out and "chain exit code: 7" in out
    if fail == "import":
        assert "publish:workflow" not in log  # a later stage never runs after a failure


def test_round2_f5_router_chain_success(tmp_path):
    status, out, log = run_function(tmp_path, "router_chain", "router_chain")
    assert status == 0 and "chain exit code: 0" in out


@pytest.mark.parametrize("fail,label", [("cp", "copy into the container"), ("import:workflow", "import"),
                                        ("publish:workflow", "publish"), ("restart n8n", "restart")])
def test_round2_f3_rollback_names_the_failed_step_and_exits_nonzero(tmp_path, fail, label):
    fail_arg = "cp " if fail == "cp" else fail
    status, out, log = run_function(tmp_path, "router_rollback", "router_rollback", fail=fail_arg)
    assert status == 7, out
    assert "ROLLBACK FAILED at: " + label in out and "rollback exit code: 7" in out
    assert "rm -f /tmp/router-before.json" in log  # the container-side temp file is removed on every path
    assert "rollback verified" not in out


def test_round2_f3_rollback_verifies_exists_active_and_node_count(tmp_path):
    status, out, log = run_function(tmp_path, "router_rollback", "router_rollback")
    assert status == 0 and "rollback verified" in out and "2 nodes" in out
    assert "--active=true" in log and "export:workflow" in log
    # a node count that differs from the saved file fails verification and says so
    status, out, _ = run_function(tmp_path, "router_rollback", "router_rollback", extra='docker() { echo "docker $*" >> "$LOG"; case "$*" in *list:workflow*) echo "aaaaaaaaaaaaaaaa R";; *"grep -o"*) echo x;; esac; return 0; }')
    assert status != 0 and "verify node count" in out


def test_round2_f3_no_failure_masking_in_the_documented_blocks():
    # `A && echo ok || echo FAILED` ends in status 0 whatever A did
    for line in CODE_LINES:
        # an `&&` chain followed by `|| echo "FAILED..."` returns 0; the status must be captured in R first
        assert not re.search(r"&&[^|]*\|\|\s*echo\s+\"(ROLLBACK|RECOVERY|FAILED)", line), line


def test_round2_f2_the_old_repo_is_renamed_aside_before_the_new_one_is_moved_in():
    step = section("## Step 0a.", "## Step 0b.")
    swap = next(l for l in fences(step) for l in l.splitlines() if "SWAP FAILED" in l)
    aside = swap.index('mv /opt/siem-repo "/opt/siem-repo.old-$TS"')
    into = swap.index("mv /opt/siem-repo.new /opt/siem-repo")
    restore = swap.index('mv "/opt/siem-repo.old-$TS" /opt/siem-repo')
    assert aside < into < restore
    assert not re.search(r"rm -rf /opt/siem-repo(\s|'|$)", step)  # the live name is never deleted
    assert "sha256sum -c siem-repo.sha256" not in step and "siem-repo.sha256" not in step
    assert 'printf "%s  siem-repo.tar.gz\\n" EXPECTED_SHA256 | sha256sum -c -' in step
    flat_step = " ".join(step.split())
    assert "ON YOUR WORKSTATION" in flat_step and "never from the box" in flat_step


def test_round2_f7_the_session_blocks_use_quoted_variables_not_placeholders():
    for name in ("recreate_n8n", "router_chain", "router_rollback"):
        body = func(name)
        bare = re.findall(r"(?<![$\w])(REPO_DIR|N8N_COMPOSE_DIR|SIEM_NETWORK|ROUTER_ID|HANDLER_ID)(?![\w])", body)
        assert not bare, (name, bare)
        for var in re.findall(r"\$(REPO_DIR|N8N_COMPOSE_DIR|SIEM_NETWORK|ROUTER_ID|HANDLER_ID)\b", body):
            pass
        for m in re.finditer(r"(?<!\")\$(REPO_DIR|N8N_COMPOSE_DIR|SIEM_NETWORK|ROUTER_ID|HANDLER_ID)\b", body):
            ctx = body[max(0, m.start() - 12):m.end() + 12]
            assert '"' in ctx or "=" in ctx, ctx  # every expansion sits inside double quotes
    assert "variables ok" in CODE and "chk_vars" in CODE


def test_round2_f7_chk_vars_rejects_metacharacters(tmp_path):
    for var, bad in (("REPO_DIR", "/tmp/a b"), ("N8N_COMPOSE_DIR", "/tmp;x"), ("ROUTER_ID", "zz"),
                     ("SIEM_NETWORK", "n et")):
        script = "\n".join(["%s=%s" % (k, ("'%s'" % bad if k == var else v)) for k, v in VARS.items()] +
                           [chk_vars_def(), "chk_vars"])
        out = subprocess.run(["bash", "-c", script], capture_output=True, text=True, timeout=20)
        assert out.returncode != 0, var
