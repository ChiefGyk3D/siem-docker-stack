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
    assert "mv -T /opt/siem-repo.next /opt/siem-repo" in step and "/opt/siem-repo-releases" in step
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


# ---- Daybreak rounds 2 and 3 on PR #176: run the documented blocks under bash with stubs ----

import os
import subprocess
import tarfile
import threading

VARS = {"REPO_DIR": "/tmp", "N8N_COMPOSE_DIR": "/tmp", "SIEM_NETWORK": "net",
        "ROUTER_ID": "aaaaaaaaaaaaaaaa", "HANDLER_ID": "bbbbbbbbbbbbbbbb"}
FUNCS = ("owner_chk_vars", "owner_recreate_n8n", "owner_router_chain", "owner_router_rollback")
ALL_FENCES = fences()


def defs_of(name, text=None):
    """The fences of `text` (default: the runbook) that DEFINE the function `name`."""
    return [f for f in (fences(text) if text else ALL_FENCES) if re.search(r"^" + name + r"\(\) \{$", f, flags=re.M)]


def def_fence(name):
    found = defs_of(name)
    assert len(found) == 1, "%s must be defined in exactly one fenced block, found %d" % (name, len(found))
    assert len(re.findall(r"^" + name + r"\(\) \{$", CODE, flags=re.M)) == 1
    return found[0]


def fence_position(fence):
    return RUNBOOK.index(fence)


def assert_under(fence, start, end):
    i = RUNBOOK.index(start)
    j = RUNBOOK.index(end, i)
    assert i < fence_position(fence) < j, "the block is not under the heading the owner is told to use: " + start


def test_round3_f5_each_function_has_exactly_one_definition_under_its_heading():
    assert_under(def_fence("owner_chk_vars"), "## Placeholders and conventions", "## Open questions")
    assert_under(def_fence("owner_recreate_n8n"), "### 6.0 ", "### 6.1 ")
    assert_under(def_fence("owner_router_chain"), "**3. Re-import the router", "**4. Post-import checks.")
    assert_under(def_fence("owner_router_rollback"), "**3. Re-import the router", "**4. Post-import checks.")
    for name, anchor in (("owner_chk_vars", "runbook-block-chk-vars-v3"), ("owner_recreate_n8n", "runbook-block-recreate-v3"),
                         ("owner_router_chain", "runbook-block-router-chain-v3"),
                         ("owner_router_rollback", "runbook-block-router-rollback-v3")):
        assert def_fence(name).count(': "%s"' % anchor) == 1
        assert "declare -f %s | grep -q '%s'" % (name, anchor) in CODE  # the call checks the installed definition


def test_round3_f5_a_duplicate_definition_is_detected():
    doc = "```\nowner_router_chain() {\n  true\n}\n```\ntext\n```\nowner_router_chain() {\n  docker restart n8n\n}\nowner_router_chain\n```\n"
    assert len(defs_of("owner_router_chain", doc)) == 2  # the detector the tests above rely on sees a redefinition
    assert len(defs_of("owner_router_chain")) == 1


STUBS = r'''
docker() {
  echo "docker $*" >> "$LOG"
  if [ -n "$FAIL" ] && [[ "$*" == *"$FAIL"* ]]; then return 7; fi
  if [ "$1" = cp ]; then case "$2" in n8n:*) printf '%s' "$STUBJSON" > "$3";; esac; fi
  case "$*" in
    *list:workflow*) echo "aaaaaaaaaaaaaaaa Router" ;;
  esac
  return 0
}
doppler() { echo "doppler" >> "$LOG"; [ "$FAIL" = doppler ] && return 7; return 0; }
sleep() { :; }
'''


def run_blocks(tmp_path, blocks, tail="", fail="", saved='{"nodes":[{},{}]}', stubjson='{"nodes":[{},{}]}', pre=""):
    """Run complete documented fences under bash with stubbed docker and doppler; return (status, stdout, log)."""
    home = tmp_path / "home"
    (home / "bin").mkdir(parents=True, exist_ok=True)
    stub = home / "bin" / "siem-run"
    stub.write_text("#!/bin/sh\n[ \"$FAIL\" = import ] && exit 7\necho import ok\nexit 0\n")
    stub.chmod(0o755)
    f = home / "router-before.json"
    f.write_text(saved)
    f.chmod(0o600)
    log = tmp_path / "log"
    log.write_text("")
    overrides = "\n".join("%s=%s" % kv for kv in VARS.items())
    script = "\n".join([STUBS, pre] + [blocks[0], overrides] + blocks[1:] + [tail, 'echo "STATUS=$?"'])
    env = dict(os.environ, HOME=str(home), LOG=str(log), FAIL=fail, STUBJSON=stubjson)
    out = subprocess.run(["bash", "-c", script], capture_output=True, text=True, env=env, timeout=60)
    m = re.findall(r"returned (\d+)", out.stdout) or re.findall(r"STATUS=(\d+)", out.stdout)
    return int(m[-1]), out.stdout + out.stderr, log.read_text()


CHK = def_fence("owner_chk_vars")
RECREATE = def_fence("owner_recreate_n8n")
CHAIN = def_fence("owner_router_chain")
ROLLBACK = def_fence("owner_router_rollback")
CALLS = [f for f in ALL_FENCES if "declare -f owner_recreate_n8n" in f and "owner_recreate_n8n() {" not in f]


def test_round2_f1_the_first_call_does_not_require_the_expiry_token():
    assert len(CALLS) == 2
    assert "EXPIRY" not in CALLS[0] and "EXPIRY_WATCH_ROUTER_TOKEN" in CALLS[1]
    assert "EXPIRY_WATCH_ROUTER_TOKEN" not in RECREATE.replace("EXPIRY_WATCH_ROUTER_SECRET", "")  # the list is an argument
    assert 'for V in $REQ_VARS' in RECREATE and '--preserve-env="$PRESERVE"' in RECREATE


@pytest.mark.parametrize("call", [0, 1])
def test_round2_f4_recreate_succeeds_with_either_call(tmp_path, call):
    status, out, _ = run_blocks(tmp_path, [CHK, RECREATE, CALLS[call]])
    assert status == 0 and "recreate exit code: 0" in out, out


@pytest.mark.parametrize("fail", ["doppler", "port n8n", "network inspect"])
def test_round2_f4_recreate_returns_the_real_status(tmp_path, fail):
    status, out, _ = run_blocks(tmp_path, [CHK, RECREATE, CALLS[1]], fail=fail)
    assert status == 7 and "recreate exit code: 7" in out and "RECOVERY:" in out, out


def test_round2_f6_a_missing_container_stops_before_recording_or_recreating(tmp_path):
    status, out, log = run_blocks(tmp_path, [CHK, RECREATE, CALLS[0]], fail="exec n8n true")
    assert status == 1 and "STOP:" in out and "recreate exit code: 1" in out
    assert "doppler" not in log
    assert not (tmp_path / "home" / "n8n-env-before.txt").exists()


def test_round2_f4_the_before_file_is_private(tmp_path):
    run_blocks(tmp_path, [CHK, RECREATE, CALLS[0]])
    before = tmp_path / "home" / "n8n-env-before.txt"
    assert before.exists() and (before.stat().st_mode & 0o077) == 0


@pytest.mark.parametrize("fail,stage", [("import", "stage 1 of 3"), ("publish:workflow", "stage 2 of 3"),
                                        ("restart n8n", "stage 3 of 3")])
def test_round2_f5_router_chain_propagates_its_status(tmp_path, fail, stage):
    status, out, log = run_blocks(tmp_path, [CHK, CHAIN], fail=fail)
    assert status == 7 and "FAILED " + stage in out and "chain exit code: 7" in out
    if fail == "import":
        assert "publish:workflow" not in log  # a later stage never runs after a failure


def test_round2_f5_router_chain_success(tmp_path):
    status, out, log = run_blocks(tmp_path, [CHK, CHAIN])
    assert status == 0 and "chain exit code: 0" in out


@pytest.mark.parametrize("fail,label", [("cp ", "copy into the container"), ("import:workflow", "import"),
                                        ("publish:workflow", "publish"), ("restart n8n", "restart")])
def test_round2_f3_rollback_names_the_failed_step_and_exits_nonzero(tmp_path, fail, label):
    status, out, log = run_blocks(tmp_path, [CHK, ROLLBACK], fail=fail)
    assert status == 7, out
    assert "ROLLBACK FAILED at: " + label in out and "rollback exit code: 7" in out
    assert "rm -f /tmp/router-before.json" in log  # the container-side temp file is removed on every path
    assert "rollback verified" not in out


def test_round2_f3_rollback_verifies_exists_active_and_node_count(tmp_path):
    status, out, log = run_blocks(tmp_path, [CHK, ROLLBACK])
    assert status == 0 and "rollback verified" in out and "2 nodes" in out
    assert "--active=true" in log and "export:workflow" in log


def test_round3_f2_a_failing_or_mismatching_live_count_never_verifies(tmp_path):
    # the live export cannot be copied out: the count command fails and the rollback must say so
    status, out, _ = run_blocks(tmp_path, [CHK, ROLLBACK], fail="cp n8n:/tmp/router-after.json")
    assert status != 0 and "verify node count" in out and "rollback verified" not in out
    # a different live count
    status, out, _ = run_blocks(tmp_path, [CHK, ROLLBACK], stubjson='{"nodes":[{}]}')
    assert status != 0 and "verify node count" in out and "rollback verified" not in out
    # garbage or an empty document where the live export should be
    for bad in ("", "not json", '{"nodes":[]}'):
        status, out, _ = run_blocks(tmp_path, [CHK, ROLLBACK], stubjson=bad)
        assert status != 0 and "rollback verified" not in out, bad


@pytest.mark.parametrize("saved", ['{"nodes":[]}', "not json", "[]", '{"nodes":{}}'])
def test_round3_f2_an_unusable_saved_copy_stops_before_anything_is_touched(tmp_path, saved):
    status, out, log = run_blocks(tmp_path, [CHK, ROLLBACK], saved=saved)
    assert status == 1 and "ROLLBACK STOP" in out and "rollback exit code: 1" in out
    assert "import:workflow" not in log and "docker cp" not in log


def test_round2_f3_no_failure_masking_in_the_documented_blocks():
    for line in CODE_LINES:
        # an `&&` chain followed by `|| echo "FAILED..."` returns 0; the status must be captured in R first
        assert not re.search(r"&&[^|;]*\|\|\s*echo\s+\"(ROLLBACK|RECOVERY|FAILED)", line), line


@pytest.mark.parametrize("bad", ["", "/tmp/a b", "/tmp;x", "/tmp\n/also", "/tmp\r", "relative", "/tmp/$(x)"])
def test_round3_f3_chk_vars_rejects_bad_paths(tmp_path, bad):
    for var in ("REPO_DIR", "N8N_COMPOSE_DIR"):
        script = "\n".join([CHK, 'REPO_DIR=/opt/x; N8N_COMPOSE_DIR=/opt/y', var + '="$BAD"', "owner_chk_vars", 'echo "RC=$?"'])
        out = subprocess.run(["bash", "-c", script], capture_output=True, text=True, env=dict(os.environ, BAD=bad), timeout=20)
        assert "RC=1" in out.stdout, (var, bad, out.stdout)


@pytest.mark.parametrize("var,bad", [("ROUTER_ID", "zz"), ("ROUTER_ID", ""), ("HANDLER_ID", "aaaaaaaaaaaaaaaa\nbbbbbbbbbbbbbbbb"),
                                     ("HANDLER_ID", "AAAAAAAAAAAAAAAA"), ("SIEM_NETWORK", "n et"),
                                     ("SIEM_NETWORK", "good\nalso-good"), ("SIEM_NETWORK", ""), ("SIEM_NETWORK", "a\rb")])
def test_round3_f3_chk_vars_rejects_bad_ids_and_networks(var, bad):
    script = "\n".join([CHK, 'REPO_DIR=/opt/x; N8N_COMPOSE_DIR=/opt/y', var + '="$BAD"', "owner_chk_vars", 'echo "RC=$?"'])
    out = subprocess.run(["bash", "-c", script], capture_output=True, text=True, env=dict(os.environ, BAD=bad), timeout=20)
    assert "RC=1" in out.stdout, (var, bad, out.stdout)


def test_round3_f3_chk_vars_accepts_the_documented_values():
    out = subprocess.run(["bash", "-c", CHK + '\necho "RC=$?"'], capture_output=True, text=True, timeout=20)
    assert "variables ok" in out.stdout and "RC=0" in out.stdout


@pytest.mark.parametrize("fence_name", ["owner_chk_vars", "owner_recreate_n8n", "owner_router_chain", "owner_router_rollback"])
def test_round3_f4_a_readonly_older_function_is_detected_not_run(tmp_path, fence_name):
    old = '%s() { echo OLD-CODE-RAN; return 0; }; readonly -f %s' % (fence_name, fence_name)
    blocks = {"owner_chk_vars": [CHK], "owner_recreate_n8n": [CHK, RECREATE, CALLS[0]],
              "owner_router_chain": [CHK, CHAIN], "owner_router_rollback": [CHK, ROLLBACK]}[fence_name]
    home = tmp_path / "h"
    home.mkdir()
    script = "\n".join([STUBS, old] + blocks + ['echo "STATUS=$?"'])
    env = dict(os.environ, HOME=str(home), LOG=str(tmp_path / "log"), FAIL="", STUBJSON="{}")
    out = subprocess.run(["bash", "-c", script], capture_output=True, text=True, env=env, timeout=30)
    assert "OLD-CODE-RAN" not in out.stdout, out.stdout
    assert "STALE FUNCTION" in out.stdout, out.stdout


def test_round2_f7_the_session_blocks_use_quoted_variables_not_placeholders():
    for body in (RECREATE, CHAIN, ROLLBACK):
        bare = re.findall(r"(?<![$\w])(REPO_DIR|N8N_COMPOSE_DIR|SIEM_NETWORK|ROUTER_ID|HANDLER_ID)(?![\w])", body)
        bare = [b for b in bare if not re.search(r"\b" + b + "=", body)]
        assert not bare, bare
        for m in re.finditer(r"\$(REPO_DIR|N8N_COMPOSE_DIR|SIEM_NETWORK|ROUTER_ID|HANDLER_ID)\b", body):
            line = body[body.rfind("\n", 0, m.start()) + 1:body.find("\n", m.end())]
            at = line.index("$" + m.group(1))
            before, after = line[:at], line[at + len(m.group(0)):]
            # the expansion is the whole of a double-quoted word (optionally after a "^" anchor), not bare shell syntax
            assert (before.endswith('"') or before.endswith('"^')) and after.startswith('"'), line
    assert "variables ok" in CODE


# ---- the repo swap (Daybreak round 2 finding 2 and round 3 finding 1): run it for real, under a temp root ----

SWAP = next(l for l in CODE_LINES if "sudo mv -T /opt/siem-repo.next /opt/siem-repo" in l and l.startswith("ssh "))
SWAP_BODY = SWAP.split("LOGGING_BOX '", 1)[1].rsplit("'", 1)[0]
SUDO = r'''
sudo() { if [ -n "$FAIL" ] && [[ "$*" == *"$FAIL"* ]]; then return 9; fi; "$@"; }
install() { local a=(); local skip=0; for x in "$@"; do if [ $skip -eq 1 ]; then skip=0; continue; fi; case "$x" in -o|-g) skip=1;; *) a+=("$x");; esac; done; command install "${a[@]}"; }
'''


def make_archive(path, symlink=False):
    import shutil
    src = path.parent / "src"
    if src.exists():
        shutil.rmtree(src)
    root = src / "siem-docker-stack"
    (root / "scripts" / "live-deploy").mkdir(parents=True)
    (root / "n8n").mkdir()
    (root / "scripts" / "live-deploy" / "siem-run").write_text("#!/bin/sh\n")
    (root / "n8n" / "grafana-alert-router.json").write_text("{}")
    if symlink:
        os.symlink("/etc", root / "n8n" / "link")
    for p in [root, *root.rglob("*")]:
        if not p.is_symlink():
            os.chmod(p, 0o775 if p.is_dir() else 0o664)
    with tarfile.open(path, "w:gz") as tar:
        tar.add(root, arcname="siem-docker-stack")
    import hashlib
    return hashlib.sha256(path.read_bytes()).hexdigest()


def run_swap(tmp_path, fail="", sha=None, symlink=False, watch=False):
    home = tmp_path / "home"
    home.mkdir(exist_ok=True)
    digest = make_archive(home / "siem-repo.tar.gz", symlink=symlink)
    root = tmp_path / "opt"
    root.mkdir(exist_ok=True)
    body = SWAP_BODY.replace("EXPECTED_SHA256", sha or digest).replace("/opt/siem-repo", str(root / "siem-repo"))
    seen_missing = []
    stop = threading.Event()
    link = root / "siem-repo"

    def poll():
        was = os.path.lexists(link)
        while not stop.is_set():
            now = os.path.lexists(link)
            if was and not now:
                seen_missing.append(True)
            was = was or now

    t = threading.Thread(target=poll)
    if watch:
        t.start()
    env = dict(os.environ, HOME=str(home), FAIL=fail)
    out = subprocess.run(["bash", "-c", SUDO + body], capture_output=True, text=True, env=env, timeout=60)
    stop.set()
    if watch:
        t.join()
    return out, root, seen_missing


def live_target(root):
    link = root / "siem-repo"
    return os.readlink(link) if link.is_symlink() else None


def test_round3_f1_first_install_and_update_flip_one_symlink_and_the_path_never_disappears(tmp_path):
    out, root, _ = run_swap(tmp_path)
    assert out.returncode == 0, out.stdout + out.stderr
    first = live_target(root)
    assert first and first.startswith(str(root / "siem-repo-releases")) and "LIVE: " + first in out.stdout
    assert (root / "siem-repo" / "scripts" / "live-deploy" / "siem-run").is_file()
    assert os.stat(root / "siem-repo" / "scripts").st_mode & 0o022 == 0  # group/other write removed
    os.utime(first, None)
    # a second release; poll the live path while the flip happens
    import time
    time.sleep(1.1)  # the release name is a UTC timestamp with one second resolution
    out2, root2, missing = run_swap(tmp_path, watch=True)
    assert out2.returncode == 0, out2.stdout + out2.stderr
    assert live_target(root) != first and "previous: " + first in out2.stdout
    assert not missing, "the live path was observed missing during the flip"


@pytest.mark.parametrize("fail", ["mv -T", "ln -s", "tar -xzf", "chmod -R", "install -d"])
def test_round3_f1_a_failure_at_any_step_leaves_the_old_tree_live(tmp_path, fail):
    out, root, _ = run_swap(tmp_path)
    assert out.returncode == 0
    old = live_target(root)
    import time
    time.sleep(1.1)
    out, root, _ = run_swap(tmp_path, fail=fail)
    assert out.returncode != 0, fail
    assert live_target(root) == old, (fail, out.stdout + out.stderr)
    assert (root / "siem-repo" / "scripts" / "live-deploy" / "siem-run").is_file()
    if fail in ("tar -xzf", "chmod -R"):
        releases = sorted(p.name for p in (root / "siem-repo-releases").iterdir())
        assert len(releases) == 1, releases  # only the failed new release folder was removed, never the old one
        assert "STAGING FAILED" in out.stdout


def test_round3_f1_a_failure_on_first_install_leaves_no_link(tmp_path):
    out, root, _ = run_swap(tmp_path, fail="mv -T")
    assert out.returncode != 0 and live_target(root) is None


def test_round3_f1_a_wrong_checksum_or_a_symlink_in_the_archive_changes_nothing(tmp_path):
    out, root, _ = run_swap(tmp_path, sha="0" * 64)
    assert out.returncode != 0 and live_target(root) is None
    assert not (root / "siem-repo-releases").exists()
    out, root, _ = run_swap(tmp_path, symlink=True)
    assert out.returncode != 0 and live_target(root) is None and "STAGING FAILED" in out.stdout


def test_round3_f1_a_real_directory_at_the_live_name_is_refused(tmp_path):
    root = tmp_path / "opt"
    (root / "siem-repo").mkdir(parents=True)
    out, root, _ = run_swap(tmp_path)
    assert out.returncode != 0 and "real directory" in out.stdout and (root / "siem-repo").is_dir()
    assert not (root / "siem-repo").is_symlink()


def test_round3_f1_the_expected_checksum_comes_from_the_workstation():
    step = " ".join(section("## Step 0a.", "## Step 0b.").split())
    assert "ON YOUR WORKSTATION" in step and "never from the box" in step
    assert "siem-repo.sha256" not in step
    assert "rm -rf /opt/siem-repo " not in step and "mv /opt/siem-repo.new" not in step
