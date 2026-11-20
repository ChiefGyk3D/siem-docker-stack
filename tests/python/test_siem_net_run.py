"""scripts/siem-net-run keeps the read-only service token out of argv and out of every environment but doppler's.

The wrapper reads a read-only token for the dev_network config from a mode 600 file in a private
config folder and hands it to `doppler run` through `exec`. Each test runs a copy of the script in a
box where doppler is a recording fake and stat and id are recording wrappers (argument list and
environment read from /proc). A sentinel token must reach the fake doppler as the DOPPLER_TOKEN
variable only: never in an argument list, never in the environment of another command, never in the
wrapper's own output, and never in a shell trace. The fake doppler copies its environment into its
child as the real one does, so the child lacking the token proves the wrapper's checker removed it.
Not claimed: the doppler process (the child's parent) still holds the token, and code running as the
same user can read the token file, so this is not a sandbox for hostile code.

What is NOT verified here: the real Doppler CLI (no network, no real token is used) and the owner
and mode of a token file on a real box; the owner check is exercised with a fake `id`.
"""
import os
import re
import shutil
import subprocess

import pytest

from conftest import REPO_ROOT

SCRIPT = REPO_ROOT / "scripts" / "siem-net-run"
PATH_LINE = "PATH=/usr/local/sbin:"  # start of the fixed PATH assignment
SENTINEL = "dp.st.Sentinel-Tok-5c1e"
PROBED = ("stat", "id")
TABLE_START = "PERMITTED_NAMES=("  # the fixed table of names the wrapper will ever inject

FAKE_DOPPLER = """#!/bin/bash
printf '%s\\n' "$$" > '@REC@/doppler-pid'
for a in "$@"; do printf '%s\\n' "$a"; done > '@REC@/doppler-argv'
cat /proc/$$/environ > '@REC@/doppler-environ'
[ -n "${FAKE_EXIT:-}" ] && exit "$FAKE_EXIT"
# Emulate `doppler run`: inject the config's secrets (hostile names included) into the child,
# keeping only the names given to --only-secrets, as the real CLI does.
only=
args=("$@")
for a in "${args[@]}"; do case "$a" in --only-secrets=*) only=",${a#--only-secrets=}," ;; esac; done
child=()
seen=0
for a in "${args[@]}"; do
    if [ "$seen" = 1 ]; then child+=("$a"); fi
    [ "$a" = -- ] && seen=1
done
inject=()
for kv in LD_PRELOAD=/evil.so BASH_ENV=/evil.sh ENV=/evil.sh PATH=/evil DOCKER_HOST=tcp://evil:1 PYTHONPATH=/evil GOOD_ONE=one GOOD_TWO=two NOT_ASKED=nope; do
    name=${kv%%=*}
    case ",${FAKE_OMIT:-}," in *",$name,"*) continue ;; esac  # a name Doppler does not hold
    if [ -z "$only" ] || [[ "$only" == *",$name,"* ]]; then inject+=("$kv"); fi
done
[ ${#child[@]} -gt 0 ] && exec env "${inject[@]}" "${child[@]}"
exit 0
"""
PROBE = """#!/bin/sh
id=$$
for a in "$@"; do printf '%s\\n' "$a"; done > '@REC@/@TOOL@-'$id'-argv'
/usr/bin/cat /proc/$$/environ > '@REC@/@TOOL@-'$id'-environ'
exec @REAL@ "$@"
"""
FAKE_ID = """#!/bin/sh
echo 4242
"""


def _exe(path, text):
    path.write_text(text, encoding="utf-8")
    path.chmod(0o755)


class Box:
    def __init__(self, tmp_path):
        self.tmp = tmp_path
        self.rec = tmp_path / "rec"
        self.rec.mkdir()
        self.bindir = tmp_path / "probe-bin"
        self.bindir.mkdir()
        _exe(self.bindir / "doppler", FAKE_DOPPLER.replace("@REC@", str(self.rec)))
        for tool in PROBED:
            real = shutil.which(tool, path="/usr/bin:/bin")
            _exe(self.bindir / tool, PROBE.replace("@REC@", str(self.rec)).replace("@TOOL@", tool)
                 .replace("@REAL@", real))
        text = SCRIPT.read_text(encoding="utf-8")
        assert PATH_LINE in text
        text = text.replace(PATH_LINE, f"PATH={self.bindir}:/usr/local/sbin:", 1)
        assert TABLE_START in text
        text = text.replace(TABLE_START, TABLE_START + "GOOD_ONE GOOD_TWO ", 1)  # test-only names, in the copy only
        self.script = tmp_path / "siem-net-run"
        _exe(self.script, text)
        self.home = tmp_path / "home"
        self.home.mkdir()
        self.cfg = self.home / ".config" / "doppler-siem-net"
        self.cfg.mkdir(parents=True)
        self.cfg.chmod(0o700)
        self.token = self.cfg / "token"

    def put_token(self, text=SENTINEL + "\n", mode=0o600):
        self.token.write_text(text, encoding="utf-8")
        self.token.chmod(mode)

    def run(self, args=("echo", "hi"), extra_env=None, require="GOOD_ONE,GOOD_TWO", optional=None, raw=None):
        env = {"PATH": "/usr/bin:/bin", "HOME": str(self.home), **(extra_env or {})}
        if raw is None:
            raw = []
            if require is not None:
                raw += ["--require", require]
            if optional is not None:
                raw += ["--optional", optional]
            raw += ["--", *args]
        cmd = [str(self.script), *raw]
        return subprocess.Popen(cmd, env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)

    def finish(self, proc):
        out, err = proc.communicate(timeout=30)
        return proc.returncode, out, err

    def recorded(self, name):
        return sorted(self.rec.glob(name))

    def everything_recorded(self):
        return "".join(p.read_text(errors="replace") for p in self.rec.iterdir() if p.is_file())


@pytest.fixture
def box(tmp_path):
    b = Box(tmp_path)
    b.put_token()
    return b


def _env_map(path):
    pairs = path.read_bytes().split(b"\0")
    return dict(p.decode(errors="replace").split("=", 1) for p in pairs if b"=" in p)


# ---- the exec chain ----------------------------------------------------------------

def test_doppler_gets_the_documented_arguments_and_the_token_in_its_environment(box):
    proc = box.run(("echo", "-n", "x.py", "--flag"))
    code, out, err = box.finish(proc)
    assert code == 0, err
    argv = (box.rec / "doppler-argv").read_text().splitlines()
    assert argv[:7] == ["run", "--config-dir", str(box.cfg), "--no-check-version", "--no-fallback",
                        "--no-exit-on-missing-only-secrets", "--only-secrets=GOOD_ONE,GOOD_TWO"]
    # the command runs behind a small checker that fails closed when a required name is empty
    assert argv[7:10] == ["--", "sh", "-c"] and argv[11:] == ["siem-net-run", "GOOD_ONE,GOOD_TWO", "echo", "-n", "x.py", "--flag"]
    assert "--fallback-readonly" not in argv  # a stale snapshot on disk is never read (Daybreak round 1, finding 2)
    env = _env_map(box.rec / "doppler-environ")
    assert env["DOPPLER_TOKEN"] == SENTINEL  # trailing newline of the file is stripped


def test_the_wrapper_process_becomes_doppler_through_exec(box):
    proc = box.run()
    box.finish(proc)
    assert int((box.rec / "doppler-pid").read_text()) == proc.pid


def test_the_exit_status_of_the_command_is_the_exit_status_of_the_wrapper(box):
    proc = box.run(extra_env={"FAKE_EXIT": "7"})
    code, _, _ = box.finish(proc)
    assert code == 7


# ---- the token never leaks ----------------------------------------------------------

def test_the_token_is_not_in_any_argument_list_or_any_other_environment(box):
    proc = box.run()
    code, out, err = box.finish(proc)
    assert code == 0
    assert SENTINEL not in out + err
    for p in box.rec.iterdir():
        text = p.read_text(errors="replace")
        if p.name == "doppler-environ":
            assert text.count(SENTINEL) == 1  # once, as the value of DOPPLER_TOKEN
        else:
            assert SENTINEL not in text, p.name
    assert not box.recorded("doppler-argv") or SENTINEL not in (box.rec / "doppler-argv").read_text()
    assert box.recorded("stat-*-argv") and box.recorded("id-*-argv")  # the probes did run before the read


def test_an_inherited_token_variable_is_replaced_not_passed_on(box):
    proc = box.run(extra_env={"DOPPLER_TOKEN": "inherited-value"})
    box.finish(proc)
    assert _env_map(box.rec / "doppler-environ")["DOPPLER_TOKEN"] == SENTINEL
    assert "inherited-value" not in box.everything_recorded()


def test_a_shell_trace_requested_from_the_environment_does_not_print_the_token(box):
    proc = box.run(extra_env={"SHELLOPTS": "xtrace", "PS4": "+TRACE "})
    code, out, err = box.finish(proc)
    assert SENTINEL not in out + err
    assert "+TRACE" not in err


def test_startup_files_and_search_variables_are_not_honored_or_passed_on(box, tmp_path):
    marker = tmp_path / "bash-env-ran"
    hook = tmp_path / "hook.sh"
    hook.write_text(f"touch '{marker}'\n", encoding="utf-8")
    proc = box.run(extra_env={"BASH_ENV": str(hook), "ENV": str(hook), "CDPATH": "/tmp",
                              "GLOBIGNORE": "*", "PS4": "+X "})
    code, _, err = box.finish(proc)
    assert code == 0, err
    assert not marker.exists()
    env = _env_map(box.rec / "doppler-environ")
    for name in ("BASH_ENV", "ENV", "CDPATH", "GLOBIGNORE", "PS4"):
        assert name not in env, name
    assert env["PATH"].startswith(str(box.bindir))  # the fixed PATH, not the caller's


# ---- refusals -----------------------------------------------------------------------

def _refused(box, proc, fragment=None):
    code, out, err = box.finish(proc)
    assert code == 2, (code, out, err)
    assert not box.recorded("doppler-*"), "doppler must not run on a refusal"
    assert SENTINEL not in out + err
    if fragment:
        assert fragment in err
    assert err.startswith("siem-net-run:")


def test_a_missing_token_file_is_refused(box):
    box.token.unlink()
    _refused(box, box.run(), "missing")


def test_a_symlinked_token_file_is_refused(box, tmp_path):
    real = tmp_path / "elsewhere"
    real.write_text(SENTINEL, encoding="utf-8")
    real.chmod(0o600)
    box.token.unlink()
    box.token.symlink_to(real)
    _refused(box, box.run(), "symlink")


@pytest.mark.parametrize("mode", [0o640, 0o604, 0o644, 0o660, 0o666, 0o620, 0o602])
def test_a_group_or_world_accessible_token_file_is_refused(box, mode):
    box.put_token(mode=mode)
    _refused(box, box.run(), "mode")


def test_a_read_only_owner_mode_is_accepted(box):
    box.put_token(mode=0o400)
    code, _, err = box.finish(box.run())
    assert code == 0, err


def test_a_directory_in_place_of_the_token_is_refused(box):
    box.token.unlink()
    box.token.mkdir()
    _refused(box, box.run())


def test_a_token_file_owned_by_someone_else_is_refused(box):
    _exe(box.bindir / "id", FAKE_ID)  # reports a uid that does not own the file
    _refused(box, box.run(), "owner")


def test_an_empty_token_file_is_refused(box):
    box.put_token(text="\n")
    _refused(box, box.run(), "empty")


@pytest.mark.parametrize("mode", [0o770, 0o707, 0o775, 0o757, 0o777])
def test_a_config_folder_others_can_write_is_refused(box, mode):
    box.cfg.chmod(mode)
    try:
        _refused(box, box.run(), "folder")
    finally:
        box.cfg.chmod(0o700)


def test_a_symlinked_config_folder_is_refused(box, tmp_path):
    real = tmp_path / "real-cfg"
    box.cfg.rename(real)
    box.cfg.symlink_to(real)
    _refused(box, box.run(), "folder")


def test_no_command_is_a_usage_error_and_reads_nothing(box):
    proc = box.run(raw=[])
    code, out, err = box.finish(proc)
    assert code == 64 and "usage" in err
    assert not box.recorded("doppler-*")
    assert not box.recorded("stat-*-argv")


@pytest.mark.parametrize("raw", [
    ["echo", "hi"],                         # no names at all
    ["--", "echo", "hi"],                   # no names at all
    ["--require", "", "--", "echo"],        # empty list
    ["--require"],                          # option without a value
    ["--require", "GOOD_ONE"],              # no separator and no command
    ["--require", "GOOD_ONE", "echo"],      # no separator
    ["--require", "GOOD_ONE", "--"],        # no command
    ["--optional", "GOOD_ONE", "--"],       # no command
    ["--require", "GOOD_ONE,,GOOD_TWO", "--", "echo"],
    ["--require", ",GOOD_ONE", "--", "echo"],
    ["--require", "GOOD_ONE,", "--", "echo"],
    ["--require", "good one", "--", "echo"],
    ["--require", "good_one", "--", "echo"],  # the second check: upper case only
    ["--require", "1BAD", "--", "echo"],
    ["--require", "A-B", "--", "echo"],
    ["--require", "A=B", "--", "echo"],
    ["--require", "GOOD_ONE", "--require", "GOOD_TWO", "--", "echo"],  # a flag twice
    ["--require", "GOOD_ONE", "--optional", "GOOD_ONE", "--", "echo"],  # a name in both lists
    ["--only", "GOOD_ONE", "--", "echo"],   # the old spelling is gone
])
def test_a_missing_or_malformed_allowlist_is_a_usage_error_and_reads_nothing(box, raw):
    code, out, err = box.finish(box.run(raw=raw))
    assert code == 64, (code, err)
    assert not box.recorded("doppler-*") and not box.recorded("stat-*-argv")


HOSTILE = ["LD_PRELOAD", "LD_LIBRARY_PATH", "LD_AUDIT", "BASH_ENV", "ENV", "PATH", "PYTHONPATH", "PYTHONHOME",
           "PYTHONSTARTUP", "DOCKER_HOST", "DOCKER_CONFIG", "COMPOSE_FILE", "SHELLOPTS", "BASHOPTS", "IFS", "HOME",
           "DOPPLER_TOKEN", "DOPPLER_CONFIG", "CDPATH", "GLOBIGNORE", "PS4", "NODE_OPTIONS", "PERL5LIB", "RUBYOPT",
           "TMPDIR", "SHELL", "USER", "SUDO_ASKPASS", "SUDO_EDITOR", "GCONV_PATH", "LOCPATH", "NLSPATH", "HOSTALIASES",
           "MALLOC_CHECK_", "GLIBC_TUNABLES", "JAVA_TOOL_OPTIONS", "LANG", "LC_ALL", "XDG_CONFIG_HOME",
           # Daybreak round 2: names a deny list missed
           "ZDOTDIR", "RUSTC_WRAPPER", "RUSTC_WORKSPACE_WRAPPER", "INPUTRC", "BROWSER", "CARGO_HOME", "GOFLAGS",
           "NPM_CONFIG_USERCONFIG", "VIMINIT", "GREP_OPTIONS", "LESSOPEN", "MANPAGER", "CC", "CFLAGS", "HTTP_PROXY",
           "https_proxy", "SSL_CERT_FILE", "KUBECONFIG", "AWS_PROFILE", "GIT_SSH_COMMAND", "OTHER_NAME"]


@pytest.mark.parametrize("flag", ["--require", "--optional"])
@pytest.mark.parametrize("name", HOSTILE)
def test_a_name_that_is_not_in_the_fixed_table_is_refused(box, name, flag):
    raw = [flag, name, "--", "echo", "hi"]
    code, out, err = box.finish(box.run(raw=raw))
    assert code in (2, 64), (code, err)  # not in the table (2), or not even a plain upper case name (64)
    assert not box.recorded("doppler-*")


@pytest.mark.parametrize("name", [n for n in HOSTILE if re.fullmatch(r"[A-Z][A-Z0-9_]*", n)])
def test_a_well_formed_name_outside_the_table_is_refused_with_exit_2(box, name):
    code, out, err = box.finish(box.run(raw=["--require", name, "--", "echo"]))
    assert code == 2 and "not permitted" in err and name in err, (code, err)


def _table():
    text = SCRIPT.read_text(encoding="utf-8")
    start = text.index(TABLE_START) + len(TABLE_START)
    return text[start:text.index(")", start)].split()


def test_the_table_holds_exactly_the_names_the_runbook_passes_and_all_are_plain():
    names = _table()
    assert names == sorted(names) and len(names) == len(set(names))
    assert all(re.fullmatch(r"[A-Z][A-Z0-9_]*", n) for n in names)
    compose = (REPO_ROOT / "docker" / "docker-compose.yml").read_text(encoding="utf-8")
    block = re.search(r"^  grafana:\n(.*?)(?=^  [a-z0-9_-]+:\n)", compose, flags=re.S | re.M).group(1)
    grafana = set(re.findall(r"\$\{([A-Za-z_][A-Za-z0-9_]*)", block)) | set(re.findall(r"^\s+- ([A-Z][A-Z0-9_]*)\s*$", block, flags=re.M))
    manual = {"DISCORD_FAILURE_WEBHOOK_URL", "GF_SMTP_ENABLED", "GF_SMTP_FROM_ADDRESS", "GF_SMTP_HOST", "GF_SMTP_PASSWORD",
              "GF_SMTP_STARTTLS_POLICY", "GF_SMTP_USER", "P1_EMAIL_TO"}
    n8n = {"HEARTBEAT_PING_URL", "HEARTBEAT_KIND", "EXPIRY_WATCH_ROUTER_TOKEN"}
    assert set(names) == grafana | manual | n8n, set(names) ^ (grafana | manual | n8n)


def test_no_dangerous_name_is_in_the_table():
    dangerous = {n for n in HOSTILE if n != "OTHER_NAME"}
    assert not dangerous & set(_table())
    for name in _table():
        assert not re.match(r"(LD_|BASH|DOCKER_|COMPOSE_|DOPPLER_|PYTHON|SUDO_|RUST|CARGO|NODE_|XDG_|LC_)", name), name
        assert name not in ("PATH", "HOME", "ENV", "IFS", "SHELL", "ZDOTDIR", "INPUTRC", "BROWSER")


def test_a_required_name_missing_from_the_config_fails_closed_even_if_the_caller_has_it(box):
    marker = box.tmp / "ran"
    probe = box.tmp / "child2.sh"
    _exe(probe, "#!/bin/sh\ntouch '" + str(marker) + "'\n")
    proc = box.run(args=(str(probe),), extra_env={"GOOD_TWO": "caller-value", "FAKE_OMIT": "GOOD_TWO"})
    code, out, err = box.finish(proc)
    assert code == 3 and "GOOD_TWO" in err and "missing" in err, (code, err)
    assert not marker.exists()
    assert "caller-value" not in out + err


def test_an_optional_name_missing_from_the_config_is_absent_not_the_callers_copy(box):
    probe = box.tmp / "child3.sh"
    _exe(probe, "#!/bin/sh\n/usr/bin/cat /proc/$$/environ > '" + str(box.rec) + "/child-environ'\n")
    proc = box.run(args=(str(probe),), require="GOOD_ONE", optional="GOOD_TWO",
                   extra_env={"GOOD_TWO": "caller-value", "FAKE_OMIT": "GOOD_TWO"})
    code, out, err = box.finish(proc)
    assert code == 0, err
    env = _env_map(box.rec / "child-environ")
    assert env["GOOD_ONE"] == "one" and "GOOD_TWO" not in env
    assert "DOPPLER_TOKEN" not in env


def test_a_required_name_that_doppler_returns_is_passed_and_the_callers_copy_is_replaced(box):
    probe = box.tmp / "child4.sh"
    _exe(probe, "#!/bin/sh\n/usr/bin/cat /proc/$$/environ > '" + str(box.rec) + "/child-environ'\n")
    code, _, err = box.finish(box.run(args=(str(probe),), extra_env={"GOOD_ONE": "caller-value"}))
    assert code == 0, err
    assert _env_map(box.rec / "child-environ")["GOOD_ONE"] == "one"


def test_the_requested_names_are_unset_in_the_wrapper_before_doppler_starts(box):
    box.finish(box.run(extra_env={"GOOD_ONE": "caller-value", "GOOD_TWO": "caller-value"}))
    env = _env_map(box.rec / "doppler-environ")
    assert "GOOD_ONE" not in env and "GOOD_TWO" not in env


def test_hostile_secrets_in_the_config_are_not_passed_to_the_command(box):
    # the fake doppler injects LD_PRELOAD, BASH_ENV, ENV, PATH, DOCKER_HOST and PYTHONPATH like a poisoned config
    probe = box.tmp / "child.sh"
    _exe(probe, "#!/bin/sh\n/usr/bin/cat /proc/$$/environ > '" + str(box.rec) + "/child-environ'\n")
    code, _, err = box.finish(box.run(args=(str(probe),)))
    assert code == 0, err
    env = _env_map(box.rec / "child-environ")
    assert env["GOOD_ONE"] == "one" and env["GOOD_TWO"] == "two"
    for bad in ("LD_PRELOAD", "BASH_ENV", "ENV", "DOCKER_HOST", "PYTHONPATH", "NOT_ASKED"):
        assert bad not in env, bad
    assert env["PATH"] != "/evil" and "/evil" not in env["PATH"]
    assert "DOPPLER_TOKEN" not in env and SENTINEL not in (box.rec / "child-environ").read_text(errors="replace")


def test_the_fake_doppler_leaks_the_token_to_its_child_like_the_real_one_and_the_wrapper_scrubs_it(box):
    # Real doppler (v3.77.1) copies its own environment, DOPPLER_TOKEN included, into the child. The fake does
    # too (proved here by running the child WITHOUT the wrapper's checker), so only the scrub keeps it out.
    fake = box.bindir / "doppler"
    probe = box.tmp / "leak.sh"
    _exe(probe, "#!/bin/sh\n/usr/bin/cat /proc/$$/environ > '" + str(box.rec) + "/leak-environ'\n")
    env = {"PATH": "/usr/bin:/bin", "DOPPLER_TOKEN": SENTINEL}
    subprocess.run([str(fake), "run", "--only-secrets=GOOD_ONE", "--", str(probe)], env=env, check=True)
    assert _env_map(box.rec / "leak-environ")["DOPPLER_TOKEN"] == SENTINEL  # the model leaks
    code, _, err = box.finish(box.run(args=("sh", "-c", 'test -z "${DOPPLER_TOKEN+x}" && echo scrubbed')))
    assert code == 0, err


def test_the_command_never_sees_the_token_even_when_a_required_check_fails(box):
    code, out, err = box.finish(box.run(args=("echo", "hi"), extra_env={"FAKE_OMIT": "GOOD_TWO"}))
    assert code == 3 and SENTINEL not in out + err


def test_the_checker_removes_the_token_before_it_starts_any_other_program():
    text = SCRIPT.read_text(encoding="utf-8")
    check = next(l for l in text.splitlines() if l.startswith("CHECK="))
    assert check.startswith("CHECK='unset DOPPLER_TOKEN; ")  # a shell builtin, ahead of printenv and the command
    assert check.index("unset DOPPLER_TOKEN") < check.index("printenv") < check.index('exec "$@"')


def test_other_doppler_variables_of_the_caller_are_removed_not_passed_on(box):
    proc = box.run(extra_env={"DOPPLER_CONFIG": "prd", "DOPPLER_PROJECT": "x", "DOPPLER_API_HOST": "http://evil"})
    box.finish(proc)
    env = _env_map(box.rec / "doppler-environ")
    assert sorted(k for k in env if k.startswith("DOPPLER_")) == ["DOPPLER_TOKEN"]


def test_the_wrapper_does_not_pass_no_read_env_because_that_hides_the_token_variable():
    # VERIFIED 2026-11-20 with the installed CLI: --no-read-env makes it ignore DOPPLER_TOKEN ("you must
    # provide a token"), and the token may not go on the command line, so the wrapper clears DOPPLER_* itself.
    exec_line = next(l for l in SCRIPT.read_text(encoding="utf-8").splitlines() if "exec doppler run" in l)
    assert "--no-read-env" not in exec_line and "--token" not in exec_line


def test_the_folder_is_configurable_and_the_default_is_the_documented_one(box, tmp_path):
    other = tmp_path / "other-cfg"
    other.mkdir()
    other.chmod(0o700)
    (other / "token").write_text("other-token\n", encoding="utf-8")
    (other / "token").chmod(0o600)
    code, _, err = box.finish(box.run(extra_env={"SIEM_NET_CONFIG_DIR": str(other)}))
    assert code == 0, err
    assert (box.rec / "doppler-argv").read_text().splitlines()[2] == str(other)
    assert _env_map(box.rec / "doppler-environ")["DOPPLER_TOKEN"] == "other-token"
    text = SCRIPT.read_text(encoding="utf-8")
    assert '"${SIEM_NET_CONFIG_DIR:-$HOME/.config/doppler-siem-net}"' in text


# ---- the script's own hardening, read from its text -------------------------------------

def test_the_script_is_hardened_at_the_top():
    lines = SCRIPT.read_text(encoding="utf-8").splitlines()
    assert lines[0] == "#!/bin/bash -p"
    head = "\n".join(lines[:60])
    assert "set +x" in head
    assert "unset BASH_ENV ENV CDPATH GLOBIGNORE PS4" in head
    assert "export PATH" in head
    assert os.access(SCRIPT, os.X_OK)
    assert "exec doppler run" in "\n".join(lines)
    assert chr(0x2014) not in "\n".join(lines)
