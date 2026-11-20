"""scripts/siem-net-run keeps the read-only service token out of argv and out of every environment but doppler's.

The wrapper reads a read-only token for the dev_network config from a mode 600 file in a private
config folder and hands it to `doppler run` through `exec`. Each test runs a copy of the script in a
box where doppler is a recording fake and stat and id are recording wrappers (argument list and
environment read from /proc). A sentinel token must reach the fake doppler as the DOPPLER_TOKEN
variable only: never in an argument list, never in the environment of another command, never in the
wrapper's own output, and never in a shell trace.

What is NOT verified here: the real Doppler CLI (no network, no real token is used) and the owner
and mode of a token file on a real box; the owner check is exercised with a fake `id`.
"""
import os
import shutil
import subprocess

import pytest

from conftest import REPO_ROOT

SCRIPT = REPO_ROOT / "scripts" / "siem-net-run"
PATH_LINE = "PATH=/usr/local/sbin:"  # start of the fixed PATH assignment
SENTINEL = "dp.st.Sentinel-Tok-5c1e"
PROBED = ("stat", "id")

FAKE_DOPPLER = """#!/bin/bash
printf '%s\\n' "$$" > '@REC@/doppler-pid'
for a in "$@"; do printf '%s\\n' "$a"; done > '@REC@/doppler-argv'
cat /proc/$$/environ > '@REC@/doppler-environ'
exit "${FAKE_EXIT:-0}"
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

    def run(self, args=("echo", "hi"), extra_env=None, bash_prefix=None):
        env = {"PATH": "/usr/bin:/bin", "HOME": str(self.home), **(extra_env or {})}
        cmd = [str(self.script), *args]
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
    proc = box.run(("python3", "-I", "x.py", "--flag"))
    code, out, err = box.finish(proc)
    assert code == 0, err
    argv = (box.rec / "doppler-argv").read_text().splitlines()
    assert argv == ["run", "--config-dir", str(box.cfg), "--no-check-version", "--fallback-readonly",
                    "--", "python3", "-I", "x.py", "--flag"]
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
    proc = box.run(args=())
    code, out, err = box.finish(proc)
    assert code == 64 and "usage" in err
    assert not box.recorded("doppler-*")
    assert not box.recorded("stat-*-argv")


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
    head = "\n".join(lines[:30])
    assert "set +x" in head
    assert "unset BASH_ENV ENV CDPATH GLOBIGNORE PS4" in head
    assert "export PATH" in head
    assert os.access(SCRIPT, os.X_OK)
    assert "exec doppler run" in "\n".join(lines)
    assert chr(0x2014) not in "\n".join(lines)
