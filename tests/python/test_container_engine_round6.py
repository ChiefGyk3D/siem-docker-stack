"""Round 6 review fixes for the CONTAINER_ENGINE setting (issue #130).

1. A signal that arrives between the fork of a child and the assignment of its PID is not lost: the
   invoking shell (runner PID) and the runner (engine PID) both remember it and act as soon as the PID
   is known, so neither the runner nor the engine is left running.
2. ce_run puts back the HUP, INT and TERM traps its caller had, instead of resetting them to default.
3. Python: SIGINT is held while the private home is deleted, like TERM and HUP.
4. The docs describe the final signal behavior.
"""
import os
import shutil
import signal
import subprocess
import time

import pytest

from conftest import REPO_ROOT, import_module_from_path

SCRIPTS = REPO_ROOT / "scripts"
ce = import_module_from_path("container_engine", SCRIPTS / "container_engine.py")
HELPER = SCRIPTS / "lib-container-engine.sh"
DOC = REPO_ROOT / "docs" / "container-engine.md"
SHELLS = [s for s in ("sh", "dash", "bash") if shutil.which(s)]

CHILD = '#!/bin/sh\necho "$HOME" > "%s/home.txt"\necho "$$" > "%s/pid.txt"\nexec /bin/sleep 300\n'


def make_exe(path, body):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.parent.chmod(0o755)
    path.write_text(body, encoding="utf-8")
    path.chmod(0o755)
    return path


def _alive(pid):
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    return True


def _dead(pid, secs=3.0):
    end = time.time() + secs
    while time.time() < end:
        if not _alive(pid):
            return True
        time.sleep(0.05)
    return False


def _gone(pathstr, secs=3.0):
    end = time.time() + secs
    while time.time() < end:
        if not os.path.exists(pathstr):
            return True
        time.sleep(0.05)
    return False


def _reap_engine(tmp_path):
    pidf = tmp_path / "pid.txt"
    if pidf.exists() and pidf.read_text().strip():
        pid = int(pidf.read_text())
        if _alive(pid):
            os.kill(pid, signal.SIGKILL)


# ------------------------------------------------------------------ 1. spawn-to-PID race

def _race_script(stub, command, who):
    # a DEBUG trap fires just before the PID assignment and signals the shell named by `who`
    return (f". '{HELPER}'\nCE_BIN='{stub}'\nset -T\n"
            f"trap 'if [[ $BASH_COMMAND == {command} ]]; then trap - DEBUG; kill -TERM {who}; fi' DEBUG\n"
            "ce_run ps\necho rc=$?\n")


@pytest.mark.parametrize("command,who,status", [
    ('_ce_runner=\\$!', '"$$"', 143),       # the invoking shell, runner forked but its PID not yet recorded
    ('_ce_child=\\$!', '"$BASHPID"', 143),  # the runner, engine forked but its PID not yet recorded
])
def test_a_signal_between_the_fork_and_the_pid_assignment_is_not_lost(command, who, status, tmp_path):
    stub = make_exe(tmp_path / "bin" / "docker", CHILD % (tmp_path, tmp_path))
    try:
        p = subprocess.Popen(["bash", "-c", _race_script(stub, command, who)], env={"PATH": "/usr/bin:/bin"},
                             stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, start_new_session=True)
        p.wait(timeout=10)
        pidf = tmp_path / "pid.txt"
        time.sleep(1.0)  # an orphaned runner would have started the engine by now
        if pidf.exists() and pidf.read_text().strip():
            assert _dead(int(pidf.read_text())), "the engine was left running"
            home = (tmp_path / "home.txt").read_text().strip()
            assert _gone(home), "the private home was left behind"
        if who == '"$$"':
            assert p.returncode == status, p.returncode
    finally:
        _reap_engine(tmp_path)


# ------------------------------------------------------------------ 2. the caller's traps survive

@pytest.mark.parametrize("shell", ["bash"])  # every caller is a bash script; dash cannot list its traps
@pytest.mark.parametrize("name,sig", [("TERM", signal.SIGTERM), ("HUP", signal.SIGHUP), ("INT", signal.SIGINT)])
def test_ce_run_leaves_the_callers_signal_traps_in_place(shell, name, sig, tmp_path):
    stub = make_exe(tmp_path / "bin" / "docker", "#!/bin/sh\nexit 0\n")
    script = (f". '{HELPER}'\nCE_BIN='{stub}'\ntrap 'echo caller-{name}; exit 77' {name}\n"
              f"ce_run ps\nkill -{name} \"$$\"\nsleep 1\necho not-reached\n")
    r = subprocess.run([shell, "-c", script], env={"PATH": "/usr/bin:/bin"}, stdin=subprocess.DEVNULL,
                       capture_output=True, text=True, timeout=20)
    assert r.returncode == 77, (r.returncode, r.stdout, r.stderr)
    assert f"caller-{name}" in r.stdout


@pytest.mark.parametrize("shell", SHELLS)
def test_a_signal_without_a_caller_trap_is_back_to_its_default(shell, tmp_path):
    stub = make_exe(tmp_path / "bin" / "docker", "#!/bin/sh\nexit 0\n")
    script = f". '{HELPER}'\nCE_BIN='{stub}'\nce_run ps\nkill -TERM \"$$\"\nsleep 1\necho not-reached\n"
    r = subprocess.run([shell, "-c", script], env={"PATH": "/usr/bin:/bin"}, stdin=subprocess.DEVNULL,
                       capture_output=True, text=True, timeout=20)
    assert r.returncode == -signal.SIGTERM and "not-reached" not in r.stdout, (r.returncode, r.stdout, r.stderr)


# ------------------------------------------------------------------ 3. python SIGINT during deletion

def test_sigint_during_deletion_does_not_interrupt_it(monkeypatch):
    saved = signal.getsignal(signal.SIGINT)
    signal.signal(signal.SIGINT, signal.default_int_handler)  # raises KeyboardInterrupt, as in a real run
    real = ce.shutil.rmtree
    made = []

    def spy(path, **kw):
        os.kill(os.getpid(), signal.SIGINT)
        time.sleep(0.05)
        return real(path, **kw)

    monkeypatch.setattr(ce.shutil, "rmtree", spy)
    try:
        with pytest.raises(KeyboardInterrupt):  # held during the deletion, delivered after it
            with ce.private_home() as d:
                made.append(d)
        assert not os.path.exists(made[0]), "SIGINT interrupted the deletion"
    finally:
        signal.signal(signal.SIGINT, saved)


# ------------------------------------------------------------------ 4. docs

def test_the_docs_describe_forwarding_and_the_main_thread_rule():
    text = " ".join(DOC.read_text(encoding="utf-8").split())
    assert "is not forwarded" not in text
    assert "still removed on every normal or exceptional exit" not in text
    assert "forwards HUP, INT and TERM" in text
    assert "refused" in text and "main thread" in text
    assert "puts back" in text
