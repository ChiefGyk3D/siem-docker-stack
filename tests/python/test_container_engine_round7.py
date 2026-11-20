"""Round 7: the simplified signal design for the CONTAINER_ENGINE setting (issue #130).

ce_run runs the engine in the foreground of a subshell with its own EXIT trap (set before the private
home exists); HUP, INT and TERM just exit so that trap runs. private_home is try/finally. These tests
replace the rounds 4 to 6 tests of the removed machinery (forwarding, async runner, pending-signal
bookkeeping, trap save and replay, pthread_sigmask, worker-thread refusal).
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
ENV = {"PATH": "/usr/bin:/bin"}

CHILD = '#!/bin/sh\necho "$HOME" > "%s/home.txt"\necho "$$" > "%s/pid.txt"\nexec /bin/sleep 300\n'


def make_exe(path, body):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.parent.chmod(0o755)
    path.write_text(body, encoding="utf-8")
    path.chmod(0o755)
    return path


def _wait_for(path, secs=5.0):
    end = time.time() + secs
    while time.time() < end:
        if path.exists() and path.read_text().strip():
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


def _dead(pid, secs=3.0):
    end = time.time() + secs
    while time.time() < end:
        try:
            os.kill(pid, 0)
        except ProcessLookupError:
            return True
        time.sleep(0.05)
    return False


def _reap(tmp_path):
    pidf = tmp_path / "pid.txt"
    if pidf.exists() and pidf.read_text().strip():
        try:
            os.kill(int(pidf.read_text()), signal.SIGKILL)
        except ProcessLookupError:
            pass


# ------------------------------------------------------------------ EXIT cleanup after a signal to the script

@pytest.mark.parametrize("shell", SHELLS)
@pytest.mark.parametrize("sig,status", [(signal.SIGTERM, 143), (signal.SIGHUP, 129), (signal.SIGINT, 130)])
def test_a_group_signal_during_the_engine_call_removes_the_home_and_exits_128_plus_signal(shell, sig, status, tmp_path):
    stub = make_exe(tmp_path / "bin" / "docker", CHILD % (tmp_path, tmp_path))
    p = subprocess.Popen([shell, "-c", f". '{HELPER}'\nCE_BIN='{stub}'\nce_run ps\necho after-rc=$?"], env=ENV,
                         stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, text=True, start_new_session=True)
    try:
        assert _wait_for(tmp_path / "pid.txt"), "the engine did not start"
        home = (tmp_path / "home.txt").read_text().strip()
        engine = int((tmp_path / "pid.txt").read_text())
        os.killpg(os.getpgid(p.pid), sig)  # what a terminal or a supervisor does
        out, _ = p.communicate(timeout=10)
        assert "after-rc" not in out, "the script went on after the signal"
        assert p.returncode in (status, -sig), (p.returncode, out)
        assert _gone(home), "the private home was left behind"
        assert _dead(engine), "the engine was left running"
    finally:
        _reap(tmp_path)


@pytest.mark.parametrize("shell", SHELLS)
@pytest.mark.parametrize("name", ["TERM", "HUP", "INT"])
def test_a_signal_to_the_subshell_leaves_through_the_exit_trap(shell, name, tmp_path):
    # the engine stub signals its parent (the ce_run subshell) and lingers, like a stop request
    rec = tmp_path / "home.txt"
    stub = make_exe(tmp_path / "bin" / "docker", f'#!/bin/sh\necho "$HOME" > "{rec}"\nkill -{name} $PPID\n/bin/sleep 1\n')
    r = subprocess.run([shell, "-c", f". '{HELPER}'\nCE_BIN='{stub}'\nce_run ps\necho rc=$?"], env=ENV,
                       stdin=subprocess.DEVNULL, capture_output=True, text=True, timeout=30)
    status = {"TERM": 143, "HUP": 129, "INT": 130}[name]
    assert f"rc={status}" in r.stdout, (r.stdout, r.stderr)
    assert _gone(rec.read_text().strip()), "the private home was left behind"


@pytest.mark.parametrize("name,status", [("TERM", 143), ("HUP", 129), ("INT", 130)])
def test_an_early_signal_during_home_creation_is_acted_on_and_the_home_is_removed(name, status, tmp_path):
    rec = tmp_path / "made.txt"
    ran = tmp_path / "ran.txt"
    stub = make_exe(tmp_path / "bin" / "docker", f"#!/bin/sh\necho x > '{ran}'\n")
    # a stand-in ce_mkhome makes the directory, then the subshell is signalled before ce_run can use it
    script = (f". '{HELPER}'\nCE_BIN='{stub}'\n"
              f"ce_mkhome() {{ _ce_home=$(/usr/bin/mktemp -d -p '{tmp_path}' early.XXXXXX); "
              f"printf '%s' \"$_ce_home\" > '{rec}'; kill -{name} \"$BASHPID\"; }}\n"
              "ce_run ps\necho rc=$?\n")
    r = subprocess.run(["bash", "-c", script], env=ENV, stdin=subprocess.DEVNULL, capture_output=True, text=True,
                       timeout=20)
    made = rec.read_text().strip()
    assert made and _gone(made), "the home created just before the signal was left behind"
    assert f"rc={status}" in r.stdout, (r.stdout, r.stderr)
    assert not ran.exists(), "the engine ran although the signal arrived first"


def test_a_second_signal_cannot_cut_the_deletion_short(tmp_path):
    # the home holds a big enough tree that rm takes a moment; a second TERM must not abort it
    rec = tmp_path / "home.txt"
    stub = make_exe(tmp_path / "bin" / "docker",
                    f'#!/bin/sh\necho "$HOME" > "{rec}"\nmkdir -p "$HOME/a/b/c"\nkill -TERM $PPID\nkill -TERM $PPID\n/bin/sleep 1\n')
    r = subprocess.run(["bash", "-c", f". '{HELPER}'\nCE_BIN='{stub}'\nce_run ps\necho rc=$?"], env=ENV,
                       stdin=subprocess.DEVNULL, capture_output=True, text=True, timeout=30)
    assert "rc=143" in r.stdout, (r.stdout, r.stderr)
    assert _gone(rec.read_text().strip())


# ------------------------------------------------------------------ the caller's traps are untouched

def test_the_callers_exit_trap_is_untouched_and_runs_once_at_the_end(tmp_path):
    stub = make_exe(tmp_path / "bin" / "docker", "#!/bin/sh\nexit 0\n")
    script = f". '{HELPER}'\nCE_BIN='{stub}'\ntrap 'echo caller-exit' EXIT\nce_run ps\ntrap\n"
    r = subprocess.run(["bash", "-c", script], env=ENV, stdin=subprocess.DEVNULL, capture_output=True, text=True,
                       timeout=20)
    assert r.stdout.count("caller-exit") == 2, r.stdout + r.stderr  # listed by `trap`, then run at exit
    assert "_ce_" not in r.stdout


@pytest.mark.parametrize("name,sig", [("TERM", signal.SIGTERM), ("HUP", signal.SIGHUP), ("INT", signal.SIGINT)])
def test_the_callers_signal_traps_are_never_replaced(name, sig, tmp_path):
    stub = make_exe(tmp_path / "bin" / "docker", "#!/bin/sh\nexit 0\n")
    script = (f". '{HELPER}'\nCE_BIN='{stub}'\ntrap 'echo caller-{name}; exit 77' {name}\ntrap > '{tmp_path}/before.txt'\n"
              f"ce_run ps\ntrap > '{tmp_path}/after.txt'\nkill -{name} \"$$\"\nsleep 1\necho not-reached\n")
    r = subprocess.run(["bash", "-c", script], env=ENV, stdin=subprocess.DEVNULL, capture_output=True, text=True,
                       timeout=20)
    assert r.returncode == 77 and f"caller-{name}" in r.stdout, (r.returncode, r.stdout, r.stderr)
    assert (tmp_path / "before.txt").read_text() == (tmp_path / "after.txt").read_text()


@pytest.mark.parametrize("shell", SHELLS)
def test_a_signal_without_a_caller_trap_keeps_its_default_after_ce_run(shell, tmp_path):
    stub = make_exe(tmp_path / "bin" / "docker", "#!/bin/sh\nexit 0\n")
    script = f". '{HELPER}'\nCE_BIN='{stub}'\nce_run ps\nkill -TERM \"$$\"\nsleep 1\necho not-reached\n"
    r = subprocess.run([shell, "-c", script], env=ENV, stdin=subprocess.DEVNULL, capture_output=True, text=True,
                       timeout=20)
    assert r.returncode == -signal.SIGTERM and "not-reached" not in r.stdout, (r.returncode, r.stdout, r.stderr)


def test_ce_run_keeps_the_status_and_stdin_of_the_engine(tmp_path):
    stub = make_exe(tmp_path / "bin" / "docker", "#!/bin/sh\ncat\nexit 7\n")
    script = f". '{HELPER}'\nCE_BIN='{stub}'\nprintf hello | ce_run exec -i x\necho \" rc=$?\"\n"
    r = subprocess.run(["bash", "-c", script], env=ENV, stdin=subprocess.DEVNULL, capture_output=True, text=True,
                       timeout=20)
    assert r.stdout == "hello rc=7\n", r.stdout + r.stderr


@pytest.mark.parametrize("shell", SHELLS)
def test_the_removed_machinery_is_gone(shell):  # guard against the old design coming back
    text = HELPER.read_text()
    for word in ("ce_fwd", "ce_stop", "ce_runner", "_ce_pend", "trap -p", "eval "):
        assert word not in text.replace("# the only eval", ""), word


# ------------------------------------------------------------------ python: try/finally

def test_private_home_is_removed_on_return_exception_keyboardinterrupt_and_systemexit():
    for exc in (None, RuntimeError, KeyboardInterrupt, SystemExit):
        made = []
        try:
            with ce.private_home() as d:
                made.append(d)
                assert oct(os.stat(d).st_mode & 0o777) == "0o700"
                if exc:
                    raise exc()
        except BaseException:
            pass
        assert made and not os.path.exists(made[0]), f"left behind after {exc}"


def test_private_home_installs_no_signal_handler_and_works_off_the_main_thread():
    import threading
    before = {s: signal.getsignal(s) for s in (signal.SIGTERM, signal.SIGHUP, signal.SIGINT)}
    result = {}

    def work():
        try:
            with ce.private_home() as d:
                result["during"] = {s: signal.getsignal(s) for s in before}
                result["dir"] = d
        except BaseException as err:
            result["err"] = err

    t = threading.Thread(target=work)
    t.start()
    t.join(15)
    assert "err" not in result, result
    assert result["during"] == before and not os.path.exists(result["dir"])
    with ce.private_home():
        assert {s: signal.getsignal(s) for s in before} == before


def test_a_sigterm_with_a_raising_handler_removes_the_python_home(tmp_path):
    driver = (f"import os, signal, sys\nsys.path.insert(0, '{SCRIPTS}')\nimport container_engine as ce\n"
              "signal.signal(signal.SIGTERM, lambda s, f: sys.exit(128 + s))\n"
              f"with ce.private_home() as d:\n    open('{tmp_path}/d.txt', 'w').write(d)\n    os.kill(os.getpid(), signal.SIGTERM)\n")
    import sys
    r = subprocess.run([sys.executable, "-I", "-c", driver], capture_output=True, text=True, timeout=20)
    assert r.returncode == 128 + signal.SIGTERM, (r.returncode, r.stderr)
    assert _gone((tmp_path / "d.txt").read_text())


# ------------------------------------------------------------------ docs

def test_the_docs_state_what_is_not_covered():
    text = " ".join(DOC.read_text(encoding="utf-8").split())
    for phrase in ("SIGKILL", "may keep running", "process group", "engine-home"):
        assert phrase in text, phrase
    for gone in ("forwards HUP", "tracked runner", "puts back"):
        assert gone not in text, gone
