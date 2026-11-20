"""Round 5 review fixes for the CONTAINER_ENGINE setting (issue #130).

1. A signal sent to the invoking script itself (not to ce_run's inner shell, not to the process group)
   stops the engine, removes the private home and ends the script with the signal status.
2. The private home is covered by the EXIT trap before it exists, so a signal right after creation
   cannot leave it behind.
3. Python: a signal that arrives while the directory is being deleted cannot interrupt the deletion
   (it is held and delivered to the restored handler afterwards), and a worker thread, which cannot
   be protected, is refused instead of silently running without protection.
"""
import os
import shutil
import signal
import subprocess
import threading
import time

import pytest

from conftest import REPO_ROOT, import_module_from_path

SCRIPTS = REPO_ROOT / "scripts"
ce = import_module_from_path("container_engine", SCRIPTS / "container_engine.py")
HELPER = SCRIPTS / "lib-container-engine.sh"
SHELLS = [s for s in ("sh", "dash", "bash") if shutil.which(s)]

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


# ------------------------------------------------------------------ 1. a signal to the script itself

@pytest.mark.parametrize("shell", SHELLS)
@pytest.mark.parametrize("sig,status", [(signal.SIGTERM, 143), (signal.SIGHUP, 129), (signal.SIGINT, 130)])
def test_a_signal_to_the_invoking_script_stops_the_engine_and_removes_the_home(shell, sig, status, tmp_path):
    stub = make_exe(tmp_path / "bin" / "docker", CHILD % (tmp_path, tmp_path))
    p = subprocess.Popen([shell, "-c", f". '{HELPER}'\nCE_BIN='{stub}'\nce_run ps\necho rc=$?"],
                         env={"PATH": "/usr/bin:/bin"}, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, text=True,
                         start_new_session=True)
    assert _wait_for(tmp_path / "pid.txt"), "the engine did not start"
    home = (tmp_path / "home.txt").read_text().strip()
    engine = int((tmp_path / "pid.txt").read_text())
    t0 = time.time()
    os.kill(p.pid, sig)  # the script's own PID only: no process group, no inner shell
    out, _ = p.communicate(timeout=10)
    assert time.time() - t0 < 3, "the signal was not handled while the engine ran"
    assert p.returncode == status, (p.returncode, out)
    assert _gone(home), "the private home was left behind"
    assert _dead(engine), "the engine was left running"


def test_the_exit_trap_of_the_caller_is_untouched_and_the_others_are_reset(tmp_path):
    stub = make_exe(tmp_path / "bin" / "docker", "#!/bin/sh\nexit 0\n")
    script = f". '{HELPER}'\nCE_BIN='{stub}'\ntrap 'echo caller-exit' EXIT\nce_run ps\ntrap\n"
    r = subprocess.run(["bash", "-c", script], env={"PATH": "/usr/bin:/bin"}, stdin=subprocess.DEVNULL,
                       capture_output=True, text=True, timeout=20)
    assert r.stdout.count("caller-exit") == 2, r.stdout + r.stderr  # listed by `trap`, then run at exit
    assert "ce_fwd" not in r.stdout


def test_ce_run_keeps_the_status_and_stdin_of_the_engine(tmp_path):
    stub = make_exe(tmp_path / "bin" / "docker", "#!/bin/sh\ncat\nexit 7\n")
    script = f". '{HELPER}'\nCE_BIN='{stub}'\nprintf hello | ce_run exec -i x\necho \" rc=$?\"\n"
    r = subprocess.run(["bash", "-c", script], env={"PATH": "/usr/bin:/bin"}, stdin=subprocess.DEVNULL,
                       capture_output=True, text=True, timeout=20)
    assert r.stdout == "hello rc=7\n", r.stdout + r.stderr


# ------------------------------------------------------------------ 2. trap before the home exists

@pytest.mark.parametrize("shell", ["bash"])
def test_a_signal_right_after_the_home_is_created_still_removes_it(shell, tmp_path):
    rec = tmp_path / "made.txt"
    stub = make_exe(tmp_path / "bin" / "docker", "#!/bin/sh\nexit 0\n")
    script = (f". '{HELPER}'\nCE_BIN='{stub}'\n"
              f"ce_mkhome() {{ _ce_home=$(/usr/bin/mktemp -d -p '{tmp_path}' early.XXXXXX); "
              f"printf '%s' \"$_ce_home\" > '{rec}'; kill -TERM \"$BASHPID\"; }}\n"
              "ce_run ps\necho rc=$?\n")
    subprocess.run([shell, "-c", script], env={"PATH": "/usr/bin:/bin"}, stdin=subprocess.DEVNULL,
                   capture_output=True, text=True, timeout=20)
    made = rec.read_text().strip()
    assert made and _gone(made), "the home created just before the signal was left behind"


# ------------------------------------------------------------------ 3. python

@pytest.fixture
def keep_handlers():
    saved = {s: signal.getsignal(s) for s in (signal.SIGTERM, signal.SIGHUP)}
    yield
    for s, h in saved.items():
        signal.signal(s, h)


def test_a_signal_during_deletion_does_not_interrupt_it(keep_handlers, monkeypatch):
    got = []
    signal.signal(signal.SIGTERM, lambda s, f: got.append(s))
    real = ce.shutil.rmtree

    def spy(path, **kw):
        os.kill(os.getpid(), signal.SIGTERM)  # arrives while the deletion is running
        time.sleep(0.05)
        return real(path, **kw)

    monkeypatch.setattr(ce.shutil, "rmtree", spy)
    with ce.private_home() as d:
        pass
    assert not os.path.exists(d), "the signal interrupted the deletion"
    assert got == [signal.SIGTERM], "the held signal must reach the restored handler afterwards"


def test_a_worker_thread_is_refused_not_left_unprotected(tmp_path, monkeypatch):
    good = tmp_path / "good"
    good.mkdir()
    good.chmod(0o755)
    make_exe(good / "docker", "#!/bin/sh\nexit 0\n")
    monkeypatch.setattr(ce, "TRUSTED_DIRS", (str(good),))
    monkeypatch.setattr(ce, "TRUSTED_UID", os.geteuid())
    monkeypatch.setattr(ce, "TRUSTED_ROOT", str(tmp_path))
    made = []
    real = ce._make_home
    monkeypatch.setattr(ce, "_make_home", lambda: made.append(real()) or made[-1])
    result = {}

    def work():
        try:
            ce.engine_run(["docker", "ps"], capture_output=True)
            result["ok"] = True
        except BaseException as err:
            result["err"] = err

    t = threading.Thread(target=work)
    t.start()
    t.join(15)
    assert isinstance(result.get("err"), ce.ContainerEngineError), result
    assert "main thread" in str(result["err"])
    assert not made or not os.path.exists(made[0]), "a home was left behind"
