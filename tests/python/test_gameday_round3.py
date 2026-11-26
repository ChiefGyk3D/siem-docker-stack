"""Fix round 3 for scripts/gameday.py (issue #84): the last Daybreak round.

1 container-side PATH, 2 canonical trusted CLI, 3 locking and snapshot compare, 4 log hardening.
Shell tests run under the local sh with shims and barriers (no sleeps for ordering).
"""
import os
import shutil
import stat
import subprocess
import time

import pytest

from test_gameday import go, gd

RID_A, RID_B = "aaaaaaaa11111111", "bbbbbbbb22222222"
LINE_A, LINE_B = gd.hosts_line("discord.com", RID_A), gd.hosts_line("pushover.example", RID_B)
ORIGINAL = b"127.0.0.1 localhost\n::1 localhost\n"
REAL = {n: shutil.which(n) for n in ("cat", "grep", "mktemp", "sleep")}


@pytest.fixture
def hosts(tmp_path):
    f = tmp_path / "hosts"
    f.write_bytes(ORIGINAL)
    return f


def run_sh(script, env=None):
    return subprocess.run(["sh", "-c", script], capture_output=True, env=env or {"PATH": "/usr/bin:/bin"})


def with_shims(script, shim_dir):
    return script.replace(gd.SAFE_BIN_PATH, f"{shim_dir}:{gd.SAFE_BIN_PATH}", 1)


def shim(d, name, body):
    d.mkdir(exist_ok=True)
    f = d / name
    f.write_text("#!/bin/sh\n" + body)
    f.chmod(0o755)


# ===== 1. container-side PATH ==============================================

UTILS = ["grep", "cat", "mktemp", "rm", "cmp", "tail", "od", "tr", "wc", "head", "mv", "kill", "sleep", "mkdir"]


def attacker_dir(tmp_path):
    atk = tmp_path / "atk"
    for name in UTILS:
        shim(atk, name, f'echo hit > "{atk}/hit-{name}"\nexit 99\n')
    return atk


@pytest.mark.parametrize("which", ["add", "remove"])
def test_attacker_controlled_path_directory_is_never_used(which, hosts, tmp_path):
    atk = attacker_dir(tmp_path)
    if which == "add":
        script = gd.hosts_add_script(LINE_A, str(hosts))
    else:
        hosts.write_bytes(ORIGINAL + LINE_A.encode() + b"\n")
        script = gd.hosts_remove_script(LINE_A, str(hosts))
    r = run_sh(script, env={"PATH": f"{atk}:/usr/bin:/bin"})
    assert r.returncode == 0, r.stderr
    assert sorted(p.name for p in atk.iterdir() if p.name.startswith("hit-")) == []
    assert (LINE_A.encode() in hosts.read_bytes()) == (which == "add")


def test_the_script_sets_a_fixed_path_before_running_anything():
    for s in (gd.hosts_add_script(LINE_A), gd.hosts_remove_script(LINE_A)):
        assert s.startswith(f"PATH='{gd.SAFE_BIN_PATH}'\nexport PATH\n")
    assert gd.SAFE_BIN_PATH == "/usr/sbin:/usr/bin:/sbin:/bin"


def test_unsafe_bin_path_text_is_refused():
    with pytest.raises(gd.GamedayError):
        gd.hosts_remove_script(LINE_A, bin_path="/usr/bin:'; reboot; '")


# ===== 2. trusted CLI: canonical path and every ancestor ====================

def mk(path, mode=0o755):
    path.mkdir(parents=True, exist_ok=True)
    path.chmod(mode)
    return path


def exe(path, text="#!/bin/sh\necho ok\n"):
    path.write_text(text)
    path.chmod(0o755)
    return path


def resolve(tmp_path, dirs):
    return gd.resolve_cli("docker", tuple(str(d) for d in dirs), os.geteuid(), str(tmp_path))


def test_symlink_through_an_attacker_writable_ancestor_is_refused(tmp_path):
    atk = mk(tmp_path / "atk", 0o777)
    exe(mk(atk / "safe") / "docker")
    trusted = mk(tmp_path / "trusted")
    (trusted / "docker").symlink_to(atk / "safe" / "docker")
    assert resolve(tmp_path, [trusted]) is None


def test_every_directory_in_a_multi_link_chain_is_checked(tmp_path):
    good = mk(tmp_path / "good")
    real_dir = mk(tmp_path / "tools" / "bin")
    mk(tmp_path / "tools")
    exe(real_dir / "docker")
    (tmp_path / "tools" / "l2").symlink_to(real_dir / "docker")
    (good / "l1").symlink_to(tmp_path / "tools" / "l2")
    (good / "docker").symlink_to(good / "l1")
    assert resolve(tmp_path, [good]) == os.path.realpath(real_dir / "docker")
    real_dir.chmod(0o777)  # one writable directory anywhere in the chain
    assert resolve(tmp_path, [good]) is None


def test_a_writable_top_ancestor_inside_the_root_is_refused(tmp_path):
    outer = mk(tmp_path / "outer")
    inner = mk(outer / "inner")
    exe(inner / "docker")
    outer.chmod(0o775)
    assert resolve(tmp_path, [inner]) is None


def test_returns_the_canonical_target_not_the_symlink(tmp_path):
    good, tools = mk(tmp_path / "good"), mk(tmp_path / "tools")
    exe(tools / "realdocker")
    (good / "docker").symlink_to("../tools/realdocker")
    got = resolve(tmp_path, [good])
    assert got == os.path.realpath(tools / "realdocker") and got != str(good / "docker")


def test_a_trusted_directory_that_is_itself_a_link_into_a_writable_directory_is_refused(tmp_path):
    atk = mk(tmp_path / "atk", 0o777)
    tools = mk(tmp_path / "tools")
    exe(tools / "realdocker")
    (atk / "docker").symlink_to(tools / "realdocker")  # the target itself is perfectly safe
    entry = tmp_path / "entry"
    entry.symlink_to(atk)
    assert resolve(tmp_path, [entry]) is None


def test_a_target_outside_the_trusted_root_is_refused(tmp_path):
    root = mk(tmp_path / "root")
    outside = mk(tmp_path / "outside")
    exe(outside / "docker")
    good = mk(root / "good")
    (good / "docker").symlink_to(outside / "docker")
    assert gd.resolve_cli("docker", (str(good),), os.geteuid(), str(root)) is None


def test_real_runner_executes_the_validated_canonical_path_with_a_validated_path(tmp_path, monkeypatch):
    good, bad, tools = mk(tmp_path / "good"), mk(tmp_path / "bad", 0o777), mk(tmp_path / "tools")
    exe(tools / "realdocker")
    (good / "docker").symlink_to("../tools/realdocker")
    monkeypatch.setattr(gd, "TRUSTED_DIRS", (str(good), str(bad)))
    monkeypatch.setattr(gd, "TRUSTED_UID", os.geteuid())
    monkeypatch.setattr(gd, "TRUSTED_ROOT", str(tmp_path))
    seen = {}

    def fake_run(args, **kw):
        seen.update(args=args, **kw)
        return subprocess.CompletedProcess(args, 0, "", "")

    monkeypatch.setattr(gd.subprocess, "run", fake_run)
    assert gd.real_runner(["docker", "ps"])[0] == 0
    assert seen["executable"] == os.path.realpath(tools / "realdocker")
    assert seen["env"]["PATH"] == str(good)  # the writable directory is not in the child PATH


# ===== 3. locking and the snapshot compare ===================================

def script_remove(hosts, line, shims=None, **kw):
    s = gd.hosts_remove_script(line, str(hosts), lock_tries=400, lock_sleep="0.05", **kw)
    return with_shims(s, shims) if shims else s


def script_add(hosts, line, shims=None):
    s = gd.hosts_add_script(line, str(hosts), lock_tries=400, lock_sleep="0.05")
    return with_shims(s, shims) if shims else s


def barrier_cat(tmp_path):
    """A cat that, when it is about to write the new content, parks the first caller until 'go' exists."""
    b = tmp_path / "barrier"
    b.mkdir()
    shim(tmp_path / "bshim", "cat", f'''case "$1" in
  */new) if mkdir "{b}/taken" 2>/dev/null; then : > "{b}/at"; while [ ! -e "{b}/go" ]; do {REAL["sleep"]} 0.02; done; fi ;;
esac
exec {REAL["cat"]} "$@"
''')
    return tmp_path / "bshim", b


def wait_for(path, timeout=20):
    end = time.time() + timeout
    while not os.path.exists(path):
        assert time.time() < end, f"timed out waiting for {path}"
        time.sleep(0.01)


def popen(script):
    return subprocess.Popen(["sh", "-c", script], stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                            env={"PATH": "/usr/bin:/bin"})


def finish(*procs):
    out = []
    for p in procs:
        try:
            o, e = p.communicate(timeout=30)
        finally:
            if p.poll() is None:
                p.kill()
        out.append((p.returncode, e))
    return out


def test_two_distinct_removals_serialize_and_neither_line_comes_back(hosts, tmp_path):
    hosts.write_bytes(ORIGINAL + LINE_A.encode() + b"\n" + LINE_B.encode() + b"\n")
    shims, b = barrier_cat(tmp_path)
    a = popen(script_remove(hosts, LINE_A, shims))
    try:
        wait_for(b / "at")
        c = popen(script_remove(hosts, LINE_B, shims))
        time.sleep(0.4)
        assert c.poll() is None, "the second remover must wait for the lock"
        (b / "go").write_text("")
        results = finish(a, c)
    finally:
        (b / "go").write_text("")
        for p in (a,):
            if p.poll() is None:
                p.kill()
    assert [rc for rc, _ in results] == [0, 0], results
    assert hosts.read_bytes() == ORIGINAL


def test_add_versus_remove_serialize_and_the_added_line_survives(hosts, tmp_path):
    hosts.write_bytes(ORIGINAL + LINE_A.encode() + b"\n")
    shims, b = barrier_cat(tmp_path)
    a = popen(script_remove(hosts, LINE_A, shims))
    try:
        wait_for(b / "at")
        c = popen(script_add(hosts, LINE_B))
        time.sleep(0.4)
        assert c.poll() is None, "the add must wait for the lock"
        (b / "go").write_text("")
        results = finish(a, c)
    finally:
        (b / "go").write_text("")
        if a.poll() is None:
            a.kill()
    assert [rc for rc, _ in results] == [0, 0], results
    assert hosts.read_bytes() == ORIGINAL + LINE_B.encode() + b"\n"


def test_an_unrelated_line_appended_between_backup_and_write_aborts_without_writing(hosts, tmp_path):
    hosts.write_bytes(ORIGINAL + LINE_A.encode() + b"\n")
    # the second cmp call is the compare right before the write: an outside writer appends just before it
    shim(tmp_path / "gs", "cmp", f'''echo x >> "{tmp_path}/cmpcalls"
if [ "$(wc -l < "{tmp_path}/cmpcalls")" -eq 2 ]; then printf '9.9.9.9 late\\n' >> "{hosts}"; fi
exec {shutil.which("cmp")} "$@"
''')
    r = run_sh(script_remove(hosts, LINE_A, tmp_path / "gs"))
    assert r.returncode != 0 and b"changed since the backup" in r.stderr
    assert hosts.read_bytes() == ORIGINAL + LINE_A.encode() + b"\n9.9.9.9 late\n"


def test_a_failed_writer_does_not_restore_over_a_newer_update(hosts, tmp_path):
    hosts.write_bytes(ORIGINAL + LINE_A.encode() + b"\n")
    shim(tmp_path / "cs", "cat", f'''case "$1" in
  */new) printf 'OTHER WRITER\\n' > "{hosts}"; exit 1 ;;
esac
exec {REAL["cat"]} "$@"
''')
    r = run_sh(script_remove(hosts, LINE_A, tmp_path / "cs"))
    assert r.returncode != 0 and b"RESTORE SKIPPED" in r.stderr
    assert hosts.read_bytes() == b"OTHER WRITER\n"


@pytest.mark.parametrize("kind", ["success", "failure"])
def test_the_lock_is_released_on_exit(kind, hosts, tmp_path):
    hosts.write_bytes(ORIGINAL + LINE_A.encode() + b"\n")
    shims = None
    if kind == "failure":
        shim(tmp_path / "cs", "cat", f'case "$1" in\n  */new) exit 1 ;;\nesac\nexec {REAL["cat"]} "$@"\n')
        shims = tmp_path / "cs"
    r = run_sh(script_remove(hosts, LINE_A, shims))
    assert (r.returncode == 0) == (kind == "success")
    assert not os.path.exists(str(hosts) + ".gameday-lock")


def test_a_stale_lock_from_a_dead_process_is_broken(hosts):
    dead = subprocess.Popen(["true"])
    dead.wait()
    lock = str(hosts) + ".gameday-lock"
    os.mkdir(lock)
    open(lock + "/pid", "w").write(f"{dead.pid}\n")
    hosts.write_bytes(ORIGINAL + LINE_A.encode() + b"\n")
    r = run_sh(script_remove(hosts, LINE_A))
    assert r.returncode == 0, r.stderr
    assert hosts.read_bytes() == ORIGINAL and not os.path.exists(lock)


def test_a_live_lock_is_honored_then_the_wait_is_bounded(hosts):
    lock = str(hosts) + ".gameday-lock"
    os.mkdir(lock)
    open(lock + "/pid", "w").write(f"{os.getpid()}\n")
    hosts.write_bytes(ORIGINAL + LINE_A.encode() + b"\n")
    s = gd.hosts_remove_script(LINE_A, str(hosts), lock_tries=3, lock_sleep="0.05")
    r = run_sh(s)
    assert r.returncode != 0 and b"lock" in r.stderr
    assert hosts.read_bytes() == ORIGINAL + LINE_A.encode() + b"\n"
    assert os.path.isdir(lock)  # someone else's lock is left alone


# ===== 4. log hardening ===========================================================

REC = {"scenario": "n8n-down"}


def test_existing_world_writable_log_is_refused(tmp_path):
    p = tmp_path / "l"
    p.write_text('{"forged":true}\n')
    p.chmod(0o666)
    assert "private" in gd.write_log(str(p), REC)
    assert p.read_text() == '{"forged":true}\n'


@pytest.mark.parametrize("mode", [0o640, 0o620, 0o604, 0o660])
def test_any_group_or_world_bit_on_an_existing_log_is_refused(mode, tmp_path):
    p = tmp_path / "l"
    p.write_text("")
    p.chmod(mode)
    assert gd.write_log(str(p), REC) != ""


def test_existing_private_log_is_appended(tmp_path):
    p = tmp_path / "l"
    p.write_text("x\n")
    p.chmod(0o600)
    assert gd.write_log(str(p), REC) == ""
    assert p.read_text().startswith("x\n") and len(p.read_text().splitlines()) == 2


def test_hard_linked_log_is_refused(tmp_path):
    p, q = tmp_path / "l", tmp_path / "other"
    p.write_text("")
    p.chmod(0o600)
    os.link(p, q)
    assert "link" in gd.write_log(str(p), REC)
    assert p.read_text() == ""


def test_short_writes_are_completed(tmp_path):
    chunks = []

    def short(fd, data):
        chunks.append(bytes(data[:3]))
        return 3

    assert gd.write_log(str(tmp_path / "l"), REC, write=short) == ""
    assert b"".join(chunks) == (gd.json.dumps(REC) + "\n").encode()


def test_a_zero_write_is_a_failure_not_a_hang(tmp_path):
    assert "write" in gd.write_log(str(tmp_path / "l"), REC, write=lambda fd, data: 0)


def test_a_failed_log_still_does_not_block_the_revert(tmp_path):
    p = tmp_path / "l"
    p.write_text("")
    p.chmod(0o666)
    rc, out, fakes = go(["n8n-down", "--apply", "--confirm-live", "--log", str(p)])
    assert rc == 0 and "log not written" in out and fakes.commands == [["docker", "stop", "n8n"]]
