"""Fix round 2 for scripts/gameday.py (issue #84): Daybreak round 2 findings.

The hosts scripts run under the local sh on temp files. Shims for cat and mktemp
sit first on PATH to inject a partial write and a swap after the guard.
"""
import os
import re
import shlex
import shutil
import stat
import subprocess

import pytest

from conftest import REPO_ROOT
from test_gameday import ENV, go, gd

RID = "abcdef0123456789"
LINE = gd.hosts_line("discord.com", RID)
LB = LINE.encode()
REAL_CAT = shutil.which("cat")
REAL_MKTEMP = shutil.which("mktemp")


def sh(script, path_prefix=None, cwd=None):
    env = {"PATH": (f"{path_prefix}:" if path_prefix else "") + "/usr/bin:/bin"}
    return subprocess.run(["sh", "-c", script], capture_output=True, env=env, cwd=cwd)


def expected_after_remove(orig: bytes) -> bytes:
    """Python model of the removal: drop this run's exact line, keep every other byte."""
    parts = orig.split(b"\n")
    out = [p for i, p in enumerate(parts) if p != LB]
    return b"\n".join(out)


CASES = {
    "plain": b"127.0.0.1 localhost\n" + LB + b"\n::1 localhost\n",
    "no_final_newline": b"127.0.0.1 localhost\n" + LB + b"\n::1 localhost",
    "multiple_final_newlines": b"127.0.0.1 localhost\n" + LB + b"\n::1 localhost\n\n\n\n",
    "nul_content": b"127.0.0.1 local\x00host\n" + LB + b"\n\x00\x01\xff binary\n",
    "large": b"".join(b"10.0.%d.%d host%d\n" % (i // 250, i % 250, i) for i in range(30000)) + LB + b"\nlast 1\n",
    "duplicates": LB + b"\nkeep\n" + LB + b"\n" + LB + b"\nend\n",
}


@pytest.fixture
def hosts(tmp_path):
    return tmp_path / "hosts"


@pytest.mark.parametrize("name", sorted(CASES))
def test_remove_preserves_every_other_byte_exactly(name, hosts):
    orig = CASES[name]
    hosts.write_bytes(orig)
    r = sh(gd.hosts_remove_script(LINE, str(hosts)))
    assert r.returncode == 0, r.stderr
    assert hosts.read_bytes() == expected_after_remove(orig)


def shim_cat(tmp_path, mode):
    """A cat that fails after a partial write (mode 'partial') or writes nothing (mode 'dead')
    when asked to read the 'new' file; everything else is the real cat."""
    d = tmp_path / "shim"
    d.mkdir(exist_ok=True)
    body = {
        "partial": 'head -c 7 "$1"; exit 1',
        "dead": "exit 1",
        "silent_short": 'head -c 7 "$1"; exit 0',
    }[mode]
    (d / "cat").write_text(
        "#!/bin/sh\n"
        'case "$1" in\n'
        f'  */new) {body} ;;\n'
        '  */orig) if [ -e "${0%/*}/restore-fails" ]; then exit 1; fi ;;\n'
        "esac\n"
        f'exec {REAL_CAT} "$@"\n')
    (d / "cat").chmod(0o755)
    return d


@pytest.mark.parametrize("name", sorted(CASES))
def test_writer_failing_after_a_partial_write_restores_the_original_exactly(name, hosts, tmp_path):
    orig = CASES[name]
    hosts.write_bytes(orig)
    r = sh(gd.hosts_remove_script(LINE, str(hosts)), path_prefix=shim_cat(tmp_path, "partial"))
    assert r.returncode != 0
    assert hosts.read_bytes() == orig


def test_a_silently_short_write_is_caught_by_the_byte_comparison_and_restored(hosts, tmp_path):
    hosts.write_bytes(CASES["plain"])
    shim = shim_cat(tmp_path, "silent_short")
    # the shim's head -c writes to the real stdout, i.e. the hosts file, then exits 0
    r = sh(gd.hosts_remove_script(LINE, str(hosts)), path_prefix=shim)
    assert r.returncode != 0
    assert hosts.read_bytes() == CASES["plain"]


def shim_grep(tmp_path, filter_cmd):
    d = tmp_path / "gshim"
    d.mkdir()
    real = shutil.which("grep")
    (d / "grep").write_text(
        "#!/bin/sh\n"
        'case "$*" in\n'
        + {"drop_first": f'  *-vxF*) {real} "$@" | sed 1d ;;\n',
           "keep_all": f'  *-vxF*) for f; do :; done; {REAL_CAT} "$f" ;;\n'}[filter_cmd] +
        f'  *) exec {real} "$@" ;;\n'
        "esac\n")
    (d / "grep").chmod(0o755)
    return d


def test_a_transform_that_loses_an_extra_line_is_refused(hosts, tmp_path):
    hosts.write_bytes(CASES["plain"])
    r = sh(gd.hosts_remove_script(LINE, str(hosts)), path_prefix=shim_grep(tmp_path, "drop_first"))
    assert r.returncode != 0 and hosts.read_bytes() == CASES["plain"]


def test_a_transform_that_keeps_the_marker_is_refused(hosts, tmp_path):
    hosts.write_bytes(CASES["plain"])
    r = sh(gd.hosts_remove_script(LINE, str(hosts)), path_prefix=shim_grep(tmp_path, "keep_all"))
    assert r.returncode != 0 and hosts.read_bytes() == CASES["plain"]
    assert b"marker still present" in r.stderr or b"line count" in r.stderr


def test_failed_restore_says_so_and_keeps_the_backup(hosts, tmp_path):
    orig = CASES["plain"]
    hosts.write_bytes(orig)
    shim = shim_cat(tmp_path, "partial")
    (shim / "restore-fails").write_text("")
    r = sh(gd.hosts_remove_script(LINE, str(hosts)), path_prefix=shim)
    assert r.returncode != 0
    assert b"RESTORE FAILED" in r.stderr and b"/orig" in r.stderr
    kept = re.search(rb"kept in (\S+)/orig", r.stderr).group(1).decode()
    assert open(kept + "/orig", "rb").read() == orig  # the backup survives for the operator


def test_remove_leaves_no_backup_directory_behind_on_success(hosts, tmp_path):
    hosts.write_bytes(CASES["plain"])
    tmp = tmp_path / "t"
    tmp.mkdir()
    env_script = f"TMPDIR='{tmp}'\nexport TMPDIR\n" + gd.hosts_remove_script(LINE, str(hosts))
    assert sh(env_script).returncode == 0
    assert list(tmp.iterdir()) == []


def test_remove_uses_a_private_mktemp_directory_not_a_fixed_name():
    s = gd.hosts_remove_script(LINE)
    assert "mktemp -d" in s and "trap" in s and "cmp" in s
    assert ".gameday-hosts" not in s


@pytest.mark.parametrize("name", ["plain", "no_final_newline", "multiple_final_newlines", "nul_content"])
def test_add_then_remove_keeps_the_original_lines(name, hosts):
    orig = CASES[name].replace(LB + b"\n", b"")
    hosts.write_bytes(orig)
    assert sh(gd.hosts_add_script(LINE, str(hosts))).returncode == 0
    added = hosts.read_bytes()
    assert added.endswith(LB + b"\n") and added.count(LB) == 1
    assert added.startswith(orig)
    assert sh(gd.hosts_remove_script(LINE, str(hosts))).returncode == 0
    assert hosts.read_bytes().rstrip(b"\n") == orig.rstrip(b"\n")


def test_add_to_a_file_without_a_final_newline_does_not_join_lines(hosts):
    hosts.write_bytes(b"127.0.0.1 localhost")
    assert sh(gd.hosts_add_script(LINE, str(hosts))).returncode == 0
    assert hosts.read_bytes() == b"127.0.0.1 localhost\n" + LB + b"\n"


# ---- 2. TOCTOU: swap after the guard ------------------------------------------

def shim_mktemp_swapping(tmp_path, hosts, victim):
    d = tmp_path / "swap"
    d.mkdir()
    (d / "mktemp").write_text(
        "#!/bin/sh\n"
        f"rm -f '{hosts}'\nln -s '{victim}' '{hosts}'\n"
        f'exec {REAL_MKTEMP} "$@"\n')
    (d / "mktemp").chmod(0o755)
    return d


def test_swapping_the_target_for_a_symlink_after_the_guard_leaves_the_victim_untouched(hosts, tmp_path):
    hosts.write_bytes(CASES["plain"])
    victim = tmp_path / "victim"
    victim.write_bytes(b"precious\n")
    r = sh(gd.hosts_remove_script(LINE, str(hosts)), path_prefix=shim_mktemp_swapping(tmp_path, hosts, victim))
    assert r.returncode != 0
    assert victim.read_bytes() == b"precious\n"


def test_the_write_is_preceded_by_a_symlink_recheck():
    s = gd.hosts_remove_script(LINE)
    assert s.count("chk ||") >= 4  # guard, before the copy, before the write, before a restore


# ---- 3. docker resolved from a fixed trusted set ----------------------------------

def make_exe(path, text, mode=0o755):
    path.parent.chmod(0o755)  # the umask may make new directories group writable
    path.write_text(text)
    path.chmod(mode)
    return path


def test_resolve_cli_picks_the_trusted_dir_not_the_path(tmp_path, monkeypatch):
    good, evil = tmp_path / "good", tmp_path / "evil"
    good.mkdir()
    evil.mkdir()
    make_exe(good / "docker", "#!/bin/sh\necho trusted\n")
    make_exe(evil / "docker", "#!/bin/sh\necho evil\n")
    monkeypatch.setenv("PATH", f"{evil}:/usr/bin:/bin")
    assert gd.resolve_cli("docker", (str(good),), os.geteuid()) == str(good / "docker")


def test_real_runner_runs_the_trusted_binary_even_with_a_malicious_path(tmp_path, monkeypatch):
    good, evil = tmp_path / "good", tmp_path / "evil"
    good.mkdir()
    evil.mkdir()
    make_exe(good / "docker", "#!/bin/sh\necho trusted\n")
    owned = tmp_path / "owned"
    make_exe(evil / "docker", f"#!/bin/sh\necho evil > '{owned}'\n")
    monkeypatch.setattr(gd, "TRUSTED_DIRS", (str(good),))
    monkeypatch.setattr(gd, "TRUSTED_UID", os.geteuid())
    monkeypatch.setenv("PATH", f"{evil}:/usr/bin:/bin")
    rc, out = gd.real_runner(["docker", "stop", "n8n"])
    assert rc == 0 and out == "trusted" and not owned.exists()


@pytest.mark.parametrize("problem", ["missing", "world_writable", "group_writable", "wrong_owner", "dir_writable"])
def test_untrusted_cli_is_refused(problem, tmp_path, monkeypatch):
    d = tmp_path / "t"
    d.mkdir()
    uid = os.geteuid()
    if problem != "missing":
        make_exe(d / "docker", "#!/bin/sh\necho x\n", {"world_writable": 0o757, "group_writable": 0o775}.get(problem, 0o755))
    if problem == "wrong_owner":
        uid = os.geteuid() + 1
    if problem == "dir_writable":
        d.chmod(0o777)  # after make_exe, which sets 755
    monkeypatch.setattr(gd, "TRUSTED_DIRS", (str(d),))
    monkeypatch.setattr(gd, "TRUSTED_UID", uid)
    rc, out = gd.real_runner(["docker", "stop", "n8n"])
    assert rc == 127 and "trusted" in out


def test_real_runner_does_not_pass_the_callers_path_on(tmp_path, monkeypatch):
    good = tmp_path / "good"
    good.mkdir()
    make_exe(good / "docker", '#!/bin/sh\necho "$PATH"\n')
    monkeypatch.setattr(gd, "TRUSTED_DIRS", (str(good),))
    monkeypatch.setattr(gd, "TRUSTED_UID", os.geteuid())
    monkeypatch.setenv("PATH", "/evil:/usr/bin")
    rc, out = gd.real_runner(["docker", "ps"])
    assert out == str(good) and "evil" not in out


def test_default_trusted_dirs_are_the_fixed_set():
    assert gd.TRUSTED_DIRS == ("/usr/bin", "/usr/local/bin", "/bin", "/snap/bin")
    assert gd.TRUSTED_UID == 0


# ---- 4. fullmatch for every validator ---------------------------------------------

@pytest.mark.parametrize("bad", ["abcdef01\n", "abcdef01\r\n", "abcdef01\nabcdef01", "abc\ndef01234", "\nabcdef01"])
def test_run_id_with_newlines_is_rejected(bad):
    rc, out, fakes = go(["discord-unreachable", "--run-id", bad])
    assert rc == 2 and "run-id" in out


@pytest.mark.parametrize("regex,good", [(gd.NAME_RE, "n8n"), (gd.HOST_RE, "discord.com"), (gd.PATH_RE, "p1"),
                                        (gd.ID_RE, "AbC1"), (gd.RUN_ID_RE, "abcdef01")])
@pytest.mark.parametrize("suffix", ["\n", "\r\n", "\nx"])
def test_every_validator_rejects_newlines(regex, good, suffix):
    gd._check(good, regex, "x")
    with pytest.raises(gd.GamedayError):
        gd._check(good + suffix, regex, "x")


@pytest.mark.parametrize("key,scenario,base", [
    ("GAMEDAY_N8N_CONTAINER", "n8n-down", "n8n"),
    ("GAMEDAY_DISCORD_HOST", "discord-unreachable", "discord.com"),
    ("GAMEDAY_ROUTER_PATH", "wrong-header", "p1"),
    ("GAMEDAY_ROUTER_WORKFLOW_ID", "router-inactive", "AbC1"),
])
def test_embedded_newline_in_config_is_refused_before_anything_runs(key, scenario, base):
    rc, out, fakes = go([scenario, "--apply", "--confirm-live"], env={**ENV, key: base + "\nx"})
    assert rc == 2 and fakes.commands == [] and fakes.posts == []


# ---- 5. docs: every command is runnable as written -----------------------------------

def doc_commands():
    text = (REPO_ROOT / "docs" / "game-day.md").read_text()
    spans = re.findall(r"`([^`\n]*gameday\.py[^`\n]*)`", text)
    return [s for s in spans if "--" in s or "list" in s]


def test_docs_have_commands_to_check():
    cmds = doc_commands()
    assert len(cmds) >= 4
    assert any("--revert" in c and "--apply" in c for c in cmds)


@pytest.mark.parametrize("scenario", gd.SCENARIO_NAMES)
def test_every_documented_command_runs_as_written(scenario, tmp_path):
    for cmd in doc_commands():
        cmd = re.sub(r"\[--run-id <id>\]", "--run-id " + RID, cmd)
        cmd = cmd.replace("<id>", RID).replace("SCENARIO", scenario)
        cmd = re.sub(r"\bID\b", RID, cmd).replace("RESULTS.jsonl", str(tmp_path / "r.jsonl"))
        cmd = re.sub(r"^(python3 )?(scripts/)?gameday\.py\s*", "", cmd)
        if cmd.startswith("list"):
            continue
        rc, out, _ = go(shlex.split(cmd))
        assert rc == 0, (cmd, out)
