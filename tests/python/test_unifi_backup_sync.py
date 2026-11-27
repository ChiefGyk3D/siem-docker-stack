"""Guards for the UniFi Pi backup sync (issue #228): scripts/unifi-backup-sync.sh, its systemd
units, its Grafana alert rules and its doc.

The script runs against fake mount, umount, mountpoint, cp and id binaries in a scratch directory
under this worktree. It never mounts anything and never opens the network. Command paths are fixed
lines in the script; a scratch copy of the script has those lines rewritten to the fakes (the same
approach as the other collector tests), so the real script has no test hooks.
"""
import os
import re
import shutil
import signal
import sys
import subprocess
import tempfile
import time
from pathlib import Path

import pytest
import yaml

from conftest import REPO_ROOT

SCRIPT = REPO_ROOT / "scripts" / "unifi-backup-sync.sh"
SERVICE = REPO_ROOT / "docs" / "systemd" / "unifi-backup-sync.service"
TIMER = REPO_ROOT / "docs" / "systemd" / "unifi-backup-sync.timer"
RULES = REPO_ROOT / "docker" / "grafana" / "provisioning" / "alerting" / "unifi-backup-alert-rule.yml"
POLICY = REPO_ROOT / "docker" / "grafana" / "provisioning" / "alerting" / "unifi-backup-notification-policy.yml.example"
DOC = REPO_ROOT / "docs" / "unifi-pi-backup.md"
SCRATCH_ROOT = REPO_ROOT / "tests" / "python" / "_scratch"

NOW = 1_800_000_000
DAY = 86400
SECRET = "-".join(["canary", "zq" * 4, "end"])  # built at run time, so no secret-shaped literal is in the file
GOOD_NAMES = (
    "autobackup_9.0.114_20261109_0300_1793000000.unf",
    "autobackup_9.0.114_20261116_0300_1793604800.unf",
    "autobackup_9.0.114_20261123_0300_1794209600.unf",
)

REAL = {
    "mv_bin": "/usr/bin/mv", "rm_bin": "/usr/bin/rm", "env_bin": "/usr/bin/env",
    "mkdir_bin": "/usr/bin/mkdir",
}


def _fake(path: Path, body: str) -> Path:
    path.write_text("#!/bin/sh\n" + body, encoding="utf-8")
    path.chmod(0o755)
    return path


class Env:
    """One scratch world: source dir, NAS mount point, state dir, credentials, fakes, a script copy."""

    def __init__(self, root: Path, mutate=None):
        self.root = root
        self.src = root / "src"
        self.mp = root / "mnt"
        self.state = root / "state"
        self.bin = root / "bin"
        self.log = root / "calls.log"
        self.marker = root / "mounted"
        self.creds = root / "smb-credentials"
        for d in (self.src, self.mp, self.state, self.bin):
            d.mkdir()
        self.state.chmod(0o700)
        self.creds.write_text("username=backup\npassword=%s\n" % SECRET, encoding="utf-8")
        self.creds.chmod(0o600)
        me = os.getuid()
        _fake(self.bin / "id", 'echo "${FAKE_UID:-%d}"\n' % me)
        _fake(self.bin / "date", 'echo "$FAKE_NOW"\n')
        # Like the real cifs driver, the fake refuses `nosymfollow` inside -o of the first mount
        # ("cifs: Unknown parameter"); only the later bind remount may set it. The fake keeps its
        # current options in a file and rewrites the fake mountinfo after every call.
        opts_file, mi, mp = root / "fake-opts", root / "mountinfo", self.mp.resolve()
        _fake(self.bin / "mount", (
            'echo "mount $*" >> "$FAKE_LOG"\n'
            '[ "${FAKE_MOUNT_FAIL:-0}" = 1 ] && exit 32\n'
            'o=""; p=""; for a; do [ "$p" = -o ] && o=$a; p=$a; done\n'
            'gen() { printf "22 1 0:21 / / rw - ext4 /dev/sda1 rw\\n36 22 0:30 / %%s %%s shared:1 - cifs //nas.example.internal/unifi-backups rw\\n" "%s" "$(cat "%s")" > "%s"; }\n'
            'case "$o" in\n'
            '  remount,*)\n'
            '    [ "${FAKE_REMOUNT_FAIL:-0}" = 1 ] && exit 32\n'
            '    [ "${FAKE_REMOUNT_NOEFFECT:-0}" = 1 ] && exit 0\n'
            '    cur=$(cat "%s"); new="$cur,nosymfollow"\n'
            '    [ "${FAKE_REMOUNT_DROP_NOSUID:-0}" = 1 ] && new=$(echo "$new" | sed "s/,nosuid//")\n'
            '    [ "${FAKE_REMOUNT_FLIP_RO:-0}" = 1 ] && new=$(echo "$new" | sed "s/^rw/ro/")\n'
            '    echo "$new" > "%s"; gen ;;\n'
            '  *nosymfollow*) echo "cifs: Unknown parameter nosymfollow" >&2; exit 32 ;;\n'
            '  *) kept=""; mode=""; IFS=,; for t in $o; do\n'
            '       case "$t" in ro|rw) mode=$t ;; nosuid|nodev|noexec) kept="$kept,$t" ;; esac\n'
            '     done; unset IFS\n'
            '     # like the kernel: one mode token, the last one asked for wins\n'
            '     kept="$mode$kept"\n'
            '     [ -n "${FAKE_MOUNT_LISTING:-}" ] && kept=$FAKE_MOUNT_LISTING\n'
            '     echo "$kept" > "%s"; gen; : > "$FAKE_MARKER" ;;\n'
            'esac\n') % (mp, opts_file, mi, opts_file, opts_file, opts_file))
        _fake(self.bin / "umount", 'echo "umount $*" >> "$FAKE_LOG"\n'
              '[ "${FAKE_UMOUNT_FAIL:-0}" = 1 ] && exit 1\nrm -f "$FAKE_MARKER"\n')
        _fake(self.bin / "mountpoint", '[ -e "$FAKE_MARKER" ]\n')
        _fake(self.bin / "stat", (
            'out=$(/usr/bin/stat "$@"); rc=$?\n'
            'for last; do :; done\n'
            'if [ -n "${FAKE_OTHER_DEV:-}" ] && [ "$*" = "-c %d -- $last" ]; then\n'
            '  case "$last" in */"$FAKE_OTHER_DEV") out=999999999 ;; esac\n'
            'fi\n'
            'if [ -n "${FAKE_OTHER_DEV:-}" ]; then\n'
            '  case "$*" in *"%F|"*) case "$last" in */"$FAKE_OTHER_DEV") out=$(printf "%s" "$out" | /usr/bin/sed "s/^\\([^|]*\\)|[^|]*|/\\1|999999999|/") ;; esac ;; esac\n'
            'fi\n'
            'printf "%s\\n" "$out"\n'
            'if [ -n "${FAKE_SWAP_PATH:-}" ] && [ -z "${FAKE_SWAP_AFTER_CP:-}" ] && [ ! -e "$FAKE_SWAP_DONE" ] && [ "$last" = "$FAKE_SWAP_PATH" ]; then\n'
            '  case "$*" in *"%F|"*) : > "$FAKE_SWAP_DONE"; /usr/bin/rm -f "$last"\n'
            '    if [ -n "${FAKE_SWAP_WRITE:-}" ]; then printf "new backup" > "$last"; elif [ -n "${FAKE_SWAP_FIFO:-}" ]; then /usr/bin/mkfifo "$last"; elif [ -n "${FAKE_SWAP_HARDLINK:-}" ]; then /usr/bin/ln "$FAKE_SWAP_TARGET" "$last"; else /usr/bin/ln -s "$FAKE_SWAP_TARGET" "$last"; fi ;; esac\n'
            'fi\n'
            'exit $rc\n'))
        # The helper runs under `env -i`, so the fakes it reaches read their switches from a file.
        src_env = '. "%s"\n' % (root / "fake.env")
        _fake(self.bin / "perl", src_env + (
            'op=$2\n'
            'if [ "$op" = stage ]; then\n'
            '  [ "${FAKE_CP_FAIL:-0}" = 1 ] && exit 1\n'
            '  if [ -n "${FAKE_CP_SLEEP:-}" ]; then : > "$FAKE_STARTED"; /usr/bin/sleep "$FAKE_CP_SLEEP"; fi\n'
            'fi\n'
            '/usr/bin/perl "$@"; rc=$?\n'
            'if [ "$op" = stage ] && [ -n "${FAKE_SWAP_AFTER_CP:-}" ] && [ ! -e "$FAKE_SWAP_DONE" ]; then\n'
            '  : > "$FAKE_SWAP_DONE"; /usr/bin/rm -f "$FAKE_SWAP_PATH"; /usr/bin/ln -s "$FAKE_SWAP_TARGET" "$FAKE_SWAP_PATH"\n'
            'fi\n'
            'exit $rc\n'))
        _fake(self.bin / "sha256sum", src_env + (
            'n=$(/usr/bin/cat "%s" 2>/dev/null || echo 0); n=$((n + 1)); echo $n > "%s"\n'
            '/usr/bin/sha256sum "$@"; rc=$?\n'
            '[ -n "${FAKE_SHA_FAIL_FROM:-}" ] && [ "$n" -ge "$FAKE_SHA_FAIL_FROM" ] && exit 1\n'
            'exit $rc\n') % (root / "sha.count", root / "sha.count"))
        _fake(self.bin / "df", 'if [ -n "${FAKE_DF_AVAIL:-}" ]; then\n'
              '  echo "Filesystem 1024-blocks Used Available Capacity Mounted on"\n'
              '  echo "fake 100 1 $FAKE_DF_AVAIL 1% /"\n'
              'else /usr/bin/df "$@"; fi\n')
        text = SCRIPT.read_text(encoding="utf-8")
        repl = dict(REAL)
        repl.update({
            "stat_bin": str(self.bin / "stat"),
            "id_bin": str(self.bin / "id"), "date_bin": str(self.bin / "date"),
            "perl_bin": str(self.bin / "perl"), "sha256_bin": str(self.bin / "sha256sum"),
            "mountinfo_file": str(root / "mountinfo"),
            "df_bin": str(self.bin / "df"), "mount_bin": str(self.bin / "mount"),
            "umount_bin": str(self.bin / "umount"), "mountpoint_bin": str(self.bin / "mountpoint"),
            "root_uid": str(me),
        })
        for name, val in repl.items():
            text, n = re.subn(r"(?m)^%s=\S+$" % name, "%s=%s" % (name, val), text)
            assert n == 1, "fixed line %s not found exactly once" % name
        self.mountinfo = root / "mountinfo"
        self.set_mountinfo("rw,nosuid,nodev,noexec,nosymfollow")
        self.text = text
        if mutate:
            self.text = mutate(self.text)
        self.script = root / "unifi-backup-sync.sh"
        self.script.write_text(self.text, encoding="utf-8")
        self.script.chmod(0o755)
        self.nas = self.mp / "unifi-autobackup"

    def set_mountinfo(self, opts):
        """A fake /proc/self/mountinfo: the NAS mount point with the given per-mount options."""
        lines = ["22 1 0:21 / / rw - ext4 /dev/sda1 rw"]
        if opts is not None:
            lines.append("36 22 0:30 / %s %s shared:1 - cifs //nas.example.internal/unifi-backups rw" % (self.mp.resolve(), opts))
        self.mountinfo.write_text("\n".join(lines) + "\n", encoding="utf-8")

    def set_hook(self, marker, perl_code):
        """Replace a `# test-hook: <marker>` comment of the helper by perl code in the scratch copy."""
        needle = "# test-hook: %s" % marker
        assert self.text.count(needle) == 1, marker
        self.text = self.text.replace(needle, perl_code)
        self.script.write_text(self.text, encoding="utf-8")

    def add_source(self, name, content=None, age_days=0, size=2048):
        p = self.src / name
        p.write_bytes(content if content is not None else (name.encode() * 200)[:size])
        t = NOW - int(age_days * DAY)
        os.utime(p, (t, t))
        return p

    def env(self, **extra):
        e = {
            "PATH": "/usr/bin:/bin", "FAKE_NOW": str(NOW), "FAKE_LOG": str(self.log),
            "FAKE_MARKER": str(self.marker), "FAKE_STARTED": str(self.root / "started"),
            "FAKE_SWAP_DONE": str(self.root / "swapped"),
            "UNIFI_BACKUP_SRC": str(self.src), "NAS_MOUNT_POINT": str(self.mp),
            "NAS_SHARE": "//nas.example.internal/unifi-backups",
            "SMB_CREDENTIALS_FILE": str(self.creds), "STATE_DIRECTORY": str(self.state),
        }
        e.update(extra)
        fake = {k: v for k, v in e.items() if k.startswith("FAKE_")}
        (self.root / "fake.env").write_text(
            "".join("export %s='%s'\n" % (k, v) for k, v in fake.items()), encoding="utf-8")
        return e

    def run(self, *args, **extra):
        return subprocess.run(["/bin/sh", str(self.script), *args], env=self.env(**extra),
                              capture_output=True, text=True, timeout=60)

    def calls(self):
        return self.log.read_text(encoding="utf-8").splitlines() if self.log.exists() else []

    def nas_files(self):
        return sorted(p.name for p in self.nas.iterdir()) if self.nas.exists() else []


@pytest.fixture()
def env():
    SCRATCH_ROOT.mkdir(exist_ok=True)
    old_umask = os.umask(0o022)
    try:
        with tempfile.TemporaryDirectory(dir=SCRATCH_ROOT) as d:
            yield Env(Path(d))
    finally:
        os.umask(old_umask)


def _metrics(out):
    result = {}
    for line in out.splitlines():
        m = re.fullmatch(r"([a-z_]+)((?:,[a-z]+=[a-z]+)?) value=(\d+)i", line)
        assert m, "not a line-protocol line: %r" % line
        result[m.group(1) + m.group(2)] = int(m.group(3))
    return result


def _populate(e):
    for i, n in enumerate(GOOD_NAMES):
        e.add_source(n, age_days=14 - 7 * i)  # 14, 7 and 0 days old


def _assert_unmounted_clean(e):
    calls = e.calls()
    mounts = [c for c in calls if c.startswith("mount ") and "remount" not in c]
    umounts = [c for c in calls if c.startswith("umount ")]
    assert len(mounts) == len(umounts), calls
    assert not e.marker.exists()


# --- happy path --------------------------------------------------------------------------------

def test_happy_path_copies_verifies_and_reports(env):
    _populate(env)
    env.add_source("autobackup_meta.json", content=b"{}")
    env.add_source("notes.unf", content=b"x")
    env.add_source("autobackup_9.0.114_2026_0300_1.unf;rm.unf", content=b"x")
    r = env.run()
    assert r.returncode == 0, r.stderr
    assert env.nas_files() == sorted(GOOD_NAMES)
    for n in GOOD_NAMES:
        assert (env.nas / n).read_bytes() == (env.src / n).read_bytes()
        assert int((env.nas / n).stat().st_mtime) == int((env.src / n).stat().st_mtime)
    m = _metrics(r.stdout)
    assert m["unifi_backup_newest_age_seconds,where=local"] == 0
    assert m["unifi_backup_newest_age_seconds,where=nas"] == 0
    assert m["unifi_backup_count,where=local"] == 3
    assert m["unifi_backup_count,where=nas"] == 3
    assert m["unifi_backup_sync_last_success_timestamp"] == NOW
    assert m["unifi_backup_sync_success"] == 1
    assert m["unifi_backup_sync_result_code"] == 0
    assert (env.state / "last-success").read_text().strip() == str(NOW)
    calls = env.calls()
    assert any(" rw" in c or ",rw" in c for c in calls if c.startswith("mount "))
    assert any("credentials=%s" % env.creds in c for c in calls)
    _assert_unmounted_clean(env)


def test_second_run_copies_only_new_files(env):
    _populate(env)
    assert env.run().returncode == 0
    first = (env.nas / GOOD_NAMES[0]).stat().st_ino
    env.add_source("autobackup_9.0.114_20261130_0300_1794814400.unf")
    assert env.run().returncode == 0
    assert (env.nas / GOOD_NAMES[0]).stat().st_ino == first
    assert len(env.nas_files()) == 4


def test_ages_are_measured_from_file_times(env):
    env.add_source(GOOD_NAMES[0], age_days=9)
    env.add_source(GOOD_NAMES[1], age_days=20)
    r = env.run()
    m = _metrics(r.stdout)
    assert m["unifi_backup_newest_age_seconds,where=local"] == 9 * DAY
    assert m["unifi_backup_newest_age_seconds,where=nas"] == 9 * DAY


# --- refusals ----------------------------------------------------------------------------------

def test_empty_source_refuses(env):
    env.add_source("autobackup_meta.json", content=b"{}")
    r = env.run()
    assert r.returncode == 1
    assert _metrics(r.stdout) == {"unifi_backup_sync_success": 0, "unifi_backup_sync_result_code": 2}
    assert env.calls() == [] and env.nas_files() == []
    assert not (env.state / "last-success").exists()


def test_missing_source_refuses(env):
    shutil.rmtree(env.src)
    r = env.run()
    assert r.returncode == 1
    assert _metrics(r.stdout)["unifi_backup_sync_result_code"] == 2
    assert env.calls() == []


def test_refuses_when_not_root(env):
    _populate(env)
    r = env.run(FAKE_UID="4242")
    assert r.returncode == 1
    assert _metrics(r.stdout)["unifi_backup_sync_result_code"] == 1
    assert env.calls() == []


@pytest.mark.parametrize("key,val", [
    ("RETENTION_DAYS", "abc"), ("RETENTION_DAYS", "0"), ("RETENTION_DAYS", "007"),
    ("RETENTION_DAYS", "99999"), ("UNIFI_BACKUP_SRC", "relative/path"),
    ("UNIFI_BACKUP_SRC", "/a/../b"), ("NAS_MOUNT_POINT", "rel"), ("NAS_DEST_SUBDIR", "a/b"),
    ("NAS_DEST_SUBDIR", ".."), ("SMB_VERS", "3.0,sec=none"), ("NAS_SHARE", "bad share"),
])
def test_bad_settings_fail_closed(env, key, val):
    _populate(env)
    r = env.run(**{key: val})
    assert r.returncode == 1
    assert _metrics(r.stdout)["unifi_backup_sync_result_code"] == 1
    assert env.calls() == []


def test_credentials_file_with_open_mode_refused(env):
    _populate(env)
    env.creds.chmod(0o644)
    r = env.run()
    assert r.returncode == 1 and env.calls() == []
    assert SECRET not in r.stdout + r.stderr


def test_mount_failure_is_a_failure(env):
    _populate(env)
    r = env.run(FAKE_MOUNT_FAIL="1")
    assert r.returncode == 1
    assert _metrics(r.stdout)["unifi_backup_sync_result_code"] == 3
    assert env.nas_files() == []


def test_already_mounted_without_opt_in_refused(env):
    _populate(env)
    env.marker.write_text("")
    r = env.run()
    assert r.returncode == 1
    assert _metrics(r.stdout)["unifi_backup_sync_result_code"] == 3
    assert env.calls() == [] and env.marker.exists()


def test_existing_mount_is_used_and_left_mounted(env):
    _populate(env)
    env.marker.write_text("")
    r = env.run(NAS_USE_EXISTING_MOUNT="1", SMB_CREDENTIALS_FILE="")
    assert r.returncode == 0, r.stderr
    assert env.calls() == [] and env.marker.exists()
    assert len(env.nas_files()) == 3


def test_existing_mount_opt_in_but_not_mounted_refused(env):
    _populate(env)
    r = env.run(NAS_USE_EXISTING_MOUNT="1")
    assert r.returncode == 1 and env.nas_files() == []


# --- failures keep the NAS safe and unmount -----------------------------------------------------

def test_failing_copy(env):
    _populate(env)
    r = env.run(FAKE_CP_FAIL="1")
    assert r.returncode == 1
    m = _metrics(r.stdout)
    assert m["unifi_backup_sync_result_code"] == 4 and m["unifi_backup_sync_success"] == 0
    assert "unifi_backup_newest_age_seconds,where=nas" not in m
    assert env.nas_files() == []
    assert not (env.state / "last-success").exists()
    _assert_unmounted_clean(env)


def test_checksum_mismatch_never_publishes_the_file(env):
    _populate(env)
    env.set_hook("after-upload-write", "sysseek($out, 0, 0); syswrite($out, \"Z\", 1);")
    r = env.run()
    assert r.returncode == 1
    assert _metrics(r.stdout)["unifi_backup_sync_result_code"] == 5
    assert env.nas_files() == []  # no final file and no leftover temp file
    _assert_unmounted_clean(env)


def test_existing_copy_with_other_size_is_not_overwritten(env):
    _populate(env)
    env.nas.mkdir()
    (env.nas / GOOD_NAMES[0]).write_bytes(b"short")
    r = env.run()
    assert r.returncode == 1
    assert _metrics(r.stdout)["unifi_backup_sync_result_code"] == 5
    assert (env.nas / GOOD_NAMES[0]).read_bytes() == b"short"
    assert len(env.nas_files()) == 3  # the other two were still copied
    _assert_unmounted_clean(env)


def test_failed_run_keeps_the_old_success_time(env):
    _populate(env)
    (env.state / "last-success").write_text("1799000000\n")
    r = env.run(FAKE_CP_FAIL="1")
    m = _metrics(r.stdout)
    assert m["unifi_backup_sync_last_success_timestamp"] == 1799000000
    assert (env.state / "last-success").read_text().strip() == "1799000000"


def test_failure_prints_no_zero_valued_metrics(env):
    _populate(env)
    r = env.run(FAKE_CP_FAIL="1")
    assert set(_metrics(r.stdout)) <= {
        "unifi_backup_sync_success", "unifi_backup_sync_result_code",
        "unifi_backup_sync_last_success_timestamp"}


def test_unmount_failure_is_a_failure_and_state_not_advanced(env):
    _populate(env)
    r = env.run(FAKE_UMOUNT_FAIL="1")
    assert r.returncode == 1
    assert _metrics(r.stdout)["unifi_backup_sync_result_code"] == 3
    assert not (env.state / "last-success").exists()


def test_sigterm_during_copy_unmounts(env):
    _populate(env)
    p = subprocess.Popen(["/bin/sh", str(env.script)], env=env.env(FAKE_CP_SLEEP="30"),
                         stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
                         start_new_session=True)
    started = env.root / "started"
    for _ in range(100):
        if started.exists():
            break
        time.sleep(0.1)
    assert started.exists()
    os.killpg(p.pid, signal.SIGTERM)
    out, err = p.communicate(timeout=30)
    assert p.returncode != 0
    assert _metrics(out)["unifi_backup_sync_success"] == 0
    _assert_unmounted_clean(env)
    assert not (env.state / "last-success").exists()


# --- prune -------------------------------------------------------------------------------------

def test_prune_removes_only_old_exact_pattern_files(env):
    _populate(env)
    env.nas.mkdir()
    old = "autobackup_8.0.1_20250101_0300_1735700000.unf"
    keepers = {
        "notes.txt": 400, "autobackup_meta.json": 400, "old.unf": 400,
        "autobackup_bad.unf": 400, ".partial-autobackup_9.0.114_20200101_0300_1.unf": 400,
        "autobackup_8.0.1_20250101_0300_1735700001.unf.bak": 400,
        "autobackup_8.0.1_20260101_0300_1767225600.unf": 60,  # inside retention
    }
    (env.nas / old).write_bytes(b"old")
    os.utime(env.nas / old, (NOW - 400 * DAY,) * 2)
    for n, age in keepers.items():
        (env.nas / n).write_bytes(b"keep")
        os.utime(env.nas / n, (NOW - age * DAY,) * 2)
    (env.nas / "sub").mkdir()
    (env.nas / "sub" / old).write_bytes(b"nested")
    r = env.run()
    assert r.returncode == 0, r.stderr
    left = set(env.nas_files())
    assert old not in left
    assert set(keepers) <= left and set(GOOD_NAMES) <= left and "sub" in left
    assert (env.nas / "sub" / old).exists()
    _assert_unmounted_clean(env)


def test_prune_never_removes_the_newest_copy(env):
    env.add_source(GOOD_NAMES[0], age_days=400)  # every backup is older than the retention
    r = env.run()
    assert r.returncode == 0, r.stderr
    assert env.nas_files() == [GOOD_NAMES[0]]
    assert _metrics(r.stdout)["unifi_backup_newest_age_seconds,where=nas"] == 400 * DAY


def test_retention_is_configurable(env):
    _populate(env)  # 14, 7, 0 days old
    r = env.run(RETENTION_DAYS="10")
    assert r.returncode == 0, r.stderr
    assert env.nas_files() == sorted(GOOD_NAMES[1:])


def test_no_prune_after_a_failed_copy(env):
    _populate(env)
    env.nas.mkdir()
    old = "autobackup_8.0.1_20250101_0300_1735700000.unf"
    (env.nas / old).write_bytes(b"old")
    os.utime(env.nas / old, (NOW - 400 * DAY,) * 2)
    recent = "autobackup_8.0.1_20261126_0300_1795000000.unf"  # makes the old copy prunable
    (env.nas / recent).write_bytes(b"recent")
    os.utime(env.nas / recent, (NOW - DAY,) * 2)
    r = env.run(FAKE_CP_FAIL="1")
    assert r.returncode == 1
    assert (env.nas / old).exists() and (env.nas / recent).exists()
    ok = env.run()  # the same setup prunes once the copies work
    assert ok.returncode == 0, ok.stderr
    assert not (env.nas / old).exists()


def test_source_is_never_modified(env):
    _populate(env)
    before = {p.name: (p.read_bytes(), p.stat().st_mtime) for p in env.src.iterdir()}
    env.run()
    after = {p.name: (p.read_bytes(), p.stat().st_mtime) for p in env.src.iterdir()}
    assert before == after


# --- race and link attacks (reviewer findings, issue #228) -----------------------------------------

def _secret(env):
    p = env.root / "root-only-secret"
    p.write_bytes((b"ROOT-ONLY-CONTENT" * 130)[:2048])  # same size as the backups, so a size check alone cannot catch a swap
    return p


def _nas_blob(env):
    return b"".join(p.read_bytes() for p in env.mp.rglob("*") if p.is_file() and not p.is_symlink())


def test_source_symlink_named_like_a_backup_is_refused(env):
    _populate(env)
    secret = _secret(env)
    (env.src / "autobackup_9.0.114_20261130_0300_1794814400.unf").symlink_to(secret)
    r = env.run()
    assert r.returncode == 1
    assert _metrics(r.stdout)["unifi_backup_sync_result_code"] == 2
    assert b"ROOT-ONLY-CONTENT" not in _nas_blob(env)
    assert not env.nas_files() or "autobackup_9.0.114_20261130_0300_1794814400.unf" not in env.nas_files()
    _assert_unmounted_clean(env)


def test_source_hardlink_is_refused(env):
    _populate(env)
    secret = _secret(env)
    os.link(secret, env.src / "autobackup_9.0.114_20261130_0300_1794814400.unf")
    os.utime(env.src / "autobackup_9.0.114_20261130_0300_1794814400.unf", (NOW, NOW))
    r = env.run()
    assert r.returncode == 1
    assert _metrics(r.stdout)["unifi_backup_sync_result_code"] == 2
    assert b"ROOT-ONLY-CONTENT" not in _nas_blob(env)


def test_source_folder_symlink_is_refused(env):
    _populate(env)
    real = env.root / "real-src"
    env.src.rename(real)
    env.src.symlink_to(real)
    r = env.run()
    assert r.returncode == 1
    assert _metrics(r.stdout)["unifi_backup_sync_result_code"] == 2
    assert env.calls() == []


def test_source_swapped_for_a_symlink_between_check_and_open(env):
    _populate(env)
    secret = _secret(env)
    victim = env.src / GOOD_NAMES[1]
    r = env.run(FAKE_SWAP_PATH=str(victim), FAKE_SWAP_TARGET=str(secret))
    assert (env.root / "swapped").exists(), "the fake did not swap; the test proves nothing"
    assert r.returncode == 1
    assert _metrics(r.stdout)["unifi_backup_sync_result_code"] == 5
    assert b"ROOT-ONLY-CONTENT" not in _nas_blob(env)
    assert GOOD_NAMES[1] not in env.nas_files()
    _assert_unmounted_clean(env)


def test_source_swapped_for_a_symlink_during_the_copy(env):
    _populate(env)
    secret = _secret(env)
    victim = env.src / GOOD_NAMES[0]
    r = env.run(FAKE_SWAP_AFTER_CP="1", FAKE_SWAP_PATH=str(victim), FAKE_SWAP_TARGET=str(secret))
    assert (env.root / "swapped").exists()
    assert r.returncode == 1
    assert _metrics(r.stdout)["unifi_backup_sync_result_code"] == 5
    assert b"ROOT-ONLY-CONTENT" not in _nas_blob(env)
    assert not list(env.state.rglob("current")) or not (env.state / "stage" / "current").exists()
    _assert_unmounted_clean(env)


def test_staging_file_is_removed_after_every_run(env):
    _populate(env)
    env.run()
    env.run(FAKE_CP_FAIL="1")
    assert not (env.state / "stage" / "current").exists()


def test_symlinked_destination_is_refused(env):
    _populate(env)
    elsewhere = env.root / "elsewhere"
    elsewhere.mkdir()
    env.nas.symlink_to(elsewhere)
    r = env.run()
    assert r.returncode == 1
    assert _metrics(r.stdout)["unifi_backup_sync_result_code"] == 3
    assert list(elsewhere.iterdir()) == []
    _assert_unmounted_clean(env)


def test_destination_on_another_device_is_refused(env):
    _populate(env)
    env.nas.mkdir()
    r = env.run(FAKE_OTHER_DEV="unifi-autobackup")
    assert r.returncode == 1
    assert _metrics(r.stdout)["unifi_backup_sync_result_code"] == 3
    assert env.nas_files() == []


def test_prune_candidate_on_another_device_is_left_alone(env):
    _populate(env)
    env.nas.mkdir()
    old = "autobackup_8.0.1_20250101_0300_1735700000.unf"
    (env.nas / old).write_bytes(b"old")
    os.utime(env.nas / old, (NOW - 400 * DAY,) * 2)
    r = env.run(FAKE_OTHER_DEV=old)
    assert r.returncode == 1
    assert _metrics(r.stdout)["unifi_backup_sync_result_code"] == 6
    assert (env.nas / old).exists()
    _assert_unmounted_clean(env)


def test_prune_never_touches_a_symlink_named_like_a_backup(env):
    _populate(env)
    env.nas.mkdir()
    victim = env.root / "victim-outside"
    victim.write_bytes(b"outside")
    os.utime(victim, (NOW - 400 * DAY,) * 2)
    link = env.nas / "autobackup_8.0.1_20250101_0300_1735700000.unf"
    link.symlink_to(victim)
    os.utime(link, (NOW - 400 * DAY,) * 2, follow_symlinks=False)
    r = env.run()
    assert r.returncode == 0, r.stderr
    assert link.is_symlink() and victim.read_bytes() == b"outside"


def test_mount_options_do_not_follow_symlinks(env):
    _populate(env)
    env.run()
    mounts = [c for c in env.calls() if c.startswith("mount ")]
    assert len(mounts) == 2, mounts
    first, second = mounts
    assert "nosymfollow" not in first and "-t cifs" in first  # the cifs driver rejects it in -o
    assert "-o remount,bind,nosymfollow " in second + " " and str(env.mp) in second
    assert "nosymfollow" in env.mountinfo.read_text(encoding="utf-8")


def _remount_failure_is_closed(env, **extra):
    _populate(env)
    r = env.run(**extra)
    assert r.returncode == 1
    assert _metrics(r.stdout)["unifi_backup_sync_result_code"] == 3
    assert not env.nas.exists() and env.nas_files() == []  # nothing was written to the share
    assert not (env.state / "last-success").exists()
    _assert_unmounted_clean(env)
    return r


def test_remount_failure_fails_closed_and_unmounts(env):
    _remount_failure_is_closed(env, FAKE_REMOUNT_FAIL="1")


def test_remount_without_the_option_in_mountinfo_fails_closed(env):
    r = _remount_failure_is_closed(env, FAKE_REMOUNT_NOEFFECT="1")
    assert "nosymfollow" in r.stderr


def test_remount_that_drops_nosuid_fails_closed(env):
    _remount_failure_is_closed(env, FAKE_REMOUNT_DROP_NOSUID="1")


def test_remount_that_flips_read_write_fails_closed(env):
    _remount_failure_is_closed(env, FAKE_REMOUNT_FLIP_RO="1")


# --- mount options come only from what the script asks for (Daybreak on PR 250, DBR-228-01) ---------

def _env_with(tmp_root, edit):
    return Env(tmp_root, mutate=edit)


@pytest.mark.parametrize("mode_args,mode", [((), "rw"), (("--dry-run",), "ro")])
def test_first_mount_asks_for_the_mode_and_every_hardening_flag(env, mode_args, mode):
    _populate(env)
    env.run(*mode_args)
    first = [c for c in env.calls() if c.startswith("mount ") and "remount" not in c][0]
    opts = first.split(" -o ")[1].split(" ")[0].split(",")
    assert opts[0] == mode
    for flag in ("nosuid", "nodev", "noexec"):
        assert flag in opts, flag
    assert "nosymfollow" not in opts
    other = "ro" if mode == "rw" else "rw"
    assert other not in opts
    info = env.mountinfo.read_text(encoding="utf-8")
    assert ("%s,nosuid,nodev,noexec,nosymfollow" % mode) in info
    assert not re.search(r"[ ,]%s[ ,]" % other, info.splitlines()[1])


@pytest.mark.parametrize("dropped,old,new", [
    ("nosuid", ",nosuid,nodev,noexec\"", ",nodev,noexec\""),
    ("nodev", ",nosuid,nodev,noexec\"", ",nosuid,noexec\""),
    ("noexec", ",nosuid,nodev,noexec\"", ",nosuid,nodev\""),
    ("mode", '-o "$mode,credentials=', '-o "credentials='),
])
def test_script_that_stops_asking_for_a_flag_fails_closed(dropped, old, new):
    SCRATCH_ROOT.mkdir(exist_ok=True)
    with tempfile.TemporaryDirectory(dir=SCRATCH_ROOT) as d:
        def edit(text):
            assert text.count(old) == 1, dropped
            return text.replace(old, new)
        e = _env_with(Path(d), edit)
        _populate(e)
        r = e.run()
        assert r.returncode == 1, r.stderr
        assert _metrics(r.stdout)["unifi_backup_sync_result_code"] == 3
        assert "missing the required option" in r.stderr
        assert not e.nas.exists()
        _assert_unmounted_clean(e)


@pytest.mark.parametrize("args,listing", [
    ((), "ro,rw,nosuid,nodev,noexec"),        # both modes listed
    ((), "nosuid,nodev,noexec"),              # no mode listed
    ((), "ro,nosuid,nodev,noexec"),           # the other mode than the one asked for
    (("--dry-run",), "rw,nosuid,nodev,noexec"),   # a dry run that came up read-write
    (("--dry-run",), "ro,rw,nosuid,nodev,noexec"),
    (("--dry-run",), "nosuid,nodev,noexec"),
])
def test_read_back_needs_exactly_the_requested_mode(env, args, listing):
    _populate(env)
    r = env.run(*args, FAKE_MOUNT_LISTING=listing)
    assert r.returncode == 1
    if args:  # a dry run prints no metrics, not even on a failure
        assert r.stdout == ""
    else:
        assert _metrics(r.stdout)["unifi_backup_sync_result_code"] == 3
    assert "exactly one of ro or rw" in r.stderr
    assert not env.nas.exists() and env.nas_files() == []
    _assert_unmounted_clean(env)


def test_a_dry_run_request_for_both_modes_is_read_write_like_the_kernel_and_refused():
    SCRATCH_ROOT.mkdir(exist_ok=True)
    with tempfile.TemporaryDirectory(dir=SCRATCH_ROOT) as d:
        def edit(text):
            old = '-o "$mode,credentials='
            assert text.count(old) == 1
            return text.replace(old, '-o "$mode,rw,credentials=')
        e = _env_with(Path(d), edit)
        _populate(e)
        r = e.run("--dry-run")
        assert r.returncode == 1
        assert r.stdout == "" and "exactly one of ro or rw" in r.stderr
        _assert_unmounted_clean(e)


# --- Daybreak round 1 findings (PR 240) -----------------------------------------------------------

def test_planted_partial_symlink_is_not_followed(env):
    _populate(env)
    env.nas.mkdir()
    victim = env.root / "victim-outside"
    victim.write_bytes(b"victim-original")
    (env.nas / (".partial-" + GOOD_NAMES[0])).symlink_to(victim)
    r = env.run()
    assert victim.read_bytes() == b"victim-original"
    assert r.returncode == 0, r.stderr
    final = env.nas / GOOD_NAMES[0]
    assert final.is_file() and not final.is_symlink()
    assert final.read_bytes() == (env.src / GOOD_NAMES[0]).read_bytes()


def test_planted_partial_symlink_with_existing_mount(env):
    _populate(env)
    env.nas.mkdir()
    env.marker.write_text("")
    victim = env.root / "victim-outside"
    victim.write_bytes(b"victim-original")
    (env.nas / (".partial-" + GOOD_NAMES[1])).symlink_to(victim)
    r = env.run(NAS_USE_EXISTING_MOUNT="1")
    assert victim.read_bytes() == b"victim-original"
    assert r.returncode == 0, r.stderr


def test_same_size_corruption_on_the_nas_is_detected(env):
    _populate(env)
    assert env.run().returncode == 0
    nas_file = env.nas / GOOD_NAMES[1]
    good = nas_file.read_bytes()
    bad = bytes((b ^ 0x55) for b in good)
    assert len(bad) == len(good) and bad != good
    nas_file.write_bytes(bad)
    r = env.run()
    assert r.returncode == 1
    assert _metrics(r.stdout)["unifi_backup_sync_result_code"] == 5
    assert nas_file.read_bytes() == bad  # never overwritten and never deleted
    assert len(env.nas_files()) == 3
    _assert_unmounted_clean(env)


def test_identical_existing_copy_is_accepted(env):
    _populate(env)
    assert env.run().returncode == 0
    r = env.run()
    assert r.returncode == 0, r.stderr
    assert _metrics(r.stdout)["unifi_backup_sync_result_code"] == 0


def test_source_swapped_for_a_fifo_does_not_hang(env):
    _populate(env)
    victim = env.src / GOOD_NAMES[1]
    r = subprocess.run(["/bin/sh", str(env.script)], timeout=30, capture_output=True, text=True,
                       stdin=subprocess.DEVNULL,
                       env=env.env(FAKE_SWAP_PATH=str(victim), FAKE_SWAP_FIFO="1"))
    assert (env.root / "swapped").exists(), "the fake did not swap; the test proves nothing"
    assert r.returncode == 1
    assert _metrics(r.stdout)["unifi_backup_sync_result_code"] in (4, 5)
    assert GOOD_NAMES[1] not in env.nas_files()
    _assert_unmounted_clean(env)


def test_file_over_the_size_limit_is_refused_before_any_copy(env):
    _populate(env)
    r = env.run(MAX_BACKUP_BYTES="1000")
    assert r.returncode == 1
    assert _metrics(r.stdout)["unifi_backup_sync_result_code"] == 2
    assert env.nas_files() == []
    assert not (env.state / "stage" / "current").exists()


@pytest.mark.parametrize("val", ["0", "abc", "007", "999999999999"])
def test_bad_size_limit_settings_fail_closed(env, val):
    _populate(env)
    r = env.run(MAX_BACKUP_BYTES=val)
    assert r.returncode == 1 and env.calls() == []
    assert _metrics(r.stdout)["unifi_backup_sync_result_code"] == 1


def test_low_free_space_refuses_before_staging(env):
    _populate(env)
    r = env.run(FAKE_DF_AVAIL="1")
    assert r.returncode == 1
    assert _metrics(r.stdout)["unifi_backup_sync_result_code"] == 4
    assert env.nas_files() == []
    assert not (env.state / "stage" / "current").exists()


def test_upload_corruption_is_never_published(env):
    _populate(env)
    env.set_hook("after-upload-write", "sysseek($out, 0, 0); syswrite($out, \"Z\", 1);")
    r = env.run()
    assert r.returncode == 1
    assert _metrics(r.stdout)["unifi_backup_sync_result_code"] == 5
    assert env.nas_files() == []


def test_reads_go_through_one_open_file_and_are_bounded():
    code = _code()
    assert "O_RDONLY | O_NOFOLLOW | O_NONBLOCK" in code
    assert "O_RDONLY | O_DIRECTORY | O_NOFOLLOW" in code
    assert "O_RDWR | O_CREAT | O_EXCL | O_NOFOLLOW" in code
    assert "$size + 1" in code and "exit 13 unless $s[0] == $dev && $s[1] == $ino && $s[3] == 1" in code
    assert "bye(24) if $? != 0" in code
    assert '"$env_bin" -i PATH=/usr/bin:/bin LC_ALL=C "$perl_bin"' in code


def test_source_swapped_for_a_hardlink_between_check_and_open(env):
    _populate(env)
    secret = _secret(env)
    os.utime(secret, (NOW, NOW))
    victim = env.src / GOOD_NAMES[1]
    r = env.run(FAKE_SWAP_PATH=str(victim), FAKE_SWAP_TARGET=str(secret), FAKE_SWAP_HARDLINK="1")
    assert (env.root / "swapped").exists(), "the fake did not swap; the test proves nothing"
    assert r.returncode == 1
    assert _metrics(r.stdout)["unifi_backup_sync_result_code"] == 5
    assert b"ROOT-ONLY-CONTENT" not in _nas_blob(env)
    _assert_unmounted_clean(env)


# --- Daybreak round 2 (PR 240) -------------------------------------------------------------------

def test_failing_hash_tool_is_never_accepted_as_a_match(env):
    _populate(env)
    assert env.run().returncode == 0
    r = env.run(FAKE_SHA_FAIL_FROM="1")  # every sha256sum exits 1 after printing a valid hash
    assert r.returncode == 1
    assert _metrics(r.stdout)["unifi_backup_sync_result_code"] == 5
    assert "copied and verified" not in r.stderr


def test_failing_hash_tool_publishes_nothing(env):
    _populate(env)
    r = env.run(FAKE_SHA_FAIL_FROM="1")
    assert r.returncode == 1 and env.nas_files() == []


def test_failing_hash_of_the_existing_copy_is_a_failure_not_a_match(env):
    _populate(env)
    assert env.run().returncode == 0
    (env.root / "sha.count").unlink()
    r = env.run(FAKE_SHA_FAIL_FROM="2")  # the staged hash works, the hash of the NAS copy fails
    assert r.returncode == 1
    assert _metrics(r.stdout)["unifi_backup_sync_result_code"] == 5


def test_existing_copy_replaced_while_it_is_hashed_is_not_accepted(env):
    _populate(env)
    assert env.run().returncode == 0
    env.set_hook("after-hash", 'unlink($pre . $name); open(my $x, ">", $pre . $name); print $x "Z" x $s[7]; close $x;')
    r = env.run()
    assert r.returncode == 1
    assert _metrics(r.stdout)["unifi_backup_sync_result_code"] == 5


def test_partial_replaced_before_the_rename_is_reported_and_never_accepted_later(env):
    _populate(env)
    clean_text = env.text
    env.set_hook("before-rename", 'unlink($pre . $pn); open(my $x, ">", $pre . $pn); print $x "attacker bytes"; close $x;')
    r = env.run()
    assert r.returncode == 1
    assert _metrics(r.stdout)["unifi_backup_sync_result_code"] == 5
    assert "rc 33" in r.stderr
    # the substituted file now sits under a final name: a later clean run must still refuse it
    env.text = clean_text
    env.script.write_text(clean_text, encoding="utf-8")
    again = env.run()
    assert again.returncode == 1
    assert _metrics(again.stdout)["unifi_backup_sync_result_code"] == 5
    assert (env.nas / GOOD_NAMES[0]).read_bytes() == b"attacker bytes"  # never overwritten, never deleted


def test_prune_candidate_replaced_before_the_helper_opens_it_is_kept(env):
    _populate(env)
    env.nas.mkdir()
    old = "autobackup_8.0.1_20250101_0300_1735700000.unf"
    (env.nas / old).write_bytes(b"old")
    os.utime(env.nas / old, (NOW - 400 * DAY,) * 2)
    r = env.run(FAKE_SWAP_PATH=str(env.nas / old), FAKE_SWAP_WRITE="1")
    assert (env.root / "swapped").exists(), "the fake did not swap; the test proves nothing"
    assert r.returncode == 1
    assert _metrics(r.stdout)["unifi_backup_sync_result_code"] == 6
    assert (env.nas / old).read_bytes() == b"new backup"


def test_prune_candidate_replaced_before_the_unlink_is_kept(env):
    _populate(env)
    env.nas.mkdir()
    old = "autobackup_8.0.1_20250101_0300_1735700000.unf"
    (env.nas / old).write_bytes(b"old")
    os.utime(env.nas / old, (NOW - 400 * DAY,) * 2)
    env.set_hook("before-unlink", 'unlink($pre . $name); open(my $x, ">", $pre . $name); print $x "new backup"; close $x;')
    r = env.run()
    assert r.returncode == 1
    assert _metrics(r.stdout)["unifi_backup_sync_result_code"] == 6
    assert (env.nas / old).read_bytes() == b"new backup"


def test_helper_runs_with_a_cleared_environment(env):
    _populate(env)
    lib = env.root / "perllib"
    lib.mkdir()
    marker = env.root / "probe-ran"
    (lib / "Probe.pm").write_text('package Probe; open(my $m, ">", "%s"); close $m; 1;\n' % marker, encoding="utf-8")
    probe = {"PERL5OPT": "-MProbe", "PERL5LIB": str(lib)}
    # control: the probe does fire when the environment is not cleared
    subprocess.run(["/usr/bin/perl", "-e", "1"], env=dict(PATH="/usr/bin", **probe), check=True)
    assert marker.exists()
    marker.unlink()
    r = env.run(**probe)
    assert r.returncode == 0, r.stderr
    assert not marker.exists()


def test_existing_mount_needs_nosymfollow(env):
    _populate(env)
    env.marker.write_text("")
    env.set_mountinfo("rw,nosuid,nodev,noexec")
    r = env.run(NAS_USE_EXISTING_MOUNT="1")
    assert r.returncode == 1
    assert _metrics(r.stdout)["unifi_backup_sync_result_code"] == 3
    assert env.nas_files() == []


def test_existing_mount_missing_from_the_mount_table_is_refused(env):
    _populate(env)
    env.marker.write_text("")
    env.set_mountinfo(None)
    r = env.run(NAS_USE_EXISTING_MOUNT="1")
    assert r.returncode == 1
    assert _metrics(r.stdout)["unifi_backup_sync_result_code"] == 3


def test_existing_mount_missing_hardening_flags_only_warns(env):
    _populate(env)
    env.marker.write_text("")
    env.set_mountinfo("rw,nosymfollow")
    r = env.run(NAS_USE_EXISTING_MOUNT="1")
    assert r.returncode == 0, r.stderr
    for flag in ("nosuid", "nodev", "noexec"):
        assert "lacks %s" % flag in r.stderr


def test_destination_writable_by_others_is_refused(env):
    _populate(env)
    env.nas.mkdir()
    env.nas.chmod(0o777)
    r = env.run()
    assert r.returncode == 1
    assert _metrics(r.stdout)["unifi_backup_sync_result_code"] == 3
    assert env.nas_files() == [] or not any(p.is_file() for p in env.nas.iterdir())
    _assert_unmounted_clean(env)


# --- credentials and dry run ----------------------------------------------------------------------

@pytest.mark.parametrize("extra", [{}, {"FAKE_MOUNT_FAIL": "1"}, {"FAKE_CP_FAIL": "1"},
                                   {"FAKE_SHA_FAIL_FROM": "2"}, {"FAKE_UMOUNT_FAIL": "1"}])
def test_credentials_never_printed(env, extra):
    _populate(env)
    r = env.run(**extra)
    blob = r.stdout + r.stderr + "\n".join(env.calls())
    assert SECRET not in blob and "password" not in blob
    assert "username" not in blob


def test_dry_run_changes_nothing(env):
    _populate(env)
    r = env.run("--dry-run")
    assert r.returncode == 0, r.stderr
    assert r.stdout == ""
    assert env.nas_files() == [] and not (env.state / "last-success").exists()
    mounts = [c for c in env.calls() if c.startswith("mount ")]
    assert len(mounts) == 2 and "remount,bind,nosymfollow" in mounts[1]
    assert re.search(r"(^|[ ,])ro([ ,]|$)", mounts[0]) and not re.search(r"(^|[ ,])rw([ ,]|$)", mounts[0])
    _assert_unmounted_clean(env)


def test_unknown_argument_refused(env):
    _populate(env)
    r = env.run("--delete")
    assert r.returncode == 1 and env.calls() == []


# --- static guards on the script -----------------------------------------------------------------

def _code():
    return "\n".join(l for l in SCRIPT.read_text(encoding="utf-8").splitlines()
                     if not l.lstrip().startswith("#"))


def test_script_has_no_delete_mirroring_or_eval():
    code = _code()
    assert re.search(r"\brsync\b", code) is None
    assert "--delete" not in code
    assert re.search(r"\beval\b", code) is None
    assert "rm -rf" not in code and "rm -r " not in code
    assert re.search(r"\|\|\s*true", code) is None


def test_script_uses_absolute_command_paths_only():
    code = _code()
    for name in ("id", "date", "stat", "env", "perl", "df", "mv", "rm", "mkdir", "sha256sum", "mount",
                 "umount", "mountpoint"):
        assert not re.search(r"(?m)(^\s*|[;&|(]\s*|\$\()%s\s" % name, code), name


def test_script_syntax_and_shellcheck():
    assert subprocess.run(["/bin/sh", "-n", str(SCRIPT)]).returncode == 0
    sc = shutil.which("shellcheck")
    if sc is None:
        venv_sc = Path(sys.executable).parent / "shellcheck"
        sc = str(venv_sc) if venv_sc.exists() else None
    if sc is None:
        pytest.skip("shellcheck not installed")
    r = subprocess.run([sc, "-s", "sh", str(SCRIPT)], capture_output=True, text=True)
    assert r.returncode == 0, r.stdout


# --- systemd units -------------------------------------------------------------------------------

def _unit(path):
    sections, cur = {}, None
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("["):
            cur = sections.setdefault(line.strip("[]"), [])
        else:
            k, _, v = line.partition("=")
            cur.append((k, v))
    return sections


def _vals(sec, key):
    return [v for k, v in sec if k == key]


def test_service_unit_is_hardened_and_keeps_the_network():
    s = _unit(SERVICE)["Service"]
    assert _vals(s, "Type") == ["oneshot"]
    assert _vals(s, "ProtectSystem") == ["strict"]
    assert _vals(s, "PrivateTmp") == ["yes"] and _vals(s, "NoNewPrivileges") == ["yes"]
    assert _vals(s, "ProtectHome") == ["read-only"]  # the source lives under /home
    assert _vals(s, "StateDirectory") == ["unifi-backup-sync"] and _vals(s, "StateDirectoryMode") == ["0700"]
    caps = _vals(s, "CapabilityBoundingSet")
    assert caps and "CAP_SYS_ADMIN" in caps[0] and "~" not in caps[0]
    assert "CAP_SYS_MODULE" not in caps[0] and "CAP_NET_ADMIN" not in caps[0]
    for bad in ("PrivateNetwork", "NetworkNamespacePath", "JoinsNamespaceOf", "PrivateUsers"):
        assert not _vals(s, bad), bad
    assert _vals(s, "TimeoutStartSec") and _vals(s, "KillMode") == ["control-group"]
    assert _vals(s, "ExecStart") == ["/usr/local/bin/unifi-backup-sync.sh"]
    assert _vals(s, "User") == [] and _vals(s, "UMask") == ["0077"]


def test_timer_is_monday_plus_daily_retry():
    t = _unit(TIMER)
    cal = _vals(t["Timer"], "OnCalendar")
    assert any(c.startswith("Mon ") for c in cal) and len(cal) >= 2
    assert _vals(t["Timer"], "Persistent") == ["yes"]
    assert _vals(t["Install"], "WantedBy") == ["timers.target"]


# --- alert rules ---------------------------------------------------------------------------------

def _rules():
    data = yaml.safe_load(RULES.read_text(encoding="utf-8"))
    assert data["apiVersion"] == 1
    return {r["uid"]: r for g in data["groups"] for r in g["rules"]}


def test_rules_ship_paused_with_the_decided_thresholds():
    rules = _rules()
    assert set(rules) == {"unifi-backup-stale-8d", "unifi-backup-stale-15d", "unifi-backup-sync-failed"}
    assert all(r["isPaused"] is True for r in rules.values())
    assert len({r["title"] for r in rules.values()}) == 3
    text = RULES.read_text(encoding="utf-8")
    assert "691200" in text and "1296000" in text
    warn, crit = rules["unifi-backup-stale-8d"], rules["unifi-backup-stale-15d"]
    assert "691200" in str(warn["data"]) and "1296000" in str(warn["data"])
    assert "1296000" in str(crit["data"]) and "691200" not in str(crit["data"])
    fail = rules["unifi-backup-sync-failed"]
    assert fail["noDataState"] == "Alerting" and fail["execErrState"] == "Alerting"
    for r in rules.values():
        assert r["execErrState"] == "Alerting"
        assert "unifi_backup_" in str(r["data"])


def test_rule_labels_use_only_allowed_labels_and_the_phone_gate():
    allowed = {"severity", "tier", "phone", "alert_group", "source"}
    for uid, r in _rules().items():
        lab = r["labels"]
        assert set(lab) <= allowed, uid
        assert all(isinstance(v, str) for v in lab.values()), uid
        assert lab["phone"] == "true" and lab["alert_group"] == "backup" and lab["source"] == "unifi"
    rules = _rules()
    assert rules["unifi-backup-stale-8d"]["labels"]["severity"] == "warning"
    assert rules["unifi-backup-stale-8d"]["labels"]["tier"] == "P2"
    for uid in ("unifi-backup-stale-15d", "unifi-backup-sync-failed"):
        assert rules[uid]["labels"]["severity"] == "critical" and rules[uid]["labels"]["tier"] == "P1"


def test_rules_are_not_matched_by_the_update_rule_glob():
    assert RULES not in set(RULES.parent.glob("*rules*.yml"))


def test_policy_example_repeats():
    root = yaml.safe_load(POLICY.read_text(encoding="utf-8"))["policies"][0]
    parent = root["routes"][0]
    assert ["alert_group", "=", "backup"] in parent["object_matchers"]
    rep = {next(m for m in r["object_matchers"] if m[0] == "severity")[2]: r["repeat_interval"]
           for r in parent["routes"]}
    assert rep == {"warning": "84h", "critical": "24h"}


# --- documentation -------------------------------------------------------------------------------

def test_doc_states_the_limits():
    d = DOC.read_text(encoding="utf-8")
    low = d.lower()
    for needle in ("not decided", "paused", "--dry-run", "restore", "never", "not verified",
                   "691200", "1296000", "mirror", "unifi-backup-sync.service", "RETENTION_DAYS"):
        assert needle.lower() in low, needle
    assert SECRET not in d
    # no real addresses or host names
    assert not re.search(r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b", d)
