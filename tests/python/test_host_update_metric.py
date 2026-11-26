"""Guards for scripts/host-update-metric.sh (issue #219): the read-only Debian-family host update
collector. A fake apt-get stands in for the real one (nothing here touches the host's apt state).
Every fail-closed path has a clean-mutant revert proof at the bottom: the real script is mutated in
a scratch copy, the same fixture must then go red, and the original file is never edited.
"""
import os
import re
import shutil
import subprocess
import time
from pathlib import Path

import pytest

from conftest import REPO_ROOT

SCRIPT = REPO_ROOT / "scripts" / "host-update-metric.sh"
DOC = REPO_ROOT / "docs" / "host-update-collector.md"

SUMMARY0 = "0 upgraded, 0 newly installed, 0 to remove and 0 not upgraded."
PREAMBLE = "Reading package lists...\nBuilding dependency tree...\nReading state information...\nCalculating upgrade...\n"

DEB_SEC = "Debian-Security:13/stable-security"
DEB_UPD = "Debian:13/stable-updates"
DEB_MAIN = "Debian:13.1/stable"
UBU_SEC = "Ubuntu:24.04/noble-security"
UBU_UPD = "Ubuntu:24.04/noble-updates"


def inst(name, old, new, origins, arch="arm64", tail=""):
    o = f"[{old}] " if old else ""
    return f"Inst {name} {o}({new} {origins} [{arch}]){tail}\n"


def apt_out(lines, summary=None):
    n_up = sum(1 for ln in lines if ln.startswith("Inst ") and "] (" in ln)
    n_new = sum(1 for ln in lines if ln.startswith("Inst ")) - n_up
    s = summary or f"{n_up} upgraded, {n_new} newly installed, 0 to remove and 0 not upgraded."
    return PREAMBLE + "".join(lines) + s + "\n"


FAKE_APT = """#!/bin/sh
printf '%s\\n' "$*" >> "$REC"
printf 'LC_ALL=%s\\n' "$LC_ALL" >> "$REC.env"
cat "$APT_FIXTURE"
exit "${{APT_RC:-0}}"
"""


def uu_log(path, seconds_ago, marker="All upgrades installed"):
    t = time.localtime(time.time() - seconds_ago)
    stamp = time.strftime("%Y-%m-%d %H:%M:%S", t) + ",123"
    path.write_text(
        f"{stamp} INFO Starting unattended upgrades script\n"
        f"{stamp} INFO Allowed origins are: origin=Debian,codename=trixie,label=Debian-Security\n"
        f"{stamp} INFO {marker}\n",
        encoding="utf-8",
    )


class Env:
    def __init__(self, tmp_path):
        self.tmp = tmp_path
        self.bin = tmp_path / "bin"
        self.bin.mkdir()
        (self.bin / "apt-get").write_text(FAKE_APT.format(), encoding="utf-8")
        (self.bin / "apt-get").chmod(0o755)
        self.fixture = tmp_path / "apt.fixture"
        self.fixture.write_text(apt_out([]), encoding="utf-8")
        self.rec = tmp_path / "calls.txt"
        self.log = tmp_path / "uu.log"
        uu_log(self.log, 3600)
        self.reboot = tmp_path / "reboot-required"
        self.state_dir = tmp_path / "state"
        self.state_dir.mkdir(mode=0o700)
        self.state_dir.chmod(0o700)
        (self.state_dir / "first-seen").write_text("host-update-state v1\n", encoding="utf-8")
        (self.state_dir / "first-seen").chmod(0o600)

    def run(self, args=("standard",), label="host-a", extra=None, apt_rc=0, script=None):
        env = {
            "PATH": "/usr/bin:/bin",
            "REC": str(self.rec),
            "APT_FIXTURE": str(self.fixture),
            "APT_RC": str(apt_rc),
            "HOST_UPDATE_APT_GET": str(self.bin / "apt-get"),
            "HOST_UPDATE_REBOOT_FILE": str(self.reboot),
            "HOST_UPDATE_UU_LOG": str(self.log),
            "HOST_UPDATE_STATE_DIR": str(self.state_dir),
        }
        if label is not None:
            env["HOST_LABEL"] = label
        env.update(extra or {})
        return subprocess.run(["/bin/sh", str(script or SCRIPT), *args], capture_output=True, text=True,
                              env=env, timeout=60, check=False, cwd=str(self.tmp))

    def calls(self):
        return self.rec.read_text(encoding="utf-8").splitlines() if self.rec.exists() else []

    def set_apt(self, text):
        self.fixture.write_text(text, encoding="utf-8")


@pytest.fixture
def env(tmp_path):
    return Env(tmp_path)


def parse(out):
    res = {}
    for line in out.strip().splitlines():
        m = re.match(r"^([a-z_]+)((?:,[a-z_]+=[A-Za-z0-9._-]+)*) value=(-?[0-9]+)i$", line)
        assert m, f"not a valid metric line: {line!r}"
        tags = dict(t.split("=") for t in m.group(2).split(",") if t)
        key = (m.group(1), tags.get("kind"), tags.get("security"))
        assert key not in res, f"duplicate {key}"
        assert tags["host"] and tags["tier"]
        res[key] = int(m.group(3))
    return res


def assert_failed(r):
    assert r.returncode != 0
    assert re.fullmatch(r"host_update_check_success(,host=[A-Za-z0-9_-]+,tier=(critical|standard))? value=0i\n", r.stdout), r.stdout


# ---------------------------------------------------------------- static guards

def test_script_syntax_and_shellcheck():
    assert SCRIPT.is_file()
    assert SCRIPT.read_text(encoding="utf-8").startswith("#!/bin/sh\n")
    assert subprocess.run(["sh", "-n", str(SCRIPT)], timeout=30).returncode == 0
    sc = shutil.which("shellcheck")
    if not sc:
        venv_sc = Path(os.environ.get("VIRTUAL_ENV", "/nonexistent")) / "bin" / "shellcheck"
        sc = str(venv_sc) if venv_sc.exists() else None
    if sc:
        assert subprocess.run([sc, "-s", "sh", str(SCRIPT)], timeout=60).returncode == 0


def test_script_is_read_only_by_denylist():
    text = SCRIPT.read_text(encoding="utf-8")
    code = "\n".join(ln for ln in text.splitlines() if not ln.lstrip().startswith("#"))
    for bad in ("apt-get update", "apt update", "upgrade -y", "install ", "curl", "wget", "sudo",
                "shutdown", "systemctl", "eval ", "dist-upgrade -y"):
        assert bad not in code, bad
    assert "PATH=/usr/bin:/bin" in code or 'PATH="/usr/bin:/bin"' in code
    assert "$PATH" not in code


# ---------------------------------------------------------------- healthy shapes

def test_nothing_pending(env):
    r = env.run()
    assert r.returncode == 0, r.stderr
    m = parse(r.stdout)
    assert m[("host_update_pending", "package", "false")] == 0
    assert m[("host_update_pending", "package", "true")] == 0
    assert m[("host_reboot_required", None, None)] == 0
    assert 3500 <= m[("host_unattended_last_run_age_seconds", None, None)] <= 3700
    assert m[("host_update_oldest_pending_age_seconds", None, None)] == 0
    assert m[("host_update_state_ok", None, None)] == 1
    assert m[("host_update_check_success", None, None)] == 1
    assert "host=host-a,tier=standard" in r.stdout
    assert r.stdout.splitlines()[-1].startswith("host_update_check_success")
    assert r.stderr == ""


def test_exact_apt_argv_and_locale(env):
    env.run()
    assert env.calls() == ["-s -o Debug::NoLocking=1 dist-upgrade"]
    assert env.rec.with_name("calls.txt.env").read_text().strip() == "LC_ALL=C"


def test_security_pending_by_origin_debian(env):
    env.set_apt(apt_out([
        inst("libssl3t64", "3.5.1-1", "3.5.1-1+deb13u1", DEB_SEC),
        inst("tzdata", "2025a", "2025b", f"{DEB_UPD}, {DEB_MAIN}"),
        inst("curl", "8.1", "8.2", f"{DEB_UPD}, {DEB_SEC}", tail=" []"),
        inst("newdep", None, "1.0", DEB_MAIN, tail=" [libfoo:arm64 ]"),
    ]))
    r = env.run(("critical",))
    assert r.returncode == 0, r.stderr
    m = parse(r.stdout)
    assert m[("host_update_pending", "package", "true")] == 2
    assert m[("host_update_pending", "package", "false")] == 2
    assert "tier=critical" in r.stdout


def test_security_pending_by_origin_ubuntu(env):
    env.set_apt(apt_out([
        inst("openssl", "3.0.13-0ubuntu3", "3.0.13-0ubuntu3.5", f"{UBU_UPD}, {UBU_SEC}"),
        inst("vim", "9.1.0-1", "9.1.0-2", UBU_UPD),
    ], ))
    m = parse(env.run().stdout)
    assert m[("host_update_pending", "package", "true")] == 1
    assert m[("host_update_pending", "package", "false")] == 1


def test_security_is_by_origin_not_name(env):
    # a package literally named "security-updates" from a non-security archive is not security,
    # and an origin that merely contains the word elsewhere is not either
    env.set_apt(apt_out([
        inst("security-updates", "1", "2", DEB_UPD),
        inst("noble-security-tool", "1", "2", "Evil-Security:13/stable"),
        inst("openssh-server", "1", "2", "Parrot 7 Echo Parakeet:parrot-security"),
    ]))
    m = parse(env.run().stdout)
    assert m[("host_update_pending", "package", "true")] == 0
    assert m[("host_update_pending", "package", "false")] == 3


def test_origin_with_spaces_and_no_archive_is_accepted(env):
    env.set_apt(apt_out([inst("element-desktop", "1.1", "1.2", "packages.element.io", arch="amd64"),
                         inst("login.defs", "1:4", "1:4+deb13u1", "Parrot 7 Echo Parakeet:parrot, Parrot 7 Echo Parakeet:parrot-security", arch="all")]))
    r = env.run()
    assert r.returncode == 0, r.stdout
    assert parse(r.stdout)[("host_update_pending", "package", "false")] == 2


def test_real_apt_autoremove_hint_is_accepted(env):
    # seen on a live Debian-family host (apt 3.x): the autoremove hint sits before the summary line
    env.set_apt(PREAMBLE + "The following packages were automatically installed and are no longer required:\n  libfoo libbar\n"
                "Use 'apt autoremove' to remove them.\n" + inst("foo", "1", "2", DEB_SEC) + "1 upgraded, 0 newly installed, 0 to remove and 0 not upgraded.\n")
    r = env.run()
    assert r.returncode == 0, r.stderr
    assert parse(r.stdout)[("host_update_pending", "package", "true")] == 1


def test_reboot_required(env):
    env.reboot.write_text("*** System restart required ***\n")
    r = env.run()
    assert parse(r.stdout)[("host_reboot_required", None, None)] == 1


def test_reboot_dir_missing_fails(env):
    r = env.run(extra={"HOST_UPDATE_REBOOT_FILE": str(env.tmp / "nodir" / "reboot-required")})
    assert_failed(r)


# ---------------------------------------------------------------- unattended-upgrades age

def test_unattended_never_run_is_failure_not_zero(env):
    env.log.write_text("2026-01-01 01:00:00,000 INFO Starting unattended upgrades script\n"
                       "2026-01-01 01:00:01,000 ERROR something broke\n")
    r = env.run()
    assert_failed(r)
    assert "host_unattended_last_run_age_seconds" not in r.stdout


def test_unattended_log_missing_is_failure(env):
    env.log.unlink()
    assert_failed(env.run())


def test_unattended_no_packages_marker_counts_as_success(env):
    uu_log(env.log, 7200, "No packages found that can be upgraded unattended and no pending auto-removals")
    m = parse(env.run().stdout)
    assert 7100 <= m[("host_unattended_last_run_age_seconds", None, None)] <= 7300


def test_unattended_last_success_wins_over_later_error(env):
    t1 = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(time.time() - 90000)) + ",000"
    t2 = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(time.time() - 100)) + ",000"
    env.log.write_text(f"{t1} INFO All upgrades installed\n{t2} ERROR Installing the upgrades failed!\n")
    m = parse(env.run().stdout)
    assert 89900 <= m[("host_unattended_last_run_age_seconds", None, None)] <= 90100


def test_unattended_future_timestamp_is_failure(env):
    t = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(time.time() + 7 * 86400)) + ",000"
    env.log.write_text(f"{t} INFO All upgrades installed\n")
    assert_failed(env.run())


# ---------------------------------------------------------------- fail closed on apt

@pytest.mark.parametrize("text", [
    "garbage\n",
    "",
    PREAMBLE,  # no summary line: truncated output
    PREAMBLE + "Inst foo [1] (2 Debian:13/stable [arm64])\n" + "0 upgraded, 0 newly installed, 0 to remove and 0 not upgraded.\n",  # count mismatch
    PREAMBLE + "Inst foo [1 (2 Debian:13/stable [arm64])\n1 upgraded, 0 newly installed, 0 to remove and 0 not upgraded.\n",
    PREAMBLE + "Inst foo [1] (2 Debian:13/stable)\n1 upgraded, 0 newly installed, 0 to remove and 0 not upgraded.\n",
    PREAMBLE + "Inst foo [1] (2 [arm64])\n1 upgraded, 0 newly installed, 0 to remove and 0 not upgraded.\n",
    PREAMBLE + "Inst foo [1] (2 Debian:13/stable [arm64]) trailing junk\n1 upgraded, 0 newly installed, 0 to remove and 0 not upgraded.\n",
    PREAMBLE + "E: Unable to locate package\n" + SUMMARY0 + "\n",
    PREAMBLE + "Inst\n1 upgraded, 0 newly installed, 0 to remove and 0 not upgraded.\n",
    PREAMBLE + SUMMARY0 + "\n" + SUMMARY0 + "\n",
], ids=["garbage", "empty", "no-summary", "count-mismatch", "bad-old-bracket", "no-arch", "no-origin",
        "trailing-junk", "error-line", "bare-inst", "two-summaries"])
def test_malformed_apt_output_fails_closed(env, text):
    env.set_apt(text)
    r = env.run()
    assert_failed(r)
    assert "host_update_pending" not in r.stdout


def test_apt_nonzero_exit_fails_closed(env):
    env.set_apt(apt_out([inst("foo", "1", "2", DEB_SEC)]))
    r = env.run(apt_rc=100)
    assert_failed(r)
    assert "host_update_pending" not in r.stdout


def test_apt_missing_fails_closed(env):
    r = env.run(extra={"HOST_UPDATE_APT_GET": str(env.tmp / "nope")})
    assert_failed(r)


BAD_NAMES = [
    "foo;touch${IFS}pwned",
    "foo$(touch pwned)",
    "foo`touch pwned`",
    "foo,host=evil",
    "foo value=1i",
    "FOO",
    "-rf",
    "foo|bar",
    "foo'bar",
    "a" * 200,
    "foo*",
]


@pytest.mark.parametrize("name", BAD_NAMES)
def test_injection_in_package_name_fails_closed(env, name):
    env.set_apt(apt_out([f"Inst {name} [1] (2 {DEB_SEC} [arm64])\n"]))
    r = env.run()
    assert_failed(r)
    assert name not in r.stdout
    assert not (env.tmp / "pwned").exists()


@pytest.mark.parametrize("origins", [
    "Debian-Security:13/stable-security;touch pwned",
    "Debian:13/$(touch pwned)",
    "Debian:13/stable\x01",
    "",
])
def test_injection_in_origin_fails_closed(env, origins):
    env.set_apt(apt_out([f"Inst foo [1] (2 {origins} [arm64])\n"]))
    assert_failed(env.run())
    assert not (env.tmp / "pwned").exists()


def test_injection_in_version_fails_closed(env):
    env.set_apt(apt_out([f"Inst foo [1] (2$(x) {DEB_SEC} [arm64])\n"]))
    assert_failed(env.run())


def test_injection_cannot_forge_output_lines(env):
    env.set_apt(apt_out([inst("foo", "1", "2", DEB_UPD)]) + "host_update_pending,kind=package,security=true value=0i\n")
    r = env.run()
    # the extra line after the summary is not a recognized apt line and must not pass through
    assert_failed(r)


# ---------------------------------------------------------------- label and tier

@pytest.mark.parametrize("label", [None, "", "a b", "a,b=c", "a\nb", "x" * 33, "-lead", "UPPER space", "a;b", "$(id)"])
def test_bad_or_missing_host_label_fails(env, label):
    r = env.run(label=label)
    assert r.returncode != 0
    assert re.fullmatch(r"host_update_check_success value=0i\n", r.stdout), r.stdout
    assert env.calls() == []


def test_never_defaults_to_real_hostname(env):
    r = env.run(label=None)
    assert r.returncode != 0
    real = subprocess.run(["hostname"], capture_output=True, text=True).stdout.strip()
    assert real not in r.stdout or real == ""


@pytest.mark.parametrize("args", [(), ("urgent",), ("critical", "x", "y"), ("Critical",), ("",)])
def test_bad_tier_fails(env, args):
    r = env.run(args)
    assert r.returncode != 0
    assert re.fullmatch(r"host_update_check_success(,host=host-a)? value=0i\n", r.stdout) or \
        re.fullmatch(r"host_update_check_success value=0i\n", r.stdout), r.stdout
    assert env.calls() == []


def test_label_as_argument_and_conflict(env):
    r = env.run(("standard", "host-b"), label=None)
    assert r.returncode == 0, r.stderr
    assert "host=host-b," in r.stdout
    r = env.run(("standard", "host-b"), label="host-a")
    assert r.returncode != 0
    assert re.fullmatch(r"host_update_check_success value=0i\n", r.stdout)


# ---------------------------------------------------------------- first-seen state

def write_state(env, entries, header="host-update-state v1", mode=0o600):
    f = env.state_dir / "first-seen"
    f.write_text(header + "\n" + "".join(f"{n} {v} {t}\n" for n, v, t in entries), encoding="utf-8")
    f.chmod(mode)
    return f


def test_first_seen_clock_is_kept_and_oldest_age_reported(env):
    now = int(time.time())
    write_state(env, [("foo", "2", now - 8 * 86400), ("gone", "9", now - 99 * 86400)])
    env.set_apt(apt_out([inst("foo", "1", "2", DEB_UPD), inst("bar", "1", "2", DEB_UPD)]))
    r = env.run()
    m = parse(r.stdout)
    assert 8 * 86400 - 5 <= m[("host_update_oldest_pending_age_seconds", None, None)] <= 8 * 86400 + 60
    assert m[("host_update_state_ok", None, None)] == 1
    new = (env.state_dir / "first-seen").read_text()
    assert f"foo 2 {now - 8 * 86400}\n" in new
    assert "bar 2 " in new
    assert "gone" not in new  # no longer pending: dropped
    assert oct((env.state_dir / "first-seen").stat().st_mode & 0o777) == "0o600"
    assert not [p for p in env.state_dir.iterdir() if p.name != "first-seen"], "temp file left behind"


def test_new_version_of_same_package_restarts_the_clock(env):
    now = int(time.time())
    write_state(env, [("foo", "2", now - 8 * 86400)])
    env.set_apt(apt_out([inst("foo", "1", "3", DEB_UPD)]))
    m = parse(env.run().stdout)
    assert m[("host_update_oldest_pending_age_seconds", None, None)] < 120


def test_state_file_lost_emits_no_age_and_state_ok_zero(env):
    (env.state_dir / "first-seen").unlink()
    env.set_apt(apt_out([inst("foo", "1", "2", DEB_UPD)]))
    r = env.run()
    assert r.returncode == 0
    m = parse(r.stdout)
    assert m[("host_update_state_ok", None, None)] == 0
    assert ("host_update_oldest_pending_age_seconds", None, None) not in m
    assert m[("host_update_check_success", None, None)] == 1
    # the clock is re-seeded so the next run has state
    assert "foo 2 " in (env.state_dir / "first-seen").read_text()
    r2 = env.run()
    assert parse(r2.stdout)[("host_update_state_ok", None, None)] == 1


def test_state_dir_absent_is_first_run_and_is_created_private(env):
    fresh = env.tmp / "fresh-state"
    env.set_apt(apt_out([inst("foo", "1", "2", DEB_UPD)]))
    r = env.run(extra={"HOST_UPDATE_STATE_DIR": str(fresh)})
    m = parse(r.stdout)
    assert m[("host_update_state_ok", None, None)] == 1
    assert m[("host_update_oldest_pending_age_seconds", None, None)] < 120
    assert oct(fresh.stat().st_mode & 0o777) == "0o700"


@pytest.mark.parametrize("content", [
    "no header\n",
    "host-update-state v1\nfoo 2\n",
    "host-update-state v1\nfoo 2 notanumber\n",
    "host-update-state v1\nfoo 2 99999999999999999999\n",
    "host-update-state v1\nFOO;x 2 1700000000\n",
    "host-update-state v1\nfoo 2 1700000000 extra\n",
    "host-update-state v1\nfoo 2 4000000000\n",  # far future
    "host-update-state v1\nfoo 2 1700000000\nfoo 2 1700000001\n",  # duplicate key
    "host-update-state v1\n\n",
    "host-update-state v1\nfoo 2 -5\n",
], ids=["no-header", "two-fields", "nan", "huge", "bad-name", "extra", "future", "dup", "blank", "negative"])
def test_corrupt_state_emits_no_age_and_is_not_overwritten(env, content):
    f = env.state_dir / "first-seen"
    f.write_text(content, encoding="utf-8")
    f.chmod(0o600)
    env.set_apt(apt_out([inst("foo", "1", "2", DEB_UPD)]))
    r = env.run()
    assert r.returncode == 0
    m = parse(r.stdout)
    assert m[("host_update_state_ok", None, None)] == 0
    assert ("host_update_oldest_pending_age_seconds", None, None) not in m
    assert f.read_text() == content, "a corrupt state file must be left for the operator"


def test_oversized_state_is_rejected(env):
    f = env.state_dir / "first-seen"
    f.write_text("host-update-state v1\n" + ("a" * 100 + "\n") * 5000)
    f.chmod(0o600)
    m = parse(env.run().stdout)
    assert m[("host_update_state_ok", None, None)] == 0
    assert ("host_update_oldest_pending_age_seconds", None, None) not in m


def test_state_dir_wrong_mode_is_rejected(env):
    env.state_dir.chmod(0o755)
    env.set_apt(apt_out([inst("foo", "1", "2", DEB_UPD)]))
    m = parse(env.run().stdout)
    assert m[("host_update_state_ok", None, None)] == 0
    assert ("host_update_oldest_pending_age_seconds", None, None) not in m


def test_state_file_wrong_mode_is_rejected(env):
    write_state(env, [], mode=0o644)
    m = parse(env.run().stdout)
    assert m[("host_update_state_ok", None, None)] == 0


def test_state_dir_symlink_is_rejected(env):
    link = env.tmp / "link-state"
    link.symlink_to(env.state_dir)
    m = parse(env.run(extra={"HOST_UPDATE_STATE_DIR": str(link)}).stdout)
    assert m[("host_update_state_ok", None, None)] == 0
    assert ("host_update_oldest_pending_age_seconds", None, None) not in m


def test_state_file_symlink_is_rejected(env):
    f = env.state_dir / "first-seen"
    target = env.tmp / "elsewhere"
    target.write_text("host-update-state v1\n")
    target.chmod(0o600)
    f.unlink()
    f.symlink_to(target)
    m = parse(env.run().stdout)
    assert m[("host_update_state_ok", None, None)] == 0
    assert target.read_text() == "host-update-state v1\n"


def test_unwritable_state_dir_sets_state_ok_zero_not_failure(env):
    env.state_dir.chmod(0o500)
    try:
        env.set_apt(apt_out([inst("foo", "1", "2", DEB_UPD)]))
        r = env.run()
    finally:
        env.state_dir.chmod(0o700)
    assert r.returncode == 0
    m = parse(r.stdout)
    assert m[("host_update_state_ok", None, None)] == 0
    assert ("host_update_oldest_pending_age_seconds", None, None) not in m
    assert m[("host_update_pending", "package", "false")] == 1


def test_state_failure_never_changes_apt_failure_output(env):
    (env.state_dir / "first-seen").unlink()
    env.set_apt("garbage\n")
    r = env.run()
    assert_failed(r)
    assert "state_ok" not in r.stdout
    assert not (env.state_dir / "first-seen").exists(), "no state write on a failed check"


# ---------------------------------------------------------------- docs

def test_docs_exist_and_use_placeholders_only():
    text = DOC.read_text(encoding="utf-8")
    for needle in ("host_update_pending", "host_reboot_required", "host_unattended_last_run_age_seconds",
                   "host_update_check_success", "host_update_oldest_pending_age_seconds", "host_update_state_ok",
                   "HOST_LABEL", "systemd", "cron", "twingate-influx-write.py", "Telegraf"):
        assert needle in text, needle
    assert not re.search(r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b", text.replace("127.0.0.1", ""))


# ---------------------------------------------------------------- revert proofs (clean mutants)
# Each mutant is a scratch copy of the real script with ONE fail-closed guard neutralized (the line
# carrying the marker comment is replaced). The scenario must satisfy its guard on the real script
# and violate it on the mutant. The real file is never edited.

def mutant(tmp_path, marker, replacement):
    lines = SCRIPT.read_text(encoding="utf-8").splitlines(keepends=True)
    hits = [i for i, ln in enumerate(lines) if f"# MUTATE:{marker}" in ln]
    assert len(hits) == 1, f"marker {marker} found {len(hits)} times"
    indent = re.match(r"\s*", lines[hits[0]]).group(0)
    lines[hits[0]] = indent + replacement + "\n"
    p = tmp_path / f"mutant-{marker}.sh"
    p.write_text("".join(lines), encoding="utf-8")
    return p


def guard_failed(r):
    return r.returncode != 0 and re.fullmatch(r"host_update_check_success(,[^ ]*)? value=0i\n", r.stdout) is not None


def guard_state_untrusted(r):
    m = parse(r.stdout)
    return m[("host_update_state_ok", None, None)] == 0 and ("host_update_oldest_pending_age_seconds", None, None) not in m


def sc_never_run(env):
    env.log.write_text("2026-01-01 01:00:00,000 INFO Starting unattended upgrades script\n")
    return {}


def sc_apt_rc(env):
    env.set_apt(apt_out([inst("foo", "1", "2", DEB_SEC)]))
    return {"apt_rc": 100}


def sc_no_summary(env):
    env.set_apt(PREAMBLE)
    return {}


def sc_count_mismatch(env):
    env.set_apt(PREAMBLE + inst("foo", "1", "2", DEB_SEC) + SUMMARY0 + "\n")
    return {}


def sc_bad_name(env):
    env.set_apt(apt_out(["Inst foo;bar [1] (2 " + DEB_SEC + " [arm64])\n"]))
    return {}


def sc_state_lost(env):
    (env.state_dir / "first-seen").unlink()
    env.set_apt(apt_out([inst("foo", "1", "2", DEB_UPD)]))
    return {}


def sc_dir_mode(env):
    env.state_dir.chmod(0o755)
    env.set_apt(apt_out([inst("foo", "1", "2", DEB_UPD)]))
    return {}


def sc_corrupt(env):
    f = env.state_dir / "first-seen"
    f.write_text("garbage\nfoo 2 1700000000\n")
    env.set_apt(apt_out([inst("foo", "1", "2", DEB_UPD)]))
    return {}


MUTANTS = {
    "unknown-age": ('[ -n "$last" ] || last="$(date \'+%Y-%m-%d %H:%M:%S\'),000"', sc_never_run, guard_failed),
    "apt-rc": ('apt_out=$(timeout 120 "$apt_bin" -s -o Debug::NoLocking=1 dist-upgrade 2>/dev/null) || :', sc_apt_rc, guard_failed),
    "summary-required": ('summary_total=$n_inst', sc_no_summary, guard_failed),
    "summary-match": (':', sc_count_mismatch, guard_failed),
    "name-charset": ('[!a-z0-9]* | *[!a-z0-9+.:-]*) : ;;', sc_bad_name, guard_failed),
    "state-lost": (':', sc_state_lost, guard_state_untrusted),
    "state-dir-mode": (':', sc_dir_mode, guard_state_untrusted),
    "state-parse": (':', sc_corrupt, guard_state_untrusted),
}


@pytest.mark.parametrize("name", sorted(MUTANTS))
def test_revert_proof_mutant_goes_red(env, name):
    repl, scenario, guard = MUTANTS[name]
    kw = scenario(env)
    assert guard(env.run(**kw)), f"guard {name} does not hold on the real script"
    # reset the scenario's side effects (state file re-seeded by the first run) and replay on the mutant
    (env.tmp / "replay").mkdir()
    env2 = Env(env.tmp / "replay")
    kw = scenario(env2)
    mpath = mutant(env.tmp, name, repl)
    res = env2.run(script=mpath, **kw)
    try:
        still_guarded = guard(res)
    except (AssertionError, KeyError):
        still_guarded = False
    assert not still_guarded, f"mutant {name} stayed green: the guard is not tested"
