"""Guards for scripts/host-update-metric.sh (issue #219): the read-only Debian-family host update
collector. A fake apt-get stands in for the real one (nothing here touches the host's apt state).
The shipped script has no test hooks: every test runs a scratch copy in which only the fixed default
path lines are rewritten (Env.build). Every fail-closed path has a clean-mutant revert proof at the
bottom: the scratch copy is mutated at one marked line, the same fixture must then go red, and the
shipped file is never edited.
"""
import os
import re
import shlex
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

DAY = 86400


def inst(name, old, new, origins, arch="arm64", tail=""):
    o = f"[{old}] " if old else ""
    return f"Inst {name} {o}({new} {origins} [{arch}]){tail}\n"


def apt_out(lines, summary=None):
    n_up = sum(1 for ln in lines if ln.startswith("Inst ") and "] (" in ln)
    n_new = sum(1 for ln in lines if ln.startswith("Inst ")) - n_up
    s = summary or f"{n_up} upgraded, {n_new} newly installed, 0 to remove and 0 not upgraded."
    return PREAMBLE + "".join(lines) + s + "\n"


# The fake apt gets nothing from its environment (the script runs it under env -i): the record, the
# fixture and the exit code are baked into its text.
FAKE_APT = """#!/bin/sh
printf '%s\\n' "$*" >> {rec}
/usr/bin/env > {rec}.env
cat {fixture}
exit "$(cat {rc})"
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
        self.fixture = tmp_path / "apt.fixture"
        self.fixture.write_text(apt_out([]), encoding="utf-8")
        self.rec = tmp_path / "calls.txt"
        self.rc = tmp_path / "apt.rc"
        self.rc.write_text("0\n")
        (self.bin / "apt-get").write_text(
            FAKE_APT.format(rec=shlex.quote(str(self.rec)), fixture=shlex.quote(str(self.fixture)),
                            rc=shlex.quote(str(self.rc))), encoding="utf-8")
        (self.bin / "apt-get").chmod(0o755)
        self.log = tmp_path / "uu.log"
        uu_log(self.log, 3600)
        self.reboot = tmp_path / "reboot-required"
        self.stamp = tmp_path / "update-success-stamp"
        self.stamp.write_text("")
        self.set_mtime(self.stamp, 3600)
        self.lists = tmp_path / "lists"
        self.lists.mkdir()
        self.packages = self.lists / "deb.example_dists_stable_main_binary-arm64_Packages"
        self.packages.write_text("Package: foo\n")
        self.set_mtime(self.packages, 7200)
        self.state_dir = tmp_path / "state"
        self.state_dir.mkdir(mode=0o700)
        self.state_dir.chmod(0o700)
        (self.state_dir / "first-seen").write_text("host-update-state v1\n", encoding="utf-8")
        (self.state_dir / "first-seen").chmod(0o600)
        self.script = self.build("script.sh")

    @staticmethod
    def set_mtime(path, seconds_ago):
        t = time.time() - seconds_ago
        os.utime(path, (t, t))

    def build(self, name, marks=None, rewrites=None):
        """A scratch copy of the shipped script. The fixed default path lines are rewritten to this
        Env's fixtures (the shipped script has no test hooks). marks: marker -> replacement line for
        a guard that is neutralized for a revert proof. The shipped file is never edited."""
        rw = {
            "id_bin": "/usr/bin/id",
            "reboot_file": str(self.reboot),
            "uu_log": str(self.log),
            "apt_bin": str(self.bin / "apt-get"),
            "stamp_file": str(self.stamp),
            "lists_dir": str(self.lists),
        }
        rw.update(rewrites or {})
        lines = SCRIPT.read_text(encoding="utf-8").splitlines(keepends=True)
        for var, value in rw.items():
            hits = [i for i, ln in enumerate(lines) if re.match(rf"\s*{var}=", ln)]
            assert len(hits) == 1, f"default line for {var} found {len(hits)} times"
            indent = re.match(r"\s*", lines[hits[0]]).group(0)
            lines[hits[0]] = f"{indent}{var}={shlex.quote(value)}\n"
        for marker, replacement in (marks or {}).items():
            hits = [i for i, ln in enumerate(lines) if ln.rstrip().endswith(f"# MUTATE:{marker}")]
            assert len(hits) == 1, f"marker {marker} found {len(hits)} times"
            indent = re.match(r"\s*", lines[hits[0]]).group(0)
            lines[hits[0]] = indent + replacement + "\n"
        p = self.tmp / name
        p.write_text("".join(lines), encoding="utf-8")
        return p

    def run(self, args=("standard",), label="host-a", extra=None, apt_rc=0, script=None):
        self.rc.write_text(f"{apt_rc}\n")
        env = {"PATH": "/usr/bin:/bin", "STATE_DIRECTORY": str(self.state_dir)}
        if label is not None:
            env["HOST_LABEL"] = label
        env.update(extra or {})
        return subprocess.run(["/bin/sh", str(script or self.script), *args], capture_output=True, text=True,
                              env=env, timeout=120, check=False, cwd=str(self.tmp))

    def calls(self):
        return self.rec.read_text(encoding="utf-8").splitlines() if self.rec.exists() else []

    def recorded_env(self):
        lines = self.rec.with_name("calls.txt.env").read_text().splitlines()
        pairs = (ln.split("=", 1) for ln in lines if "=" in ln)
        return {k: v for k, v in pairs if k not in {"PWD", "OLDPWD", "SHLVL", "_"}}

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


def val(r, name):
    return parse(r.stdout)[(name, None, None)]


def assert_failed(r):
    assert r.returncode != 0
    assert re.fullmatch(r"host_update_check_success(,host=[A-Za-z0-9_-]+,tier=(critical|standard))? value=0i\n", r.stdout), r.stdout


CLEAN_APT_ENV = {"PATH": "/usr/bin:/bin", "LC_ALL": "C", "APT_CONFIG": "/dev/null"}
HOSTILE_ENV = {"APT_CONFIG": "/nonexistent/evil.conf", "APT_OPTIONS": "-o x=y", "DPKG_ROOT": "/nonexistent/root",
               "DPKG_COLORS": "always", "LD_PRELOAD": "/nonexistent/evil.so", "http_proxy": "http://localhost:9"}


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
    # apt runs in a scrubbed environment, bounded in time and in output
    assert "timeout -k 10 120 env -i PATH=/usr/bin:/bin LC_ALL=C APT_CONFIG=/dev/null" in code
    assert "head -c 4194305" in code
    assert "apt_bin=/usr/bin/apt-get" in code


def has_test_hooks(text):
    return re.search(r"HOST_UPDATE_[A-Z_]+", text) is not None


def test_shipped_script_has_no_test_hooks():
    text = SCRIPT.read_text(encoding="utf-8")
    assert not has_test_hooks(text), "the shipped script must not read HOST_UPDATE_* variables"
    names = set(re.findall(r"\$\{?([A-Z][A-Z0-9_]+)", text))
    assert names, "no environment variable reads collected"
    assert names <= {"HOST_LABEL", "HOME", "XDG_STATE_HOME", "STATE_DIRECTORY", "IFS"}, names


def test_hook_guard_bites():
    # negative case: the guard flags a script that reads a test hook again
    mutated = SCRIPT.read_text(encoding="utf-8").replace(
        "apt_bin=/usr/bin/apt-get", "apt_bin=${HOST_UPDATE_APT_GET:-/usr/bin/apt-get}")
    assert mutated != SCRIPT.read_text(encoding="utf-8")
    assert has_test_hooks(mutated)


@pytest.mark.parametrize("var", ["id_bin", "reboot_file", "uu_log", "apt_bin", "stamp_file", "lists_dir"])
def test_default_path_lines_are_fixed_literals(var):
    lines = [ln for ln in SCRIPT.read_text(encoding="utf-8").splitlines() if re.match(rf"{var}=", ln)]
    assert len(lines) == 1 and re.fullmatch(rf"{var}=/[A-Za-z0-9._/-]+", lines[0]), lines


# ---------------------------------------------------------------- healthy shapes

def test_nothing_pending(env):
    r = env.run()
    assert r.returncode == 0, r.stderr
    m = parse(r.stdout)
    assert m[("host_update_pending", "package", "false")] == 0
    assert m[("host_update_pending", "package", "true")] == 0
    assert m[("host_update_held_back", None, None)] == 0
    assert m[("host_reboot_required", None, None)] == 0
    assert 3500 <= m[("host_unattended_last_run_age_seconds", None, None)] <= 3700
    assert 3500 <= m[("host_update_lists_age_seconds", None, None)] <= 3800
    assert m[("host_update_oldest_pending_age_seconds", None, None)] == 0
    assert m[("host_update_state_ok", None, None)] == 1
    assert m[("host_update_check_success", None, None)] == 1
    assert "host=host-a,tier=standard" in r.stdout
    assert r.stdout.splitlines()[-1].startswith("host_update_check_success")
    assert r.stderr == ""


def test_exact_apt_argv_and_locale(env):
    env.run()
    assert env.calls() == ["-s -o Debug::NoLocking=1 dist-upgrade"]
    assert env.recorded_env() == CLEAN_APT_ENV


def test_apt_environment_is_scrubbed(env):
    r = env.run(extra=HOSTILE_ENV)
    assert r.returncode == 0, r.stderr
    assert env.recorded_env() == CLEAN_APT_ENV


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


def test_held_back_updates_are_reported_and_not_pending(env):
    env.set_apt(apt_out([inst("foo", "1", "2", DEB_SEC)],
                        summary="1 upgraded, 0 newly installed, 0 to remove and 3 not upgraded."))
    r = env.run()
    assert r.returncode == 0, r.stderr
    m = parse(r.stdout)
    assert m[("host_update_held_back", None, None)] == 3
    assert m[("host_update_pending", "package", "true")] == 1
    assert m[("host_update_pending", "package", "false")] == 0


def test_reboot_required(env):
    env.reboot.write_text("*** System restart required ***\n")
    r = env.run()
    assert parse(r.stdout)[("host_reboot_required", None, None)] == 1


def test_reboot_dir_missing_fails(env):
    r = env.run(script=env.build("noreboot.sh", rewrites={"reboot_file": str(env.tmp / "nodir" / "reboot-required")}))
    assert_failed(r)


# ---------------------------------------------------------------- root and numeric safety

def fake_id(env, uid):
    p = env.bin / "id"
    p.write_text(f"#!/bin/sh\necho {uid}\n")
    p.chmod(0o755)
    return str(p)


def test_refuses_to_run_as_root(env):
    r = env.run(script=env.build("root.sh", rewrites={"id_bin": fake_id(env, 0)}))
    assert_failed(r)
    assert "refusing to run as root" in r.stderr
    assert env.calls() == []


def test_non_root_uid_runs(env):
    r = env.run(script=env.build("nonroot.sh", rewrites={"id_bin": fake_id(env, 1000)}))
    assert r.returncode == 0, r.stderr


@pytest.mark.parametrize("summary", [
    "08 upgraded, 0 newly installed, 0 to remove and 0 not upgraded.",
    "0 upgraded, 007 newly installed, 0 to remove and 0 not upgraded.",
    "0 upgraded, 0 newly installed, 0 to remove and 09 not upgraded.",
    "0 upgraded, 0 newly installed, 0 to remove and x not upgraded.",
    "0 upgraded, 0 newly installed, 0 to remove and 123456789012 not upgraded.",
])
def test_non_canonical_summary_numbers_fail_closed(env, summary):
    env.set_apt(PREAMBLE + summary + "\n")
    r = env.run()
    assert_failed(r)
    assert "internal error" not in r.stderr, "must be rejected by validation, not by a shell error"


NEUTRAL_UINT = '"") return 1 ;;'


def test_exit_trap_prints_failure_on_internal_error(env):
    # with the numeric validation neutralized, a leading-zero summary makes the shell's own
    # arithmetic fail; the EXIT trap must still print the failure line
    env.set_apt(PREAMBLE + "08 upgraded, 0 newly installed, 0 to remove and 0 not upgraded.\n")
    r = env.run(script=env.build("trap-on.sh", marks={"uint": NEUTRAL_UINT}))
    assert_failed(r)
    assert "internal error" in r.stderr
    # negative case: without the trap the same internal error prints nothing and the guard bites
    r2 = env.run(script=env.build("trap-off.sh", marks={"uint": NEUTRAL_UINT, "exit-trap": ":"}))
    assert r2.returncode != 0
    assert r2.stdout == ""


# ---------------------------------------------------------------- apt list freshness

def test_lists_age_is_newest_of_stamp_and_lists(env):
    env.set_mtime(env.stamp, 2 * DAY)
    env.set_mtime(env.packages, 600)
    assert 500 <= val(env.run(), "host_update_lists_age_seconds") <= 800
    env.set_mtime(env.stamp, 300)
    env.set_mtime(env.packages, 2 * DAY)
    assert 200 <= val(env.run(), "host_update_lists_age_seconds") <= 500


def test_lists_only_stamp_or_only_lists_is_enough(env):
    env.packages.unlink()
    assert val(env.run(), "host_update_check_success") == 1
    env.stamp.unlink()
    (env.lists / "x_dists_stable_Release").write_text("Origin: x\n")
    assert val(env.run(), "host_update_check_success") == 1


def test_lists_both_missing_fails(env):
    env.stamp.unlink()
    env.packages.unlink()
    r = env.run()
    assert_failed(r)
    assert "host_update_pending" not in r.stdout


def test_lists_empty_files_do_not_count(env):
    env.stamp.unlink()
    env.packages.write_text("")
    assert_failed(env.run())


def test_lists_symlink_does_not_count(env):
    env.stamp.unlink()
    env.packages.unlink()
    target = env.tmp / "elsewhere-list"
    target.write_text("Package: x\n")
    (env.lists / "x_Packages").symlink_to(target)
    assert_failed(env.run())


def test_lists_stale_fails_with_default_three_days(env):
    env.set_mtime(env.stamp, 3 * DAY + 600)
    env.set_mtime(env.packages, 3 * DAY + 600)
    r = env.run()
    assert_failed(r)
    assert "older than 3 days" in r.stderr
    env.set_mtime(env.stamp, 3 * DAY - 600)
    assert env.run().returncode == 0


def test_lists_max_age_argument(env):
    env.set_mtime(env.stamp, 2 * DAY)
    env.set_mtime(env.packages, 2 * DAY)
    assert env.run().returncode == 0
    assert_failed(env.run(("--max-lists-age-days=1", "standard")))
    assert env.run(("--max-lists-age-days=7", "standard")).returncode == 0


@pytest.mark.parametrize("value", ["0", "31", "99", "abc", "08", "", "-1", "1.5", "1000000000000"])
def test_lists_max_age_argument_is_validated(env, value):
    r = env.run((f"--max-lists-age-days={value}", "standard"))
    assert r.returncode != 0
    assert re.fullmatch(r"host_update_check_success value=0i\n", r.stdout), r.stdout
    assert env.calls() == []


def test_lists_future_mtime_is_clamped_to_zero(env):
    env.set_mtime(env.stamp, -3600)
    env.set_mtime(env.packages, 2 * DAY)
    assert val(env.run(), "host_update_lists_age_seconds") == 0


def test_stale_lists_never_give_healthy_zero_pending(env):
    # the original defect: wiped lists make apt report nothing pending
    for p in list(env.lists.iterdir()):
        p.unlink()
    env.stamp.unlink()
    env.set_apt(apt_out([]))
    r = env.run()
    assert_failed(r)
    assert "host_update_pending" not in r.stdout


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


def test_unattended_rotated_log_fallback(env):
    env.log.write_text("2026-01-01 01:00:00,000 INFO Starting unattended upgrades script\n")
    uu_log(env.log.with_name("uu.log.1"), 5400)
    r = env.run()
    assert r.returncode == 0, r.stderr
    assert 5300 <= val(r, "host_unattended_last_run_age_seconds") <= 5500


def test_unattended_current_log_wins_over_rotated(env):
    uu_log(env.log.with_name("uu.log.1"), 90000)
    assert 3500 <= val(env.run(), "host_unattended_last_run_age_seconds") <= 3700


@pytest.mark.parametrize("suffix,prefix", [(" and then the host crashed", ""), ("", "x"), (" ", "")])
def test_unattended_marker_must_match_the_whole_line(env, suffix, prefix):
    t = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(time.time() - 100)) + ",000"
    env.log.write_text(f"{prefix}{t} INFO All upgrades installed{suffix}\n")
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
    r = env.run(script=env.build("noapt.sh", rewrites={"apt_bin": str(env.tmp / "nope")}))
    assert_failed(r)


def test_apt_path_must_be_absolute(env):
    # the fake is reachable by a relative path from the working directory; the script must refuse it
    r = env.run(script=env.build("relapt.sh", rewrites={"apt_bin": "bin/apt-get"}))
    assert_failed(r)
    assert env.calls() == []


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
    "Debian:13/stable\x01",
    "Debian-Security:13/stable-security\xe9",
    "Debian-Security:13/stable-security|x",
])
def test_unknown_origin_characters_count_as_non_security(env, origins):
    env.set_apt(apt_out([f"Inst foo [1] (2 {origins} [arm64])\n"]))
    r = env.run()
    assert r.returncode == 0, r.stderr
    m = parse(r.stdout)
    assert m[("host_update_pending", "package", "false")] == 1
    assert m[("host_update_pending", "package", "true")] == 0
    assert not (env.tmp / "pwned").exists()


def test_origin_that_breaks_the_line_shape_fails_closed(env):
    env.set_apt(apt_out(["Inst foo [1] (2 Debian:13/$(touch pwned) [arm64])\n"]))
    assert_failed(env.run())
    assert not (env.tmp / "pwned").exists()


def test_empty_origin_still_fails_closed(env):
    env.set_apt(apt_out(["Inst foo [1] (2  [arm64])\n"]))
    assert_failed(env.run())


def test_package_name_version_and_arch_stay_strict(env):
    for line in ("Inst foo\xe9 [1] (2 Debian:13/stable [arm64])\n",
                 "Inst foo [1\xe9] (2 Debian:13/stable [arm64])\n",
                 "Inst foo [1] (2\xe9 Debian:13/stable [arm64])\n",
                 "Inst foo [1] (2 Debian:13/stable [arm\xe964])\n"):
        env.set_apt(apt_out([line]))
        assert_failed(env.run())


def test_injection_in_version_fails_closed(env):
    for old, new in (("1", "2$(x)"), ("1$(x)", "2"), ("1", "2;x"), ("1;x", "2"), ("1", "2|x")):
        env.set_apt(apt_out([f"Inst foo [{old}] ({new} {DEB_SEC} [arm64])\n"]))
        assert_failed(env.run())


@pytest.mark.parametrize("arch", ["arm;64", "ARM64", "arm 64", ""])
def test_bad_architecture_charset_fails_closed(env, arch):
    env.set_apt(apt_out([f"Inst foo [1] (2 {DEB_SEC} [{arch}])\n"]))
    assert_failed(env.run())


def test_injection_cannot_forge_output_lines(env):
    env.set_apt(apt_out([inst("foo", "1", "2", DEB_UPD)]) + "host_update_pending,kind=package,security=true value=0i\n")
    r = env.run()
    # the extra line after the summary is not a recognized apt line and must not pass through
    assert_failed(r)


# ---------------------------------------------------------------- bounds

def pkg_lines(n):
    return [inst(f"pkg{i}", "1", "2", DEB_UPD) for i in range(n)]


def test_one_thousand_pending_is_accepted(env):
    env.set_apt(apt_out(pkg_lines(1000)))
    r = env.run()
    assert r.returncode == 0, r.stderr
    assert parse(r.stdout)[("host_update_pending", "package", "false")] == 1000
    assert (env.state_dir / "first-seen").read_text().count("\n") == 1001


def test_more_than_one_thousand_pending_fails_closed(env):
    env.set_apt(apt_out(pkg_lines(1001)))
    assert_failed(env.run())


def test_line_count_bound(env):
    ok = PREAMBLE + "\n" * 49000 + SUMMARY0 + "\n"
    env.set_apt(ok)
    assert env.run().returncode == 0
    env.set_apt(PREAMBLE + "\n" * 50000 + SUMMARY0 + "\n")
    assert_failed(env.run())


def big_output(nbytes):
    # lines of 99 spaces (accepted by the parser): the size bound is the only thing under test
    return PREAMBLE + (" " * 98 + "\n") * (nbytes // 99) + SUMMARY0 + "\n"


def test_output_size_bound(env):
    env.set_apt(big_output(4000000))
    assert env.run().returncode == 0
    env.set_apt(big_output(4300000))
    assert_failed(env.run())


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


def test_state_lookup_is_anchored_to_the_line_start(env):
    # reviewer fixture: libfoo and foo are both pending at the same version, libfoo is listed first
    now = int(time.time())
    write_state(env, [("libfoo", "2", now - 8 * DAY), ("foo", "2", now - 1 * DAY)])
    env.set_apt(apt_out([inst("libfoo", "1", "2", DEB_UPD), inst("foo", "1", "2", DEB_UPD)]))
    r = env.run()
    assert r.returncode == 0, r.stderr
    new = (env.state_dir / "first-seen").read_text()
    assert f"\nfoo 2 {now - 1 * DAY}\n" in new
    assert f"\nlibfoo 2 {now - 8 * DAY}\n" in new


def test_state_of_libfoo_does_not_age_foo(env):
    now = int(time.time())
    write_state(env, [("libfoo", "2", now - 8 * DAY)])
    env.set_apt(apt_out([inst("foo", "1", "2", DEB_UPD)]))
    r = env.run()
    assert val(r, "host_update_oldest_pending_age_seconds") < 120
    assert re.search(r"\nfoo 2 (\d+)\n", (env.state_dir / "first-seen").read_text()).group(1) != str(now - 8 * DAY)


def test_new_version_of_same_package_restarts_the_clock(env):
    now = int(time.time())
    write_state(env, [("foo", "2", now - 8 * 86400)])
    env.set_apt(apt_out([inst("foo", "1", "3", DEB_UPD)]))
    m = parse(env.run().stdout)
    assert m[("host_update_oldest_pending_age_seconds", None, None)] < 120


def test_oldest_age_is_clamped_at_zero(env):
    now = int(time.time())
    write_state(env, [("foo", "2", now + 3600)])
    env.set_apt(apt_out([inst("foo", "1", "2", DEB_UPD)]))
    r = env.run()
    assert val(r, "host_update_state_ok") == 1
    assert val(r, "host_update_oldest_pending_age_seconds") == 0


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
    r = env.run(extra={"STATE_DIRECTORY": str(fresh)})
    m = parse(r.stdout)
    assert m[("host_update_state_ok", None, None)] == 1
    assert m[("host_update_oldest_pending_age_seconds", None, None)] < 120
    assert oct(fresh.stat().st_mode & 0o777) == "0o700"


def test_state_directory_first_entry_of_a_list_is_used(env):
    r = env.run(extra={"STATE_DIRECTORY": f"{env.state_dir}:{env.tmp / 'other'}"})
    assert val(r, "host_update_state_ok") == 1


def test_relative_state_directory_is_rejected(env):
    rel = env.tmp / "relstate"
    rel.mkdir(mode=0o700)
    rel.chmod(0o700)
    (rel / "first-seen").write_text("host-update-state v1\n")
    (rel / "first-seen").chmod(0o600)
    r = env.run(extra={"STATE_DIRECTORY": "relstate"})
    assert val(r, "host_update_state_ok") == 0


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
    "host-update-state v1\nfoo 2 01700000000\n",  # leading zero
    "host-update-state v1\nfoo 2 08\n",
    "host-update-state v1\nfoo 2 00\n",
], ids=["no-header", "two-fields", "nan", "huge", "bad-name", "extra", "future", "dup", "blank", "negative",
        "leading-zero", "leading-zero-8", "double-zero"])
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


def long_state(n, name_len=128):
    now = int(time.time()) - 100
    return "host-update-state v1\n" + "".join(
        f"{('a' * (name_len - 4)) + format(i, '04d')} {'1' * 128} {now}\n" for i in range(n))


def test_oversized_state_is_rejected(env):
    f = env.state_dir / "first-seen"
    f.write_text("host-update-state v1\n" + ("a" * 100 + "\n") * 5000)
    f.chmod(0o600)
    m = parse(env.run().stdout)
    assert m[("host_update_state_ok", None, None)] == 0
    assert ("host_update_oldest_pending_age_seconds", None, None) not in m


def test_state_size_cap_alone_rejects_a_well_formed_file(env):
    text = long_state(1000)
    assert 262144 < len(text) and text.count("\n") == 1001  # valid entries, within the entry cap
    f = env.state_dir / "first-seen"
    f.write_text(text)
    f.chmod(0o600)
    assert val(env.run(), "host_update_state_ok") == 0


def test_state_entry_cap(env):
    now = int(time.time()) - 100
    f = env.state_dir / "first-seen"
    f.write_text("host-update-state v1\n" + "".join(f"p{i} 1 {now}\n" for i in range(1000)))
    f.chmod(0o600)
    assert val(env.run(), "host_update_state_ok") == 1
    f.write_text("host-update-state v1\n" + "".join(f"p{i} 1 {now}\n" for i in range(1001)))
    f.chmod(0o600)
    assert val(env.run(), "host_update_state_ok") == 0


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
    m = parse(env.run(extra={"STATE_DIRECTORY": str(link)}).stdout)
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


def test_temp_file_is_created_without_clobbering(env):
    # a planted symlink at the temp name must not be written through
    victim = env.tmp / "victim"
    victim.write_text("victim\n")
    (env.state_dir / ".first-seen.fixed").symlink_to(victim)
    env.set_apt(apt_out([inst("foo", "1", "2", DEB_UPD)]))
    script = env.build("fixedtmp.sh", rewrites={"tmpf": str(env.state_dir / ".first-seen.fixed")})
    r = env.run(script=script)
    assert r.returncode == 0
    assert val(r, "host_update_state_ok") == 0
    assert victim.read_text() == "victim\n"


# ---------------------------------------------------------------- docs

def test_docs_exist_and_use_placeholders_only():
    text = DOC.read_text(encoding="utf-8")
    assert "HOST_UPDATE_" not in text
    for needle in ("host_update_held_back", "host_update_lists_age_seconds", "STATE_DIRECTORY", "max-lists-age-days",
                   "not upgraded", "label itself", "host_update_pending", "host_reboot_required",
                   "host_unattended_last_run_age_seconds", "host_update_check_success",
                   "host_update_oldest_pending_age_seconds", "host_update_state_ok",
                   "HOST_LABEL", "systemd", "cron", "twingate-influx-write.py", "Telegraf", "uid 0"):
        assert needle in text, needle
    assert not re.search(r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b", text.replace("127.0.0.1", ""))


# ---------------------------------------------------------------- revert proofs (clean mutants)
# Each mutant is a scratch copy of the script with ONE guard neutralized (the line carrying the
# marker comment is replaced). The scenario must satisfy its guard on the unmutated copy and violate
# it on the mutant. A scenario may return "rewrites" (extra fixed-line rewrites for both copies).

def guard_failed(r, env):
    return r.returncode != 0 and re.fullmatch(r"host_update_check_success(,[^ ]*)? value=0i\n", r.stdout) is not None


def guard_ok(r, env):
    return r.returncode == 0 and re.search(r"host_update_check_success,[^ ]* value=1i\n", r.stdout) is not None


def guard_state_untrusted(r, env):
    m = parse(r.stdout)
    return m[("host_update_state_ok", None, None)] == 0 and ("host_update_oldest_pending_age_seconds", None, None) not in m


def guard_state_trusted(r, env):
    return parse(r.stdout)[("host_update_state_ok", None, None)] == 1


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


def sc_apt_env(env):
    return {"extra": HOSTILE_ENV}


def guard_apt_env_clean(r, env):
    return r.returncode == 0 and env.recorded_env() == CLEAN_APT_ENV


def sc_apt_bound(env):
    env.set_apt(big_output(4300000))
    return {}


def sc_line_cap(env):
    env.set_apt(PREAMBLE + "\n" * 50000 + SUMMARY0 + "\n")
    return {}


def sc_inst_cap(env):
    env.set_apt(apt_out(pkg_lines(1001)))
    return {}


def sc_abs_apt(env):
    return {"rewrites": {"apt_bin": "bin/apt-get"}}


def sc_arch(env):
    env.set_apt(apt_out([inst("foo", "1", "2", DEB_SEC, arch="arm;64")]))
    return {}


def sc_version(env):
    env.set_apt(apt_out([f"Inst foo [1] (2;x {DEB_SEC} [arm64])\n"]))
    return {}


def sc_origin(env):
    env.set_apt(apt_out([f"Inst foo [1] (2 {DEB_SEC};x [arm64])\n"]))
    return {}


def guard_origin_non_security(r, env):
    m = parse(r.stdout)
    return r.returncode == 0 and m[("host_update_pending", "package", "false")] == 1 \
        and m[("host_update_pending", "package", "true")] == 0


def sc_held(env):
    env.set_apt(apt_out([inst("foo", "1", "2", DEB_SEC)],
                        summary="1 upgraded, 0 newly installed, 0 to remove and 3 not upgraded."))
    return {}


def guard_held_three(r, env):
    return r.returncode == 0 and val(r, "host_update_held_back") == 3


def sc_root(env):
    return {"rewrites": {"id_bin": fake_id(env, 0)}}


def sc_leading_zero_state(env):
    f = env.state_dir / "first-seen"
    f.write_text("host-update-state v1\nfoo 2 08\n")
    f.chmod(0o600)
    env.set_apt(apt_out([inst("foo", "1", "2", DEB_UPD)]))
    return {}


def sc_state_size(env):
    f = env.state_dir / "first-seen"
    f.write_text(long_state(1000))
    f.chmod(0o600)
    return {}


def sc_state_count(env):
    now = int(time.time()) - 100
    f = env.state_dir / "first-seen"
    f.write_text("host-update-state v1\n" + "".join(f"p{i} 1 {now}\n" for i in range(1001)))
    f.chmod(0o600)
    return {}


def sc_state_abs(env):
    rel = env.tmp / "relstate"
    rel.mkdir(mode=0o700)
    rel.chmod(0o700)
    (rel / "first-seen").write_text("host-update-state v1\n")
    (rel / "first-seen").chmod(0o600)
    return {"extra": {"STATE_DIRECTORY": "relstate"}}


def sc_state_anchor(env):
    now = int(time.time())
    f = env.state_dir / "first-seen"
    f.write_text(f"host-update-state v1\nlibfoo 2 {now - 8 * DAY}\nfoo 2 {now - 1 * DAY}\n")
    f.chmod(0o600)
    env.set_apt(apt_out([inst("libfoo", "1", "2", DEB_UPD), inst("foo", "1", "2", DEB_UPD)]))
    env.anchor_expect = f"\nfoo 2 {now - 1 * DAY}\n"
    return {}


def guard_state_anchor(r, env):
    new = (env.state_dir / "first-seen").read_text()
    return r.returncode == 0 and env.anchor_expect in new


def sc_noclobber(env):
    victim = env.tmp / "victim"
    victim.write_text("victim\n")
    (env.state_dir / ".first-seen.fixed").symlink_to(victim)
    env.set_apt(apt_out([inst("foo", "1", "2", DEB_UPD)]))
    return {"rewrites": {"tmpf": str(env.state_dir / ".first-seen.fixed")}}


def guard_noclobber(r, env):
    return (env.tmp / "victim").read_text() == "victim\n" and guard_state_untrusted(r, env)


def sc_oldest_clamp(env):
    f = env.state_dir / "first-seen"
    f.write_text(f"host-update-state v1\nfoo 2 {int(time.time()) + 3600}\n")
    f.chmod(0o600)
    env.set_apt(apt_out([inst("foo", "1", "2", DEB_UPD)]))
    return {}


def guard_oldest_zero(r, env):
    return r.returncode == 0 and val(r, "host_update_oldest_pending_age_seconds") == 0


def sc_uu_fallback(env):
    env.log.write_text("2026-01-01 01:00:00,000 INFO Starting unattended upgrades script\n")
    uu_log(env.log.with_name("uu.log.1"), 5400)
    return {}


def sc_uu_anchor(env):
    t = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(time.time() - 100)) + ",000"
    env.log.write_text(f"{t} INFO All upgrades installed and then the host crashed\n")
    return {}


def sc_lists_missing(env):
    env.stamp.unlink()
    env.packages.unlink()
    return {}


def sc_lists_empty(env):
    env.stamp.unlink()
    env.packages.write_text("")
    return {}


def sc_lists_stale(env):
    env.set_mtime(env.stamp, 5 * DAY)
    env.set_mtime(env.packages, 5 * DAY)
    return {}


def sc_lists_newest(env):
    env.set_mtime(env.stamp, 600)
    env.set_mtime(env.packages, 2 * DAY)
    (env.lists / "x_dists_stable_InRelease").write_text("x\n")
    env.set_mtime(env.lists / "x_dists_stable_InRelease", 1 * DAY)
    return {}


def guard_lists_newest(r, env):
    return r.returncode == 0 and 500 <= val(r, "host_update_lists_age_seconds") <= 800


def sc_lists_clamp(env):
    env.set_mtime(env.stamp, -3600)
    return {}


def guard_lists_zero(r, env):
    return r.returncode == 0 and val(r, "host_update_lists_age_seconds") == 0


def sc_lists_arg(env):
    return {"args": ("--max-lists-age-days=99", "standard")}


MUTANTS = {
    "unknown-age": ('[ -n "$last" ] || last="$(date \'+%Y-%m-%d %H:%M:%S\'),000"', sc_never_run, guard_failed),
    "apt-rc": (':', sc_apt_rc, guard_failed),
    "apt-env": ('timeout -k 10 120 "$apt_bin" -s -o Debug::NoLocking=1 dist-upgrade </dev/null 2>/dev/null',
                sc_apt_env, guard_apt_env_clean),
    "apt-bound": ('} | head -c 999999999)', sc_apt_bound, guard_failed),
    "apt-abs": (':', sc_abs_apt, guard_failed),
    "summary-required": ('summary_total=$n_inst', sc_no_summary, guard_failed),
    "summary-match": (':', sc_count_mismatch, guard_failed),
    "name-charset": ('[!a-z0-9]* | *[!a-z0-9+.:-]*) : ;;', sc_bad_name, guard_failed),
    "arch-charset": ('"") fail "bad architecture" ;;', sc_arch, guard_failed),
    "version-charset": ('"") return 1 ;;', sc_version, guard_failed),
    "origin-label": ('*[!A-Za-z0-9._:/+,\\ -]*) fail "unexpected characters in origin" ;;', sc_origin,
                     guard_origin_non_security),
    "held-back": ('n_held=0', sc_held, guard_held_three),
    "line-cap": (':', sc_line_cap, guard_failed),
    "inst-cap": (':', sc_inst_cap, guard_failed),
    "root": (':', sc_root, guard_failed),
    "uint": ('"") return 1 ;;', sc_leading_zero_state, guard_state_untrusted),
    "state-uint": (':', sc_leading_zero_state, guard_state_untrusted),
    "state-lost": (':', sc_state_lost, guard_state_untrusted),
    "state-dir-mode": (':', sc_dir_mode, guard_state_untrusted),
    "state-parse": (':', sc_corrupt, guard_state_untrusted),
    "state-size": (':', sc_state_size, guard_state_untrusted),
    "state-count": (':', sc_state_count, guard_state_untrusted),
    "state-abs": (':', sc_state_abs, guard_state_untrusted),
    "state-anchor": ('e=${old_text#*"$k "}', sc_state_anchor, guard_state_anchor),
    "noclobber": (':', sc_noclobber, guard_noclobber),
    "oldest-clamp": (':', sc_oldest_clamp, guard_oldest_zero),
    "uu-fallback": ('for f in "$uu_log"; do', sc_uu_fallback, guard_ok),
    "uu-anchor": ("uu_re='All upgrades installed'", sc_uu_anchor, guard_failed),
    "lists-missing": ('[ -n "$newest" ] || newest=$now', sc_lists_missing, guard_failed),
    "lists-nonempty": (':', sc_lists_empty, guard_failed),
    "lists-stale": (':', sc_lists_stale, guard_failed),
    "lists-newest": ('if [ -z "$newest" ] || [ "$m" -lt "$newest" ]; then newest=$m; fi', sc_lists_newest,
                     guard_lists_newest),
    "lists-clamp": (':', sc_lists_clamp, guard_lists_zero),
    "lists-arg": (':', sc_lists_arg, guard_failed),
}


def test_every_marker_in_the_script_has_a_mutant():
    markers = set(re.findall(r"# MUTATE:([a-z-]+)\s*$", SCRIPT.read_text(encoding="utf-8"), re.M))
    assert markers, "no markers collected"
    # exit-trap is proved by test_exit_trap_prints_failure_on_internal_error (needs two neutralized guards)
    assert markers - {"exit-trap"} == set(MUTANTS), markers ^ set(MUTANTS)


@pytest.mark.parametrize("name", sorted(MUTANTS))
def test_revert_proof_mutant_goes_red(env, name):
    repl, scenario, guard = MUTANTS[name]
    kw = scenario(env)
    rewrites = kw.pop("rewrites", None)
    real = env.build("real-copy.sh", rewrites=rewrites)
    assert guard(env.run(script=real, **kw), env), f"guard {name} does not hold on the unmutated copy"
    # replay the same scenario in a fresh Env on the mutant
    (env.tmp / "replay").mkdir()
    env2 = Env(env.tmp / "replay")
    kw = scenario(env2)
    rewrites = kw.pop("rewrites", None)
    mpath = env2.build(f"mutant-{name}.sh", marks={name: repl}, rewrites=rewrites)
    assert mpath.read_text() != real.read_text()
    assert subprocess.run(["sh", "-n", str(mpath)], timeout=30).returncode == 0, "mutant is not valid shell"
    res = env2.run(script=mpath, **kw)
    try:
        still_guarded = guard(res, env2)
    except (AssertionError, KeyError):
        still_guarded = False
    assert not still_guarded, f"mutant {name} stayed green: the guard is not tested"
