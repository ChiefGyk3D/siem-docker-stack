"""Tests for the file handling of scripts/live-deploy/grafana-deploy.py (issue #125).

Everything runs against temporary directories: no network, no Docker, no live Grafana.
The script must never start a process (Popen is booby-trapped). Tests marked GUARD protect a safety rule; each
one was reverted against the code to prove it fails without the rule.
"""
import os
import re
import shutil
import subprocess
import sys

import pytest

from conftest import REPO_ROOT, import_module_from_path

LIVE = REPO_ROOT / "scripts" / "live-deploy"
SRC = REPO_ROOT / "docker" / "grafana" / "provisioning" / "alerting"
ACTIVE = ("contact-points.yml", "update-alert-rules-unifi.yml", "update-alert-rules-pfsense.yml",
          "heartbeat-alert-rule.yml", "notification-failure-alert-rule.yml")
EMAIL_CP = "email-contact-point.yml.example"
EMAIL_POLICY = "email-notification-policy.yml.example"
COMPOSE = "services:\n  grafana:\n    environment:\n      - GF_SERVER_ROOT_URL=http://localhost:3000\n"
SECRET = "supersecretvalue-0123456789"
ROUTER = "grafana-alerts-" + "z" * 20

@pytest.fixture(autouse=True)
def _umask_022():
    """The script refuses group-writable directories; make the temp dirs 755 whatever the user's umask."""
    old = os.umask(0o022)
    yield
    os.umask(old)

@pytest.fixture()
def gd():
    return import_module_from_path("grafana_deploy_files", LIVE / "grafana-deploy.py")

@pytest.fixture()
def env(gd, tmp_path, monkeypatch):
    siem, stage, cfg, alert = (tmp_path / n for n in ("siem", "stage", "cfg", "alerting"))
    for d in (siem, stage, cfg):
        d.mkdir()
    (siem / "docker-compose.yml").write_text(COMPOSE, encoding="utf-8")
    (cfg / "router-path").write_text(ROUTER, encoding="utf-8")
    for name in ACTIVE + (EMAIL_CP, EMAIL_POLICY):
        shutil.copy(SRC / name, stage / name)
        (stage / name).chmod(0o644)
    monkeypatch.setattr(gd, "STAGE", str(stage))
    monkeypatch.setattr(gd, "PATH_FILE", str(cfg / "router-path"))
    monkeypatch.setattr(gd, "SIEM", str(siem))
    monkeypatch.setattr(gd, "ALERT_DIR", str(alert))
    monkeypatch.setattr(gd, "DS_FILE", str(tmp_path / "ds.yml"))
    monkeypatch.setenv("GRAFANA_WEBHOOK_SECRET", SECRET)
    calls = []

    def no_process(*args, **kwargs):
        calls.append(args)
        raise AssertionError("the deploy script must never start a process")

    monkeypatch.setattr(subprocess, "Popen", no_process)
    return type("Env", (), dict(stage=stage, alert=alert, tmp=tmp_path, calls=calls, siem=siem))

def run(gd, capsys, args):
    code = gd.main(args)
    out = capsys.readouterr()
    return code, out.out, out.err

# ---- the allowlist -------------------------------------------------------------------

def test_allowlist_is_explicit_and_complete(gd):
    assert "notification-failure-alert-rule.yml" in gd.FILES
    assert set(gd.EXAMPLE_FILES) == {EMAIL_CP, EMAIL_POLICY}
    assert not set(gd.EXAMPLE_FILES) & set(gd.FILES), "examples are never in the always-on list"
    for name in tuple(gd.FILES) + tuple(gd.EXAMPLE_FILES):
        assert (SRC / name).is_file(), name
    assert all("*" not in n for n in tuple(gd.FILES) + tuple(gd.EXAMPLE_FILES))

# ---- dry run is the default (GUARD) --------------------------------------------------

def test_no_flag_is_a_dry_run_that_changes_nothing(gd, env, capsys):  # GUARD
    code, out, _ = run(gd, capsys, [])
    assert code == 0 and "dry run" in out
    assert not env.alert.exists() and not (env.tmp / "ds.yml").exists() and env.calls == []
    for name in ACTIVE:
        assert name in out

def test_dry_run_flag_is_the_same_as_no_flag(gd, env, capsys):
    code, out, _ = run(gd, capsys, ["--dry-run"])
    assert code == 0 and "dry run" in out and not env.alert.exists()

def test_apply_needs_the_explicit_flag(gd, env, capsys):
    code, _, _ = run(gd, capsys, ["--apply"])
    assert code == 0 and (env.alert / "notification-failure-alert-rule.yml").is_file()

def test_failure_rule_is_deployed_verbatim_with_mode_644(gd, env, capsys):
    run(gd, capsys, ["--apply"])
    target = env.alert / "notification-failure-alert-rule.yml"
    assert target.read_text(encoding="utf-8") == (SRC / "notification-failure-alert-rule.yml").read_text(encoding="utf-8")
    assert target.stat().st_mode & 0o777 == 0o644

def test_unknown_or_conflicting_flags_exit_nonzero(gd, env, capsys):
    for args in (["--bogus"], ["--apply", "--dry-run"], ["--apply", "--stage"], ["extra"],
                 ["--include-example"], ["--apply", "--force"]):
        code, _, err = run(gd, capsys, args)
        assert code != 0 and err, args
    assert not env.alert.exists() and env.calls == []

# ---- examples stay inactive (GUARD) --------------------------------------------------

def test_examples_are_not_installed_without_naming_them(gd, env, capsys):  # GUARD
    code, out, _ = run(gd, capsys, ["--apply"])
    assert code == 0
    assert not (env.alert / "email-contact-point.yml").exists()
    assert not (env.alert / "email-notification-policy.yml").exists()
    assert not list(env.alert.glob("*.example"))
    assert "inactive" in out

def test_naming_an_example_installs_it_without_the_suffix(gd, env, capsys):
    code, _, _ = run(gd, capsys, ["--apply", "--include-example", EMAIL_CP])
    assert code == 0
    assert (env.alert / "email-contact-point.yml").read_text(encoding="utf-8") == (SRC / EMAIL_CP).read_text(encoding="utf-8")
    assert not (env.alert / "email-notification-policy.yml").exists(), "only the named one"
    assert not (env.alert / EMAIL_CP).exists()

def test_naming_an_example_in_a_dry_run_changes_nothing_and_lists_variable_names(gd, env, capsys):
    code, out, _ = run(gd, capsys, ["--include-example", EMAIL_CP])
    assert code == 0 and not env.alert.exists()
    assert "P1_EMAIL_TO" in out

def test_policy_example_warns_that_it_replaces_the_tree(gd, env, capsys):
    code, out, _ = run(gd, capsys, ["--include-example=" + EMAIL_POLICY])
    assert code == 0 and "replaces the whole notification policy tree" in out

@pytest.mark.parametrize("bad", ["contact-points.yml", "contact-points.yml.example", "../x.example",
                                 "/etc/passwd", "heartbeat-notification-policy.yml.example", "*", ""])
def test_only_allowlisted_examples_can_be_named(gd, env, capsys, bad):  # GUARD
    code, _, err = run(gd, capsys, ["--apply", "--include-example", bad])
    assert code != 0 and err
    assert not env.alert.exists() and env.calls == []

def test_a_named_example_missing_from_the_stage_dir_is_an_error(gd, env, capsys):
    (env.stage / EMAIL_CP).unlink()
    code, _, err = run(gd, capsys, ["--apply", "--include-example", EMAIL_CP])
    assert code != 0 and "missing staged file: " + EMAIL_CP in err
    assert not env.alert.exists()

def test_unnamed_example_may_be_absent_from_the_stage_dir(gd, env, capsys):
    (env.stage / EMAIL_CP).unlink()
    assert run(gd, capsys, ["--apply"])[0] == 0

# ---- backup and diff before overwriting (GUARD) --------------------------------------

def _live(env, name, text, mode=0o644):
    env.alert.mkdir(exist_ok=True)
    (env.alert / name).write_text(text, encoding="utf-8")
    (env.alert / name).chmod(mode)

def test_overwrite_makes_a_timestamped_backup_and_prints_a_diff(gd, env, capsys):  # GUARD
    _live(env, "contact-points.yml", "apiVersion: 1\nold-line: keepme\n")
    code, out, _ = run(gd, capsys, ["--apply"])
    assert code == 0
    backups = list(env.alert.glob("contact-points.yml.bak-*"))
    assert len(backups) == 1
    assert backups[0].read_text(encoding="utf-8") == "apiVersion: 1\nold-line: keepme\n"
    assert backups[0].stat().st_mode & 0o777 == 0o600
    assert "keepme" not in out and "changed: +" in out and "lines" in out
    assert "keepme" not in (env.alert / "contact-points.yml").read_text(encoding="utf-8")

def test_backup_name_has_a_utc_timestamp(gd, env, capsys, monkeypatch):
    monkeypatch.setattr(gd, "timestamp", lambda: "20261119T120000Z")
    _live(env, "contact-points.yml", "old\n")
    run(gd, capsys, ["--apply"])
    assert (env.alert / "contact-points.yml.bak-20261119T120000Z").is_file()

def test_two_backups_in_one_second_do_not_clobber_each_other(gd, env, capsys, monkeypatch):
    monkeypatch.setattr(gd, "timestamp", lambda: "20261119T120000Z")
    _live(env, "contact-points.yml", "first\n")
    run(gd, capsys, ["--apply"])
    _live(env, "contact-points.yml", "second\n")
    run(gd, capsys, ["--apply"])
    texts = sorted(p.read_text(encoding="utf-8") for p in env.alert.glob("contact-points.yml.bak-*"))
    assert texts == ["first\n", "second\n"]

def test_dry_run_prints_the_diff_but_writes_no_backup(gd, env, capsys):
    _live(env, "contact-points.yml", "old-line: x\n")
    code, out, _ = run(gd, capsys, [])
    assert code == 0 and "old-line" not in out and "changed: +" in out
    assert not list(env.alert.glob("*.bak-*"))
    assert (env.alert / "contact-points.yml").read_text(encoding="utf-8") == "old-line: x\n"

def test_unchanged_file_gets_no_backup(gd, env, capsys):
    run(gd, capsys, ["--apply"])
    code, out, _ = run(gd, capsys, ["--apply"])
    assert code == 0 and not list(env.alert.glob("*.bak-*"))
    assert "unchanged" in out

def test_overwriting_the_policy_example_target_is_backed_up_too(gd, env, capsys):  # GUARD
    _live(env, "email-notification-policy.yml", "live-policy: precious\n")
    code, out, _ = run(gd, capsys, ["--apply", "--include-example", EMAIL_POLICY])
    assert code == 0
    (backup,) = env.alert.glob("email-notification-policy.yml.bak-*")
    assert backup.read_text(encoding="utf-8") == "live-policy: precious\n"
    assert "precious" not in out and "changed: +" in out

def test_a_failed_backup_stops_before_anything_is_written(gd, env, capsys, monkeypatch):  # GUARD
    _live(env, "heartbeat-alert-rule.yml", "old\n")  # not the first file: the first must not be written either

    def boom(*a, **k):
        raise gd.GuardError("backup failed")

    monkeypatch.setattr(gd, "write_backup", boom)
    code, _, err = run(gd, capsys, ["--apply"])
    assert code != 0 and "backup failed" in err
    assert (env.alert / "heartbeat-alert-rule.yml").read_text(encoding="utf-8") == "old\n"
    assert not (env.alert / "contact-points.yml").exists() and env.calls == []

# ---- secrets are never printed (GUARD) -----------------------------------------------

LEAKY = [
    "headers: {Authorization: Bearer topsecret123}\n",
    "password: |\n  topsecret123\n  secondsecret456\n",
    "token: ${API_TOKEN:-topsecret123}\n",
    "url: https://host/api?access_token=topsecret123\n",
    "clientSecretValue: topsecret123\n",
    "cookie: topsecret123\nprivate: secondsecret456\n",
    "base: &x topsecret123\nref: *x\n",
    "url: https://user:topsecret123@host/hook\n",
    "url: http://n8n/webhook/%s\npassword: hunter2hunter2\n" % ROUTER,
]

@pytest.mark.parametrize("live", LEAKY)
@pytest.mark.parametrize("args", [[], ["--apply"], ["--stage"]])
def test_no_live_file_content_or_secret_reaches_the_output(gd, env, capsys, live, args):  # GUARD
    _live(env, "contact-points.yml", live)
    code, out, err = run(gd, capsys, args)
    assert code == 0
    blob = out + err
    for needle in ("topsecret123", "secondsecret456", "hunter2hunter2", "zzzzzzzz", SECRET, "Bearer"):
        assert needle not in blob, needle

def test_no_new_file_content_is_printed_either(gd, env, capsys):  # GUARD
    code, out, _ = run(gd, capsys, ["--apply"])
    assert code == 0 and ROUTER not in out and "webhook" not in out

def test_variable_names_lists_names_only(gd):
    assert gd.variable_names("addresses: $P1_EMAIL_TO\nx: {{ $labels.a }} ${OTHER_NAME}\n") == ["OTHER_NAME", "P1_EMAIL_TO"]

# ---- paths: symlinks, FIFOs, outside, unexpected (GUARD) -----------------------------

def test_symlinked_staged_file_is_refused(gd, env, capsys):  # GUARD
    outside = env.tmp / "outside.yml"
    outside.write_text("evil: 1\n", encoding="utf-8")
    (env.stage / "heartbeat-alert-rule.yml").unlink()
    (env.stage / "heartbeat-alert-rule.yml").symlink_to(outside)
    code, _, err = run(gd, capsys, ["--apply"])
    assert code != 0 and "symlink" in err
    assert not env.alert.exists() and env.calls == []

def test_symlinked_stage_dir_is_refused(gd, env, capsys, monkeypatch):  # GUARD
    link = env.tmp / "stage-link"
    link.symlink_to(env.stage)
    monkeypatch.setattr(gd, "STAGE", str(link))
    code, _, err = run(gd, capsys, ["--apply"])
    assert code != 0 and "symlink" in err and not env.alert.exists()

def test_symlinked_target_is_refused_and_the_link_destination_untouched(gd, env, capsys):  # GUARD
    victim = env.tmp / "victim.txt"
    victim.write_text("do not touch", encoding="utf-8")
    env.alert.mkdir()
    (env.alert / "heartbeat-alert-rule.yml").symlink_to(victim)
    code, _, err = run(gd, capsys, ["--apply"])
    assert code != 0 and "symlink" in err
    assert victim.read_text(encoding="utf-8") == "do not touch"
    assert env.calls == []

def test_symlinked_alerting_dir_is_refused(gd, env, capsys):  # GUARD
    real = env.tmp / "real-alerting"
    real.mkdir()
    env.alert.symlink_to(real)
    code, _, err = run(gd, capsys, ["--apply"])
    assert code != 0 and "symlink" in err and not list(real.iterdir())

def test_fifo_in_the_stage_dir_is_refused_without_hanging(gd, env, capsys):  # GUARD
    (env.stage / "heartbeat-alert-rule.yml").unlink()
    os.mkfifo(env.stage / "heartbeat-alert-rule.yml")
    code, _, err = run(gd, capsys, ["--apply"])
    assert code != 0 and "regular file" in err and not env.alert.exists()

def test_oversized_staged_file_is_refused(gd, env, capsys):  # GUARD
    (env.stage / "heartbeat-alert-rule.yml").write_text("x" * (gd.MAX_BYTES + 1), encoding="utf-8")
    code, _, err = run(gd, capsys, ["--apply"])
    assert code != 0 and "too large" in err and not env.alert.exists()

@pytest.mark.parametrize("name", ["../etc/passwd", "sub/contact-points.yml", "/etc/passwd", "other.yml",
                                  "contact-points.yml/", "", "heartbeat-notification-policy.yml.example"])
def test_read_staged_refuses_names_off_the_allowlist(gd, env, name):  # GUARD
    with pytest.raises(gd.GuardError):
        gd.read_staged(str(env.stage), name)

def test_non_utf8_target_is_refused_not_clobbered(gd, env, capsys):
    env.alert.mkdir()
    (env.alert / "contact-points.yml").write_bytes(bytes([255, 254, 0]) + b"bad")
    code, _, err = run(gd, capsys, ["--apply"])
    assert code != 0 and err
    assert (env.alert / "contact-points.yml").read_bytes() == bytes([255, 254, 0]) + b"bad"

# ---- errors stop everything, exit nonzero --------------------------------------------

def test_a_missing_file_aborts_before_any_write(gd, env, capsys):  # GUARD
    (env.stage / "notification-failure-alert-rule.yml").unlink()
    code, _, err = run(gd, capsys, ["--apply"])
    assert code != 0 and "missing staged file: notification-failure-alert-rule.yml" in err
    assert not env.alert.exists() and not (env.tmp / "ds.yml").exists() and env.calls == []

def test_stage_flag_keeps_its_one_line_output(gd, env, capsys):
    code, out, _ = run(gd, capsys, ["--stage"])
    assert code == 0 and out.strip() == "staged files ok; router path length 35"
    assert not env.alert.exists()

def test_command_line_default_is_a_dry_run(tmp_path):
    env = {"PATH": "/usr/bin:/bin", "SIEM_DIR": str(tmp_path / "siem"), "SIEM_STAGE_DIR": str(tmp_path / "stage"),
           "SIEM_CONFIG_DIR": str(tmp_path / "cfg")}
    for d in ("siem", "stage", "cfg"):
        (tmp_path / d).mkdir()
    (tmp_path / "siem" / "docker-compose.yml").write_text(COMPOSE, encoding="utf-8")
    (tmp_path / "cfg" / "router-path").write_text(ROUTER, encoding="utf-8")
    for name in ACTIVE:
        shutil.copy(SRC / name, tmp_path / "stage" / name)
        (tmp_path / "stage" / name).chmod(0o644)
    r = subprocess.run([sys.executable, "-I", str(LIVE / "grafana-deploy.py")], capture_output=True, text=True,
                       timeout=60, env=env, check=False)
    assert r.returncode == 0 and "dry run" in r.stdout and ROUTER not in r.stdout
    assert not (tmp_path / "siem" / "grafana").exists()

# ---- docs ----------------------------------------------------------------------------

def test_runbook_documents_the_new_behavior():
    text = " ".join((REPO_ROOT / "docs" / "live-deploy-runbook.md").read_text(encoding="utf-8").split())
    for needle in ("--include-example", "dry run", "notification-failure-alert-rule.yml", EMAIL_CP,
                   EMAIL_POLICY, "bak-", "replaces the whole notification policy tree"):
        assert needle in text, needle
    assert "—" not in text

def test_script_docstring_documents_the_flags():
    head = (LIVE / "grafana-deploy.py").read_text(encoding="utf-8")[:4500]
    for needle in ("--apply", "--include-example", "dry run"):
        assert needle in head, needle

# ---- round 1 review: directories pinned by fd (GUARD) --------------------------------

def test_ancestor_symlink_above_the_alerting_dir_is_refused(gd, env, capsys, monkeypatch):  # GUARD
    real = env.tmp / "real-prov"
    (real / "alerting").mkdir(parents=True)
    link = env.tmp / "prov-link"
    link.symlink_to(real)
    monkeypatch.setattr(gd, "ALERT_DIR", str(link / "alerting"))
    code, _, err = run(gd, capsys, ["--apply"])
    assert code != 0 and "symlink" in err
    assert not list((real / "alerting").iterdir()) and env.calls == []

def test_ancestor_symlink_above_the_stage_dir_is_refused(gd, env, capsys, monkeypatch):  # GUARD
    link = env.tmp / "top-link"
    link.symlink_to(env.tmp)
    monkeypatch.setattr(gd, "STAGE", str(link / "stage"))
    code, _, err = run(gd, capsys, ["--apply"])
    assert code != 0 and "symlink" in err and not env.alert.exists()

def test_ancestor_symlink_above_the_datasource_dir_is_refused(gd, env, capsys, monkeypatch):  # GUARD
    real = env.tmp / "real-ds"
    real.mkdir()
    link = env.tmp / "ds-link"
    link.symlink_to(real)
    monkeypatch.setattr(gd, "DS_FILE", str(link / "sub" / "ds.yml"))
    code, _, err = run(gd, capsys, ["--apply"])
    assert code != 0 and not list(real.iterdir()) and env.calls == []

def test_world_writable_alerting_dir_is_refused(gd, env, capsys):  # GUARD
    env.alert.mkdir()
    env.alert.chmod(0o777)
    code, _, err = run(gd, capsys, ["--apply"])
    assert code != 0 and "writable by others" in err and env.calls == []

def test_swapping_the_alerting_path_mid_apply_cannot_redirect_the_writes(gd, env, capsys, monkeypatch):  # GUARD
    evil = env.tmp / "evil"
    evil.mkdir()
    env.alert.mkdir()
    moved = env.tmp / "alerting.real"
    real_rename = os.rename
    state = {"n": 0}

    def swapping(src, dst, *a, **k):
        if state["n"] == 0:
            state["n"] = 1
            real_rename(str(env.alert), str(moved))
            os.symlink(str(evil), str(env.alert))
        return real_rename(src, dst, *a, **k)

    monkeypatch.setattr(gd.os, "rename", swapping)
    code, _, _ = run(gd, capsys, ["--apply"])
    assert code == 0
    assert not list(evil.iterdir()), "writes followed the swapped path"
    assert (moved / "notification-failure-alert-rule.yml").is_file()

def test_a_target_changed_after_planning_aborts_with_nothing_lost(gd, env, capsys, monkeypatch):  # GUARD
    _live(env, "heartbeat-alert-rule.yml", "planned-state\n")

    def edit_then_stamp():
        (env.alert / "heartbeat-alert-rule.yml").write_text("edited-by-someone-else\n", encoding="utf-8")
        return "20261119T120000Z"

    monkeypatch.setattr(gd, "timestamp", edit_then_stamp)
    code, _, err = run(gd, capsys, ["--apply"])
    assert code != 0 and "changed since planning" in err
    assert (env.alert / "heartbeat-alert-rule.yml").read_text(encoding="utf-8") == "edited-by-someone-else\n"
    assert not (env.alert / "contact-points.yml").exists() and env.calls == []
    assert not list(env.alert.glob("*.bak-*")) and not list(env.alert.glob(".*.new-*"))

# ---- round 1 review: apply is transactional (GUARD) ----------------------------------

def _seed_old_set(env):
    _live(env, "contact-points.yml", "old-cp\n")
    _live(env, "heartbeat-alert-rule.yml", "old-hb\n", 0o600)
    (env.tmp / "ds.yml").write_text("old-ds\n", encoding="utf-8")
    return {"contact-points.yml": "old-cp\n", "heartbeat-alert-rule.yml": "old-hb\n"}

# ---- round 1 review: compose backup and edit (GUARD) ---------------------------------

# ---- round 1 review: GRAFANA_SERVICE cannot carry compose options (GUARD) ------------

# ---- round 2 review ------------------------------------------------------------------

def test_no_content_derived_hash_is_printed(gd, env, capsys):  # GUARD
    _live(env, "contact-points.yml", "old\n")
    for args in ([], ["--apply"]):
        code, out, err = run(gd, capsys, args)
        assert code == 0 and "changed: +" in out
        assert "sha256" not in out + err and not re.search(r"[0-9a-f]{10,}", out + err)
        _live(env, "contact-points.yml", "old\n")

def test_a_failed_backup_write_leaves_no_backup_file(gd, env, capsys, monkeypatch):  # GUARD
    _live(env, "contact-points.yml", "old\n")
    real = os.fsync

    def failing(fd):
        try:
            target = os.readlink("/proc/self/fd/%d" % fd)
        except OSError:
            target = ""
        if ".bak-" in target:
            raise OSError(28, "no space")
        return real(fd)

    monkeypatch.setattr(gd.os, "fsync", failing)
    code, _, err = run(gd, capsys, ["--apply"])
    assert code != 0
    assert not list(env.alert.glob("*.bak-*")) and not list(env.alert.glob(".*part*"))
    assert (env.alert / "contact-points.yml").read_text(encoding="utf-8") == "old\n"
    assert not list(env.alert.glob(".*.new-*")) and env.calls == []

def test_a_file_changed_between_backup_and_rename_is_not_overwritten(gd, env, capsys, monkeypatch):  # GUARD
    _live(env, "contact-points.yml", "old-cp\n")
    _live(env, "heartbeat-alert-rule.yml", "old-hb\n")
    real = gd.write_backup

    def spy(dfd, target, text, stamp):
        out = real(dfd, target, text, stamp)
        if target == "heartbeat-alert-rule.yml":
            (env.alert / "contact-points.yml").write_text("concurrent\n", encoding="utf-8")
        return out

    monkeypatch.setattr(gd, "write_backup", spy)
    code, _, err = run(gd, capsys, ["--apply"])
    assert code != 0 and "changed since planning" in err
    assert (env.alert / "contact-points.yml").read_text(encoding="utf-8") == "concurrent\n"
    assert (env.alert / "heartbeat-alert-rule.yml").read_text(encoding="utf-8") == "old-hb\n"
    assert env.calls == [] and not list(env.alert.glob(".*.new-*"))

# ---- round 2: docker must not consume a swapped path (GUARD) -------------------------

def test_a_group_writable_ancestor_is_refused(gd, env, capsys):  # GUARD
    env.tmp.chmod(0o775)
    code, _, err = run(gd, capsys, ["--apply"])
    assert code != 0 and "writable by others" in err and env.calls == []

def test_a_sticky_world_writable_ancestor_is_allowed(gd, env, capsys, monkeypatch):  # GUARD
    (env.tmp / "dsdir").mkdir()
    monkeypatch.setattr(gd, "DS_FILE", str(env.tmp / "dsdir" / "ds.yml"))
    env.tmp.chmod(0o1777)
    assert run(gd, capsys, ["--apply"])[0] == 0

# ---- round 3: simple apply, failure report, docker binary ----------------------------

def _count_manifest(out):
    return len(re.findall(r"^manifest: ", out, flags=re.M))

@pytest.mark.parametrize("fail_on", [1, 3, 5, 6])
def test_a_failed_rename_stops_and_reports_exactly_what_was_replaced(gd, env, capsys, monkeypatch, fail_on):  # GUARD
    _seed_old_set(env)
    real = gd.commit_rename
    state = {"n": 0}

    def flaky(dfd, tmp, name):
        state["n"] += 1
        if state["n"] == fail_on:
            raise OSError("boom")
        return real(dfd, tmp, name)

    monkeypatch.setattr(gd, "commit_rename", flaky)
    code, out, err = run(gd, capsys, ["--apply"])
    assert code != 0 and env.calls == []
    assert _count_manifest(out) == fail_on - 1, "one manifest line per replaced file, printed as it happens"
    if fail_on == 1:
        assert "nothing was replaced" in err
        assert (env.alert / "contact-points.yml").read_text(encoding="utf-8") == "old-cp\n"
    else:
        assert "already replaced" in err.lower()
        for name in re.findall(r"^manifest: (?:replaced|created) (\S+)", out, flags=re.M):
            assert name in err
        for name in re.findall(r"^manifest: replaced (\S+)", out, flags=re.M):
            for backup in list(env.alert.glob(name + ".bak-*")) \
                    + list(env.tmp.glob(name + ".bak-*")):
                assert backup.name in err, "the report names the backup that restores each file"
        assert "cp " in err, "the report says how to restore by hand"
    assert not list(env.alert.glob(".*.new-*")) and not list(env.tmp.glob(".*.new-*"))
    assert (env.siem / "docker-compose.yml").read_text(encoding="utf-8") == COMPOSE

def test_files_after_the_failure_are_never_touched(gd, env, capsys, monkeypatch):  # GUARD
    _seed_old_set(env)
    real = gd.commit_rename
    state = {"n": 0}

    def flaky(dfd, tmp, name):
        state["n"] += 1
        if state["n"] == 2:
            raise OSError("boom")
        return real(dfd, tmp, name)

    monkeypatch.setattr(gd, "commit_rename", flaky)
    run(gd, capsys, ["--apply"])
    assert (env.alert / "heartbeat-alert-rule.yml").read_text(encoding="utf-8") == "old-hb\n"
    assert (env.tmp / "ds.yml").read_text(encoding="utf-8") == "old-ds\n"
    assert not (env.alert / "update-alert-rules-pfsense.yml").exists()

def test_a_failure_staging_a_temp_file_replaces_nothing_after_it(gd, env, capsys, monkeypatch):  # GUARD
    _seed_old_set(env)
    real = gd.stage_temp
    state = {"n": 0}

    def flaky(*a, **k):
        state["n"] += 1
        if state["n"] == 3:
            raise OSError("disk full")
        return real(*a, **k)

    monkeypatch.setattr(gd, "stage_temp", flaky)
    code, out, err = run(gd, capsys, ["--apply"])
    assert code != 0 and _count_manifest(out) == 2 and "already replaced" in err.lower()
    assert not (env.alert / "update-alert-rules-pfsense.yml").exists()
    assert not list(env.alert.glob(".*.new-*"))

# ---- work directory: validated root, fd based, cleaned up ----------------------------

def test_error_messages_do_not_echo_input_derived_names(gd, env, capsys, monkeypatch):  # GUARD
    real = env.tmp / "realdir"
    (real / "alerting").mkdir(parents=True)
    (env.tmp / "secretcomponent99").symlink_to(real)
    monkeypatch.setattr(gd, "ALERT_DIR", str(env.tmp / "secretcomponent99" / "alerting"))
    code, out, err = run(gd, capsys, ["--apply"])
    assert code != 0 and "secretcomponent99" not in out + err
    code, out, err = run(gd, capsys, ["--tokenvalue123"])
    assert code != 0 and "tokenvalue123" not in out + err
    code, out, err = run(gd, capsys, ["--include-example", "tokenvalue456"])
    assert code != 0 and "tokenvalue456" not in out + err

@pytest.mark.parametrize("payload", [
    "grafana-alerts-good\n        injected: true", "grafana-alerts-good\r\nx: y", "grafana-alerts-ab cdefghij",
    "grafana-alerts-abcdefgh'", 'grafana-alerts-abcdefgh"', "grafana-alerts-abc:defghij", "grafana-alerts-abc#defghij",
    "grafana-alerts-abcdefgh\x00", "grafana-alerts-" + "a" * 200, "grafana-alerts-abcdefg", "grafana-alerts-abc/../defgh",
    "grafana-alerts-{{x}}-abcdef", "grafana-alerts-$(id)-abcdef",
])
def test_router_path_injection_is_refused(gd, env, capsys, payload):  # GUARD
    assert not gd.valid_router_path(payload)
    with pytest.raises(ValueError):
        gd.contact_with_path("url: http://n8n/webhook/grafana-alerts\n", payload)
    (env.tmp / "cfg" / "router-path").write_text(payload + "\n", encoding="utf-8")
    code, _, err = run(gd, capsys, ["--apply"])
    assert code != 0 and "router path" in err and not env.alert.exists()

def test_router_path_good_values_still_work(gd):
    assert gd.valid_router_path("grafana-alerts-" + "aB3_-" * 4)
    assert not gd.valid_router_path("")

@pytest.mark.parametrize("bad", ["http://x\ninjected: 1", "http://x y", "javascript:alert", "http://x'", "ftp://x",
                                 "http://x#frag", "http://x\r\n", "http://x:80/a b"])
def test_urls_written_into_yaml_are_validated(gd, bad):  # GUARD
    with pytest.raises(ValueError):
        gd.datasources_yaml(bad)
    with pytest.raises(ValueError):
        gd.contact_with_path("url: http://n8n/webhook/grafana-alerts\n", "grafana-alerts-abcdefgh", base=bad)

def test_good_urls_are_accepted(gd):
    assert "http://192.0.2.7:8086" in gd.datasources_yaml("http://192.0.2.7:8086")
    assert gd.contact_with_path("url: http://n8n/webhook/grafana-alerts\n", "grafana-alerts-abcdefgh",
                                base="https://n8n.example.com:5678/").startswith("url: https://n8n.example.com:5678/webhook/")


# ---- round 4: the script only deploys files (GUARD) ----------------------------------

def _script_tree():
    import ast
    src = (LIVE / "grafana-deploy.py").read_text(encoding="utf-8")
    return ast.parse(src)


def test_the_script_cannot_start_a_process(gd):  # GUARD
    import ast
    tree = _script_tree()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            assert not {a.name.split(".")[0] for a in node.names} & {"subprocess", "shlex", "pty", "multiprocessing"}
        if isinstance(node, ast.ImportFrom):
            assert (node.module or "").split(".")[0] not in {"subprocess", "shlex", "pty", "multiprocessing"}
        if isinstance(node, ast.Attribute) and isinstance(node.value, ast.Name) and node.value.id == "os":
            assert not node.attr.startswith(("exec", "spawn", "popen", "system", "posix_spawn", "fork"))
    assert not hasattr(gd, "subprocess")


def test_the_script_never_names_docker_or_the_compose_file_in_code(gd):  # GUARD
    import ast
    tree = _script_tree()
    docstring = ast.get_docstring(tree, clean=False)
    for node in ast.walk(tree):
        if isinstance(node, ast.Constant) and isinstance(node.value, str) and node.value != docstring:
            low = node.value.lower()
            assert "docker" not in low and "compose" not in low and "webhook_secret" not in low, node.value[:60]
        if isinstance(node, ast.Name):
            assert node.id not in {"COMPOSE", "SERVICE", "docker", "find_docker", "compose_edit"}
    for gone in ("compose_edit", "find_docker", "docker_environment", "Work", "validate_env_file", "project_name"):
        assert not hasattr(gd, gone), gone


def test_the_compose_file_is_never_read_or_changed(gd, env, capsys):  # GUARD
    compose = env.siem / "docker-compose.yml"
    compose.chmod(0)
    try:
        code, _, _ = run(gd, capsys, ["--apply"])
    finally:
        compose.chmod(0o644)
    assert code == 0
    assert compose.read_text(encoding="utf-8") == COMPOSE
    assert sorted(p.name for p in env.siem.iterdir()) == ["docker-compose.yml"]


def test_no_environment_value_is_needed(gd, env, capsys, monkeypatch):
    monkeypatch.delenv("GRAFANA_WEBHOOK_SECRET", raising=False)
    monkeypatch.setenv("GRAFANA_SERVICE", "--remove-orphans")
    assert run(gd, capsys, ["--apply"])[0] == 0


def test_after_a_successful_apply_it_lists_the_files_and_points_at_the_manual_steps(gd, env, capsys):  # GUARD
    _live(env, "contact-points.yml", "old\n")
    code, out, _ = run(gd, capsys, ["--apply"])
    assert code == 0
    tail = out[out.index("files replaced:"):]
    for name in ("contact-points.yml", "heartbeat-alert-rule.yml", "notification-failure-alert-rule.yml", "ds.yml"):
        assert name in tail
    assert "docs/live-deploy-runbook.md" in tail and "by hand" in tail
    assert "docker" not in tail.lower()


def test_when_nothing_changes_it_says_so_and_prints_no_reminder(gd, env, capsys):
    run(gd, capsys, ["--apply"])
    code, out, _ = run(gd, capsys, ["--apply"])
    assert code == 0 and "nothing was replaced" in out and "files replaced:" not in out


def test_manual_steps_are_documented_in_both_runbooks():  # GUARD
    live = " ".join((REPO_ROOT / "docs" / "live-deploy-runbook.md").read_text(encoding="utf-8").split())
    owner = " ".join((REPO_ROOT / "docs" / "owner-runbook.md").read_text(encoding="utf-8").split())
    for text in (live, owner):
        assert "- GRAFANA_WEBHOOK_SECRET" in text
        assert "docker-compose.yml.bak-" in text
        assert ("doppler run --project homelab --config DEV_CONFIG --" in text
                or '"$HOME/bin/siem-net-run" docker compose up -d grafana' in text)
        assert "docker compose ls" in text and "healthy" in text
    assert "never starts docker" in live.lower() and "never reads the compose file" in live.lower()
    assert "grafana-deploy.py" in owner and "--apply" in owner
    for text in (live, owner):
        assert "adds one pass-through line" not in text.lower() and "private copy" not in text.lower()


# ---- round 5: sticky final dirs, strict input files, backup cleanup, ports ------------

@pytest.mark.parametrize("which", ["stage", "alert"])
def test_a_sticky_world_writable_final_directory_is_refused(gd, env, capsys, which):  # GUARD
    target = env.stage if which == "stage" else env.alert
    target.mkdir(exist_ok=True)
    target.chmod(0o1777)
    code, _, err = run(gd, capsys, ["--apply"])
    assert code != 0 and "writable by others" in err
    assert which == "stage" or not list(env.alert.iterdir())


def test_a_sticky_world_writable_config_directory_is_refused(gd, env, capsys):  # GUARD
    (env.tmp / "cfg").chmod(0o1777)
    code, _, err = run(gd, capsys, ["--apply"])
    assert code != 0 and "writable by others" in err and not env.alert.exists()


def test_a_sticky_datasource_directory_is_refused(gd, env, capsys, monkeypatch):  # GUARD
    ds = env.tmp / "dsdir"
    ds.mkdir()
    ds.chmod(0o1777)
    monkeypatch.setattr(gd, "DS_FILE", str(ds / "ds.yml"))
    code, _, err = run(gd, capsys, ["--apply"])
    assert code != 0 and "writable by others" in err and not env.alert.exists()


@pytest.mark.parametrize("mode", [0o664, 0o666, 0o646])
def test_a_staged_file_writable_by_group_or_others_is_refused(gd, env, capsys, mode):  # GUARD
    (env.stage / "heartbeat-alert-rule.yml").chmod(mode)
    code, _, err = run(gd, capsys, ["--apply"])
    assert code != 0 and "writable by group or others" in err and not env.alert.exists()


@pytest.mark.parametrize("mode", [0o664, 0o666])
def test_a_router_path_file_writable_by_group_or_others_is_refused(gd, env, capsys, mode):  # GUARD
    (env.tmp / "cfg" / "router-path").chmod(mode)
    code, _, err = run(gd, capsys, ["--apply"])
    assert code != 0 and "writable by group or others" in err and not env.alert.exists()


def test_a_directory_fsync_failure_after_the_backup_link_removes_the_backup(gd, env, capsys, monkeypatch):  # GUARD
    import stat as stat_module
    _live(env, "contact-points.yml", "old\n")
    real = os.fsync

    def failing(fd):
        if stat_module.S_ISDIR(os.fstat(fd).st_mode):
            raise OSError(5, "io error")
        return real(fd)

    monkeypatch.setattr(gd.os, "fsync", failing)
    code, _, err = run(gd, capsys, ["--apply"])
    assert code != 0 and "backup" in err
    assert not list(env.alert.glob("*.bak-*")) and not list(env.alert.glob(".*part*"))
    assert (env.alert / "contact-points.yml").read_text(encoding="utf-8") == "old\n"


@pytest.mark.parametrize("bad", ["http://x:0", "http://x:00", "http://x:00080", "http://x:65536", "http://x:99999",
                                 "http://x:08080", "http://x:\u0668\u0660", "http://x:123456", "http://x:"])
def test_impossible_ports_are_refused(gd, bad):  # GUARD
    assert not gd.valid_url(bad)
    with pytest.raises(ValueError):
        gd.datasources_yaml(bad)


@pytest.mark.parametrize("good", ["http://x:1", "http://x:80", "http://x:8086", "http://x:65535", "https://x.example.com"])
def test_real_ports_are_accepted(gd, good):
    assert gd.valid_url(good)


def test_the_manual_compose_steps_are_safe_in_both_runbooks():  # GUARD
    live = " ".join((REPO_ROOT / "docs" / "live-deploy-runbook.md").read_text(encoding="utf-8").split())
    owner = " ".join((REPO_ROOT / "docs" / "owner-runbook.md").read_text(encoding="utf-8").split())
    assert "umask 077" in live and "cp --no-clobber" in live and "-rw-------" in live
    assert "only to the grafana service" in live and "awk" in live
    assert "docker compose config" in live and "prints resolved values" in live
    assert "umask 077" in owner or "live runbook" in owner
    assert "any other service" in live
    assert "sed -i '/^      - GF_SERVER_ROOT_URL=/a" not in live + owner
    assert "chmod 644" in live and "group or others" in live


def test_the_docstring_says_only_what_is_true(gd):  # GUARD
    head = " ".join((LIVE / "grafana-deploy.py").read_text(encoding="utf-8").split('"""')[1].lower().split())
    assert "never starts docker" in head and "never reads the compose file" in head
    for stale in ("project-name", "--env-file", "private copy", "sigterm", "grafana_service", "find_docker",
                  "compose_edit", "grafana_webhook_secret"):
        assert stale not in head, stale
    assert "partial" in head and "by hand" in head and "no atomicity" in head

