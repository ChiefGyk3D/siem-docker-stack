"""Fix round 3 for the state backup (issue #83): helper rollback names, Grafana
restore stop semantics, initial container state, strict config typing.

Shares fakes and fixtures with tests/python/test_state_backup.py.
"""
import os
import shutil
import subprocess

import pytest

from test_state_backup import (  # noqa: F401  (fixtures are used by name)
    GDB, RECIPIENT, FakeEncryptor, FakeRuntime, at, cfg, identity, lib, make_backup, restore_cli,
)
from test_state_backup_round1 import NO_OUT  # noqa: F401
from test_state_backup_round2 import AmbiguousStop  # noqa: F401

SH = shutil.which("sh")
TOKEN = "deadbeef"


def _run(tmp, final, side, token=TOKEN):
    args = [str(tmp), str(final), str(os.getuid()), str(os.getgid()), "0600", token, *map(str, side)]
    return subprocess.run(["sh", "-c", lib.HELPER_SCRIPT, "sh", *args], capture_output=True, text=True)


def _fixture(d):
    (d / "db").write_bytes(b"OLD-DB")
    (d / "db-wal").write_bytes(b"OLD-WAL")
    (d / "db-shm").write_bytes(b"OLD-SHM")
    (d / "db.restore").write_bytes(b"NEW")
    return d / "db.restore", d / "db", [d / "db-wal", d / "db-shm"]


def _plant(path, kind):
    if kind == "file":
        path.write_bytes(b"EARLIER-RECOVERY-MATERIAL")
    elif kind == "dir":
        path.mkdir()
    else:
        os.symlink("/nonexistent-target", path)


def _snapshot(d):
    out = {}
    for root, dirs, files in os.walk(d):
        for n in dirs + files:
            p = os.path.join(root, n)
            out[os.path.relpath(p, d)] = ("link", os.readlink(p)) if os.path.islink(p) else (
                ("dir",) if os.path.isdir(p) else ("file", open(p, "rb").read()))
    return out


# ---------------------------------------------------- MED: aside path safety
@pytest.mark.skipif(SH is None, reason="needs a POSIX sh")
@pytest.mark.parametrize("kind", ["file", "dir", "symlink"])
@pytest.mark.parametrize("which", ["db", "db-wal", "db-shm"])
def test_helper_refuses_when_an_aside_path_already_exists(tmp_path, kind, which):
    tmp, final, side = _fixture(tmp_path)
    _plant(tmp_path / f"{which}.old.{TOKEN}", kind)
    before = _snapshot(tmp_path)
    r = _run(tmp, final, side)
    assert r.returncode != 0 and "exists" in r.stderr
    assert _snapshot(tmp_path) == before  # nothing moved, nothing overwritten, nothing nested


@pytest.mark.skipif(SH is None, reason="needs a POSIX sh")
def test_helper_rollback_restores_plain_files_with_a_foreign_old_dir_nearby(tmp_path):
    tmp, final, side = _fixture(tmp_path)
    (tmp_path / "db.old.1").mkdir()  # the PID-style name the old script used; must be irrelevant now
    r = _run(tmp, tmp_path / "nodir" / "db", side)
    assert r.returncode != 0
    for n, data in (("db-wal", b"OLD-WAL"), ("db-shm", b"OLD-SHM")):
        p = tmp_path / n
        assert p.is_file() and not p.is_symlink() and p.read_bytes() == data
    assert (tmp_path / "db.old.1").is_dir()


def test_install_argv_carries_a_random_hex_token_and_is_fresh_each_time():
    a = lib.install_argv("/t", "/f", 1, 2, "0600", ["/w"])
    b = lib.install_argv("/t", "/f", 1, 2, "0600", ["/w"])
    ta, tb = a[9], b[9]
    assert a[:4] == ["sh", "-c", lib.HELPER_SCRIPT, "sh"] and a[4:9] == ["/t", "/f", "1", "2", "0600"]
    assert len(ta) >= 16 and all(c in "0123456789abcdef" for c in ta) and ta != tb
    assert a[10:] == ["/w"]


# ---------------------------------- MED: restore_grafana and ambiguous stop
def test_grafana_restore_restarts_after_an_ambiguous_stop_failure(cfg, identity):
    final, _, enc = make_backup(cfg)
    rt = AmbiguousStop(sqlite3_available=True)
    with pytest.raises(lib.BackupError, match="lost contact") as ei:
        lib.run_restore(cfg, rt, enc, final, identity, apply=True, only="grafana", now=at(50), out=NO_OUT)
    assert rt.running["grafana"] is True and ("start", "grafana") in rt.calls
    assert "nothing was replaced" in str(ei.value)
    assert not any(c[0] in ("cp_to", "run_helper") for c in rt.calls)


def test_grafana_restore_reports_both_errors_when_the_restart_fails_too(cfg, identity):
    final, _, enc = make_backup(cfg)
    rt = AmbiguousStop(sqlite3_available=True, fail_on="start grafana")
    with pytest.raises(lib.BackupError) as ei:
        lib.run_restore(cfg, rt, enc, final, identity, apply=True, only="grafana", now=at(51), out=NO_OUT)
    msg = str(ei.value)
    assert "RECOVERY NEEDED" in msg and "lost contact" in msg and "fake failure on start grafana" in msg


def test_confirmed_stop_and_good_replacement_leave_grafana_stopped(cfg, identity):
    final, _, enc = make_backup(cfg)
    rt = FakeRuntime(sqlite3_available=True)
    lib.run_restore(cfg, rt, enc, final, identity, apply=True, only="grafana", now=at(52), out=NO_OUT)
    assert rt.running["grafana"] is False and ("start", "grafana") not in rt.calls
    assert rt.fs["grafana"]["/var/lib/grafana/grafana.db"] == GDB


def test_grafana_restore_of_an_already_stopped_container_does_not_stop_or_start_it(cfg, identity):
    final, _, enc = make_backup(cfg)
    rt = FakeRuntime(sqlite3_available=True)
    rt.running["grafana"] = False
    lib.run_restore(cfg, rt, enc, final, identity, apply=True, only="grafana", now=at(53), out=NO_OUT)
    assert ("stop", "grafana") not in rt.calls and ("start", "grafana") not in rt.calls
    assert rt.fs["grafana"]["/var/lib/grafana/grafana.db"] == GDB


# ------------------------------------------- LOW: initial state is preserved
def test_initially_stopped_container_stays_stopped():
    rt = FakeRuntime()
    rt.running["n8n"] = False
    ran = []
    lib.run_while_stopped(rt, "n8n", lambda: ran.append(1), "hint")
    assert ran == [1] and rt.running["n8n"] is False
    assert ("start", "n8n") not in rt.calls and ("stop", "n8n") not in rt.calls


def test_initially_running_container_is_started_again():
    rt = FakeRuntime()
    lib.run_while_stopped(rt, "n8n", lambda: None, "hint")
    assert rt.running["n8n"] is True and ("stop", "n8n") in rt.calls and ("start", "n8n") in rt.calls


def test_failed_inspect_stops_before_any_mutation():
    rt = FakeRuntime()
    rt.inspect_fails = True
    ran = []
    with pytest.raises(lib.BackupError, match="inspect"):
        lib.run_while_stopped(rt, "n8n", lambda: ran.append(1), "hint")
    assert ran == [] and rt.calls == []


def test_stop_copy_backup_leaves_an_already_stopped_grafana_stopped(cfg):
    cfg.grafana_db_method = "stop-copy"
    rt = FakeRuntime(sqlite3_available=True)
    rt.running["grafana"] = False
    lib.run_backup(cfg, rt, FakeEncryptor(), now=at(54))
    assert rt.running["grafana"] is False and ("start", "grafana") not in rt.calls


def test_docker_runtime_inspect_parses_state(monkeypatch):
    seen = {}

    def fake_run(argv, what):
        seen["argv"] = argv

        class R:
            stdout = b"true\n"
        return R()

    monkeypatch.setattr(lib, "_run", fake_run)
    assert lib.DockerRuntime("docker").is_running("n8n") is True
    assert seen["argv"][:2] == ["docker", "inspect"] and "n8n" in seen["argv"]
    monkeypatch.setattr(lib, "_run", lambda argv, what: type("R", (), {"stdout": b"false\n"})())
    assert lib.DockerRuntime("docker").is_running("n8n") is False
    monkeypatch.setattr(lib, "_run", lambda argv, what: type("R", (), {"stdout": b"maybe\n"})())
    with pytest.raises(lib.BackupError):
        lib.DockerRuntime("docker").is_running("n8n")


# ------------------------------------------------------ LOW: strict typing
@pytest.mark.parametrize("field,value", [
    ("helper_image", 7), ("helper_image", ["alpine"]), ("helper_image", None),
    ("grafana_db_method", 5), ("container_runtime", 5), ("n8n_container", 5), ("grafana_container", None),
    ("grafana_db_mode", 600), ("n8n_key_mode", 0o600), ("retention", "14"), ("retention", 14.0),
    ("max_total_bytes", "big"), ("max_member_bytes", 1.5), ("grafana_uid", "472"), ("n8n_gid", None),
    ("rclone_remote", 7), ("age_recipients_file", 7), ("grafana_data_host_dir", 7),
])
def test_every_field_is_type_checked_before_its_regex(tmp_path, field, value):
    kw = dict(destination_dir=str(tmp_path / "d"), age_recipients=[RECIPIENT])
    kw[field] = value
    with pytest.raises(lib.BackupError):  # never a TypeError
        lib.validate_config(lib.Config(**kw))


def test_load_config_turns_wrong_types_into_backup_errors(tmp_path):
    f = tmp_path / "c.toml"
    f.write_text(f'destination_dir = "{tmp_path}/d"\nage_recipients = ["{RECIPIENT}"]\nhelper_image = 7\n')
    with pytest.raises(lib.BackupError):
        lib.load_config(str(f))
    f.write_text("this is = = not toml")
    with pytest.raises(lib.BackupError):
        lib.load_config(str(f))


def test_cli_exit_1_for_a_wrongly_typed_config(tmp_path, capsys, identity):
    f = tmp_path / "c.toml"
    f.write_text(f'destination_dir = "{tmp_path}/d"\nage_recipients = ["{RECIPIENT}"]\nhelper_image = 7\n')
    arch = tmp_path / "a.age"
    arch.write_bytes(b"x")
    rc = restore_cli.main(["--config", str(f), "--identity", identity, str(arch)], runtime=FakeRuntime(),
                          encryptor=FakeEncryptor())
    assert rc == 1 and "Traceback" not in capsys.readouterr().err
