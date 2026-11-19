"""Fix round 2 for the state backup (issue #83): tar metadata bounds, Grafana
replacement atomicity, ambiguous stop failures, config type checks.

Shares fakes and fixtures with tests/python/test_state_backup.py.
"""
import io
import os
import shutil
import subprocess
import tarfile

import pytest

from test_state_backup import (  # noqa: F401  (fixtures are used by name)
    GDB, RECIPIENT, FakeEncryptor, FakeRuntime, at, cfg, identity, lib, make_backup, scratch_entries,
)
from test_state_backup_round1 import NO_OUT, _host_cfg, _manifest_entry  # noqa: F401

MIB = 1 << 20


# ------------------------------------------------- HIGH: tar metadata bounds
def _raw_archive(cfg, tmp_path, items, name="siem-state-20260404T000000Z.tar.gz.age", fmt=tarfile.GNU_FORMAT):
    """items: (TarInfo, bytes). Lets a test forge LongLink and PAX records."""
    raw = tmp_path / "raw.tar.gz"
    with tarfile.open(raw, "w:gz", format=fmt) as t:
        for ti, body in items:
            ti.size = len(body)
            t.addfile(ti, io.BytesIO(body))
    os.makedirs(cfg.destination_dir, exist_ok=True)
    out = os.path.join(cfg.destination_dir, name)
    FakeEncryptor().encrypt(str(raw), out, [RECIPIENT])
    return out


def _tiny_caps(cfg):
    cfg.max_archive_bytes = 10 * MIB  # the compressed bomb is far smaller than this
    cfg.max_member_bytes = 1
    cfg.max_total_bytes = 1


def _dry(cfg, identity, archive):
    return lib.run_restore(cfg, FakeRuntime(), FakeEncryptor(), archive, identity, out=NO_OUT)


def test_gnu_longlink_bomb_is_bounded(cfg, identity, tmp_path):
    _tiny_caps(cfg)
    ll = tarfile.TarInfo("././@LongLink")
    ll.type = tarfile.GNUTYPE_LONGNAME
    a = _raw_archive(cfg, tmp_path, [(ll, b"A" * (8 * MIB))])
    assert os.path.getsize(a) < 100_000  # the attack is cheap to ship
    with pytest.raises(lib.BackupError, match="limit"):
        _dry(cfg, identity, a)
    assert scratch_entries(cfg) == []


def test_oversized_pax_header_is_bounded(cfg, identity, tmp_path):
    _tiny_caps(cfg)
    px = tarfile.TarInfo("PaxHeader/x")
    px.type = tarfile.XHDTYPE
    a = _raw_archive(cfg, tmp_path, [(px, b"A" * (8 * MIB))])
    with pytest.raises(lib.BackupError, match="limit"):
        _dry(cfg, identity, a)


def test_pax_extension_records_are_refused(cfg, identity, tmp_path):
    manifest_bytes = _manifest_entry({"workflows.json": b"[]"})[1]
    mi = tarfile.TarInfo("MANIFEST.json")
    mi.pax_headers = {"comment": "x"}
    a = _raw_archive(cfg, tmp_path, [(mi, manifest_bytes)], fmt=tarfile.PAX_FORMAT)
    with pytest.raises(lib.BackupError, match="extended"):
        _dry(cfg, identity, a)


def test_bounded_reader_caps_the_decompressed_stream():
    r = lib.BoundedReader(io.BytesIO(b"\0" * (3 * MIB)), 4096)
    got = 0
    with pytest.raises(lib.BackupError, match="limit"):
        while True:
            chunk = r.read(65536)
            if not chunk:
                break
            got += len(chunk)
    assert got <= 4096 + 65536


def test_stream_ceiling_scales_with_the_payload_caps(cfg):
    small = lib.stream_ceiling(cfg)
    cfg.max_total_bytes += 5 * MIB
    assert lib.stream_ceiling(cfg) == small + 5 * MIB
    assert small >= cfg.max_total_bytes - 5 * MIB + lib.MAX_MANIFEST_BYTES


def test_valid_archive_still_restores_under_the_ceiling(cfg, identity):
    final, _, enc = make_backup(cfg)
    assert lib.run_restore(cfg, FakeRuntime(), enc, final, identity, out=NO_OUT) == ["n8n", "grafana"]


# ------------------------------------- MED: Grafana replacement is atomic-ish
def _old_set(gdir):
    (gdir / "grafana.db").write_bytes(b"OLD-DB")
    (gdir / "grafana.db-wal").write_bytes(b"OLD-WAL")
    (gdir / "grafana.db-shm").write_bytes(b"OLD-SHM")


def _assert_old_set_intact(gdir):
    assert (gdir / "grafana.db").read_bytes() == b"OLD-DB"
    assert (gdir / "grafana.db-wal").read_bytes() == b"OLD-WAL"
    assert (gdir / "grafana.db-shm").read_bytes() == b"OLD-SHM"
    assert sorted(os.listdir(gdir)) == ["grafana.db", "grafana.db-shm", "grafana.db-wal"]  # no temp or .old left


def _host_setup(cfg, tmp_path):
    gdir = _host_cfg(cfg, tmp_path)
    _old_set(gdir)
    cfg.grafana_uid, cfg.grafana_gid = os.getuid(), os.getgid()
    new = tmp_path / "new.db"
    new.write_bytes(GDB)
    return gdir, str(new)


def test_host_rollback_when_final_rename_fails(cfg, tmp_path, monkeypatch):
    gdir, new = _host_setup(cfg, tmp_path)
    real = os.replace

    def boom(src, dst, *a, **k):
        if str(dst).endswith("grafana.db"):
            raise OSError(28, "No space left on device")
        return real(src, dst, *a, **k)

    monkeypatch.setattr(os, "replace", boom)
    with pytest.raises(lib.BackupError):
        lib._restore_grafana_host(cfg, new)
    monkeypatch.undo()
    _assert_old_set_intact(gdir)


def test_host_rollback_when_a_side_file_cannot_be_moved(cfg, tmp_path, monkeypatch):
    gdir, new = _host_setup(cfg, tmp_path)
    real = os.rename

    def boom(src, dst, *a, **k):
        if str(src).endswith("grafana.db-shm"):
            raise OSError(5, "I/O error")
        return real(src, dst, *a, **k)

    monkeypatch.setattr(os, "rename", boom)
    with pytest.raises(lib.BackupError):
        lib._restore_grafana_host(cfg, new)
    monkeypatch.undo()
    _assert_old_set_intact(gdir)


def test_host_success_leaves_only_the_new_database(cfg, tmp_path):
    gdir, new = _host_setup(cfg, tmp_path)
    lib._restore_grafana_host(cfg, new)
    assert (gdir / "grafana.db").read_bytes() == GDB
    assert sorted(os.listdir(gdir)) == ["grafana.db"]


SH = shutil.which("sh")


def _helper(args):
    args = args[:5] + ["abc123"] + args[5:]  # tmp final uid gid mode TOKEN side files...
    return subprocess.run(["sh", "-c", lib.HELPER_SCRIPT, "sh", *args], capture_output=True, text=True)


@pytest.mark.skipif(SH is None, reason="needs a POSIX sh")
def test_helper_script_success(tmp_path):
    (tmp_path / "db").write_bytes(b"OLD")
    (tmp_path / "db-wal").write_bytes(b"W")
    (tmp_path / "db-shm").write_bytes(b"S")
    (tmp_path / "db.restore").write_bytes(b"NEW")
    r = _helper([str(tmp_path / "db.restore"), str(tmp_path / "db"), str(os.getuid()), str(os.getgid()), "0640",
                 str(tmp_path / "db-wal"), str(tmp_path / "db-shm")])
    assert r.returncode == 0, r.stderr
    assert sorted(os.listdir(tmp_path)) == ["db"]
    assert (tmp_path / "db").read_bytes() == b"NEW" and oct((tmp_path / "db").stat().st_mode & 0o777) == "0o640"


@pytest.mark.skipif(SH is None, reason="needs a POSIX sh")
def test_helper_script_restores_side_files_when_the_final_move_fails(tmp_path):
    (tmp_path / "db-wal").write_bytes(b"W")
    (tmp_path / "db-shm").write_bytes(b"S")
    (tmp_path / "db.restore").write_bytes(b"NEW")
    r = _helper([str(tmp_path / "db.restore"), str(tmp_path / "nodir" / "db"), str(os.getuid()), str(os.getgid()),
                 "0600", str(tmp_path / "db-wal"), str(tmp_path / "db-shm")])
    assert r.returncode != 0
    assert (tmp_path / "db-wal").read_bytes() == b"W" and (tmp_path / "db-shm").read_bytes() == b"S"
    assert sorted(os.listdir(tmp_path)) == ["db-shm", "db-wal", "db.restore"]


@pytest.mark.skipif(SH is None, reason="needs a POSIX sh")
def test_helper_script_touches_nothing_when_chown_fails(tmp_path):
    (tmp_path / "db").write_bytes(b"OLD")
    (tmp_path / "db-wal").write_bytes(b"W")
    (tmp_path / "db.restore").write_bytes(b"NEW")
    r = _helper([str(tmp_path / "db.restore"), str(tmp_path / "db"), "not-a-uid", "not-a-gid", "0600",
                 str(tmp_path / "db-wal")])
    assert r.returncode != 0
    assert (tmp_path / "db").read_bytes() == b"OLD" and (tmp_path / "db-wal").read_bytes() == b"W"


# ----------------------------------------------- MED: ambiguous stop failures
class AmbiguousStop(FakeRuntime):
    """stop() takes effect and then reports failure, as a lost daemon connection can."""

    def __init__(self, *a, **k):
        super().__init__(*a, **k)
        self.running = {"n8n": True, "grafana": True}

    def stop(self, container):
        self.running[container] = False
        self._record("stop", container)
        raise lib.BackupError("lost contact with the daemon while stopping")

    def start(self, container):
        self._record("start", container)
        self.running[container] = True


def test_restore_key_restarts_after_an_ambiguous_stop_failure(cfg, identity):
    final, _, enc = make_backup(cfg)
    rt = AmbiguousStop(sqlite3_available=True)
    rt.fs["n8n"]["/home/node/.n8n/config"] = b'{"encryptionKey":"different"}'
    with pytest.raises(lib.BackupError, match="lost contact"):
        lib.run_restore(cfg, rt, enc, final, identity, apply=True, restore_key=True, now=at(30), out=NO_OUT)
    assert ("start", "n8n") in rt.calls and rt.running["n8n"] is True


def test_stop_copy_backup_restarts_after_an_ambiguous_stop_failure(cfg):
    cfg.grafana_db_method = "stop-copy"
    rt = AmbiguousStop(sqlite3_available=True)
    with pytest.raises(lib.BackupError, match="lost contact"):
        lib.run_backup(cfg, rt, FakeEncryptor(), now=at(31))
    assert ("start", "grafana") in rt.calls and rt.running["grafana"] is True


def test_recovery_message_preserves_both_errors(cfg, identity):
    final, _, enc = make_backup(cfg)
    rt = AmbiguousStop(sqlite3_available=True, fail_on="start n8n")
    rt.fs["n8n"]["/home/node/.n8n/config"] = b'{"encryptionKey":"different"}'
    with pytest.raises(lib.BackupError) as ei:
        lib.run_restore(cfg, rt, enc, final, identity, apply=True, restore_key=True, now=at(32), out=NO_OUT)
    msg = str(ei.value)
    assert "RECOVERY NEEDED" in msg and "lost contact" in msg and "fake failure on start n8n" in msg


# ------------------------------------------------------- LOW: config schema
@pytest.mark.parametrize("field,value", [
    ("allow_missing_n8n_key", "false"), ("allow_missing_n8n_key", 0), ("allow_missing_n8n_key", None),
    ("components", "n8n"), ("components", [1]), ("components", ["n8n", None]),
    ("age_recipients", RECIPIENT), ("age_recipients", None), ("age_recipients", [RECIPIENT, 5]),
    ("age_recipients_file", "relative.txt"), ("age_recipients_file", "/a\nb"), ("age_recipients_file", 5),
    ("age_recipients_file", ["/x"]), ("destination_dir", 5), ("temp_dir", 0), ("rclone_remote", 7),
])
def test_config_type_checks(tmp_path, field, value):
    kw = dict(destination_dir=str(tmp_path / "d"), age_recipients=[RECIPIENT])
    kw[field] = value
    with pytest.raises(lib.BackupError):
        lib.validate_config(lib.Config(**kw))


def test_config_accepts_recipients_file_alone(tmp_path):
    lib.validate_config(lib.Config(destination_dir=str(tmp_path), age_recipients_file="/etc/siem.recipients",
                                   allow_missing_n8n_key=True))


def test_recipients_file_must_be_a_regular_non_symlink_at_use_time(cfg, tmp_path):
    cfg.age_recipients = []
    cfg.age_recipients_file = str(tmp_path / "missing.txt")
    with pytest.raises(lib.BackupError, match="recipients file"):
        lib.run_backup(cfg, FakeRuntime(sqlite3_available=True), FakeEncryptor(), now=at(40))
    real = tmp_path / "real.txt"
    real.write_text(RECIPIENT + "\n")
    link = tmp_path / "link.txt"
    os.symlink(real, link)
    cfg.age_recipients_file = str(link)
    with pytest.raises(lib.BackupError, match="recipients file"):
        lib.run_backup(cfg, FakeRuntime(sqlite3_available=True), FakeEncryptor(), now=at(41))
    cfg.age_recipients_file = str(real)
    assert lib.run_backup(cfg, FakeRuntime(sqlite3_available=True), FakeEncryptor(), now=at(42))


@pytest.mark.parametrize("field,value", [
    ("components", "n8n"), ("components", [1]), ("age_recipients", RECIPIENT), ("age_recipients", None),
])
def test_collection_fields_get_an_explicit_type_error(tmp_path, field, value):
    kw = dict(destination_dir=str(tmp_path / "d"), age_recipients=[RECIPIENT])
    kw[field] = value
    with pytest.raises(lib.BackupError, match="list of strings"):
        lib.validate_config(lib.Config(**kw))
