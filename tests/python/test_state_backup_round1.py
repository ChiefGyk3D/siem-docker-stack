"""Fix round 1 for the state backup (issue #83): findings from the Daybreak review.

Extends tests/python/test_state_backup.py (fakes and fixtures are shared).
"""
import hashlib
import io
import json
import os
import stat
import tarfile

import pytest

from test_state_backup import (  # noqa: F401  (fixtures are used by name)
    DOC, GDB, RECIPIENT, FakeEncryptor, FakeRuntime, at, cfg, identity, lib, make_backup, restore_cli,
    scratch_entries,
)

NO_OUT = lambda *_: None  # noqa: E731


def _good_manifest(members):
    return {"version": 1, "created": "20260101T000000Z",
            "members": {n: {"sha256": hashlib.sha256(b).hexdigest(), "size": len(b)} for n, b in members.items()}}


def _manifest_entry(members):
    return ("MANIFEST.json", json.dumps(_good_manifest(members)).encode())


def _craft(cfg, tmp_path, entries, name="siem-state-20260303T000000Z.tar.gz.age"):
    """Encrypted archive from raw (name, bytes) tar entries, in order, duplicates allowed."""
    raw = tmp_path / "craft.tar.gz"
    with tarfile.open(raw, "w:gz") as t:
        for n, b in entries:
            ti = tarfile.TarInfo(n)
            ti.size = len(b)
            t.addfile(ti, io.BytesIO(b))
    os.makedirs(cfg.destination_dir, exist_ok=True)
    out = os.path.join(cfg.destination_dir, name)
    FakeEncryptor().encrypt(str(raw), out, [RECIPIENT])
    return out


def _dry(cfg, identity, archive):
    return lib.run_restore(cfg, FakeRuntime(), FakeEncryptor(), archive, identity, out=NO_OUT)


# ---------------------------------------------------------------- HIGH 1
def test_duplicate_member_refused(cfg, identity, tmp_path):
    mem = {"workflows.json": b"[]", "credentials.json": b"[]"}
    a = _craft(cfg, tmp_path, [_manifest_entry(mem), ("workflows.json", b"[]"), ("workflows.json", b"[]"),
                               ("credentials.json", b"[]")])
    with pytest.raises(lib.BackupError, match="duplicate"):
        _dry(cfg, identity, a)


def test_exactly_one_manifest_required(cfg, identity, tmp_path):
    mem = {"workflows.json": b"[]"}
    two = _craft(cfg, tmp_path, [_manifest_entry(mem), _manifest_entry(mem)])
    with pytest.raises(lib.BackupError, match="duplicate"):
        _dry(cfg, identity, two)
    none = _craft(cfg, tmp_path, [("workflows.json", b"[]")], name="siem-state-20260304T000000Z.tar.gz.age")
    with pytest.raises(lib.BackupError, match="first archive member"):
        _dry(cfg, identity, none)
    late = _craft(cfg, tmp_path, [("workflows.json", b"[]"), _manifest_entry(mem)],
                  name="siem-state-20260305T000000Z.tar.gz.age")
    with pytest.raises(lib.BackupError, match="first archive member"):
        _dry(cfg, identity, late)


def test_member_count_capped(cfg, identity, tmp_path):
    entries = [_manifest_entry({"workflows.json": b"[]"})] + [(f"x{i}", b"") for i in range(lib.MAX_MEMBERS + 5)]
    with pytest.raises(lib.BackupError, match="too many|unexpected"):
        _dry(cfg, identity, _craft(cfg, tmp_path, entries))


def test_oversized_member_refused(cfg, identity, tmp_path):
    cfg.max_member_bytes = 100
    big = b"A" * 5000
    a = _craft(cfg, tmp_path, [_manifest_entry({"grafana.db": big}), ("grafana.db", big)])
    with pytest.raises(lib.BackupError, match="limit"):
        _dry(cfg, identity, a)
    assert scratch_entries(cfg) == []


def test_total_size_capped(cfg, identity, tmp_path):
    cfg.max_member_bytes = 1000
    cfg.max_total_bytes = 1500
    mem = {"workflows.json": b"w" * 900, "credentials.json": b"c" * 900}
    a = _craft(cfg, tmp_path, [_manifest_entry(mem), ("workflows.json", mem["workflows.json"]),
                               ("credentials.json", mem["credentials.json"])])
    with pytest.raises(lib.BackupError, match="limit"):
        _dry(cfg, identity, a)


def test_bounded_copy_stops_at_the_cap(tmp_path):
    src = io.BytesIO(b"\0" * (3 << 20))  # a 3 MiB "bomb" against a 4 KiB cap
    out = tmp_path / "o"
    with open(out, "wb") as fh, pytest.raises(lib.BackupError, match="limit"):
        lib.copy_bounded(src, fh, 4096)
    assert os.path.getsize(out) <= 4096 + lib.CHUNK


def test_lying_manifest_bomb_is_refused(cfg, identity, tmp_path):
    # manifest claims 10 bytes; the member is far larger than the claim
    man = ("MANIFEST.json", json.dumps({"version": 1, "created": "20260101T000000Z", "members": {
        "grafana.db": {"sha256": "0" * 64, "size": 10}}}).encode())
    a = _craft(cfg, tmp_path, [man, ("grafana.db", b"\0" * (1 << 20))])
    with pytest.raises(lib.BackupError, match="size|limit"):
        _dry(cfg, identity, a)


def test_archive_size_cap_before_decrypt(cfg, identity):
    final, _, _ = make_backup(cfg)
    cfg.max_archive_bytes = 10

    class NoDecrypt(FakeEncryptor):
        def decrypt(self, *a):  # pragma: no cover
            raise AssertionError("decrypt must not run on an oversized archive")

    with pytest.raises(lib.BackupError, match="limit"):
        lib.run_restore(cfg, FakeRuntime(), NoDecrypt(), final, identity, out=NO_OUT)


def test_manifest_size_capped(cfg, identity, tmp_path):
    pad = {"version": 1, "created": "20260101T000000Z", "members": {}, "pad": "x" * (lib.MAX_MANIFEST_BYTES + 10)}
    a = _craft(cfg, tmp_path, [("MANIFEST.json", json.dumps(pad).encode())])
    with pytest.raises(lib.BackupError, match="limit"):
        _dry(cfg, identity, a)


def test_member_size_must_match_manifest(cfg, identity, tmp_path):
    mem = {"workflows.json": b"[]", "credentials.json": b"[]"}
    man = _good_manifest(mem)
    man["members"]["workflows.json"]["size"] = 1
    a = _craft(cfg, tmp_path, [("MANIFEST.json", json.dumps(man).encode()), ("workflows.json", b"[]"),
                               ("credentials.json", b"[]")])
    with pytest.raises(lib.BackupError, match="size|mismatch"):
        _dry(cfg, identity, a)


# ------------------------------------------------------------------ LOW
_H = b"a" * 64
_BAD = [
    b"{", b"null", b"[]", b'{"members":[]}',
    b'{"version":2,"created":"20260101T000000Z","members":{}}',
    b'{"version":1,"created":5,"members":{"workflows.json":{"sha256":"%s","size":1}}}' % _H,
    b'{"version":1,"created":"20260101T000000Z","members":{"workflows.json":{"sha256":"zz","size":1}}}',
    b'{"version":1,"created":"20260101T000000Z","members":{"workflows.json":{"sha256":"%s","size":"1"}}}' % _H,
    b'{"version":1,"created":"20260101T000000Z","members":{"workflows.json":{"sha256":"%s","size":-1}}}' % _H,
    b'{"version":1,"created":"20260101T000000Z","members":{"workflows.json":{"sha256":"%s","size":true}}}' % _H,
    b'{"version":1,"created":"20260101T000000Z","members":{"evil":{"sha256":"%s","size":1}}}' % _H,
    b'{"version":1,"created":"20260101T000000Z","members":{}}',
    b"\xff\xfe",
]


@pytest.mark.parametrize("raw", _BAD)
def test_malformed_manifest_is_a_clean_error(cfg, identity, tmp_path, raw):
    a = _craft(cfg, tmp_path, [("MANIFEST.json", raw), ("workflows.json", b"[]")])
    with pytest.raises(lib.BackupError):
        _dry(cfg, identity, a)


def test_cli_turns_hostile_manifest_into_exit_1(cfg, identity, tmp_path, capsys):
    a = _craft(cfg, tmp_path, [("MANIFEST.json", b"null")])
    cfgfile = tmp_path / "c.toml"
    cfgfile.write_text(f'destination_dir = "{cfg.destination_dir}"\ntemp_dir = "{cfg.temp_dir}"\n'
                       f'age_recipients = ["{RECIPIENT}"]\n')
    rc = restore_cli.main(["--config", str(cfgfile), "--identity", identity, a], runtime=FakeRuntime(),
                          encryptor=FakeEncryptor())
    assert rc == 1 and "Traceback" not in capsys.readouterr().err


# ---------------------------------------------------------------- HIGH 2
def test_destination_symlink_refused(cfg, tmp_path):
    real = tmp_path / "real"
    real.mkdir(mode=0o700)
    os.symlink(real, cfg.destination_dir)
    with pytest.raises(lib.BackupError, match="symlink"):
        lib.run_backup(cfg, FakeRuntime(sqlite3_available=True), FakeEncryptor(), now=at(0))
    assert os.listdir(real) == []


@pytest.mark.parametrize("mode", [0o770, 0o707, 0o777])
def test_destination_writable_by_others_refused(cfg, mode):
    os.makedirs(cfg.destination_dir)
    os.chmod(cfg.destination_dir, mode)
    with pytest.raises(lib.BackupError, match="writable"):
        lib.run_backup(cfg, FakeRuntime(sqlite3_available=True), FakeEncryptor(), now=at(0))


def test_destination_not_a_directory_refused(cfg):
    open(cfg.destination_dir, "w").close()
    with pytest.raises(lib.BackupError, match="directory"):
        lib.run_backup(cfg, FakeRuntime(sqlite3_available=True), FakeEncryptor(), now=at(0))


def test_preplanted_sidecar_symlink_is_not_followed(cfg, tmp_path):
    victim = tmp_path / "victim.txt"
    victim.write_text("precious")
    os.makedirs(cfg.destination_dir, mode=0o700)
    name = lib.manifest_name(lib.archive_name("siem-state", lib.timestamp(at(0))))
    os.symlink(victim, os.path.join(cfg.destination_dir, name))
    with pytest.raises(lib.BackupError, match="exists"):
        lib.run_backup(cfg, FakeRuntime(sqlite3_available=True), FakeEncryptor(), now=at(0))
    assert victim.read_text() == "precious"
    assert scratch_entries(cfg) == []


def test_existing_archive_never_overwritten(cfg):
    final, _, _ = make_backup(cfg, now=at(0))
    before = lib.sha256_file(final)
    with pytest.raises(lib.BackupError, match="exists"):
        lib.run_backup(cfg, FakeRuntime(sqlite3_available=True), FakeEncryptor(), now=at(0))
    assert lib.sha256_file(final) == before
    assert not [n for n in os.listdir(cfg.destination_dir) if ".partial" in n or n.startswith(".")]


def test_publish_never_overwrites_even_if_it_loses_a_race(tmp_path):
    # the early lexists() check can lose a race; the link-based publish must still refuse
    victim = tmp_path / "victim"
    victim.write_text("precious")
    final = tmp_path / "final"
    os.symlink(victim, final)
    partial = tmp_path / "partial"
    partial.write_text("new")
    with pytest.raises(lib.BackupError, match="already exists"):
        lib._publish(str(partial), str(final))
    assert victim.read_text() == "precious" and os.path.islink(final)


def test_host_restore_target_symlink_refused_even_past_preflight(cfg, tmp_path):
    gdir = _host_cfg(cfg, tmp_path)
    victim = tmp_path / "victim.db"
    victim.write_bytes(b"precious")
    os.symlink(victim, gdir / "grafana.db")
    src = tmp_path / "new.db"
    src.write_bytes(GDB)
    with pytest.raises(lib.BackupError, match="symlink"):
        lib._restore_grafana_host(cfg, str(src))
    assert victim.read_bytes() == b"precious"


def test_sidecar_is_private_and_regular(cfg):
    final, _, _ = make_backup(cfg)
    st = os.lstat(final + ".manifest.json")
    assert stat.S_ISREG(st.st_mode) and stat.S_IMODE(st.st_mode) == 0o600


# ------------------------------------------------------------------- MED
def _stale(rt):
    p = "/var/lib/grafana/grafana.db"
    rt.fs["grafana"][p + "-wal"] = b"stale-wal"
    rt.fs["grafana"][p + "-shm"] = b"stale-shm"


def test_container_grafana_restore_removes_wal_and_sets_owner(cfg, identity):
    final, _, enc = make_backup(cfg)
    rt = FakeRuntime(sqlite3_available=True)
    _stale(rt)
    lib.run_restore(cfg, rt, enc, final, identity, apply=True, only="grafana", now=at(5), out=NO_OUT)
    db = "/var/lib/grafana/grafana.db"
    assert db + "-wal" not in rt.fs["grafana"] and db + "-shm" not in rt.fs["grafana"]
    assert rt.meta[("grafana", db)] == (472, 472, 0o600)
    assert rt.fs["grafana"][db] == GDB
    assert not any(k.endswith(".restore") for k in rt.fs["grafana"])
    stops = [i for i, c in enumerate(rt.calls) if c == ("stop", "grafana")]
    helper = [i for i, c in enumerate(rt.calls) if c[0] == "run_helper"]
    assert stops and helper and stops[0] < helper[0]  # only ever replaced while stopped


@pytest.mark.parametrize("missing", ["helper_image", "grafana_uid", "grafana_gid"])
def test_container_grafana_restore_fails_closed_without_owner_config(cfg, identity, missing):
    final, _, enc = make_backup(cfg)
    setattr(cfg, missing, "" if missing == "helper_image" else -1)
    rt = FakeRuntime(sqlite3_available=True)
    with pytest.raises(lib.BackupError, match=missing):
        lib.run_restore(cfg, rt, enc, final, identity, apply=True, only="grafana", now=at(5), out=NO_OUT)
    assert ("stop", "grafana") not in rt.calls  # checked before anything is touched


def test_corrupt_grafana_db_refused_before_stopping(cfg, identity, tmp_path):
    mem = {"grafana.db": b"not a sqlite file at all" * 10}
    a = _craft(cfg, tmp_path, [_manifest_entry(mem), ("grafana.db", mem["grafana.db"])])
    rt = FakeRuntime()
    with pytest.raises(lib.BackupError, match="integrity|sqlite"):
        lib.run_restore(cfg, rt, FakeEncryptor(), a, identity, apply=True, now=at(5), out=NO_OUT)
    assert ("stop", "grafana") not in rt.calls


def _host_cfg(cfg, tmp_path):
    gdir = tmp_path / "gf"
    gdir.mkdir()
    cfg.grafana_data_host_dir = str(gdir)
    return gdir


def test_host_restore_fresh_requires_owner_config(cfg, identity, tmp_path):
    final, _, enc = make_backup(cfg)
    gdir = _host_cfg(cfg, tmp_path)
    cfg.grafana_db_method = "container-sqlite3"
    cfg.grafana_uid = -1
    with pytest.raises(lib.BackupError, match="grafana_uid"):
        lib.run_restore(cfg, FakeRuntime(), enc, final, identity, apply=True, only="grafana", now=at(5), out=NO_OUT)
    assert not (gdir / "grafana.db").exists()


def test_host_restore_removes_wal_and_keeps_existing_owner(cfg, identity, tmp_path):
    final, _, enc = make_backup(cfg)
    gdir = _host_cfg(cfg, tmp_path)
    cfg.grafana_db_method = "container-sqlite3"
    (gdir / "grafana.db").write_bytes(b"old")
    (gdir / "grafana.db-wal").write_bytes(b"w")
    (gdir / "grafana.db-shm").write_bytes(b"s")
    st = os.stat(gdir / "grafana.db")
    cfg.grafana_uid, cfg.grafana_gid = st.st_uid, st.st_gid
    lib.run_restore(cfg, FakeRuntime(sqlite3_available=True), enc, final, identity, apply=True, only="grafana",
                    now=at(5), out=NO_OUT)
    assert (gdir / "grafana.db").read_bytes() == GDB
    assert sorted(os.listdir(gdir)) == ["grafana.db"]  # wal, shm and temp file all gone
    assert stat.S_IMODE(os.stat(gdir / "grafana.db").st_mode) == 0o600


def test_host_restore_refuses_symlink_target(cfg, identity, tmp_path):
    final, _, enc = make_backup(cfg)
    gdir = _host_cfg(cfg, tmp_path)
    cfg.grafana_db_method = "container-sqlite3"
    victim = tmp_path / "victim.db"
    victim.write_bytes(b"precious")
    os.symlink(victim, gdir / "grafana.db")
    with pytest.raises(lib.BackupError, match="symlink"):
        lib.run_restore(cfg, FakeRuntime(sqlite3_available=True), enc, final, identity, apply=True,
                        only="grafana", now=at(5), out=NO_OUT)
    assert victim.read_bytes() == b"precious"


def test_two_applies_keep_both_safety_backups(cfg, identity):
    cfg.retention = 1
    final, _, enc = make_backup(cfg)
    for minute in (20, 21):
        lib.run_restore(cfg, FakeRuntime(sqlite3_available=True), enc, final, identity, apply=True,
                        only="grafana", now=at(minute), out=NO_OUT)
    names = os.listdir(cfg.destination_dir)
    assert len([n for n in names if n.startswith("siem-prerestore-") and n.endswith(".age")]) == 2
    assert len([n for n in names if n.startswith("siem-prerestore-") and n.endswith(".manifest.json")]) == 2
    assert len([n for n in names if n.startswith("siem-state-") and n.endswith(".age")]) == 1


@pytest.mark.parametrize("field,value", [
    ("n8n_container", "--help"), ("n8n_container", "-v"), ("n8n_container", "a:b"), ("n8n_container", "a\nb"),
    ("n8n_container", ""), ("grafana_container", "--config=/tmp/x"), ("container_runtime", "/tmp/attacker"),
    ("container_runtime", "sh"), ("rclone_remote", "--config=/tmp/attacker-rclone.conf"),
    ("rclone_remote", "-x:y"), ("rclone_remote", "remote:a\nb"), ("rclone_remote", "nocolon"),
    ("n8n_key_file", "relative/path"), ("n8n_key_file", "/a\nb"), ("grafana_db_path", "db"),
    ("grafana_data_host_dir", "relative"), ("helper_image", "--privileged"), ("helper_image", "a b"),
    ("destination_dir", "relative"), ("temp_dir", "rel"), ("grafana_db_mode", "rwx"), ("n8n_key_mode", "9999"),
])
def test_config_rejects_option_looking_values(tmp_path, field, value):
    kw = dict(destination_dir=str(tmp_path / "d"), age_recipients=[RECIPIENT])
    kw[field] = value
    with pytest.raises(lib.BackupError):
        lib.validate_config(lib.Config(**kw))


def test_config_accepts_normal_values(tmp_path):
    lib.validate_config(lib.Config(
        destination_dir=str(tmp_path), age_recipients=[RECIPIENT], container_runtime="podman",
        rclone_remote="offsite:siem-state-backups", n8n_container="n8n-1", helper_image="docker.io/library/alpine:3"))


def test_runtime_wrappers_refuse_option_looking_names():
    with pytest.raises(lib.BackupError):
        lib.DockerRuntime("docker").exec("--help", ["true"])
    with pytest.raises(lib.BackupError):
        lib.Remote("--config=/tmp/x").list()


def test_restore_key_restarts_n8n_when_install_fails(cfg, identity):
    final, _, enc = make_backup(cfg)
    rt = FakeRuntime(sqlite3_available=True, fail_on="run_helper n8n")
    key = "/home/node/.n8n/config"
    rt.fs["n8n"][key] = b'{"encryptionKey":"different"}'
    with pytest.raises(lib.BackupError):
        lib.run_restore(cfg, rt, enc, final, identity, apply=True, restore_key=True, now=at(7), out=NO_OUT)
    assert ("stop", "n8n") in rt.calls and ("start", "n8n") in rt.calls
    assert rt.fs["n8n"][key] == b'{"encryptionKey":"different"}'  # old key intact


def test_restore_key_reports_recovery_when_start_fails(cfg, identity):
    final, _, enc = make_backup(cfg)
    rt = FakeRuntime(sqlite3_available=True, fail_on="start n8n")
    rt.fs["n8n"]["/home/node/.n8n/config"] = b'{"encryptionKey":"different"}'
    with pytest.raises(lib.BackupError, match="RECOVERY"):
        lib.run_restore(cfg, rt, enc, final, identity, apply=True, restore_key=True, now=at(8), out=NO_OUT)


def test_restore_key_fails_closed_without_owner_config(cfg, identity):
    final, _, enc = make_backup(cfg)
    cfg.n8n_uid = -1
    rt = FakeRuntime(sqlite3_available=True)
    rt.fs["n8n"]["/home/node/.n8n/config"] = b'{"encryptionKey":"different"}'
    with pytest.raises(lib.BackupError, match="n8n_uid"):
        lib.run_restore(cfg, rt, enc, final, identity, apply=True, restore_key=True, now=at(9), out=NO_OUT)
    assert ("stop", "n8n") not in rt.calls


class SymlinkingRuntime(FakeRuntime):
    def cp_from(self, container, src, dest):
        self._record("cp_from", container, src)
        if src.endswith("workflows.json"):
            os.symlink("/etc/passwd", dest)
        else:
            super().cp_from(container, src, dest)


def test_symlink_from_docker_cp_is_refused(cfg):
    with pytest.raises(lib.BackupError, match="regular file"):
        lib.run_backup(cfg, SymlinkingRuntime(sqlite3_available=True), FakeEncryptor(), now=at(0))
    assert scratch_entries(cfg) == []


def test_docs_state_limits_of_the_checks():
    doc = DOC.read_text().lower()
    assert "advisory" in doc  # the outer manifest is not authentication
    assert "not proof" in doc  # the magic-prefix check
    assert "helper_image" in doc and "max_total_bytes" in doc
