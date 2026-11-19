"""Guards for the n8n and Grafana state backup and restore (issue #83).

No docker and no age binary: the container runtime and the encryption command
sit behind two small interfaces and are faked here. SQLite is real (stdlib).
"""
import json
import os
import re
import sqlite3
import tarfile
from datetime import datetime, timezone

import pytest

from conftest import REPO_ROOT, import_module_from_path

lib = import_module_from_path("state_backup_lib", REPO_ROOT / "scripts" / "state_backup_lib.py")
backup_cli = import_module_from_path("backup_state_cli", REPO_ROOT / "scripts" / "backup-state.py")
restore_cli = import_module_from_path("restore_state_cli", REPO_ROOT / "scripts" / "restore-state.py")

SECRET_MARK = b"SUPER-SECRET-MARKER"


def _sqlite_bytes():
    import tempfile
    with tempfile.TemporaryDirectory() as d:
        c = sqlite3.connect(os.path.join(d, "g.db"))
        c.execute("create table t(x)")
        c.execute("insert into t values ('dash')")
        c.commit()
        c.close()
        return open(os.path.join(d, "g.db"), "rb").read()


GDB = _sqlite_bytes()
RECIPIENT = "age1" + "q" * 58


class FakeRuntime:
    """Container filesystem in a dict; records every call."""

    def __init__(self, sqlite3_available=False, fail_on=None):
        self.fs = {
            "n8n": {"/home/node/.n8n/config": b'{"encryptionKey":"' + SECRET_MARK + b'"}'},
            "grafana": {"/var/lib/grafana/grafana.db": GDB},
        }
        self.meta = {}  # (container, path) -> (uid, gid, mode)
        self.calls = []
        self.running = {"n8n": True, "grafana": True}
        self.inspect_fails = False
        self.sqlite3_available = sqlite3_available
        self.fail_on = fail_on  # substring of a command to fail

    def _record(self, *c):
        self.calls.append(c)
        if self.fail_on and self.fail_on in " ".join(map(str, c)):
            raise lib.BackupError(f"fake failure on {self.fail_on}")

    def exec(self, container, argv):
        self._record("exec", container, *argv)
        fs = self.fs[container]
        if argv[0] == "n8n" and argv[1].startswith("export:"):
            out = next(a.split("=", 1)[1] for a in argv if a.startswith("--output="))
            if argv[1] == "export:workflow":
                fs[out] = b'[{"id":"w1","name":"router"}]'
            else:
                fs[out] = b'[{"id":"c1","data":"n8n-encrypted-blob"}]'
        elif argv[0] == "sqlite3":
            if not self.sqlite3_available:
                raise lib.BackupError("sqlite3: not found")
            fs[argv[2][len(".backup '"):-1]] = fs[argv[1]]
        elif argv[0] == "rm":
            for k in [k for k in fs if any(k.startswith(a) for a in argv[1:] if a.startswith("/"))]:
                del fs[k]
        return b""

    def cp_from(self, container, src, dest):
        self._record("cp_from", container, src)
        if src not in self.fs[container]:
            raise lib.BackupError(f"no such file {src}")
        with open(dest, "wb") as fh:
            fh.write(self.fs[container][src])

    def cp_to(self, container, src, dest):
        self._record("cp_to", container, dest)
        with open(src, "rb") as fh:
            self.fs[container][dest] = fh.read()
        self.meta[(container, dest)] = (0, 0, 0o600)  # docker cp gives no useful ownership

    def run_helper(self, container, image, argv):
        self._record("run_helper", container, image, *argv)
        assert argv[:2] == ["sh", "-c"] and argv[3] == "sh"
        tmp, final, uid, gid, mode, token, *remove = argv[4:]
        assert token and all(c in '0123456789abcdef' for c in token)
        fs = self.fs[container]
        for x in remove:
            fs.pop(x, None)
        fs[final] = fs.pop(tmp)
        self.meta.pop((container, tmp), None)
        self.meta[(container, final)] = (int(uid), int(gid), int(mode, 8))

    def is_running(self, container):
        if self.inspect_fails:
            raise lib.BackupError("inspect failed")
        return self.running[container]

    def stop(self, container):
        self._record("stop", container)
        self.running[container] = False

    def start(self, container):
        self._record("start", container)
        self.running[container] = True

    def mutating(self):
        return [c for c in self.calls if c[0] in ("cp_to", "stop", "start")
                or (c[0] == "exec" and "import" in " ".join(c[2:]))]


class FakeEncryptor:
    """Reversible stand-in for age: magic header + byte-flipped body."""

    def __init__(self):
        self.encrypt_calls = []

    def encrypt(self, src, dest, recipients, recipients_file=""):
        self.encrypt_calls.append(list(recipients))
        with open(src, "rb") as fh:
            body = fh.read()
        with open(dest, "wb") as fh:
            fh.write(lib.AGE_MAGIC + b"\n" + bytes(b ^ 0x5A for b in body))

    def decrypt(self, src, dest, identity):
        with open(identity) as fh:
            if fh.read().strip() != "AGE-SECRET-KEY-FAKE":
                raise lib.BackupError("age decrypt failed (exit 1): no identity matched")
        with open(src, "rb") as fh:
            data = fh.read()
        if not data.startswith(lib.AGE_MAGIC):
            raise lib.BackupError("age decrypt failed: not an age file")
        with open(dest, "wb") as fh:
            fh.write(bytes(b ^ 0x5A for b in data[len(lib.AGE_MAGIC) + 1:]))


class PlaintextEncryptor:
    """A broken encryptor that just copies; the guard must refuse it."""

    def encrypt(self, src, dest, recipients, recipients_file=""):
        with open(src, "rb") as fh, open(dest, "wb") as out:
            out.write(fh.read())

    def decrypt(self, src, dest, identity):  # pragma: no cover
        raise AssertionError


class FakeRemote:
    def __init__(self):
        self.files = {}

    def put(self, local, name):
        with open(local, "rb") as fh:
            self.files[name] = fh.read()

    def list(self):
        return sorted(self.files)

    def delete(self, name):
        del self.files[name]


@pytest.fixture
def cfg(tmp_path):
    return lib.Config(
        destination_dir=str(tmp_path / "dest"),
        temp_dir=str(tmp_path / "scratch"),
        age_recipients=[RECIPIENT],
        retention=3,
        helper_image="alpine",
        grafana_uid=472, grafana_gid=472,
        n8n_uid=1000, n8n_gid=1000,
    )


@pytest.fixture
def identity(tmp_path):
    p = tmp_path / "id.txt"
    p.write_text("AGE-SECRET-KEY-FAKE\n")
    return str(p)


def at(minute):
    return datetime(2026, 1, 1, 0, minute, 0, tzinfo=timezone.utc)


def scratch_entries(cfg):
    return os.listdir(cfg.temp_dir) if os.path.isdir(cfg.temp_dir) else []


def make_backup(cfg, rt=None, enc=None, now=None):
    rt = rt or FakeRuntime(sqlite3_available=True)
    enc = enc or FakeEncryptor()
    return lib.run_backup(cfg, rt, enc, now=now or at(0)), rt, enc


# ---------------------------------------------------------------- backup
def test_backup_is_encrypted_with_manifest_and_no_plaintext(cfg):
    final, rt, enc = make_backup(cfg)
    assert final.endswith(".tar.gz.age")
    data = open(final, "rb").read()
    assert data.startswith(lib.AGE_MAGIC)
    assert SECRET_MARK not in data and b"n8n-encrypted-blob" not in data
    assert enc.encrypt_calls == [[RECIPIENT]]
    outer = json.load(open(final + ".manifest.json"))
    assert outer["sha256"] == lib.sha256_file(final)
    assert outer["members"] == ["credentials.json", "grafana.db", "n8n-config", "workflows.json"]
    assert sorted(os.listdir(cfg.destination_dir)) == sorted(
        [os.path.basename(final), os.path.basename(final) + ".manifest.json"])
    assert oct(os.stat(final).st_mode & 0o777) == "0o600"
    assert scratch_entries(cfg) == []


def test_refuses_to_write_unencrypted(cfg):
    with pytest.raises(lib.BackupError, match="unencrypted"):
        lib.run_backup(cfg, FakeRuntime(sqlite3_available=True), PlaintextEncryptor(), now=at(0))
    assert os.listdir(cfg.destination_dir) == []  # no archive, no .partial
    assert scratch_entries(cfg) == []


def test_config_has_no_unencrypted_mode(tmp_path):
    base = dict(destination_dir=str(tmp_path))
    with pytest.raises(lib.BackupError, match="no unencrypted mode"):
        lib.validate_config(lib.Config(**base))
    with pytest.raises(lib.BackupError, match="SECRET key"):
        lib.validate_config(lib.Config(age_recipients=["AGE-SECRET-KEY-1ABC"], **base))
    with pytest.raises(lib.BackupError, match="public key"):
        lib.validate_config(lib.Config(age_recipients=["hunter2"], **base))
    with pytest.raises(lib.BackupError, match="retention"):
        lib.validate_config(lib.Config(age_recipients=[RECIPIENT], retention=0, **base))


def test_never_uses_decrypted_flag(cfg):
    _, rt, _ = make_backup(cfg)
    flat = [" ".join(map(str, c)) for c in rt.calls]
    assert any("export:credentials" in c for c in flat)
    assert not any("--decrypted" in c for c in flat)
    with pytest.raises(lib.BackupError, match="--decrypted"):
        lib._n8n_cli(rt, cfg, ["export:credentials", "--all", "--decrypted"])
    with pytest.raises(lib.BackupError, match="--decrypted"):
        lib._run(["echo", "--decrypted"], "x")


def test_credentials_flag_absent_from_source():
    # Loose collect, strict assert: the only mention allowed is the guard constant.
    src = (REPO_ROOT / "scripts" / "state_backup_lib.py").read_text()
    uses = [ln for ln in src.splitlines() if "--decrypted" in ln]
    assert uses, "guard not found"
    assert all("FORBIDDEN_FLAG" in ln or "refusing" in ln or ln.lstrip().startswith(('"""', "#")) for ln in uses), uses


def test_temp_dir_removed_on_error(cfg):
    rt = FakeRuntime(sqlite3_available=True, fail_on="export:credentials")
    with pytest.raises(lib.BackupError):
        lib.run_backup(cfg, rt, FakeEncryptor(), now=at(0))
    assert scratch_entries(cfg) == []
    # the in-container temp dir is removed too
    assert not any(k.startswith("/tmp/siem-backup-") for k in rt.fs["n8n"])


def test_temp_dir_is_private_while_running(cfg):
    seen = {}

    class Spy(FakeEncryptor):
        def encrypt(self, src, dest, recipients, recipients_file=""):
            seen["mode"] = os.stat(os.path.dirname(src)).st_mode & 0o777
            super().encrypt(src, dest, recipients, recipients_file)

    make_backup(cfg, enc=Spy())
    assert seen["mode"] == 0o700


def test_missing_n8n_key_fails_unless_allowed(cfg):
    rt = FakeRuntime(sqlite3_available=True)
    del rt.fs["n8n"]["/home/node/.n8n/config"]
    with pytest.raises(lib.BackupError, match="key file"):
        lib.run_backup(cfg, rt, FakeEncryptor(), now=at(0))
    cfg.allow_missing_n8n_key = True
    final, _, _ = make_backup(cfg, rt=rt)
    assert os.path.exists(final)


def test_retention_keeps_exactly_n(cfg):
    for m in range(5):
        make_backup(cfg, now=at(m))
    # a pre-restore safety archive and an unrelated file must never be counted or deleted
    lib_safe = os.path.join(cfg.destination_dir, lib.archive_name(lib.SAFETY_PREFIX, "20250101T000000Z"))
    open(lib_safe, "wb").write(b"x")
    open(os.path.join(cfg.destination_dir, "notes.txt"), "w").write("keep")
    lib.apply_retention_local(cfg.destination_dir, cfg.retention)
    names = sorted(os.listdir(cfg.destination_dir))
    kept = [n for n in names if n.startswith("siem-state-") and n.endswith(".age")]
    assert kept == [lib.archive_name("siem-state", f"20260101T00{m:02d}00Z") for m in (2, 3, 4)]
    assert len([n for n in names if n.endswith(".manifest.json")]) == 3
    assert "notes.txt" in names and os.path.basename(lib_safe) in names


def test_retention_selector_is_pure():
    names = [lib.archive_name("siem-state", f"2026010{d}T000000Z") for d in range(1, 6)]
    assert lib.select_for_retention(names, 5) == []
    assert lib.select_for_retention(names, 2) == names[:3]
    assert lib.select_for_retention(names + ["junk"], 1) == names[:4]


def test_remote_gets_copies_and_retention(cfg):
    remote = FakeRemote()
    for m in range(5):
        lib.run_backup(cfg, FakeRuntime(sqlite3_available=True), FakeEncryptor(), remote, now=at(m))
    archives = [n for n in remote.files if n.endswith(".age")]
    assert len(archives) == 3 and len(remote.files) == 6
    assert all(v.startswith(lib.AGE_MAGIC) for k, v in remote.files.items() if k.endswith(".age"))


def test_grafana_method_never_silently_copies_live_db(cfg):
    # auto without a host dir needs sqlite3 in the image; absent -> loud failure, no raw cp
    rt = FakeRuntime(sqlite3_available=False)
    with pytest.raises(lib.BackupError):
        lib.run_backup(cfg, rt, FakeEncryptor(), now=at(0))
    assert not any(c[0] == "cp_from" and c[2].endswith("grafana.db") for c in rt.calls)


def test_grafana_stop_copy_always_restarts(cfg):
    cfg.grafana_db_method = "stop-copy"
    rt = FakeRuntime(fail_on="/var/lib/grafana/grafana.db")
    with pytest.raises(lib.BackupError):
        lib.run_backup(cfg, rt, FakeEncryptor(), now=at(0))
    assert ("start", "grafana") in rt.calls


def test_host_sqlite_copy_is_consistent(cfg, tmp_path):
    gdir = tmp_path / "gf"
    gdir.mkdir()
    db = sqlite3.connect(gdir / "grafana.db")
    db.execute("pragma journal_mode=wal")
    db.execute("create table t(x)")
    db.execute("insert into t values (42)")
    db.commit()  # stays open: live writer
    cfg.grafana_data_host_dir = str(gdir)
    rt = FakeRuntime()
    final, _, _ = make_backup(cfg, rt=rt)
    assert not any(c[0] == "exec" and c[2] == "sqlite3" for c in rt.calls)
    dest = tmp_path / "copy.db"
    lib.host_sqlite_copy(str(gdir / "grafana.db"), str(dest))
    assert sqlite3.connect(dest).execute("select x from t").fetchall() == [(42,)]
    db.close()


# --------------------------------------------------------------- restore
def test_dry_run_changes_nothing(cfg, identity):
    final, _, enc = make_backup(cfg)
    before = {n: lib.sha256_file(os.path.join(cfg.destination_dir, n)) for n in os.listdir(cfg.destination_dir)}
    rt = FakeRuntime()
    fs_before = json.dumps({k: {p: v.hex() for p, v in d.items()} for k, d in rt.fs.items()}, sort_keys=True)
    lines = []
    parts = lib.run_restore(cfg, rt, enc, final, identity, out=lines.append)
    assert parts == ["n8n", "grafana"]
    assert rt.calls == []  # not even a read
    assert json.dumps({k: {p: v.hex() for p, v in d.items()} for k, d in rt.fs.items()}, sort_keys=True) == fs_before
    assert before == {n: lib.sha256_file(os.path.join(cfg.destination_dir, n)) for n in os.listdir(cfg.destination_dir)}
    assert scratch_entries(cfg) == []
    assert any("dry run" in ln for ln in lines) and any("would restore: n8n" in ln for ln in lines)


def test_cli_default_is_dry_run(cfg, identity, tmp_path, capsys):
    final, _, enc = make_backup(cfg)
    cfgfile = tmp_path / "c.toml"
    cfgfile.write_text(
        f'destination_dir = "{cfg.destination_dir}"\ntemp_dir = "{cfg.temp_dir}"\n'
        f'age_recipients = ["{RECIPIENT}"]\n')
    rt = FakeRuntime()
    rc = restore_cli.main(["--config", str(cfgfile), "--identity", identity, final], runtime=rt, encryptor=enc)
    assert rc == 0 and rt.calls == []
    assert "dry run" in capsys.readouterr().out
    rc = restore_cli.main(["--config", str(cfgfile), "--identity", identity, "--apply", "--dry-run", final],
                          runtime=rt, encryptor=enc)
    assert rc == 2


def test_wrong_identity_stops(cfg, tmp_path):
    final, _, enc = make_backup(cfg)
    bad = tmp_path / "bad.txt"
    bad.write_text("nope")
    with pytest.raises(lib.BackupError, match="decrypt"):
        lib.run_restore(cfg, FakeRuntime(), enc, final, str(bad), apply=True)
    assert scratch_entries(cfg) == []


def test_outer_manifest_mismatch_aborts(cfg, identity):
    final, _, enc = make_backup(cfg)
    with open(final, "ab") as fh:
        fh.write(b"tamper")
    rt = FakeRuntime()
    with pytest.raises(lib.BackupError, match="checksum mismatch"):
        lib.run_restore(cfg, rt, enc, final, identity, apply=True)
    assert rt.calls == []


def _forge(cfg, tmp_path, enc, mutate):
    """Archive whose inner member no longer matches the inner manifest."""
    final, _, _ = make_backup(cfg)
    plain = tmp_path / "plain.tar.gz"
    enc.decrypt(final, str(plain), str(tmp_path / "id.txt"))
    out = tmp_path / "forged"
    out.mkdir()
    with tarfile.open(plain) as t:
        t.extractall(out, filter="data")
    mutate(out)
    forged_tar = tmp_path / "forged.tar.gz"
    with tarfile.open(forged_tar, "w:gz", format=tarfile.USTAR_FORMAT) as t:
        for n in sorted(os.listdir(out)):
            t.add(out / n, arcname=n)
    forged = os.path.join(cfg.destination_dir, lib.archive_name("siem-state", "20260202T000000Z"))
    enc.encrypt(str(forged_tar), forged, [RECIPIENT])
    return forged


def test_inner_manifest_checksum_mismatch_aborts(cfg, identity, tmp_path):
    enc = FakeEncryptor()
    forged = _forge(cfg, tmp_path, enc, lambda d: (d / "workflows.json").write_bytes(b"[]"))
    rt = FakeRuntime()
    with pytest.raises(lib.BackupError, match="checksum mismatch: workflows.json"):
        lib.run_restore(cfg, rt, enc, forged, identity, apply=True)
    assert rt.mutating() == [] and rt.calls == []


def test_extra_member_refused(cfg, identity, tmp_path):
    enc = FakeEncryptor()
    forged = _forge(cfg, tmp_path, enc, lambda d: (d / "evil.sh").write_text("x"))
    with pytest.raises(lib.BackupError, match="unexpected archive member"):
        lib.run_restore(cfg, FakeRuntime(), enc, forged, identity)


def test_apply_restores_in_order_with_safety_backup(cfg, identity):
    final, _, enc = make_backup(cfg)
    rt = FakeRuntime(sqlite3_available=True)
    rt.fs["n8n"]["/home/node/.n8n/config"] = b'{"encryptionKey":"' + SECRET_MARK + b'"}'
    lines = []
    parts = lib.run_restore(cfg, rt, enc, final, identity, apply=True, out=lines.append)
    assert parts == ["n8n", "grafana"]
    flat = [" ".join(map(str, c)) for c in rt.calls]
    imp_c = next(i for i, c in enumerate(flat) if "import:credentials" in c)
    imp_w = next(i for i, c in enumerate(flat) if "import:workflow" in c)
    assert imp_c < imp_w
    assert "--decrypted" not in " ".join(flat)
    assert ("stop", "grafana") in rt.calls and ("start", "grafana") not in rt.calls
    assert rt.fs["grafana"]["/var/lib/grafana/grafana.db"] == GDB
    safeties = [n for n in os.listdir(cfg.destination_dir) if n.startswith("siem-prerestore-") and n.endswith(".age")]
    assert len(safeties) == 1
    first_export = next(i for i, c in enumerate(flat) if "export:workflow" in c)
    assert first_export < imp_c  # replaced state is saved before anything is replaced
    text = "\n".join(lines)
    assert "publish:workflow" in text and "restart n8n" in text and "start grafana" in text
    assert scratch_entries(cfg) == []
    assert not any(k.startswith("/tmp/siem-restore-") for k in rt.fs["n8n"])


def test_apply_stops_at_first_error(cfg, identity):
    final, _, enc = make_backup(cfg)
    rt = FakeRuntime(sqlite3_available=True, fail_on="import:credentials")
    with pytest.raises(lib.BackupError):
        lib.run_restore(cfg, rt, enc, final, identity, apply=True)
    flat = [" ".join(map(str, c)) for c in rt.calls]
    assert not any("import:workflow" in c for c in flat)
    assert ("stop", "grafana") not in rt.calls


def test_key_mismatch_aborts_without_flag(cfg, identity):
    final, _, enc = make_backup(cfg)
    rt = FakeRuntime(sqlite3_available=True)
    rt.fs["n8n"]["/home/node/.n8n/config"] = b'{"encryptionKey":"different"}'
    with pytest.raises(lib.BackupError, match="--restore-n8n-key"):
        lib.run_restore(cfg, rt, enc, final, identity, apply=True, now=at(10))
    assert not any("import:" in " ".join(map(str, c)) for c in rt.calls)
    lib.run_restore(cfg, rt, enc, final, identity, apply=True, restore_key=True, now=at(11))
    key = "/home/node/.n8n/config"
    assert SECRET_MARK in rt.fs["n8n"][key]
    assert rt.meta[("n8n", key)] == (1000, 1000, 0o600)  # not left root-owned by docker cp
    assert ("start", "n8n") in rt.calls and not any(k.endswith(".restore") for k in rt.fs["n8n"])


def test_only_flag_limits_scope(cfg, identity):
    final, _, enc = make_backup(cfg)
    rt = FakeRuntime(sqlite3_available=True)
    parts = lib.run_restore(cfg, rt, enc, final, identity, apply=True, only="grafana")
    assert parts == ["grafana"]
    assert not any("import:" in " ".join(map(str, c)) for c in rt.calls)


def test_backup_cli_exit_codes(cfg, tmp_path, capsys):
    cfgfile = tmp_path / "c.toml"
    cfgfile.write_text(
        f'destination_dir = "{cfg.destination_dir}"\ntemp_dir = "{cfg.temp_dir}"\n'
        f'age_recipients = ["{RECIPIENT}"]\nretention = 2\n')
    rc = backup_cli.main(["--config", str(cfgfile)], runtime=FakeRuntime(sqlite3_available=True),
                         encryptor=FakeEncryptor())
    assert rc == 0 and "backup written" in capsys.readouterr().out
    assert backup_cli.main(["--config", str(tmp_path / "missing.toml")]) == 1
    assert SECRET_MARK.decode() not in capsys.readouterr().out


# ------------------------------------------------------------------ docs
EXAMPLES = REPO_ROOT / "docs" / "examples"
DOC = REPO_ROOT / "docs" / "backup-restore.md"


def test_examples_and_docs_are_placeholders_only():
    files = [EXAMPLES / n for n in ("siem-state-backup.service", "siem-state-backup.timer",
                                    "siem-state-backup.cron", "siem-state-backup.example.toml")]
    assert all(f.exists() for f in files), [f.name for f in files if not f.exists()]
    for f in files + [DOC]:
        assert "AGE-SECRET-KEY-1" not in f.read_text(), f
    for f in files:
        assert "—" not in f.read_text(), f  # no em dash in new files
    # the shipped example must pass the real validator, so it cannot rot
    example = lib.load_config(str(EXAMPLES / "siem-state-backup.example.toml"))
    assert example.age_recipients and re.match(r"age1\w+$", example.age_recipients[0])
    assert "example.com" in (EXAMPLES / "siem-state-backup.example.toml").read_text()
    doc = DOC.read_text().lower()
    for needle in ("backup-state.py", "restore-state.py", "--apply", "secret material", "not verified"):
        assert needle in doc, needle
