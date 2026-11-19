"""Round 4 for the state backup (issue #83): --restore-n8n-key against a stopped n8n.

The fake here rejects `exec` while a container is stopped, as docker does.
test_state_backup.py's FakeRuntime is subclassed, not changed.
"""
import pytest

from test_state_backup import (  # noqa: F401  (fixtures are used by name)
    FakeRuntime, at, cfg, identity, lib, make_backup,
)

NO_OUT = lambda *_: None  # noqa: E731
KEY = "/home/node/.n8n/config"
OLD = b'{"encryptionKey":"different"}'


class StrictRuntime(FakeRuntime):
    """exec fails on a stopped container; helper-container rm cleanup is supported."""

    def __init__(self, *a, fail_install=False, **k):
        super().__init__(*a, **k)
        self.fail_install = fail_install

    def exec(self, container, argv):
        if not self.running[container]:
            self._record("exec", container, *argv)
            raise lib.BackupError(f"container {container} is not running")
        return super().exec(container, argv)

    def run_helper(self, container, image, argv):
        if argv[:2] == ["sh", "-c"] and argv[2].startswith("rm "):  # cleanup helper
            self._record("run_helper_rm", container, *argv[4:])
            for p in argv[4:]:
                self.fs[container].pop(p, None)
            return
        if self.fail_install:
            self._record("run_helper", container, image, *argv)
            raise lib.BackupError("fake helper failure")
        return super().run_helper(container, image, argv)


def _restore(cfg, identity, final, rt, minute):
    return lib.run_restore(cfg, rt, FakeEnc, final, identity, apply=True, restore_key=True,
                           now=at(minute), out=NO_OUT)


FakeEnc = None


@pytest.fixture
def setup(cfg):
    global FakeEnc
    final, _, enc = make_backup(cfg)
    FakeEnc = enc
    return final


def test_stopped_n8n_refuses_before_any_mutation(cfg, identity, setup):
    rt = StrictRuntime(sqlite3_available=True)
    rt.fs["n8n"][KEY] = OLD
    rt.running["n8n"] = False
    with pytest.raises(lib.BackupError, match="Start n8n and re-run"):
        _restore(cfg, identity, setup, rt, 40)
    assert rt.fs["n8n"][KEY] == OLD
    assert not [c for c in rt.calls if c[0] != "cp_from"]  # no exec, cp_to, helper, stop or start
    assert not any(k.endswith(".restore") for k in rt.fs["n8n"])
    assert rt.running["n8n"] is False  # left as found


def test_helper_failure_with_failed_restart_leaves_no_restore_file(cfg, identity, setup):
    rt = StrictRuntime(sqlite3_available=True, fail_install=True, fail_on="start n8n")
    rt.fs["n8n"][KEY] = OLD
    with pytest.raises(lib.BackupError, match="RECOVERY"):
        _restore(cfg, identity, setup, rt, 41)
    assert rt.running["n8n"] is False  # restart failed, so cleanup could not use exec
    assert rt.fs["n8n"][KEY] == OLD
    assert not any(k.endswith(".restore") for k in rt.fs["n8n"])


def test_helper_failure_with_running_n8n_leaves_no_restore_file(cfg, identity, setup):
    rt = StrictRuntime(sqlite3_available=True, fail_install=True)
    rt.fs["n8n"][KEY] = OLD
    with pytest.raises(lib.BackupError, match="fake helper failure"):
        _restore(cfg, identity, setup, rt, 42)
    assert rt.fs["n8n"][KEY] == OLD
    assert not any(k.endswith(".restore") for k in rt.fs["n8n"])
    assert rt.running["n8n"] is True


def test_running_n8n_key_restore_still_works(cfg, identity, setup):
    rt = StrictRuntime(sqlite3_available=True)
    rt.fs["n8n"][KEY] = OLD
    _restore(cfg, identity, setup, rt, 43)
    assert rt.fs["n8n"][KEY] != OLD
    assert not any(k.endswith(".restore") for k in rt.fs["n8n"])
    assert rt.running["n8n"] is True
    assert any(c[0] == "exec" and "import:credentials" in c for c in rt.calls)
