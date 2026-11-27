#!/usr/bin/python3 -I
"""Root-side generation handling for the Twingate collector (issue #222, review round 5).

Run only from `+` (privileged) unit commands, with fixed arguments:

  publish --src DIR --dest DIR   validate the one generation the broker wrote under DIR and copy
                                 it to the root-owned DEST/<run id>/ (no symlink followed for the files inside it), then
                                 point DEST/current at it and remove every older generation
  claim   --dest DIR             the writer records which generation it is about to consume
  cleanup --dest DIR             remove exactly the claimed generation, never any other
  purge   --dest DIR [--if-failed]
                                 remove every generation except the claimed one; with --if-failed
                                 only when $SERVICE_RESULT is not "success" (a missing value counts
                                 as failed)

A generation directory is named by a random run id (32 hex characters) and holds collector.json,
writer.json and manifest.json (run id plus SHA-256 of both files). The stage units read it through
the fixed path DEST/current, a symlink only root can change; every stage re-checks the manifest, so
a switch of `current` between steps can only make a stage refuse to run, never mix two runs.
"""
import contextlib
import fcntl
import hashlib
import json
import os
import re
import secrets
import shutil
import sys
import time

RUN_ID = re.compile(r"[0-9a-f]{32}")   # always used with fullmatch: `$` would accept a trailing newline
MAX_BYTES = 65536
LOCK_WAIT = 30.0   # seconds to wait for another invocation before failing closed
FILES = ("collector.json", "writer.json")


def die(msg):
    print("twingate-generation: " + msg, file=sys.stderr)
    return 1


def secure_dest(dest):
    """Create DEST if needed and require a real directory of the caller's own, mode 700."""
    if not os.path.isabs(dest):
        raise ValueError("dest must be absolute")
    if not os.path.lexists(dest):
        os.makedirs(dest, mode=0o700)
    st = os.lstat(dest)
    if not os.path.isdir(dest) or os.path.islink(dest) or st.st_uid != os.geteuid() or st.st_mode & 0o077:
        raise ValueError("dest is not a private directory of this user")


@contextlib.contextmanager
def locked(dest):
    """Check DEST, then hold an exclusive advisory lock on the directory itself until the block ends.

    Every mutation (publish, claim, cleanup, purge) runs inside it, so two invocations never
    interleave. The directory is opened without following a symlink; the wait is bounded and a
    timeout is an error (fail closed), never a mutation without the lock.
    """
    secure_dest(dest)
    fd = os.open(dest, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        deadline = time.monotonic() + LOCK_WAIT
        while True:
            try:
                fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                break
            except BlockingIOError:
                if time.monotonic() >= deadline:
                    raise OSError("destination is locked by another invocation")
                time.sleep(0.05)
        yield
    finally:
        os.close(fd)


def read_bounded(directory, name):
    fd = os.open(os.path.join(directory, name), os.O_RDONLY | os.O_NOFOLLOW)
    with os.fdopen(fd, "rb") as fh:
        raw = fh.read(MAX_BYTES + 1)
    if len(raw) > MAX_BYTES:
        raise ValueError("file too large")
    return raw


def generations(directory):
    return sorted(e for e in os.listdir(directory) if RUN_ID.fullmatch(e))


def claimed(dest):
    try:
        raw = read_bounded(dest, "claim").decode("ascii")
    except (OSError, ValueError):
        return None
    if raw.endswith("\n"):          # exactly the id, or the id and one newline: nothing else is stripped
        raw = raw[:-1]
    return raw if RUN_ID.fullmatch(raw) else None


def remove_generation(dest, run_id):
    shutil.rmtree(os.path.join(dest, run_id), ignore_errors=True)
    try:
        if os.readlink(os.path.join(dest, "current")) == run_id:
            os.unlink(os.path.join(dest, "current"))
    except OSError:
        pass


def atomic_private(path, raw):
    tmp = path + ".tmp"
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, "wb") as fh:
        fh.write(raw)
    os.replace(tmp, path)


def publish(src, dest):
    with locked(dest):
        publish_locked(src, dest)


def publish_locked(src, dest):
    found = [e for e in os.listdir(src) if RUN_ID.fullmatch(e)]
    if len(found) != 1:
        raise ValueError("expected exactly one generation")
    run_id = found[0]
    gdir = os.path.join(src, run_id)
    if os.path.islink(gdir) or not os.path.isdir(gdir):
        raise ValueError("generation is not a directory")
    manifest_raw = read_bounded(gdir, "manifest.json")
    manifest = json.loads(manifest_raw)
    if not isinstance(manifest, dict) or manifest.get("run_id") != run_id or not isinstance(manifest.get("files"), dict):
        raise ValueError("manifest does not match the generation")
    if set(manifest["files"]) != set(FILES):
        raise ValueError("manifest lists the wrong files")
    contents = {}
    for name in FILES:
        raw = read_bounded(gdir, name)
        if hashlib.sha256(raw).hexdigest() != manifest["files"][name]:
            raise ValueError("file does not match the manifest")
        body = json.loads(raw)
        if not isinstance(body, dict) or body.get("run_id") != run_id:
            raise ValueError("file belongs to another run")
        contents[name] = raw
    target = os.path.join(dest, run_id)
    os.mkdir(target, 0o700)      # an existing generation of this id is a collision: refuse, touch nothing
    try:
        for name in FILES:
            atomic_private(os.path.join(target, name), contents[name])
        atomic_private(os.path.join(target, "manifest.json"), manifest_raw)
        link = os.path.join(dest, "current." + secrets.token_hex(8) + ".tmp")     # never shared between invocations
        try:
            os.symlink(run_id, link)
            os.replace(link, os.path.join(dest, "current"))
        except BaseException:
            with contextlib.suppress(OSError):
                os.unlink(link)
            raise
    except BaseException:
        shutil.rmtree(target, ignore_errors=True)
        raise
    keep = {run_id, claimed(dest)}
    for old in generations(dest):
        if old not in keep:
            shutil.rmtree(os.path.join(dest, old), ignore_errors=True)


def claim(dest):
    with locked(dest):
        claim_locked(dest)


def claim_locked(dest):
    run_id = os.readlink(os.path.join(dest, "current"))
    if not RUN_ID.fullmatch(run_id) or not os.path.isdir(os.path.join(dest, run_id)):
        raise ValueError("no current generation")
    atomic_private(os.path.join(dest, "claim"), run_id.encode("ascii"))


def cleanup(dest):
    with locked(dest):
        cleanup_locked(dest)


def cleanup_locked(dest):
    run_id = claimed(dest)
    if run_id:
        remove_generation(dest, run_id)
    try:
        os.unlink(os.path.join(dest, "claim"))
    except FileNotFoundError:
        pass


def purge(dest, if_failed):
    if if_failed and os.environ.get("SERVICE_RESULT") == "success":
        return
    with locked(dest):
        purge_locked(dest)


def purge_locked(dest):
    keep = claimed(dest)
    for old in generations(dest):
        if old != keep:
            remove_generation(dest, old)
    if os.path.islink(os.path.join(dest, "current")) and not os.path.exists(os.path.join(dest, "current")):
        os.unlink(os.path.join(dest, "current"))


def option(argv, name):
    if name in argv:
        i = argv.index(name)
        if i + 1 < len(argv):
            return argv[i + 1]
    return None


def main(argv):
    if len(argv) < 2:
        return die("usage: publish|claim|cleanup|purge")
    cmd, dest, src = argv[1], option(argv, "--dest"), option(argv, "--src")
    if not dest:
        return die("--dest is required")
    try:
        if cmd == "publish":
            if not src or not os.path.isabs(src):
                return die("--src must be an absolute path")
            publish(src, dest)
        elif cmd == "claim":
            claim(dest)
        elif cmd == "cleanup":
            cleanup(dest)
        elif cmd == "purge":
            purge(dest, "--if-failed" in argv)
        else:
            return die("unknown command")
    except (OSError, ValueError, UnicodeError):
        return die(cmd + " failed")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
