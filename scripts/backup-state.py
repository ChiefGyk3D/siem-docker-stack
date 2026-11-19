#!/usr/bin/env python3
"""Encrypted off-host backup of n8n and Grafana state (issue #83).

Usage: backup-state.py --config /etc/siem-state-backup.toml
See docs/backup-restore.md. Every archive is encrypted with age before it is written.
"""
import argparse
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import state_backup_lib as lib  # noqa: E402


def main(argv=None, runtime=None, encryptor=None, remote=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--config", required=True)
    args = ap.parse_args(argv)
    try:
        cfg = lib.load_config(args.config)
        rt = runtime or lib.DockerRuntime(cfg.container_runtime)
        enc = encryptor or lib.AgeEncryptor()
        if remote is None and cfg.rclone_remote:
            remote = lib.Remote(cfg.rclone_remote)
        final = lib.run_backup(cfg, rt, enc, remote)
    except lib.BackupError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1
    print(f"backup written: {final}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
