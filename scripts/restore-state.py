#!/usr/bin/env python3
"""Restore n8n and Grafana state from an encrypted backup (issue #83).

Dry run by default: decrypts into a private temp dir, verifies the manifest
checksums and lists what would be restored. Nothing changes without --apply.
Usage: restore-state.py --config CFG --identity KEYFILE ARCHIVE [--apply]
"""
import argparse
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import state_backup_lib as lib  # noqa: E402


def main(argv=None, runtime=None, encryptor=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--config", required=True)
    ap.add_argument("--identity", required=True, help="age identity (private key) file")
    ap.add_argument("--apply", action="store_true", help="really restore (default is a dry run)")
    ap.add_argument("--dry-run", action="store_true", help="default; accepted for clarity")
    ap.add_argument("--only", choices=("n8n", "grafana"))
    ap.add_argument("--restore-n8n-key", action="store_true",
                    help="replace the running n8n key file with the backup's (needed on a fresh host)")
    ap.add_argument("archive")
    args = ap.parse_args(argv)
    if args.apply and args.dry_run:
        print("ERROR: --apply and --dry-run conflict", file=sys.stderr)
        return 2
    try:
        cfg = lib.load_config(args.config)
        rt = runtime or lib.DockerRuntime(cfg.container_runtime)
        enc = encryptor or lib.AgeEncryptor()
        lib.run_restore(cfg, rt, enc, args.archive, args.identity, apply=args.apply,
                        restore_key=args.restore_n8n_key, only=args.only)
    except lib.BackupError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
