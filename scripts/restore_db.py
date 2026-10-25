#!/usr/bin/env python3
"""
AegisSOC AI — Automated Database Restore Script
Verifies SHA-256 integrity hash prior to restoration to protect against tampering.
"""

import hashlib
import os
import subprocess
import sys
from pathlib import Path


def verify_integrity(backup_path: Path, sha_path: Path) -> bool:
    if not backup_path.exists() or not sha_path.exists():
        print(f"[-] Missing backup or hash file: {backup_path}, {sha_path}")
        return False

    with open(sha_path) as f:
        expected_hash = f.read().split()[0].strip()

    hasher = hashlib.sha256()
    with open(backup_path, "rb") as f:
        while chunk := f.read(65536):
            hasher.update(chunk)
    actual_hash = hasher.hexdigest()

    if actual_hash != expected_hash:
        print(f"[!] INTEGRITY ERROR: Expected {expected_hash}, calculated {actual_hash}. Aborting restore.")
        return False

    print(f"[+] SHA-256 Verified: {actual_hash}")
    return True


def perform_restore(backup_file_path: str) -> bool:
    backup_path = Path(backup_file_path)
    sha_path = Path(str(backup_path) + ".sha256")

    print(f"[*] Verifying integrity for: {backup_path}...")
    if not verify_integrity(backup_path, sha_path):
        return False

    pg_host = os.environ.get("POSTGRES_SERVER", "localhost")
    pg_port = os.environ.get("POSTGRES_PORT", "5432")
    pg_user = os.environ.get("POSTGRES_USER", "aegissoc_user")
    pg_db = os.environ.get("POSTGRES_DB", "aegissoc_db")
    pg_pass = os.environ.get("POSTGRES_PASSWORD", "")

    env = os.environ.copy()
    env["PGPASSWORD"] = pg_pass

    cmd = f"gunzip -c {backup_path} | psql -h {pg_host} -p {pg_port} -U {pg_user} -d {pg_db}"

    print(f"[*] Restoring '{backup_path.name}' into '{pg_db}' on {pg_host}:{pg_port}...")
    try:
        res = subprocess.run(cmd, shell=True, env=env, capture_output=True, text=True)
        if res.returncode == 0:
            print("[+] Database restored successfully.")
            return True
        else:
            print(f"[-] Restore command output: {res.stderr}")
            return False
    except Exception as e:
        print(f"[-] Error during restore execution: {e}")
        return False


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python scripts/restore_db.py <path_to_backup.sql.gz>")
        sys.exit(1)

    success = perform_restore(sys.argv[1])
    sys.exit(0 if success else 1)
