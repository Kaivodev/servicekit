#!/usr/bin/env python3
"""Prepare the disposable Compose stack in its own directory."""
import argparse
import fcntl
import json
import os
import secrets
import shutil
import sys

sys.dont_write_bytecode = True
from stack_config import STATE, prepare, refresh, upgrade_demo, write

root = STATE / "compose"


def extend_legacy():
    # Existing installations used these flags to append passwords in place.
    # Their old Compose project keeps its own certs, volumes and five-role layout.
    services = ("iam", "payment", "ledger", "settlement", "reconciliation")
    fd = os.open(STATE / "stack.env", os.O_RDWR | os.O_APPEND | os.O_NOFOLLOW)
    with os.fdopen(fd, "r+") as f:
        fcntl.flock(f, fcntl.LOCK_EX)
        if os.fstat(fd).st_mode & 0o077:
            raise ValueError("legacy stack.env must be private")
        original = f.read()
        present = {line.split("=", 1)[0] for line in original.splitlines()}
        keys = ("QUEUE_REDIS_PASSWORD", *(svc.upper() + "_DB_PASSWORD" for svc in services))
        missing = [key for key in keys if key not in present]
        if missing:
            if original and not original.endswith("\n"):
                f.write("\n")
            for key in missing:
                f.write(f"{key}={json.dumps(secrets.token_hex(24))}\n")
    for svc in services:
        (STATE / "logs" / svc).mkdir(mode=0o700, exist_ok=True)
    print("Legacy credential check complete. The phase 2 project uses a separate prepare.")


def main():
    os.umask(0o077)
    parser = argparse.ArgumentParser(description=__doc__)
    group = parser.add_mutually_exclusive_group()
    group.add_argument("--demo-config", action="store_true", help="upgrade the prepared Compose demo configuration")
    group.add_argument("--refresh-market", action="store_true")
    group.add_argument("--add-missing-credentials", "--add-queue-credentials", action="store_true",
                       help="extend only the legacy five-service stack")
    args = parser.parse_args()
    if args.add_missing_credentials:
        extend_legacy()
        return
    if args.demo_config:
        if not (root / "prepared").is_file():
            raise ValueError("run prepare first")
        with (root / "refresh.lock").open("a") as lock:
            fcntl.flock(lock, fcntl.LOCK_EX)
            upgrade_demo(root, compose=True)
        print("Updated Compose demo configuration. Recreate the service containers to load it.")
        return
    if args.refresh_market:
        with (root / "refresh.lock").open("a") as lock:
            fcntl.flock(lock, fcntl.LOCK_EX)
            refresh(root)
        print("Refreshed fixtures. Restart reconciliation to load them.")
        return
    passwords = {k: secrets.token_hex(24) for k in ("POSTGRES_PASSWORD", "REDIS_PASSWORD", "QUEUE_REDIS_PASSWORD")}
    prepare(root, "postgresql://postgres@postgres:5432/postgres?sslmode=disable",
            f"redis://:{passwords['REDIS_PASSWORD']}@redis:6379",
            f"redis://:{passwords['QUEUE_REDIS_PASSWORD']}@queue-redis:6379", compose=True)
    path = str(root).replace("'", "\\'")
    try:
        write(root / "stack.env", f"AIPAY_DEV_DIR='{path}'\nAIPAY_DEV_UID={os.getuid()}\nAIPAY_DEV_GID={os.getgid()}\n" +
          "".join(f"{k}={v}\n" for k, v in passwords.items()))
    except BaseException:
        shutil.rmtree(root)
        raise
    print("Prepared Compose stack under ../.local/dev/compose")


if __name__ == "__main__":
    try:
        main()
    except FileExistsError:
        sys.exit("Existing Compose state preserved")
