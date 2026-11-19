#!/usr/bin/env python3
"""Local process stack for the sibling Kaivo repositories."""
import argparse
import fcntl
import os
from pathlib import Path
import shutil
import subprocess
from urllib.parse import parse_qsl, unquote, urlsplit
import sys
import tempfile

sys.dont_write_bytecode = True
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from stack_config import LIBRARY, OWNERS, SERVICES, STATE, WORKSPACE, prepare, read_env, refresh
from verify import verify
from processes import health, request, services, start, stop, supervise

ROOT = STATE / "native"


def build(out):
    out.mkdir(mode=0o700, parents=True, exist_ok=True)
    env = os.environ | {"GOWORK": "off"}
    for svc in (*OWNERS, "upstream-sim"):
        repo = WORKSPACE / svc
        with tempfile.TemporaryDirectory() as tmp:
            # Even module resolution must not update the read-only sibling repos.
            mod = Path(tmp) / "go.mod"
            shutil.copyfile(repo / "go.mod", mod)
            if (repo / "go.sum").exists():
                shutil.copyfile(repo / "go.sum", mod.with_suffix(".sum"))
            if svc in ("iam", "payment"):
                subprocess.run(["go", "mod", "edit", "-require=github.com/Kaivodev/servicekit@v0.5.0", str(mod)],
                               env=env, cwd=repo, check=True)
            target = "./cmd/upstream-sim" if svc == "upstream-sim" else "."
            subprocess.run(["go", "build", "-mod=mod", "-modfile", str(mod), "-o", str(out / svc), target],
                           cwd=repo, env=env, check=True)
        print(f"built {svc}", flush=True)


def provision():
    admin = os.getenv("AIPAY_DEV_POSTGRES_ADMIN_URL")
    if not admin:
        raise ValueError("set AIPAY_DEV_POSTGRES_ADMIN_URL")
    # No administrator URL in command lines, generated env files or logs.
    u = urlsplit(admin)
    prepared = urlsplit(read_env(ROOT / "env/iam-migrate.env")["AIPAY_DATABASE_URL"])
    if (u.scheme, u.hostname, u.port or 5432, u.query) != (prepared.scheme, prepared.hostname, prepared.port or 5432, prepared.query):
        raise ValueError("administrator URL must target the prepared PostgreSQL instance")
    user = unquote(u.username or os.getenv("USER", "postgres"))
    env = {"PATH": os.environ["PATH"], "PGHOST": u.hostname, "PGPORT": str(u.port or 5432),
           "PGDATABASE": unquote(u.path.lstrip("/")) or user, "PGUSER": user, "PGCONNECT_TIMEOUT": "10"}
    if u.password is not None:
        env["PGPASSWORD"] = unquote(u.password)
    for k, v in parse_qsl(u.query):
        env[{"sslmode": "PGSSLMODE", "sslrootcert": "PGSSLROOTCERT", "connect_timeout": "PGCONNECT_TIMEOUT",
             "application_name": "PGAPPNAME"}[k]] = v
    subprocess.run(["sh", str(LIBRARY / "dev/init-databases.sh")], check=True,
                   env=env | read_env(ROOT / "env/provision.env"))
    (ROOT / "provisioned").touch(mode=0o600)


def migrate():
    if not (ROOT / "provisioned").exists():
        raise ValueError("run provision with the prepared stack first")
    for svc in OWNERS:
        env = read_env(ROOT / "env" / (svc + "-migrate.env"))
        with (ROOT / "logs" / svc / "migration.log").open("ab") as log:
            result = subprocess.run([str(ROOT / "bin" / svc), "migrate", "up"], env=env,
                                    stdin=subprocess.DEVNULL, stdout=log, stderr=log)
        if result.returncode:
            raise RuntimeError(f"{svc} migration failed; inspect its migration.log")
        print(f"{svc} migrated", flush=True)


def main():
    os.umask(0o077)
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="action", required=True)
    sub.add_parser("prepare").add_argument("--files-only", action="store_true", help="defer database provisioning")
    sub.add_parser("build").add_argument("--bin-dir", type=Path, help="build separately before prepare")
    for action in ("provision", "migrate", "up", "down", "status", "verify", "refresh-market"):
        sub.add_parser(action)
    args = parser.parse_args()
    if args.action == "prepare":
        admin = os.environ.get("AIPAY_DEV_POSTGRES_ADMIN_URL")
        cache = os.environ.get("AIPAY_DEV_REDIS_URL")
        if not admin or not cache:
            raise ValueError("set AIPAY_DEV_POSTGRES_ADMIN_URL and AIPAY_DEV_REDIS_URL")
        prepare(ROOT, admin, cache, os.getenv("AIPAY_DEV_QUEUE_REDIS_URL"))
        if not args.files_only:
            provision()
        return
    if args.action == "build" and args.bin_dir:
        build(args.bin_dir.resolve())
        return
    if not (ROOT / "prepared").is_file():
        raise ValueError("run prepare first")
    (ROOT / "run").mkdir(mode=0o700, exist_ok=True)
    os.chdir(ROOT / "run")
    with open("controller.lock", "a") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        names = services(ROOT)
        if args.action == "build":
            build(ROOT / "bin")
        elif args.action == "provision":
            provision()
        elif args.action == "migrate":
            migrate()
        elif args.action == "up":
            started = []
            try:
                for name in names:
                    worker = start(ROOT, name)
                    if worker:
                        started.append((name, worker))
            except BaseException:
                for name, worker in reversed(started):
                    stop(name)
                    worker.wait(5)
                raise
        elif args.action == "down":
            for name in reversed(names):
                stop(name)
        elif args.action == "status":
            ready = True
            for name in names:
                pid = request(name, "pid")
                state = "stopped" if not pid else "ready" if health(ROOT, name) else "unready"
                print(f"{name:16} {state:8} {pid or '-'}")
                ready &= state == "ready"
            return 0 if ready else 1
        elif args.action == "verify":
            verify(ROOT)
            print("Verified certificates, public registries, identities and credentials")
        elif args.action == "refresh-market":
            refresh(ROOT)
            if request("reconciliation", "pid"):
                stop("reconciliation")
                start(ROOT, "reconciliation")
            print("Refreshed development minute and coverage")


if __name__ == "__main__":
    try:
        if len(sys.argv) == 3 and sys.argv[1] == "_run" and sys.argv[2] in (*SERVICES, "queue-redis"):
            os.umask(0o077)
            supervise(Path.cwd().parent, sys.argv[2])
        else:
            sys.exit(main())
    except FileExistsError:
        sys.exit("Existing stack state preserved; use provision to resume database setup.")
    except (OSError, RuntimeError, ValueError, subprocess.CalledProcessError) as exc:
        # Do not include raw URLs/configuration in diagnostics.
        sys.exit(str(exc) if isinstance(exc, (RuntimeError, ValueError)) else
                 f"Stack command failed ({exc.strerror if isinstance(exc, OSError) else 'subprocess error'}).")
