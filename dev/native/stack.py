#!/usr/bin/env python3
"""Local process stack for the sibling Kaivo repositories."""
import argparse
import fcntl
import json
import os
from pathlib import Path
import shutil
import subprocess
from urllib.parse import parse_qsl, unquote, urlsplit
import sys
import tempfile

sys.dont_write_bytecode = True
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from stack_config import (DEPOSIT_SERVICES, LIBRARY, OWNERS, SERVICES, STATE, WORKSPACE,
                          native_deposit_inputs, prepare, read_env, refresh, routes, save_env, seller_ceremony_env, write)
from deposit_scenario import SPEC, generate
from verify import verify
from processes import health, request, service_env, services, start, stop, supervise

ROOT = STATE / "native"


def build(out):
    out.mkdir(mode=0o700, parents=True, exist_ok=True)
    env = os.environ | {"GOWORK": "off"}
    for name in (*DEPOSIT_SERVICES, "demo"):
        binary = "kaivo-" + name
        subprocess.run(["go", "build", "-mod=readonly", "-o", str(out / binary), "./cmd/" + binary],
                       cwd=LIBRARY / "dev/tools", env=env, check=True)
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
    passwords = read_env(ROOT / "env/provision.env")
    if "COLLECTION_DEV_DB_PASSWORD" not in passwords:
        native_deposit_inputs(ROOT, admin, passwords)
        save_env(ROOT / "env/provision.env", passwords)
    subprocess.run(["sh", str(LIBRARY / "dev/init-databases.sh")], check=True,
                   env=env | passwords)
    (ROOT / "provisioned").touch(mode=0o600)


def migrate():
    if not (ROOT / "provisioned").exists():
        raise ValueError("run provision with the prepared stack first")
    subprocess.run([str(ROOT / "bin/kaivo-devcollection"), "migrate"],
                   env=service_env(ROOT, "devcollection"), check=True)
    for svc in OWNERS:
        env = read_env(ROOT / "env" / (svc + "-migrate.env"))
        with (ROOT / "logs" / svc / "migration.log").open("ab") as log:
            result = subprocess.run([str(ROOT / "bin" / svc), "migrate", "up"], env=env,
                                    stdin=subprocess.DEVNULL, stdout=log, stderr=log)
        if result.returncode:
            raise RuntimeError(f"{svc} migration failed; inspect its migration.log")
        print(f"{svc} migrated", flush=True)


def deposits(root, seller, finalized, spec=None, delay_collection=False):
    if any(request(name, "pid") for name in (*DEPOSIT_SERVICES, "ledger", "reconciliation")):
        raise ValueError("run down before changing the deposit configuration")
    marker = root / "deposits.enabled"
    if seller is None:
        marker.unlink(missing_ok=True)
        return
    if not (root / "env/devcollection.env").is_file():
        raise ValueError("run provision, build and migrate to prepare the development collection database")
    out = root / "deposits"
    if not out.exists():
        generate(out, seller, spec or SPEC)
    elif spec is not None:
        raise ValueError("a dataset already exists; omit --spec to reuse it")
    elif json.loads((out / "scenario.json").read_text())["account_id"] != seller:
        raise ValueError("this dataset already belongs to another seller")
    if finalized is not None and not 0 <= finalized < len(json.loads((out / "chain.json").read_text())["blocks"]):
        raise ValueError("finalized height outside dataset")
    delay = root / "deposits.delay-collection"
    if delay_collection:
        write(delay, "on")
    else:
        delay.unlink(missing_ok=True)
    write(marker, "" if finalized is None else str(finalized))


def demo_config(root):
    """Upgrade the previous native stack without regenerating credentials or database roles."""
    if any(request(name, "pid") for name in services(root)):
        raise ValueError("run down before updating the native demo configuration")
    seller_ceremony_env(root, read_env(root / "env/iam-migrate.env")["AIPAY_DATABASE_URL"])
    table = root / "inputs/iam/routes.json"
    current = json.loads(table.read_text())
    by_path = {(r["method"], r["path"]): r for r in current}
    for rule in routes():
        key = rule["method"], rule["path"]
        if key in by_path and by_path[key] != rule:
            raise ValueError("conflicting IAM route: " + " ".join(key))
        by_path[key] = rule
    write(table, json.dumps(list(by_path.values()), separators=(",", ":")) + "\n")
    review = root / "inputs/payment/seller-reviews.json"
    if not review.exists():
        write(review, "[]\n")
    changes = {
        "backend": {"AIPAY_RECONCILIATION_GRPC_ADDR": "127.0.0.1:9104",
                    "AIPAY_HTTP_MAX_BODY_BYTES": "23068672", "AIPAY_TELEGRAM_KEY_MESSAGE_TTL": "10s",
                    "AIPAY_TELEGRAM_MONITOR_INTERVAL": "2s"},
        "ledger": {"AIPAY_LEDGER_PAYMENT_EVENTS": "on", "AIPAY_LEDGER_PAYMENT_ADDR": "127.0.0.1:9105",
                   "AIPAY_LEDGER_DEV_USD_RATES_FILE": str(root / "inputs/ledger/usd-rates.json"),
                   "AIPAY_LEDGER_PAYMENT_SERVER_NAME": "payment",
                   "AIPAY_LEDGER_PAYMENT_JWKS_FILE": str(root / "certs/public/payment.jwks")},
        "payment": {"AIPAY_PAYMENT_DEV_SELLER_REVIEWS_FILE": str(review)},
    }
    for svc, additions in changes.items():
        path = root / "env" / (svc + ".env")
        values = read_env(path)
        if svc == "payment" and values.get("AIPAY_PAYMENT_DEV_SELLER_REVIEWS_FILE"):
            continue
        save_env(path, values | additions)
    path = root / "env/notifier.env"
    values = read_env(path)
    if values.get("AIPAY_NOTIFIER_ALLOWED_HOSTS") == "127.0.0.1":
        save_env(path, values | {"AIPAY_NOTIFIER_ALLOWED_HOSTS": "localhost"})


def main():
    os.umask(0o077)
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="action", required=True)
    sub.add_parser("prepare").add_argument("--files-only", action="store_true", help="defer database provisioning")
    sub.add_parser("build").add_argument("--bin-dir", type=Path, help="build separately before prepare")
    enable = sub.add_parser("deposits-on")
    enable.add_argument("--seller-account-id", required=True)
    enable.add_argument("--finalized", type=int)
    enable.add_argument("--delay-ledger-collection", action="store_true")
    enable.add_argument("--spec", type=lambda arg: Path(arg).resolve())
    receipt = sub.add_parser("receipt")
    receipt.add_argument("operation", choices=("add", "replay"))
    receipt.add_argument("key")
    for action in ("demo-config", "deposits-off", "head", "provision", "migrate", "up", "down", "status", "verify", "refresh-market"):
        sub.add_parser(action)
    sub.add_parser("ledger-matches").add_argument("mode", choices=("pause", "resume"))
    sub.add_parser("ledger-reader").add_argument("mode", choices=("on", "off"))
    demo = sub.add_parser("demo")
    demo.add_argument("command", choices=("serve", "setup", "run"))
    demo.add_argument("target", nargs="?")
    args = parser.parse_args()
    if args.action == "demo":
        # A demo may invoke controller commands. Never take controller.lock here.
        if not (ROOT / "prepared").is_file():
            raise ValueError("run prepare first")
        cmd = [str(ROOT / "bin/kaivo-demo"), str(ROOT), str(LIBRARY), args.command]
        if args.target:
            cmd.append(args.target)
        os.execve(cmd[0], cmd, os.environ | {"GOWORK": "off"})
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
        if args.action == "ledger-reader":
            if args.mode == "off":
                stop("ledger-reader")
            else:
                if not (ROOT / "deposits.enabled").exists():
                    raise ValueError("enable deposits before starting the second ledger reader")
                (ROOT / "logs/ledger-reader").mkdir(mode=0o700, exist_ok=True)
                start(ROOT, "ledger-reader")
        elif args.action == "ledger-matches":
            marker = ROOT / "deposits.delay-matches"
            if args.mode == "pause" and not (ROOT / "deposits.enabled").exists():
                raise ValueError("enable deposits before delaying the matches reader")
            stop("ledger")
            if args.mode == "pause":
                write(marker, "on")
            else:
                marker.unlink(missing_ok=True)
            start(ROOT, "ledger")
        elif args.action in ("deposits-on", "deposits-off"):
            deposits(ROOT, getattr(args, "seller_account_id", None), getattr(args, "finalized", None), getattr(args, "spec", None),
                     getattr(args, "delay_ledger_collection", False))
        elif args.action in ("receipt", "head"):
            if not (ROOT / "deposits.enabled").is_file():
                raise ValueError("enable the deposit phase first")
            cmd = ["receipt", args.operation, str(ROOT / "deposits/scenario.json"), args.key] if args.action == "receipt" else ["head"]
            subprocess.run([str(ROOT / "bin/kaivo-devcollection"), *cmd], env=service_env(ROOT, "devcollection"), check=True)
        elif args.action == "build":
            build(ROOT / "bin")
        elif args.action == "demo-config":
            demo_config(ROOT)
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
            stop("ledger-reader")
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
            print("Refreshed development market minute, coverage and ledger USDT/USD rate")


if __name__ == "__main__":
    try:
        if len(sys.argv) == 3 and sys.argv[1] == "_run" and sys.argv[2] in (*SERVICES, *DEPOSIT_SERVICES, "queue-redis", "ledger-reader"):
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
