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
from stack_config import (DEPOSIT_SERVICES, GATEWAYS, LIBRARY, OWNERS, SERVICES, STATE, WORKSPACE,
                          coverage_mode, current_client_env, dump, gateway_client_keys, native_deposit_inputs, new_epay_account,
                          prepare, read_env, refresh, save_env, switch_gateways, upgrade_demo, write)
from deposit_scenario import SPEC, generate
from verify import epay_handoff, verify, verify_gateway_transport
import telemetry
from processes import health, request, service_env, services, start, stop, supervise, transport

ROOT = STATE / "native"


def tools_workspace(directory):
    directory = Path(directory).resolve()
    modules = (LIBRARY / "dev/tools", LIBRARY, WORKSPACE / "protobuf", WORKSPACE / "observability")
    subprocess.run(["go", "work", "init", *(os.path.relpath(p, directory) for p in modules)],
                   cwd=directory, env=os.environ | {"GOWORK": "off"}, check=True)
    return directory / "go.work"


def build_gateway(out):
    repo = WORKSPACE / "upstream-gateway"
    if not (repo / "crates/upstream-gateway/Cargo.toml").is_file():
        raise ValueError("missing sibling upstream-gateway repository (crates/upstream-gateway)")
    if not shutil.which("cargo"):
        raise ValueError("building upstream-gateway requires cargo and the pinned Rust toolchain")
    if not shutil.which("wasm-tools"):
        raise ValueError("building upstream-gateway requires wasm-tools (version in upstream-gateway/build-config.json)")
    with tempfile.TemporaryDirectory(dir=out) as tmp:
        stage = Path(tmp)
        cache = ROOT / "build/cargo" if out == ROOT / "bin" else stage / "target"
        target = (repo / os.environ.get("CARGO_TARGET_DIR", cache)).resolve()
        subprocess.run(["cargo", "build", "--release", "--locked", "-p", "upstream-gateway"],
                       cwd=repo, env=os.environ | {"CARGO_TARGET_DIR": str(target)}, check=True)
        binary = stage / "upstream-gateway"
        shutil.copy2(target / "release/upstream-gateway", binary)
        binary.replace(out / binary.name)
    print("built upstream-gateway", flush=True)


def build(out, workspace=False):
    out.mkdir(mode=0o700, parents=True, exist_ok=True)
    env = os.environ | {"GOWORK": "off"}
    work = WORKSPACE / "go.work"
    if workspace and not work.is_file():
        raise ValueError("--workspace requires go.work in the workspace root")
    build_gateway(out)
    with tempfile.TemporaryDirectory() as tmp:
        tools_env = env | {"GOWORK": str(tools_workspace(tmp))} if workspace else env
        for name in (*DEPOSIT_SERVICES, "demo", "devtoken"):
            binary = "kaivo-" + name
            subprocess.run(["go", "build", "-mod=readonly", "-o", str(out / binary), "./cmd/" + binary],
                           cwd=LIBRARY / "dev/tools", env=tools_env, check=True)
    for svc in (*OWNERS, "upstream-sim"):
        repo = WORKSPACE / svc
        if workspace and svc != "upstream-sim":
            # Pre-release verification only: unreleased sibling libraries come from
            # the workspace. Go records new checksums in go.work.sum, not the repos.
            subprocess.run(["go", "build", "-o", str(out / svc), "."], cwd=repo, env=os.environ | {"GOWORK": str(work)}, check=True)
            print(f"built {svc} (workspace)", flush=True)
            continue
        with tempfile.TemporaryDirectory() as tmp:
            # Even module resolution must not update the read-only sibling repos.
            mod = Path(tmp) / "go.mod"
            shutil.copyfile(repo / "go.mod", mod)
            if (repo / "go.sum").exists():
                shutil.copyfile(repo / "go.sum", mod.with_suffix(".sum"))
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
    if seller is not None and transport(root) == "plaintext":
        raise ValueError("deposits-on conflicts with plaintext because devcollection requires mTLS")
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


def change_mode(root, action, mode, endpoint=None):
    if any(request(name, "pid") for name in (*telemetry.PROCESSES, "devtoken", "queue-redis", *DEPOSIT_SERVICES, *GATEWAYS, *SERVICES, "ledger-reader")):
        raise ValueError(f"run down before changing {action}")
    if action == "telemetry":
        telemetry.configure(root, mode, endpoint)
    elif action == "transport":
        marker = root / "transport.plaintext"
        if mode == "plaintext":
            if (root / "deposits.enabled").exists():
                raise ValueError("plaintext conflicts with deposits-on because devcollection requires mTLS")
            switch_gateways(root, plaintext=True)
            write(marker, "")
        else:
            switch_gateways(root, plaintext=False)
            marker.unlink(missing_ok=True)
    elif mode == "stdout":
        write(root / "logs.stdout", "")
    else:
        (root / "logs.stdout").unlink(missing_ok=True)


def demo_config(root):
    """Upgrade the previous native stack without regenerating credentials or database roles."""
    if any(request(name, "pid") for name in services(root)):
        raise ValueError("run down before updating the native demo configuration")
    upgrade_demo(root)


def epay_on(root):
    if (root / "stack.env").is_file():
        raise ValueError("epay-on requires a native stack; the native controller cannot check running Compose containers")
    if any(request(name, "pid") for name in ("upstream-sim", "payment", "reconciliation", *GATEWAYS)):
        raise ValueError("run down before enabling EPay")

    payment_path = root / "env/payment.env"
    recon_path = root / "env/reconciliation.env"
    old_payment, old_recon = read_env(payment_path), read_env(recon_path)
    payment = current_client_env("payment", old_payment)
    recon = current_client_env("reconciliation", old_recon)
    if not payment.get("AIPAY_UPSTREAM_GATEWAY_ADDRESS") or not recon.get("AIPAY_RECONCILIATION_UPSTREAM_GATEWAY_ADDRESS"):
        raise ValueError("epay-on requires configured trade and verification gateways")
    callback = "AIPAY_PLUGIN_CALLBACK_URL"
    url = urlsplit(payment[callback])
    if url.scheme not in ("http", "https") or not url.hostname:
        raise ValueError("invalid payment callback URL")
    mapping = "AIPAY_RECONCILIATION_PLUGIN_CHANNELS"
    channels = json.loads(recon[mapping])
    sim_path = root / "inputs/upstream-sim/config.json"
    sim = json.loads(sim_path.read_bytes())
    accounts = sim["accounts"]
    if not accounts or accounts[0]["id"] != "md5-demo" or accounts[0]["style"] != "form-md5":
        raise ValueError("expected md5-demo as the primary form-md5 account")
    append_epay = not any(a["id"] == "epay-demo" for a in accounts)
    if append_epay:
        accounts.append(new_epay_account())
    credential = epay_handoff(accounts)
    handoff = root / "handoff/epay.json"
    previous = json.loads(handoff.read_bytes()) if handoff.exists() else None

    # Persist the authoritative key first so a retry can complete any interrupted upgrade.
    if append_epay:
        dump(sim_path, sim, mode=sim_path.stat().st_mode & 0o777)
    # This also migrates the legacy "shared" field using the simulator's existing key.
    if previous != credential:
        dump(handoff, credential, mode=handoff.stat().st_mode & 0o777 if handoff.exists() else 0o600)
    if url.path != "/callback/{channel_code}":
        payment[callback] = url._replace(path="/callback/{channel_code}").geturl()
    if payment != old_payment:
        save_env(payment_path, payment, mode=payment_path.stat().st_mode & 0o777)
    if channels.get("epay_v1_verify") != "epay_v1":
        channels["epay_v1_verify"] = "epay_v1"
        recon[mapping] = json.dumps(channels, separators=(",", ":"))
    if recon != old_recon:
        save_env(recon_path, recon, mode=recon_path.stat().st_mode & 0o777)
    verify(root)


def main():
    os.umask(0o077)
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="action", required=True)
    sub.add_parser("prepare").add_argument("--files-only", action="store_true", help="defer database provisioning")
    build_parser = sub.add_parser("build")
    build_parser.add_argument("--bin-dir", type=Path, help="build separately before prepare")
    build_parser.add_argument("--workspace", action="store_true",
                              help="build owners and development tools with local workspace modules (pre-release checks)")
    sub.add_parser("transport").add_argument("mode", choices=("mtls", "plaintext", "status"))
    coverage = sub.add_parser("coverage")
    coverage.add_argument("mode", choices=("file", "attestation", "status"))
    coverage.add_argument("--validity", metavar="DURATION", help="attestation lifetime (default 4m, range 1m to 26h)")
    sub.add_parser("epay-on", help="upgrade a stopped native gateway stack in place for the EPay demo")
    modes = sub.add_parser("telemetry").add_subparsers(dest="mode", required=True)
    modes.add_parser("on").add_argument("--endpoint")
    modes.add_parser("off")
    modes.add_parser("status")
    sub.add_parser("logs").add_argument("mode", choices=("stdout", "file"))
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
    demo = sub.add_parser("demo").add_subparsers(dest="command", required=True)
    demo.add_parser("serve")
    demo.add_parser("setup").add_argument("target", nargs="?", help="setup phase")
    run = demo.add_parser("run")
    run.add_argument("target", help="demo scenario")
    run.add_argument("-o", dest="report", metavar="FILE")
    invite = demo.add_parser("invite").add_subparsers(dest="kind", required=True)
    platform = invite.add_parser("platform")
    platform.add_argument("email")
    platform.add_argument("roles", nargs="+", metavar="ROLE")
    invite.add_parser("seller").add_argument("email")
    args = parser.parse_args()
    if args.action == "demo":
        # A demo may invoke controller commands. Never take controller.lock here.
        if not (ROOT / "prepared").is_file():
            raise ValueError("run prepare first")
        cmd = [str(ROOT / "bin/kaivo-demo"), str(ROOT), str(LIBRARY), args.command]
        if args.command == "invite":
            cmd.extend([args.kind, args.email, *getattr(args, "roles", [])])
        elif getattr(args, "target", None):
            cmd.append(args.target)
        if args.command == "run" and args.report is not None:
            cmd.extend(["-o", args.report])
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
        build(args.bin_dir.resolve(), args.workspace)
        return
    if not (ROOT / "prepared").is_file():
        raise ValueError("run prepare first")
    (ROOT / "run").mkdir(mode=0o700, exist_ok=True)
    os.chdir(ROOT / "run")
    with open("controller.lock", "a") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        names = services(ROOT)
        if args.action == "telemetry" and args.mode == "status":
            config = telemetry.state(ROOT)
            print(config["mode"], config.get("endpoint", ""))
        elif args.action == "transport" and args.mode == "status":
            print(transport(ROOT))
        elif args.action == "coverage":
            if args.mode != "status" and request("reconciliation", "pid"):
                raise ValueError("run down before changing coverage mode")
            mode, validity = coverage_mode(ROOT, args.mode, args.validity)
            print(f"coverage mode={mode}, validity={validity}. Changes take effect on the next up or reconciliation restart.")
        elif args.action in ("telemetry", "logs", "transport"):
            change_mode(ROOT, args.action, args.mode, getattr(args, "endpoint", None))
        elif args.action == "ledger-reader":
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
            build(ROOT / "bin", args.workspace)
        elif args.action == "demo-config":
            demo_config(ROOT)
        elif args.action == "epay-on":
            epay_on(ROOT)
            print("Verified native EPay configuration")
        elif args.action == "provision":
            provision()
        elif args.action == "migrate":
            migrate()
        elif args.action == "up":
            mode = transport(ROOT)
            for name, peer in GATEWAYS.items():
                env = read_env(ROOT / "env" / (peer + ".env"))
                address, server_name = gateway_client_keys(name)
                if not env.get(address) or (mode == "plaintext" and env.get(server_name) != name):
                    raise ValueError(f"{peer} gateway settings are incomplete. Rerun stack transport {mode}.")
            verify_gateway_transport(ROOT)
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
            for name in telemetry.PROCESSES:
                if name not in names:
                    print(f"{name:16} disabled")
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
            # reconciliation reloads the development market file when it changes.
            refresh(ROOT)
            print("Refreshed development market minute, coverage and ledger USDT/USD rate")


if __name__ == "__main__":
    try:
        if len(sys.argv) == 3 and sys.argv[1] == "_run" and sys.argv[2] in (*SERVICES, *GATEWAYS, *DEPOSIT_SERVICES, *telemetry.PROCESSES, "devtoken", "queue-redis", "ledger-reader"):
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
