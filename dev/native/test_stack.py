"""Offline orchestration tests. Generated development secrets stay in memory."""
import base64
from datetime import datetime, timedelta, timezone
import json
import os
from pathlib import Path
import socket
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.dont_write_bytecode = True
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import processes
import stack_config as cfg


class Configuration(unittest.TestCase):
    def test_profiles(self):
        for compose in (False, True):
            with self.subTest(compose=compose), tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp) / "state"
                files = {}
                # Exercise actual OpenSSL RSA generation and every env/fixture builder.
                # Only the devcert subprocess and its on-disk checks require the real state directory.
                run = subprocess.run
                cert_calls = []

                def execute(args, **kwargs):
                    if args[0] == "go":
                        cert_calls.append(args)
                        return
                    return run(args, **kwargs)

                with patch.object(cfg, "write", side_effect=files.__setitem__), patch("verify.verify"), \
                     patch("subprocess.run", side_effect=execute):
                    cfg.prepare(root, "postgresql://admin:only-in-test@localhost:5433/postgres?sslmode=disable",
                                "redis://localhost:6379", "redis://queue-redis:6379" if compose else None, compose)
                    with self.assertRaises(FileExistsError):
                        cfg.prepare(root, "", "", "")
                self.assertEqual(len(cert_calls), 1)
                for name in ("notifier", "collection", "iam", "payment", "reconciliation"):
                    self.assertIn(name, cert_calls[0][cert_calls[0].index("--services") + 1].split(","))
                envs = {name: dict(line.split("=", 1) for line in files[root / "env" / (name + ".env")].splitlines())
                        for name in cfg.SERVICES}
                for svc in cfg.OWNERS:
                    self.assertNotIn("only-in-test", envs[svc]["AIPAY_DATABASE_URL"])
                    self.assertIn("/aipay_" + svc, envs[svc]["AIPAY_DATABASE_URL"])
                self.assertEqual(envs["payment"]["AIPAY_IAM_EVENT_KEYS_FILE"], envs["ledger"]["AIPAY_IAM_ASSERTION_KEYS_FILE"])
                self.assertTrue(envs["reconciliation"]["AIPAY_PAYMENT_EVENT_KEYS_FILE"].endswith("/payment.jwks"))
                self.assertIn("payment", envs["iam"]["AIPAY_RPC_ALLOWED_PEERS"].split(","))
                self.assertTrue(envs["payment"]["AIPAY_QUEUE_REDIS_URL"].endswith("/5"))
                self.assertTrue(envs["iam"]["AIPAY_QUEUE_REDIS_URL"].endswith("/1"))
                self.assertEqual(envs["payment"]["AIPAY_IAM_RPC_ADDRESS"], "iam:9101" if compose else "127.0.0.1:9101")
                self.assertFalse(any("DATABASE" in k or "SIGNING" in k or "REDIS" in k for k in envs["notifier"]))
                sim = json.loads(files[root / "inputs/upstream-sim/config.json"])["accounts"][0]
                query = json.loads(files[root / "handoff/query.json"])["query_key"]
                payment = json.loads(files[root / "inputs/payment/plugins.json"])["credentials"]["sim-md5-v1"]
                self.assertTrue(query == sim["query_shared_secret"] != sim["shared_secret"])
                self.assertTrue(base64.b64decode(payment["secrets"]["shared"]).decode() == sim["shared_secret"])
                der = files[root / "inputs/iam/epay.der"]
                self.assertTrue(all(der == files[root / "inputs" / s / "epay.der"] for s in ("backend", "payment")))
                self.assertTrue(subprocess.check_output(["openssl", "pkey", "-inform", "DER", "-pubout"], input=der)
                                == files[root / "handoff/platform-public.pem"])

    def test_refresh_preserves_original_minutes(self):
        # These three files contain only synthetic prices, timestamps and public digests.
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            for svc in ("payment", "reconciliation"):
                (root / "inputs" / svc).mkdir(parents=True)
            now = datetime(2026, 11, 19, 12, 30, 10, tzinfo=timezone.utc)
            rate = root / "inputs/payment/rate.json"
            market = root / "inputs/reconciliation/market.json"
            cfg.refresh(root, now)
            previous = [p.read_bytes() for p in (rate, market)]
            cfg.refresh(root, now + timedelta(seconds=30))
            self.assertEqual(previous, [p.read_bytes() for p in (rate, market)])
            cfg.refresh(root, now + timedelta(minutes=1))
            records = json.loads(market.read_text())
            self.assertEqual(len(records), 4)
            self.assertEqual(records[:2], json.loads(previous[1]))
            self.assertEqual(json.loads(rate.read_text())["minute"], records[-1]["minute"])
            self.assertEqual(rate.stat().st_mode & 0o777, 0o600)

    def test_provisioning_sql_uses_all_role_envs(self):
        # Capture precisely the stdin sent to psql. No server or credentials are used.
        with tempfile.TemporaryDirectory() as tmp:
            wrapper = Path(tmp) / "psql"
            sql = Path(tmp) / "commands.sql"
            wrapper.write_text('#!/bin/sh\ncat > "$CAPTURE_SQL"\n')
            wrapper.chmod(0o700)
            env = {"PATH": tmp + os.pathsep + os.environ["PATH"], "STACK_ID": "test", "CAPTURE_SQL": str(sql)}
            subprocess.run(["sh", str(cfg.LIBRARY / "dev/init-databases.sh")], check=True, env=env)
            commands = sql.read_text()
            for svc in cfg.OWNERS:
                self.assertIn("\\getenv pw " + svc.upper() + "_DB_PASSWORD\n", commands)
            for svc in cfg.APP_ROLES:
                self.assertIn("\\getenv pw " + svc.upper() + "_APP_PASSWORD\n", commands)
            self.assertLess(commands.index("AS collision"), commands.index("CREATE ROLE"))
            self.assertIn("REVOKE ALL ON DATABASE", commands)

    def test_database_targets(self):
        dsn = cfg.database_url("postgresql://adm:p%40ss@[::1]:5433/postgres?sslmode=require", "iam_app", "a+b", "iam")
        self.assertEqual(dsn, "postgresql://iam_app:a%2Bb@[::1]:5433/aipay_iam?sslmode=require")
        with self.assertRaises(ValueError):
            cfg.database_url("postgres://host/postgres?user=postgres", "iam_app", "", "iam")
        with self.assertRaises(ValueError):
            cfg.redis_db("redis://host/0?db=0", 5)


@unittest.skipUnless(os.getenv("AIPAY_TEST_SIM_BINARY"), "supply the built upstream-sim binary for process tests")
class ProcessLifecycle(unittest.TestCase):
    def test_simulator_and_unowned_pid(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp).resolve()
            for subdir in ("run", "logs/upstream-sim", "env", "bin"):
                (root / subdir).mkdir(parents=True)
            (root / "bin/upstream-sim").symlink_to(Path(os.environ["AIPAY_TEST_SIM_BINARY"]).resolve())
            with socket.socket() as port:
                port.bind(("127.0.0.1", 0))
                address = port.getsockname()[1]
            cfg.save_env(root / "env/upstream-sim.env", {"UPSTREAM_SIM_LISTEN": f"127.0.0.1:{address}"})
            cwd = Path.cwd()
            os.chdir(root / "run")
            try:
                with patch.dict(processes.PORTS, {"upstream-sim": address}):
                    worker = processes.start(root, "upstream-sim")
                    self.assertIsInstance(worker, subprocess.Popen)
                    self.assertFalse(processes.start(root, "upstream-sim"))
                    pidfile = Path("upstream-sim.pid")
                    self.assertEqual(processes.request("upstream-sim", "pid"), pidfile.read_text().strip())
                    self.assertTrue(processes.health(root, "upstream-sim"))
                    # Overwrite even a live PID record. Shutdown still addresses only the owned child.
                    pidfile.write_text(str(os.getpid()))
                    processes.stop("upstream-sim")
                    self.assertEqual(worker.wait(3), 0)
                    self.assertFalse(processes.health(root, "upstream-sim"))
                    pidfile.write_text(str(os.getpid()))
                    processes.stop("upstream-sim")
                    self.assertTrue(pidfile.exists())
            finally:
                processes.stop("upstream-sim")
                os.chdir(cwd)


if __name__ == "__main__":
    unittest.main()
