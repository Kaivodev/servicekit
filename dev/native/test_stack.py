"""Offline orchestration tests. Generated development secrets stay in memory."""
from datetime import datetime, timedelta, timezone
import hashlib
import json
import os
from pathlib import Path
import socket
import subprocess
import sys
import tempfile
import unittest
import uuid
from unittest.mock import patch

sys.dont_write_bytecode = True
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import telemetry
import processes
import stack
import deposit_scenario as fixture
import stack_config as cfg


class Configuration(unittest.TestCase):
    def test_gateway_configs_migrate_on_start(self):
        import tomllib
        for compose in (False, True):
            with tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp)
                for folder in ("inputs", "logs", "env"):
                    (root / folder).mkdir()
                passwords = {}
                cfg.gateway_inputs(root, "postgresql://admin:secret@127.0.0.1:5432/postgres", passwords, compose)
                for name in cfg.GATEWAYS:
                    settings = tomllib.loads((root / "inputs" / name / "gateway.toml").read_text())
                    self.assertEqual(settings["mode"], "development")
                    self.assertIs(settings["migrate_on_start"], True)

    def test_existing_gateway_configs_gain_migrate_on_start(self):
        import tomllib
        old = 'role = "trade"\nmode = "development"\nlisten = "127.0.0.1:9107"\n'
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            trade, verification = (root / "inputs" / name for name in cfg.GATEWAYS)
            trade.mkdir(parents=True)
            (trade / "gateway.toml").write_text(old)
            # A gateway without inputs (for example a stack prepared before UG-4) is skipped.
            for _ in range(2):
                cfg.enable_gateway_migration(root)
                text = (trade / "gateway.toml").read_text()
                self.assertEqual(text.count("migrate_on_start"), 1)
                self.assertIs(tomllib.loads(text)["migrate_on_start"], True)
                self.assertTrue(text.startswith('role = "trade"\nmode = "development"\nmigrate_on_start = true\n'))
            self.assertFalse(verification.exists())
            # An explicit operator choice is kept.
            (trade / "gateway.toml").write_text(old + "migrate_on_start = false\n")
            cfg.enable_gateway_migration(root)
            self.assertIs(tomllib.loads((trade / "gateway.toml").read_text())["migrate_on_start"], False)
            (trade / "gateway.toml").write_text(old.replace("development", "production"))
            with self.assertRaises(ValueError):
                cfg.enable_gateway_migration(root)

    def test_demo_routes_and_reader_settings(self):
        routes = cfg.routes()
        by_key = {(r["method"], r["path"]): r for r in routes}
        self.assertEqual(len(by_key), len(routes))
        bot = [r for r in routes if r["path"].startswith("/bot/")]
        self.assertEqual(len(bot), 21)
        for method, path, permission, owner in (
            ("GET", "/api/v1/platform/archived-work", "payment.work.read", "payment"),
            ("POST", "/api/v1/platform/archived-work/:kind/:object_id/requeue", "payment.work.requeue", "payment"),
            ("GET", "/bot/statements", "ledger.statement.read", "ledger"),
            ("GET", "/bot/statements/:date", "ledger.statement.read", "ledger"),
        ):
            self.assertEqual(by_key[method, path], dict(method=method, path=path, permission=permission, audiences=[owner]))
        contract = cfg.WORKSPACE / "backend/docs/examples/telegram-routes.json"
        if contract.exists():
            self.assertEqual(bot, json.loads(contract.read_text()))
        coverage = [r for r in routes if r["path"].startswith("/api/v1/platform/coverage/")]
        expected = [
            ("GET", "status", "read"), ("GET", "addresses", "read"), ("GET", "attestations", "read"),
            ("GET", "attestations/:id", "read"), ("POST", "attestations", "submit"),
            ("POST", "attestations/approvals/:id/assertions", "approve"),
            ("POST", "attestations/:id/revocation", "revoke"),
        ]
        self.assertEqual(coverage, [dict(method=m, path="/api/v1/platform/coverage/" + p,
                                         permission="reconciliation.coverage." + perm, audiences=["reconciliation"])
                                    for m, p, perm in expected])
        staging = cfg.LIBRARY / "dev/tools/cmd/kaivo-stagingseed/routes.json"
        self.assertEqual(json.loads(staging.read_text()), routes)
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            (root / "env").mkdir()
            cfg.save_env(root / "env/ledger.env", {"AIPAY_GRPC_ADDR": "127.0.0.1:9102"})
            (root / "deposits.enabled").touch()
            (root / "deposits.delay-matches").touch()
            self.assertEqual(processes.service_env(root, "ledger")["AIPAY_LEDGER_RECONCILIATION_ADDR"], "127.0.0.1:1")
            reader = processes.service_env(root, "ledger-reader")
            self.assertEqual(reader["AIPAY_GRPC_ADDR"], "127.0.0.1:9122")
            self.assertEqual(reader["AIPAY_LEDGER_JOBS"], "off")
            self.assertEqual(processes.command(root,"ledger-reader"), [str(root / "bin/ledger"), "serve"])

    def test_coverage_mode(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            path = root / "env/reconciliation.env"
            path.parent.mkdir()
            other = {"AIPAY_RECONCILIATION_ADMIN": "on", "OTHER": "with=equals"}
            period = "AIPAY_RECONCILIATION_COVERAGE_VALIDITY"
            initial = other | {"AIPAY_RECONCILIATION_COVERAGE_DEVELOPMENT_FILE":
                               str(root / "inputs/reconciliation/coverage.json")}
            cfg.save_env(path, initial)
            path.chmod(0o640)
            self.assertEqual(cfg.coverage_mode(root, "status"), ("file", "from coverage.json"))
            self.assertEqual(cfg.coverage_mode(root, "attestation"), ("attestation", "4m"))
            self.assertEqual(cfg.read_env(path), other | {period: "4m"})
            with patch.object(cfg, "save_env", side_effect=AssertionError("unexpected rewrite")):
                self.assertEqual(cfg.coverage_mode(root, "attestation"), cfg.coverage_mode(root, "status"))
                for mode, value in [("file", "4m"), ("status", "4m")] + [
                        ("attestation", v) for v in ("", "59.9s", "26h1us", "60s1ns", "4", "-1h", "1m!")]:
                    with self.subTest(mode=mode, value=value), self.assertRaises(ValueError):
                        cfg.coverage_mode(root, mode, value)
            for duration in ("1m", "1m30.5s", "26h"):
                self.assertEqual(cfg.coverage_mode(root, "attestation", duration), ("attestation", duration))
                self.assertEqual(cfg.read_env(path), other | {period: duration})
            self.assertEqual(cfg.coverage_mode(root, "file"), ("file", "from coverage.json"))
            self.assertEqual(cfg.read_env(path), initial)
            self.assertEqual(path.stat().st_mode & 0o777, 0o640)
            with patch.object(cfg, "save_env", side_effect=AssertionError("unexpected rewrite")):
                cfg.coverage_mode(root, "file")

    def test_coverage_controller_while_running(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "prepared").touch()
            (root / "env").mkdir()
            path = root / "env/reconciliation.env"
            cfg.save_env(path, {"AIPAY_RECONCILIATION_COVERAGE_VALIDITY": "4m"})
            cwd = Path.cwd()
            try:
                with patch.object(stack, "ROOT", root), patch.object(stack, "request", return_value="123") as pid, \
                     patch("os.umask"), patch("builtins.print") as output:
                    for mode in ("file", "attestation"):
                        with patch.object(sys, "argv", ["stack.py", "coverage", mode]), self.assertRaisesRegex(ValueError, "run down"):
                            stack.main()
                        pid.assert_called_with("reconciliation", "pid")
                    with patch.object(sys, "argv", ["stack.py", "coverage", "status"]):
                        stack.main()
                    self.assertIn("mode=attestation, validity=4m", output.call_args.args[0])
                    self.assertEqual(cfg.read_env(path), {"AIPAY_RECONCILIATION_COVERAGE_VALIDITY": "4m"})
            finally:
                os.chdir(cwd)

    def test_epay_upgrade_in_place(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            for directory in ("env", "inputs/upstream-sim", "handoff"):
                (root / directory).mkdir(parents=True)
            sim_path = root / "inputs/upstream-sim/config.json"
            payment_path, recon_path = (root / "env" / (s + ".env") for s in ("payment", "reconciliation"))
            handoff = root / "handoff/epay.json"
            md5 = dict(id="md5-demo", style="form-md5", shared_secret="trade", query_shared_secret="query")
            sim = dict(listen="127.0.0.1:9080", control_token="keep-token", accounts=[md5, dict(md5, id="other")])
            cfg.dump(sim_path, sim)
            callback = "AIPAY_PLUGIN_CALLBACK_URL"
            mapping = "AIPAY_RECONCILIATION_PLUGIN_CHANNELS"
            origin = "https://[::1]:18080"
            payment = cfg.gateway_client_settings("upstream-gateway-trade") | {
                callback: origin + "/callback/sim_form_md5?site=dev", "OTHER": "with=equals"}
            channels = {"sim_form_md5_verify": "sim_form_md5", "other_verify": "other"}
            cfg.save_env(payment_path, payment)
            cfg.save_env(recon_path, cfg.gateway_client_settings("upstream-gateway-verification") |
                         {mapping: json.dumps(channels), "OTHER": "keep"})
            cfg.coverage_mode(root, "attestation", "6m")
            recon = cfg.read_env(recon_path)
            for path in (sim_path, payment_path, recon_path):
                path.chmod(0o640)
            # Exercise the writer's permission preservation separately from the full 0600 verifier.
            with patch.object(stack, "request", return_value=None), patch.object(stack, "verify") as verify:
                stack.epay_on(root)
                verify.assert_called_once_with(root)
                updated = json.loads(sim_path.read_text())
                epay = updated["accounts"].pop()
                self.assertEqual(updated, sim)
                key = epay.pop("shared_secret")
                self.assertTrue(len(key) == 32 and key.isascii() and key.isalnum())
                self.assertEqual(epay, dict(id="epay-demo", style="epay-v1", pid=1001))
                self.assertTrue(json.loads(handoff.read_text()) == {"merchant_key": key})
                self.assertEqual(cfg.read_env(payment_path), payment | {callback: origin + "/callback/{channel_code}?site=dev"})
                after = cfg.read_env(recon_path)
                self.assertEqual(json.loads(after.pop(mapping)), channels | {"epay_v1_verify": "epay_v1"})
                recon.pop(mapping)
                self.assertEqual(after, recon)
                for path in (sim_path, payment_path, recon_path):
                    self.assertEqual(path.stat().st_mode & 0o777, 0o640)
                self.assertEqual(handoff.stat().st_mode & 0o777, 0o600)
                with patch.object(cfg, "write", side_effect=AssertionError("unexpected rewrite")):
                    stack.epay_on(root)
                # Retry after the simulator was updated but the handoff was not installed.
                handoff.unlink()
                stack.epay_on(root)
                self.assertTrue(json.loads(handoff.read_text()) == {"merchant_key": key})
                for previous in ({"shared": key}, {"shared": "stale"}):
                    cfg.dump(handoff, previous, mode=0o640)
                    stack.epay_on(root)
                    self.assertTrue(json.loads(handoff.read_text()) == {"merchant_key": key})
                    self.assertEqual(handoff.stat().st_mode & 0o777, 0o640)
                    with patch.object(cfg, "write", side_effect=AssertionError("unexpected rewrite")):
                        stack.epay_on(root)

    def test_epay_refuses_running_services(self):
        with tempfile.TemporaryDirectory() as tmp:
            for running in ("upstream-sim", "payment", "reconciliation", *cfg.GATEWAYS):
                with self.subTest(running=running), patch.object(stack, "request", side_effect=lambda n, a: n == running), \
                     self.assertRaisesRegex(ValueError, "run down"):
                    stack.epay_on(Path(tmp))

    def test_epay_requires_native_gateway(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            for marker, reason in (("transport.plaintext", "plaintext"), ("stack.env", "Compose")):
                with self.subTest(marker=marker):
                    (root / marker).touch()
                    with self.assertRaisesRegex(ValueError, reason):
                        stack.epay_on(root)
                    (root / marker).unlink()
            (root / "env").mkdir()
            cfg.save_env(root / "env/payment.env", {})
            cfg.save_env(root / "env/reconciliation.env", {})
            with patch.object(stack, "request", return_value=None), self.assertRaisesRegex(ValueError, "gateways"):
                stack.epay_on(root)

    def test_dev_cert_days_boundaries(self):
        for days in (1, 30):
            with self.subTest(days=days), patch.dict(os.environ, AIPAY_DEV_CERT_DAYS=str(days)):
                self.assertEqual(cfg.dev_cert_days(), days)

    def test_prepare_rejects_invalid_cert_days_before_creating_state(self):
        for value in ("0", "31", "07", "-1", "+7", "7d", " 7", "seven", "7\n", "\u0667"):
            with self.subTest(value=value), tempfile.TemporaryDirectory() as tmp, \
                 patch.dict(os.environ, AIPAY_DEV_CERT_DAYS=value), patch("subprocess.run") as run:
                root = Path(tmp) / "new-parent" / "state"
                with self.assertRaisesRegex(ValueError, "^AIPAY_DEV_CERT_DAYS must be a whole number of days from 1 to 30$"):
                    cfg.prepare(root, "", "", "")
                run.assert_not_called()
                self.assertFalse(root.exists())
                self.assertFalse(root.parent.exists())

    def test_default_prepared_env_files(self):
        # The digests cover every filename and byte, including key order.
        # Fix the volatile env inputs and substitute the temporary state path.
        for compose, expected in (
            (False, "1879ebc8f5d9aaece17a3b169c7a76250589314b115090dea3f493360850cd3d"),
            (True, "2141843472fb960879be8397933fc28d21bdd7676110d62d24849b8e00d52b48"),
        ):
            with self.subTest(compose=compose), tempfile.TemporaryDirectory() as tmp, \
                 patch.dict(os.environ, {}, clear=True), patch.object(cfg, "generate_inputs"), \
                 patch.object(cfg, "ensure_report_key"), patch("verify.verify"), \
                 patch.object(cfg.uuid, "uuid4", return_value=uuid.UUID(int=1)), \
                 patch.object(cfg.secrets, "token_hex", return_value="test-password"), \
                 patch.object(cfg.secrets, "token_urlsafe", return_value="test-token"), \
                 patch.object(cfg.secrets, "token_bytes", side_effect=bytes), patch.object(cfg, "datetime") as clock:
                root = Path(tmp) / "state"
                clock.now.return_value = datetime(2026, 1, 1, tzinfo=timezone.utc)

                def directories(*args):
                    for name in ("env", "inputs", "logs"):
                        (root / name).mkdir()

                cfg.generate_inputs.side_effect = directories
                cfg.prepare(root, "postgresql://admin@localhost/postgres", "redis://localhost",
                            "redis://queue:6379", compose)
                digest = hashlib.sha256()
                for path in sorted((root / "env").iterdir()):
                    digest.update(path.name.encode() + b"\0" + path.read_bytes().replace(os.fsencode(root), b"STATE") + b"\0")
                self.assertEqual(digest.hexdigest(), expected)

    def test_portal_origins(self):
        platform, seller = "AIPAY_DEV_PLATFORM_ORIGIN", "AIPAY_DEV_SELLER_ORIGIN"
        cashier = "AIPAY_DEV_CASHIER_ORIGIN"
        defaults = ("https://admin.aipay.test", "https://seller.aipay.test", "https://pay.aipay.test")
        custom = "https://" + "a" * 63 + ".web-9.demo"
        self.assertEqual(cfg.dev_portal_origins({}), defaults)
        self.assertEqual(cfg.dev_portal_origins({platform: "", seller: "", cashier: ""}), defaults)
        self.assertEqual(cfg.dev_portal_origins({platform: custom}), (custom, defaults[1], defaults[2]))
        self.assertEqual(cfg.dev_portal_origins({seller: custom}), (defaults[0], custom, defaults[2]))
        self.assertEqual(cfg.dev_portal_origins({cashier: custom}), (*defaults[:2], custom))
        for other in (platform, seller):
            with self.assertRaisesRegex(ValueError, cashier):
                cfg.dev_portal_origins({other: custom, cashier: custom})
        with self.assertRaisesRegex(ValueError, f"{platform}.*{seller}"):
            cfg.dev_portal_origins({platform: defaults[1]})

        for key in (platform, seller, cashier):
            for value in ("http://a.b", "HTTPS://a.b", "https://A.b", "https://local", "https://a.b:443",
                          "https://a.b/", "https://a.b?", "https://a.b#", "https://u@a.b", "https://a.b.",
                          "https://*.b", "https://-a.b", "https://a.b-", "https://a..b", "https://a_b.c",
                          "https://a.b\n", "https://é.test", "https://127.0.0.1", "https://127.1", "https://0x7f.0x1",
                          "https://" + "a" * 64 + ".b", "https://" + ".".join(["a" * 63] * 4)):
                with self.subTest(key=key, value=value), tempfile.TemporaryDirectory() as tmp, \
                     patch.dict(os.environ, {key: value}):
                    with self.assertRaisesRegex(ValueError, key):
                        cfg.prepare(Path(tmp) / "parent" / "state", "", "", "")
                    self.assertFalse((Path(tmp) / "parent").exists())

    def test_demo_invite_cli(self):
        with tempfile.TemporaryDirectory() as tmp, patch.object(stack, "ROOT", Path(tmp)), patch("os.umask"):
            (Path(tmp) / "prepared").touch()
            for args in (["invite", "platform", "p@demo.test", "risk", "finance"],
                         ["invite", "seller", "s@demo.test"], ["setup"], ["setup", "iam"],
                         ["serve"], ["run", "main", "-o", "report.md"]):
                with self.subTest(args=args), patch.object(sys, "argv", ["stack.py", "demo", *args]), \
                     patch("os.execve", side_effect=SystemExit) as execute:
                    with self.assertRaises(SystemExit):
                        stack.main()
                    self.assertEqual(execute.call_args.args[1][3:], args)
            for args in (["invite", "seller", "s@demo.test", "extra"], ["invite", "platform", "p@demo.test"],
                         ["invite", "platform", "p@demo.test", "risk", "-o", "out"], ["setup", "-o", "out"]):
                with self.subTest(args=args), patch.object(sys, "argv", ["stack.py", "demo", *args]), \
                     patch("sys.stderr"), self.assertRaises(SystemExit) as error:
                    stack.main()
                self.assertEqual(error.exception.code, 2)

    def test_profiles(self):
        for compose, cert_days in ((False, None), (True, ""), (False, "30"), (True, "30")):
            with self.subTest(compose=compose, cert_days=cert_days), tempfile.TemporaryDirectory() as tmp, patch.dict(os.environ):
                platform, seller = ("https://admin.demo.test", "https://portal.demo.test") if cert_days == "30" else (
                    "https://admin.aipay.test", "https://seller.aipay.test")
                os.environ.update(AIPAY_DEV_PLATFORM_ORIGIN=platform, AIPAY_DEV_SELLER_ORIGIN=seller)
                cashier = "https://pay.demo.test" if cert_days == "30" else ""
                os.environ["AIPAY_DEV_CASHIER_ORIGIN"] = cashier
                if cert_days is None:
                    os.environ.pop("AIPAY_DEV_CERT_DAYS", None)
                else:
                    os.environ["AIPAY_DEV_CERT_DAYS"] = cert_days
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
                if cert_days:
                    self.assertEqual(cert_calls[0][-2:], ["--days", cert_days])
                else:
                    self.assertNotIn("--days", cert_calls[0])
                if not compose:
                    tool = dict(line.split("=", 1) for line in files[root / "env/devcollection.env"].splitlines())
                    self.assertEqual(tool["AIPAY_RPC_ALLOWED_PEERS"], "ledger,reconciliation")
                    self.assertTrue(tool["AIPAY_DATABASE_URL"].split("?")[0].endswith("/collection_dev"))
                    self.assertEqual(tool["AIPAY_SIGNING_KEY_ID"], "collection-dev")
                    self.assertEqual(tool["AIPAY_SIGNING_KEY_FILE"], str(root / "certs/collection/signing.pem"))
                    self.assertIn("COLLECTION_DEV_DB_PASSWORD=", files[root / "env/provision.env"])
                    self.assertIn("AIPAY_LOG_OUTPUT=file", files[root / "env/devchain.env"])
                else:
                    self.assertNotIn(root / "env/devcollection.env", files)
                for name in ("notifier", "collection", "iam", "payment", "reconciliation", *cfg.GATEWAYS):
                    self.assertIn(name, cert_calls[0][cert_calls[0].index("--services") + 1].split(","))
                envs = {name: dict(line.split("=", 1) for line in files[root / "env" / (name + ".env")].splitlines())
                        for name in cfg.SERVICES}
                self.assertTrue(all(env["AIPAY_LOG_OUTPUT"] == "file" for env in envs.values()))
                self.assertEqual(envs["backend"]["AIPAY_PLATFORM_ORIGIN"], platform)
                self.assertEqual(envs["backend"]["AIPAY_SELLER_ORIGIN"], seller)
                self.assertEqual(envs["backend"]["AIPAY_CASHIER_ORIGIN"], cashier or "https://pay.aipay.test")
                self.assertNotIn("AIPAY_EPAY_JSON_URL_INSTRUCTION", envs["backend"])
                for prefix in ("IAM_WEBAUTHN", "LEDGER_APPROVAL", "PAYMENT_APPROVAL",
                               "RECONCILIATION_ADMIN", "RECONCILIATION_WEBAUTHN"):
                    env = envs[prefix.split("_")[0].lower()]
                    self.assertEqual(env[f"AIPAY_{prefix}_RP_ID"], platform.removeprefix("https://"))
                    self.assertEqual(env[f"AIPAY_{prefix}_ORIGINS"], platform)
                self.assert_demo_settings(envs, root, compose)
                issuer = files[root / "env/iam-sellers.env"]
                owner = files[root / "env/iam-migrate.env"].removeprefix("AIPAY_DATABASE_URL=")
                self.assertEqual(issuer, "AIPAY_IAM_SELLERS_DATABASE_URL=" + owner)
                self.assertNotEqual(owner.strip(), envs["iam"]["AIPAY_DATABASE_URL"])
                self.assertFalse(any("AIPAY_IAM_SELLERS_DATABASE_URL" in values for values in envs.values()))
                for svc in cfg.OWNERS:
                    self.assertNotIn("only-in-test", envs[svc]["AIPAY_DATABASE_URL"])
                    self.assertIn("/aipay_" + svc, envs[svc]["AIPAY_DATABASE_URL"])
                self.assertEqual(envs["payment"]["AIPAY_IAM_EVENT_KEYS_FILE"], envs["ledger"]["AIPAY_IAM_ASSERTION_KEYS_FILE"])
                ledger_rates = root / "inputs/ledger/usd-rates.json"
                self.assertEqual(envs["ledger"]["AIPAY_LEDGER_DEV_USD_RATES_FILE"],
                                 "/run/kaivo/inputs/usd-rates.json" if compose else str(ledger_rates))
                self.assertEqual(json.loads(files[ledger_rates])[0]["asset"], "USDT")
                self.assertTrue(envs["reconciliation"]["AIPAY_PAYMENT_EVENT_KEYS_FILE"].endswith("/payment.jwks"))
                self.assertIn("payment", envs["iam"]["AIPAY_RPC_ALLOWED_PEERS"].split(","))
                self.assertTrue(envs["payment"]["AIPAY_QUEUE_REDIS_URL"].endswith("/5"))
                self.assertTrue(envs["iam"]["AIPAY_QUEUE_REDIS_URL"].endswith("/1"))
                self.assertEqual(envs["payment"]["AIPAY_IAM_RPC_ADDRESS"], "iam:9101" if compose else "127.0.0.1:9101")
                self.assertFalse(any("DATABASE" in k or "SIGNING" in k or "REDIS" in k for k in envs["notifier"]))
                sim, epay = json.loads(files[root / "inputs/upstream-sim/config.json"])["accounts"]
                self.assertEqual((sim["id"], sim["style"]), ("md5-demo", "form-md5"))
                self.assertEqual((epay["id"], epay["style"], epay["pid"]), ("epay-demo", "epay-v1", 1001))
                self.assertTrue(len(epay["shared_secret"]) == 32 and epay["shared_secret"].isascii()
                                and epay["shared_secret"].isalnum())
                self.assertTrue(json.loads(files[root / "handoff/epay.json"]) == {"merchant_key": epay["shared_secret"]})
                host = "backend" if compose else "127.0.0.1"
                self.assertEqual(envs["payment"]["AIPAY_PLUGIN_CALLBACK_URL"], f"http://{host}:8080/callback/{{channel_code}}")
                self.assertEqual(json.loads(envs["reconciliation"]["AIPAY_RECONCILIATION_PLUGIN_CHANNELS"]),
                                 {"epay_v1_verify": "epay_v1", "sim_form_md5_verify": "sim_form_md5"})
                query = json.loads(files[root / "handoff/query.json"])["query_key"]
                trade = json.loads(files[root / "handoff/trade.json"])["shared"]
                self.assertTrue(query == sim["query_shared_secret"] != sim["shared_secret"] == trade)
                self.assertNotIn(root / "inputs/payment/plugins.json", files)
                for name, peer in cfg.GATEWAYS.items():
                    self.assertNotIn(name, cfg.PEERS)
                    self.assertNotIn(name, cert_calls[0][cert_calls[0].index("--signing-services") + 1].split(","))
                    self.assertEqual(len(files[root / "inputs" / name / "kek"]), 32)
                    self.assertTrue(cfg.gateway_client_settings(name).items() <= envs[peer].items())
                    self.assertFalse(cfg.embedded_client_settings(root, peer).keys() & envs[peer].keys())
                    self.assertNotIn("AIPAY_GRPC_ADDR", files[root / "env" / (name + ".env")])
                    db = "aipay_" + name.replace("-", "_")
                    self.assertIn("://" + db + ":", files[root / "env" / (name + ".env")])
                    self.assertIn("/" + db + "?", files[root / "env" / (name + ".env")])
                der = files[root / "inputs/iam/epay.der"]
                self.assertTrue(all(der == files[root / "inputs" / s / "epay.der"] for s in ("backend", "payment")))
                self.assertTrue(subprocess.check_output(["openssl", "pkey", "-inform", "DER", "-pubout"], input=der)
                                == files[root / "handoff/platform-public.pem"])

    def assert_demo_settings(self, envs, root, compose):
        public = Path("/run/kaivo/public") if compose else root / "certs/public"
        inputs = Path("/run/kaivo/inputs") if compose else root / "inputs/ledger"
        self.assertEqual(envs["payment"]["AIPAY_PAYMENT_REFUND_OBJECTION_WINDOW"], "10s")
        self.assertEqual(envs["payment"]["AIPAY_PAYMENT_REFUND_NOTICES_ENABLED"], "true")
        self.assertEqual(envs["reconciliation"]["AIPAY_RECONCILIATION_REFUND_OBJECTION_WINDOW_MIN"], "10s")
        self.assertEqual(envs["payment"]["AIPAY_PAYMENT_EVENTS"], "on")
        self.assertEqual(envs["payment"]["AIPAY_LEDGER_EVENT_KEYS_FILE"], str(public / "ledger.jwks"))
        self.assertEqual(envs["payment"]["AIPAY_LEDGER_RPC_ADDRESS"], "ledger:9102" if compose else "127.0.0.1:9102")
        self.assertEqual(envs["payment"]["AIPAY_LEDGER_RPC_SERVER_NAME"], "ledger")
        self.assertEqual(envs["backend"]["AIPAY_PAYMENT_EVENT_KEYS_FILE"], str(public / "payment.jwks"))
        self.assertEqual(envs["backend"]["AIPAY_ACCOUNT_NOTICES_ENABLED"], "true")
        self.assertEqual(envs["backend"]["AIPAY_ACCOUNT_NOTICES_GRPC_ADDR"], "upstream-sim:9105" if compose else "127.0.0.1:9105")
        self.assertEqual(envs["backend"]["AIPAY_ACCOUNT_NOTICES_SERVER_NAME"], "payment")
        self.assertEqual(envs["backend"]["AIPAY_ACCOUNT_NOTICES_PULL_INTERVAL"], "1s")
        self.assertEqual(envs["ledger"]["AIPAY_LEDGER_REPORT_KEY_FILE"], str(inputs / "report.pem"))
        self.assertEqual(envs["ledger"]["AIPAY_LEDGER_REPORT_KEY_ID"], "ledger-report-dev")

    def test_demo_config_upgrade_and_key_reuse(self):
        for compose in (False, True):
            with tempfile.TemporaryDirectory() as tmp, patch.object(stack, "request", return_value=None):
                root = Path(tmp)
                for folder in ("env", "inputs/iam", "inputs/payment", "inputs/ledger", "handoff"):
                    (root / folder).mkdir(parents=True)
                cfg.dump(root / "inputs/iam/routes.json", [])
                for name in ("backend", "payment", "ledger", "notifier", "reconciliation"):
                    cfg.save_env(root / "env" / (name + ".env"), {})
                cfg.save_env(root / "env/iam-migrate.env", {"AIPAY_DATABASE_URL": "iam-owner"})
                cfg.save_env(root / "env/iam.env", {"AIPAY_DATABASE_URL": "iam-runtime"})
                cfg.save_env(root / "env/payment.env", {"AIPAY_PAYMENT_DEV_SELLER_REVIEWS_FILE": "custom-review.json"})
                seed = None
                for _ in range(2):
                    if compose:
                        cfg.upgrade_demo(root, compose=True)
                    else:
                        stack.demo_config(root)
                    key = root / "inputs/ledger/report.pem"
                    self.assertEqual(key.stat().st_mode & 0o777, 0o600)
                    if seed is None:
                        seed = key.read_bytes()
                    self.assertTrue(seed == key.read_bytes())
                    self.assertTrue(seed.startswith(b"-----BEGIN PRIVATE KEY-----"))
                    self.assertTrue((root / "handoff/ledger-report-public.pem").read_bytes() ==
                                    subprocess.check_output(["openssl", "pkey", "-in", key, "-pubout"]))
                    envs = {s: cfg.read_env(root / "env" / (s + ".env")) for s in ("backend", "ledger", "payment", "reconciliation")}
                    self.assert_demo_settings(envs, root, compose)
                    self.assertEqual(envs["payment"]["AIPAY_PAYMENT_DEV_SELLER_REVIEWS_FILE"], "custom-review.json")
                    self.assertEqual(json.loads((root / "inputs/iam/routes.json").read_bytes()), cfg.routes())
                    self.assertEqual(cfg.read_env(root / "env/iam-sellers.env"),
                                     {"AIPAY_IAM_SELLERS_DATABASE_URL": "iam-owner"})
                    self.assertEqual(cfg.read_env(root / "env/iam.env"), {"AIPAY_DATABASE_URL": "iam-runtime"})
                    self.assertEqual(cfg.read_env(root / "env/ledger.env")["AIPAY_LEDGER_DEV_USD_RATES_FILE"],
                                     "/run/kaivo/inputs/usd-rates.json" if compose else str(root / "inputs/ledger/usd-rates.json"))

                renamed = root / "inputs/ledger/custom.pem"
                key.rename(renamed)
                ledger = envs["ledger"] | {"AIPAY_LEDGER_REPORT_KEY_FILE": "/run/kaivo/inputs/custom.pem" if compose else str(renamed),
                                          "AIPAY_LEDGER_REPORT_KEY_ID": "existing-report-id"}
                cfg.save_env(root / "env/ledger.env", ledger)
                cfg.upgrade_demo(root, compose)
                self.assertEqual(ledger, cfg.read_env(root / "env/ledger.env"))
                self.assertFalse(key.exists())

    def test_deposit_phase(self):
        seller = "019ab233-4567-7890-8123-456789abcdef"
        with tempfile.TemporaryDirectory() as tmp, patch.object(stack, "request", return_value=None):
            root = Path(tmp)
            (root / "env").mkdir()
            (root / "logs").mkdir()
            cfg.native_deposit_inputs(root, "postgres://localhost:5432/postgres", {})
            for name, flag in (("ledger", "AIPAY_LEDGER_DEPOSITS"), ("reconciliation", "AIPAY_RECON_DEPOSITS")):
                cfg.save_env(root / "env" / (name + ".env"), {flag: "off"})
                self.assertEqual(processes.service_env(root, name)[flag], "off")
            self.assertNotIn("devchain", processes.services(root))
            genesis = int(datetime(2027, 1, 2, 3, 4, 5, tzinfo=timezone.utc).timestamp())
            with patch.object(fixture, "time", return_value=genesis):
                stack.deposits(root, seller, None)
            self.assertEqual(processes.services(root)[:2], ("devchain", "devcollection"))
            self.assertEqual(processes.command(root, "devchain"), [str(root / "bin/kaivo-devchain"), "serve"])
            self.assertEqual(processes.command(root, "devcollection"), [str(root / "bin/kaivo-devcollection"), "serve"])
            env = processes.service_env(root, "reconciliation")
            self.assertEqual(env["AIPAY_RECON_EVM_CHAIN_ID"], "31337")
            self.assertEqual(env["AIPAY_RECON_EVM_RPC_URL"], "http://127.0.0.1:8545")
            self.assertEqual(env["AIPAY_RECON_EVM_REGISTRY_VERSION"], "bsc-usdt-v1")
            self.assertEqual(env["AIPAY_RECON_SCREENING_MODE"], "development_allow")
            self.assertEqual(env["AIPAY_RECON_DEPOSITS"], "on")
            self.assertEqual(processes.service_env(root, "ledger")["AIPAY_LEDGER_DEPOSITS"], "on")
            binding, = json.loads(Path(env["AIPAY_RECON_BINDINGS_FILE"]).read_text())["bindings"]
            self.assertEqual((binding["account_id"], binding["valid_from_block"], binding["valid_to_block"]), (seller, 1, 3))
            chain_file = Path(processes.service_env(root, "devchain")["AIPAY_DEVCHAIN_DATASET"])
            scenario = json.loads((root / "deposits/scenario.json").read_text())
            self.assertEqual(scenario["replay_key"], "normal")
            normal, mismatch = (scenario["receipts"][k] for k in ("normal", "mismatch"))
            chain = json.loads(chain_file.read_text())
            timestamps = [int(b["timestamp"], 16) for b in chain["blocks"]]
            self.assertEqual(timestamps, [genesis, genesis + 3, genesis + 6, genesis + 9])
            for claim in scenario["receipts"].values():
                confirmed = datetime.fromtimestamp(timestamps[claim["block_number"]], timezone.utc)
                self.assertEqual(claim["confirmed_at"], cfg.stamp(confirmed))
            for claim in (normal, mismatch):
                log, = chain["receipts"][claim["chain_transaction_id"]]["logs"]
                self.assertEqual(int(log["logIndex"], 16), claim["transfer_index"])
                self.assertEqual(log["topics"][2][-40:], binding["deposit_address"][2:])
                self.assertEqual(str(int(log["data"], 16)) == claim["raw_amount"], claim == normal)
            self.assertGreater(scenario["receipts"]["unfinalized"]["block_number"], chain["finalized"])
            spec = json.loads(fixture.SPEC.read_text())
            spec["transfers"][0]["receipt_raw"] = "900000000000000000000"
            cfg.dump(root / "changed-spec.json", spec)
            with patch.object(fixture, "time", return_value=genesis):
                fixture.generate(root / "changed", seller, root / "changed-spec.json")
            self.assertEqual((root / "changed/chain.json").read_bytes(), chain_file.read_bytes())
            self.assertNotEqual((root / "changed/scenario.json").read_bytes(), (root / "deposits/scenario.json").read_bytes())
            with patch.object(fixture, "time", return_value=genesis + 60):
                stack.deposits(root, seller, 3)
                fixture.generate(root / "new", seller)
            self.assertEqual(json.loads(chain_file.read_text()), chain)
            self.assertEqual(json.loads((root / "deposits/scenario.json").read_text()), scenario)
            self.assertEqual(int(json.loads((root / "new/chain.json").read_text())["blocks"][0]["timestamp"], 16), genesis + 60)
            self.assertEqual(processes.service_env(root, "devchain")["AIPAY_DEVCHAIN_FINALIZED"], "3")
            with self.assertRaises(ValueError):
                stack.deposits(root, seller, 4)
            with self.assertRaises(ValueError):
                stack.deposits(root, "019ab233-4567-7890-8123-456789abcdee", None)
            stack.deposits(root, None, None)
            self.assertEqual(processes.service_env(root, "ledger")["AIPAY_LEDGER_DEPOSITS"], "off")
            self.assertTrue(chain_file.exists())

    def test_raw_amounts(self):
        for raw, units in (("1000000000000000000000", 10**9), ("1999999999999", 1),
                           (str((2**63-1)*10**12), 2**63-1)):
            self.assertEqual(fixture.ledger_units(raw), units)
        for raw in ("1", "00", "-1", "1e21", str(2**63*10**12)):
            with self.assertRaises(ValueError):
                fixture.ledger_units(raw)

    def test_refresh_preserves_original_minutes(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            for svc in ("payment", "reconciliation", "ledger"):
                (root / "inputs" / svc).mkdir(parents=True)
            now = datetime(2026, 11, 19, 12, 30, 10, tzinfo=timezone.utc)
            rate = root / "inputs/payment/rate.json"
            market = root / "inputs/reconciliation/market.json"
            ledger = root / "inputs/ledger/usd-rates.json"
            cfg.refresh(root, now)
            previous = [p.read_bytes() for p in (rate, market, ledger)]
            first = dict(asset="USDT", source_a="dev-a", rate_a="1.0000", source_b="dev-b", rate_b="0.9999",
                         observed_at="2026-11-19T12:29:00Z")
            self.assertEqual(json.loads(previous[2]), [first])
            cfg.refresh(root, now + timedelta(seconds=30))
            self.assertEqual(previous, [p.read_bytes() for p in (rate, market, ledger)])
            cfg.refresh(root, now + timedelta(minutes=1))
            records = json.loads(market.read_text())
            self.assertEqual(len(records), 4)
            self.assertEqual(records[:2], json.loads(previous[1]))
            self.assertEqual(json.loads(rate.read_text())["minute"], records[-1]["minute"])
            self.assertEqual(rate.stat().st_mode & 0o777, 0o600)
            self.assertEqual(json.loads(ledger.read_text()), [first, first | {"observed_at": records[-1]["minute"]}])
            self.assertEqual(ledger.stat().st_mode & 0o777, 0o600)
            # payment internal IDs are UUIDv7; ledger rejects any other rate_snapshot_id.
            snapshot = json.loads(rate.read_text())["rate_snapshot_id"]
            parsed = uuid.UUID(snapshot)
            self.assertEqual((parsed.version, str(parsed)), (7, snapshot))
            self.assertNotEqual(snapshot, json.loads(previous[0])["rate_snapshot_id"])

    def test_ledger_rate_limit_preserves_history(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "usd-rates.json"
            minute = datetime(2026, 11, 19, 12, 30, tzinfo=timezone.utc)
            cfg.append_ledger_rate(path, minute)
            row, = json.loads(path.read_bytes())
            # In the compact array each additional row costs its JSON bytes and a comma.
            row_bytes = len(json.dumps(row, separators=(",", ":")).encode()) + 1
            count = ((64 << 10) - len(b"]\n")) // row_bytes
            cfg.dump(path, [row | {"observed_at": cfg.stamp(minute + timedelta(minutes=i))} for i in range(count - 1)])
            cfg.append_ledger_rate(path, minute + timedelta(minutes=count - 1))
            full = path.read_bytes()
            self.assertLessEqual(len(full), 64 << 10)
            cfg.append_ledger_rate(path, minute)
            with self.assertRaisesRegex(ValueError, "ledger USD rate history is full"):
                cfg.append_ledger_rate(path, minute + timedelta(minutes=count))
            self.assertEqual(path.read_bytes(), full)

    def test_provisioning_sql_uses_all_role_envs(self):
        # Capture precisely the stdin sent to psql. No server or credentials are used.
        with tempfile.TemporaryDirectory() as tmp:
            wrapper = Path(tmp) / "psql"
            sql = Path(tmp) / "commands.sql"
            wrapper.write_text('#!/bin/sh\ncat > "$CAPTURE_SQL"\n')
            wrapper.chmod(0o700)
            env = {"PATH": tmp + os.pathsep + os.environ["PATH"], "STACK_ID": "test", "CAPTURE_SQL": str(sql),
                   "UPSTREAM_GATEWAY_TRADE_DB_PASSWORD": "trade", "UPSTREAM_GATEWAY_VERIFICATION_DB_PASSWORD": "verify"}
            subprocess.run(["sh", str(cfg.LIBRARY / "dev/init-databases.sh")], check=True, env=env)
            self.assertNotIn("collection_dev", sql.read_text())
            subprocess.run(["sh", str(cfg.LIBRARY / "dev/init-databases.sh")], check=True,
                           env=env | {"COLLECTION_DEV_DB_PASSWORD": "fixture"})
            commands = sql.read_text()
            self.assertIn("\\getenv pw COLLECTION_DEV_DB_PASSWORD", commands)
            self.assertIn("('collection_dev', 'collection_dev', 'collection_dev')", commands)
            for svc in cfg.OWNERS:
                self.assertIn("\\getenv pw " + svc.upper() + "_DB_PASSWORD\n", commands)
            for name in cfg.GATEWAYS:
                db = "aipay_" + name.replace("-", "_")
                self.assertIn(f"('{db}', '{db}', '{db}')", commands)
                self.assertIn("\\getenv pw " + name.upper().replace("-", "_") + "_DB_PASSWORD\n", commands)
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


class Transport(unittest.TestCase):
    def test_switch_and_injection(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "env").mkdir()
            for directory in ("handoff", "inputs/iam", "inputs/payment", "inputs/reconciliation"):
                (root / directory).mkdir(parents=True)
            cfg.dump(root / "inputs/iam/routes.json", cfg.routes())
            cfg.dump(root / "handoff/trade.json", {"shared": "demo-shared"})
            tls = {"AIPAY_TLS_CERT_FILE": "cert", "AIPAY_NOTIFIER_TLS_KEY_FILE": "private"}
            for name in cfg.SERVICES:
                cfg.save_env(root / "env" / (name + ".env"), tls)
            self.assertEqual(processes.transport(root), "mtls")
            with patch.object(stack, "request", side_effect=lambda name, _: name == "ledger-reader"):
                with self.assertRaisesRegex(ValueError, "down"):
                    stack.change_mode(root, "transport", "plaintext")
            stack.change_mode(root, "transport", "plaintext")
            self.assertEqual(processes.services(root)[0], "devtoken")
            self.assertNotIn("settlement", processes.services(root))
            self.assertFalse(set(cfg.GATEWAYS) & set(processes.services(root)))
            self.assertTrue((root / "inputs/payment/plugins.json").is_file())
            self.assertEqual(list(reversed(processes.services(root)))[-1], "devtoken")
            self.assertEqual(json.loads(processes.command(root, "devtoken")[-1]), processes.token_targets())
            self.assertEqual({(c, t) for c, ts in processes.token_targets().items() for t in ts},
                             {(c, t) for t, callers in cfg.PEERS.items() for c in callers.split(",")})
            for name in (*processes.TOKEN_SERVICES, "ledger-reader"):
                env = processes.service_env(root, name)
                owner = "ledger" if name == "ledger-reader" else name
                self.assertEqual(env["AIPAY_RPC_TRANSPORT"], "plaintext")
                self.assertEqual(env["AIPAY_RPC_TOKEN_DIR"], str(root / "tokens" / owner))
                self.assertEqual(env["AIPAY_RPC_TOKEN_JWKS_FILE"], str(root / "token-issuer/jwks.json"))
                self.assertEqual(env["AIPAY_RPC_TOKEN_ISSUER"], processes.TOKEN_ISSUER)
                self.assertIn(owner + "=local", env["AIPAY_RPC_SERVICE_NAMESPACES"].split(","))
                self.assertFalse(env.keys() & tls.keys())
                expected = dict(tls)
                if owner in cfg.GATEWAYS.values():
                    expected.update({k: str(v) for k, v in cfg.embedded_client_settings(root, owner).items()})
                self.assertEqual(cfg.read_env(root / "env" / (owner + ".env")), expected)
            self.assertNotIn("AIPAY_RPC_TRANSPORT", processes.service_env(root, "cashier"))
            with self.assertRaisesRegex(ValueError, "devcollection requires mTLS"):
                stack.deposits(root, "seller", None)
            with patch.object(stack, "request", side_effect=lambda name, _: name == "devtoken"):
                with self.assertRaisesRegex(ValueError, "down"):
                    stack.change_mode(root, "transport", "mtls")
            stack.change_mode(root, "transport", "mtls")
            self.assertNotIn("devtoken", processes.services(root))
            self.assertFalse((root / "inputs/payment/plugins.json").exists())
            for name, peer in cfg.GATEWAYS.items():
                self.assertLess(processes.services(root).index(name), processes.services(root).index("payment"))
                self.assertEqual(cfg.read_env(root / "env" / (peer + ".env")), tls | cfg.gateway_client_settings(name))
            self.assertEqual(processes.service_env(root, "notifier")["AIPAY_NOTIFIER_TLS_KEY_FILE"], "private")
            (root / "deposits.enabled").touch()
            with self.assertRaisesRegex(ValueError, "devcollection requires mTLS"):
                stack.change_mode(root, "transport", "plaintext")

    @unittest.skipUnless(os.getenv("AIPAY_TEST_DEVTOKEN_BINARY"), "supply kaivo-devtoken for process test")
    def test_managed_issuer(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp).resolve()
            for name in ("run", "bin", "logs"):
                (root / name).mkdir()
            (root / "bin/kaivo-devtoken").symlink_to(Path(os.environ["AIPAY_TEST_DEVTOKEN_BINARY"]).resolve())
            cwd = Path.cwd()
            os.chdir(root / "run")
            try:
                worker = processes.start(root, "devtoken")
                try:
                    self.assertTrue(processes.health(root, "devtoken"))
                    self.assertTrue((root / "tokens/notifier/payment").is_file())
                    self.assertFalse((root / "tokens/notifier/iam").exists())
                    self.assertEqual((root / "token-issuer/issuer.key").stat().st_mode & 0o777, 0o600)
                finally:
                    processes.stop("devtoken")
                    self.assertEqual(worker.wait(3), 0)
                self.assertFalse(processes.health(root, "devtoken"))
            finally:
                os.chdir(cwd)


class Telemetry(unittest.TestCase):
    def test_local_binaries_config_and_state(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp).resolve()
            for name in ("otelcol", "prometheus", "custom-collector"):
                exe = root / name
                exe.touch(mode=0o700)
            with patch.dict(os.environ, {"PATH": tmp}, clear=True):
                stack.change_mode(root, "telemetry", "on")
                config = telemetry.state(root)
                self.assertEqual(config, {"mode": "local", "endpoint": telemetry.LOCAL_ENDPOINT,
                                          "otelcol": str(root / "otelcol"), "prometheus": str(root / "prometheus")})
                self.assertEqual((root / "telemetry.json").stat().st_mode & 0o777, 0o600)
                (root / "otelcol-contrib").touch(mode=0o700)
                stack.change_mode(root, "telemetry", "on")
                self.assertEqual(telemetry.state(root)["otelcol"], str(root / "otelcol-contrib"))
                with patch.dict(os.environ, {"AIPAY_DEV_OTELCOL_BIN": str(root / "custom-collector"),
                                             "AIPAY_DEV_PROMETHEUS_BIN": str(root / "prometheus"), "PATH": ""}):
                    stack.change_mode(root, "telemetry", "on")
                self.assertEqual(processes.command(root, "otelcol")[0], str(root / "custom-collector"))
                (root / "prometheus").unlink()
                with self.assertRaisesRegex(ValueError, "install prometheus"):
                    stack.change_mode(root, "telemetry", "on")
                self.assertEqual(telemetry.state(root)["otelcol"], str(root / "custom-collector"))
            self.assertEqual(processes.services(root)[:2], telemetry.PROCESSES)
            self.assertTrue((root / "data/prometheus").is_dir())
            self.assertIn("--web.enable-otlp-receiver", processes.command(root, "prometheus"))
            self.assertIn("--storage.tsdb.retention.time=2d", processes.command(root, "prometheus"))
            self.assertIn("metrics_endpoint: http://127.0.0.1:9090/api/v1/otlp/v1/metrics",
                          (root / "telemetry/collector.yaml").read_text())
            self.assertIn("[deployment.environment.name, kaivo.domain]", (root / "telemetry/prometheus.yaml").read_text())
            self.assertNotIn("AIPAY_METRICS_ENDPOINT", processes.service_env(root, "otelcol"))
            self.assertNotIn("AIPAY_METRICS_ALLOW_INSECURE", telemetry.environment(root))
            stack.change_mode(root, "telemetry", "off")
            self.assertEqual(telemetry.state(root), {"mode": "off"})
            self.assertNotIn("otelcol", processes.services(root))

    def test_external_and_logs(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "env").mkdir()
            for name in (*cfg.SERVICES, *cfg.DEPOSIT_SERVICES):
                cfg.save_env(root / "env" / (name + ".env"), {"AIPAY_LOG_OUTPUT": "file"})
            for endpoint, insecure in (("http://127.0.0.9:4317", False), ("http://[::1]:4317", False),
                                       ("http://localhost:4317", False), ("https://remote:4317", False),
                                       ("http://collector.ns:4317", True)):
                with self.subTest(endpoint=endpoint), patch("shutil.which", side_effect=AssertionError):
                    stack.change_mode(root, "telemetry", "on", endpoint)
                    self.assertNotIn("prometheus", processes.services(root))
                    for name in (*cfg.OWNERS, *cfg.DEPOSIT_SERVICES, "notifier", "ledger-reader", "upstream-sim"):
                        env = processes.service_env(root, name)
                        self.assertEqual(env["AIPAY_METRICS_ENDPOINT"], endpoint)
                        self.assertEqual(env["AIPAY_METRICS_ENVIRONMENT"], "local")
                        self.assertEqual(env["AIPAY_METRICS_INTERVAL"], "5s")
                        self.assertEqual(env["AIPAY_METRICS_EXPORT_TIMEOUT"], "3s")
                        self.assertEqual(env.get("AIPAY_METRICS_ALLOW_INSECURE"), "true" if insecure else None)
            stack.change_mode(root, "logs", "stdout")
            self.assertEqual(processes.service_env(root, "notifier")["AIPAY_LOG_OUTPUT"], "stdout")
            self.assertEqual(cfg.read_env(root / "env/notifier.env"), {"AIPAY_LOG_OUTPUT": "file"})
            stack.change_mode(root, "logs", "file")
            stack.change_mode(root, "telemetry", "off")
            self.assertEqual(processes.service_env(root, "ledger-reader")["AIPAY_LOG_OUTPUT"], "file")
            self.assertNotIn("AIPAY_METRICS_ENDPOINT", processes.service_env(root, "notifier"))
            self.assertFalse((root / "telemetry").exists())

    def test_requires_down_and_valid_url(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            with patch.object(stack, "request", side_effect=lambda name, _: "123" if name == "ledger-reader" else None):
                for action, mode in (("telemetry", "on"), ("telemetry", "off"), ("logs", "stdout"), ("logs", "file")):
                    with self.assertRaisesRegex(ValueError, "down"):
                        stack.change_mode(root, action, mode)
            for value in ("", "collector:4317", "ftp://host:1", "http://host", "http://host:0",
                          "http://host:65536", "http://host:foo", "http://user:private@host:12", "http://host:1/",
                          "http://host:1/path", "https://host:42?", "http://host:1#x", "http://[::1]suffix:1",
                          "http://[bad]:1", "http://two words:1", "http://host..name:12"):
                with self.subTest(value=value), self.assertRaisesRegex(ValueError, "^metrics endpoint requires"):
                    telemetry.configure(root, "on", value)
            self.assertFalse((root / "telemetry.json").exists())


class GatewayLifecycle(unittest.TestCase):
    def test_fenced_instance_exits_independently(self):
        # Exercise the real supervisor and TCP probe without a PostgreSQL server.
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp).resolve()
            for folder in ("env", "run", "bin"):
                (root / folder).mkdir()
            binary = root / "bin/upstream-gateway"
            binary.write_text("""#!/usr/bin/env python3
import os, socket, sys
from pathlib import Path
flag, config = sys.argv[1:]
assert flag == "--config" and Path(config).parent.name == os.environ["GATEWAY_DATABASE_URL"]
with socket.socket() as server:
    server.bind(("127.0.0.1", int(Path(config).read_text())))
    server.listen()
    while True:
        client, _ = server.accept()
        with client:
            if client.recv(8) == b"fence":
                sys.exit(17)
""")
            binary.chmod(0o700)
            ports = {}
            workers = {}
            cwd = Path.cwd()
            os.chdir(root / "run")
            try:
                for name in cfg.GATEWAYS:
                    with socket.socket() as probe:
                        probe.bind(("127.0.0.1", 0))
                        ports[name] = probe.getsockname()[1]
                    (root / "inputs" / name).mkdir(parents=True)
                    (root / "logs" / name).mkdir(parents=True)
                    (root / "inputs" / name / "gateway.toml").write_text(str(ports[name]))
                    cfg.save_env(root / "env" / (name + ".env"), {"GATEWAY_DATABASE_URL": name})
                    with patch.dict(processes.PORTS, ports):
                        workers[name] = processes.start(root, name)
                trade, query = cfg.GATEWAYS
                with socket.create_connection(("127.0.0.1", ports[trade]), timeout=2) as conn:
                    conn.sendall(b"fence")
                self.assertNotEqual(workers[trade].wait(5), 0)
                self.assertIsNone(processes.request(trade, "pid"))
                with patch.dict(processes.PORTS, ports):
                    self.assertTrue(processes.health(root, query))
                processes.stop(query)
                self.assertEqual(workers[query].wait(5), 0)
            finally:
                for name in reversed(workers):
                    processes.stop(name)
                    workers[name].wait(5)
                os.chdir(cwd)


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
