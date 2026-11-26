"""Shared inputs for the native and Compose development stacks."""
import base64
from datetime import datetime, timedelta, timezone
from fractions import Fraction
import hashlib
import json
import os
from pathlib import Path
import re
import secrets
import shutil
import string
import subprocess
import tempfile
from urllib.parse import quote, urlsplit, urlunsplit, parse_qsl
import uuid

LIBRARY = Path(__file__).resolve().parents[1]
WORKSPACE = LIBRARY.parent
STATE = WORKSPACE / ".local" / "dev"
SERVICES = ("iam", "ledger", "payment", "notifier", "reconciliation", "settlement", "upstream-sim", "cashier", "backend")
OWNERS = tuple(s for s in SERVICES if s not in ("notifier", "upstream-sim", "cashier"))
APP_ROLES = ("iam", "ledger", "payment", "reconciliation")
DEPOSIT_SERVICES = ("devchain", "devcollection")
PORTS = {"otelcol": 4317, "prometheus": 9090, "devchain": 8545, "devcollection": 9106, "iam": 9101, "ledger": 9102, "settlement": 9103, "reconciliation": 9104, "payment": 9105,
         "upstream-gateway-trade": 9107, "upstream-gateway-verification": 9108,
         "notifier": 9115, "upstream-sim": 9080, "cashier": 9443, "backend": 8080}
CACHE_DB = {"backend": 0, "iam": 1, "ledger": 2, "settlement": 3, "reconciliation": 4, "payment": 5}
PEERS = {"iam": "backend,payment,settlement", "ledger": "backend,payment,reconciliation,settlement",
         "payment": "backend,ledger,reconciliation,notifier", "reconciliation": "backend,ledger,settlement",
         "settlement": "backend"}
GATEWAYS = {"upstream-gateway-trade": "payment", "upstream-gateway-verification": "reconciliation"}
RP = "admin.aipay.test"
ORIGIN = "https://" + RP
LEDGER_RATE_FILE_LIMIT = 64 << 10  # ledger/internal/fx/devfile.go


def write(path, data, *, mode=None):
    """Atomic replacement, including first creation. Never follow the destination."""
    data = data.encode() if isinstance(data, str) else data
    with tempfile.NamedTemporaryFile(dir=path.parent, delete=False) as f:
        try:
            f.write(data)
            f.flush()
            if mode is not None:
                os.fchmod(f.fileno(), mode)
            os.replace(f.name, path)
        finally:
            Path(f.name).unlink(missing_ok=True)


def dump(path, value, **write_options):
    write(path, json.dumps(value, separators=(",", ":")) + "\n", **write_options)


def save_env(path, values, **write_options):
    if any(any(c in str(v) for c in "\x00\r\n") for v in values.values()):
        raise ValueError("invalid multiline environment value")
    write(path, "".join(f"{k}={v}\n" for k, v in values.items()), **write_options)


def read_env(path):
    return dict(line.split("=", 1) for line in path.read_text().splitlines() if line)


def coverage_mode(root, mode, validity=None):
    path = root / "env/reconciliation.env"
    values = read_env(path)
    updated = values.copy()
    source = "AIPAY_RECONCILIATION_COVERAGE_DEVELOPMENT_FILE"
    period = "AIPAY_RECONCILIATION_COVERAGE_VALIDITY"
    if validity is not None and mode != "attestation":
        raise ValueError("--validity requires coverage attestation")
    if mode == "attestation":
        validity = "4m" if validity is None else validity
        # Match time.ParseDuration units and reconciliation's whole-microsecond policy.
        units = {"h": 3600000000000, "m": 60000000000, "s": 1000000000, "ms": 1000000,
                 "us": 1000, "µs": 1000, "μs": 1000, "ns": 1}
        parts = re.findall(r"([0-9]+(?:\.[0-9]*)?|\.[0-9]+)(ns|[uµμm]s|[smh])", validity.removeprefix("+"))
        if not parts or "".join(n + u for n, u in parts) != validity.removeprefix("+"):
            raise ValueError("expected a duration between 1m and 26h")
        nanos = sum(int(Fraction(n) * units[u]) for n, u in parts)
        if not units["m"] <= nanos <= 26 * units["h"] or nanos % 1000:
            raise ValueError("coverage validity must be 1m to 26h at whole-microsecond precision")
        updated.pop(source, None)
        updated[period] = validity
    elif mode == "file":
        updated[source] = str(root / "inputs/reconciliation/coverage.json")
        updated.pop(period, None)
    elif mode != "status":
        raise ValueError("unknown coverage mode")
    if updated != values:
        save_env(path, updated, mode=path.stat().st_mode & 0o777)
    return ("file", "from coverage.json") if updated.get(source) else ("attestation", updated.get(period, "26h"))


def seller_ceremony_env(root, iam_owner_dsn):
    save_env(root / "env/iam-sellers.env", {"AIPAY_IAM_SELLERS_DATABASE_URL": iam_owner_dsn})


def url_parts(raw, schemes):
    if not raw or any(c.isspace() for c in raw):
        raise ValueError("expected a database or Redis URL")
    try:
        u = urlsplit(raw)
        _ = u.port
    except ValueError:
        raise ValueError("invalid database or Redis endpoint") from None
    if u.scheme not in schemes or not u.hostname or u.fragment:
        raise ValueError("invalid database or Redis URL")
    return u


def database_url(admin, owner, password, db, prefix="aipay_"):
    u = url_parts(admin, ("postgres", "postgresql"))
    # An admin DSN's identity/target must never override the service's URI.
    if any(k not in ("sslmode", "sslrootcert", "connect_timeout", "application_name")
           for k, _ in parse_qsl(u.query, keep_blank_values=True)):
        raise ValueError("unsupported PostgreSQL URL option (see dev/README.md)")
    host = u.netloc.rsplit("@", 1)[-1]
    return urlunsplit((u.scheme, f"{owner}:{quote(password, safe='')}@{host}", "/" + prefix + db, u.query, ""))


def redis_db(raw, index):
    u = url_parts(raw, ("redis", "rediss"))
    if any(k.lower() == "db" for k, _ in parse_qsl(u.query)):
        raise ValueError("select the Redis DB by URL path")
    return urlunsplit((u.scheme, u.netloc, "/" + str(index), u.query, ""))


def stamp(time):
    return time.isoformat().replace("+00:00", "Z")


def b64(data):
    return base64.b64encode(data).decode("ascii")


def append_ledger_rate(path, minute):
    history = []
    if path.exists():
        if path.stat().st_size > LEDGER_RATE_FILE_LIMIT:
            raise ValueError("existing ledger USD rate file exceeds 64 KiB")
        history = json.loads(path.read_bytes())
        if not isinstance(history, list):
            raise ValueError("ledger USD rate history must be a JSON array")
    observed_at = stamp(minute)
    if any(row["asset"] == "USDT" and row["observed_at"] == observed_at for row in history):
        return
    history.append(dict(asset="USDT", source_a="dev-a", rate_a="1.0000",
                        source_b="dev-b", rate_b="0.9999", observed_at=observed_at))
    data = (json.dumps(history, separators=(",", ":")) + "\n").encode()
    if len(data) > LEDGER_RATE_FILE_LIMIT:
        raise ValueError("ledger USD rate history is full; archive completed demo minutes before refreshing")
    write(path, data)


def minute_snapshot_id(minute):
    """Deterministic UUIDv7 for one development rate minute.

    payment internal IDs are UUIDv7 and ledger rejects quotes whose
    rate_snapshot_id is not one. The timestamp is the minute itself and the
    random bits come from the minute, so refreshing a minute again yields the
    same ID.
    """
    ms = int(minute.timestamp() * 1000)
    rand = int.from_bytes(hashlib.sha256(b"kaivo-dev-rate:" + stamp(minute).encode()).digest()[:10], "big")
    value = (ms & ((1 << 48) - 1)) << 80 | 0x7 << 76 | (rand >> 68 & 0xFFF) << 64 | 0b10 << 62 | (rand & ((1 << 62) - 1))
    return str(uuid.UUID(int=value))


def refresh(root, now=None):
    now = now or datetime.now(timezone.utc)
    end = now.replace(second=0, microsecond=0)
    minute = end - timedelta(minutes=1)
    key = minute_snapshot_id(minute)
    rate = {"rate_snapshot_id": key, "minute": stamp(minute), "collected_at": stamp(end),
            "usable_for_quoting": True, "expires_at": stamp(minute + timedelta(minutes=10))}
    market_file = root / "inputs/reconciliation/market.json"
    records = json.loads(market_file.read_text()) if market_file.exists() else []
    existing = {(row["source"], row["minute"]) for row in records}
    for source, median in (("okx", "7.2"), ("binance", "7.21")):
        rate[source + "_median"] = dict(base_currency="USDT", quote_currency="CNY", value=median, version_id=key)
        rate[source + "_sample_count"] = 10
        if (source, stamp(minute)) not in existing:
            sample = f"development {source} {stamp(minute)} {median}".encode()
            records.append(dict(source=source, minute=stamp(minute), median=median, samples=10,
                                collected_at=stamp(end), recorded_at=stamp(end),
                                raw_sha256=b64(hashlib.sha256(sample).digest())))
    if len(json.dumps(records).encode()) >= 1 << 20:
        raise ValueError("market history exceeds the reconciliation file limit; archive completed demo minutes first")
    append_ledger_rate(root / "inputs/ledger/usd-rates.json", minute)
    dump(market_file, records)
    dump(market_file.with_name("coverage.json"), dict(covered=True, as_of=stamp(now), expires_at=stamp(now + timedelta(hours=1))))
    dump(root / "inputs/payment/rate.json", rate)


TRADE_CREDENTIALS_ROUTE = {"method": "POST", "path": "/api/v1/platform/channel-accounts/credentials",
                          "permission": "payment.channel.manage", "audiences": ["payment"]}


def routes():
    rules = []
    for methods, path, perm in (
        ("GET POST", "/submit.php", "payment.order.create"), ("POST", "/mapi.php", "payment.order.create"),
        ("GET POST", "/api/pay/submit", "payment.order.create"), ("POST", "/api/pay/create", "payment.order.create"),
        ("POST", "/api/pay/query", "payment.order.read"), ("POST", "/api/pay/close", "payment.order.close"),
        ("POST", "/api/pay/refund", "payment.refund.create"), ("POST", "/api/pay/refundquery", "payment.refund.read"),
        ("POST", "/api/merchant/orders", "payment.order.read"), ("POST", "/api/merchant/info", "merchant.profile.read"),
    ):
        rules.extend(dict(method=m, path=path, permission=perm,
                          audiences=["ledger" if path == "/api/merchant/info" else "payment"]) for m in methods.split())
    return rules + json.loads((LIBRARY / "dev/portal-routes.json").read_text())


def new_epay_account():
    key = "".join(secrets.choice(string.ascii_letters + string.digits) for _ in range(32))
    return dict(id="epay-demo", style="epay-v1", pid=1001, shared_secret=key)


def generate_inputs(root, sim_listen):
    for svc in SERVICES:
        for parent in ("inputs", "logs", "data"):
            (root / parent / svc).mkdir(parents=True, mode=0o700)
    for directory in ("env", "handoff", "data/iam/mail", "data/ledger/anchors", "data/payment/evidence"):
        (root / directory).mkdir(mode=0o700)
    ids = ",".join((*PEERS, *GATEWAYS, "backend", "notifier", "collection", "probe", "cashier"))
    subprocess.run(["go", "run", "-mod=readonly", "./cmd/devcert", "--services", ids,
                    "--signing-services", ",".join((*PEERS, "collection")),
                    "--out", str(root / "certs")], env=os.environ | {"GOWORK": "off"}, cwd=LIBRARY, check=True)
    inputs = root / "inputs"
    write(inputs / "iam/sealer.key", secrets.token_bytes(32))
    # IAM, backend and payment use the same platform RSA key for EPay V2.
    rsa = subprocess.check_output(["openssl", "genpkey", "-algorithm", "RSA", "-pkeyopt", "rsa_keygen_bits:2048"],
                                  stderr=subprocess.DEVNULL)
    der = subprocess.check_output(["openssl", "pkcs8", "-topk8", "-nocrypt", "-outform", "DER"], input=rsa)
    for svc in ("iam", "backend", "payment"):
        write(inputs / svc / "epay.der", der)
    write(root / "handoff/platform-public.pem", subprocess.check_output(["openssl", "pkey", "-pubout"], input=rsa))
    payment_secret, query_secret = secrets.token_hex(32), secrets.token_hex(32)
    epay = new_epay_account()
    dump(inputs / "payment/seller-reviews.json", [])
    dump(root / "handoff/trade.json", {"shared": payment_secret})
    dump(root / "handoff/query.json", {"query_key": query_secret})
    dump(root / "handoff/epay.json", {"merchant_key": epay["shared_secret"]})
    dump(inputs / "upstream-sim/config.json", dict(environment="test", listen=sim_listen, base_url="https://127.0.0.1:9443",
         control_token=secrets.token_urlsafe(32), accounts=[dict(id="md5-demo", style="form-md5",
         shared_secret=payment_secret, query_shared_secret=query_secret), epay]))
    dump(inputs / "iam/routes.json", routes())
    write(inputs / "backend/bot-token", "10001:" + secrets.token_urlsafe(32))
    refresh(root)


def gateway_inputs(root, admin, passwords, compose):
    for name, peer in GATEWAYS.items():
        inputs = root / "inputs" / name
        inputs.mkdir(mode=0o700)
        (root / "logs" / name).mkdir(mode=0o700)
        db = "aipay_" + name.replace("-", "_")
        password = secrets.token_hex(24)
        passwords[name.upper().replace("-", "_") + "_DB_PASSWORD"] = password
        save_env(root / "env" / (name + ".env"), {
            "GATEWAY_DATABASE_URL": database_url(admin, db, password, db, prefix=""),
        })
        write(inputs / "kek", secrets.token_bytes(32))
        certs = Path("/run/kaivo/identity") if compose else Path("../../certs") / name
        ca = "/run/kaivo/ca.crt" if compose else "../../certs/ca.crt"
        listen = "0.0.0.0" if compose else "127.0.0.1"
        write(inputs / "gateway.toml", f'''role = "{name.removeprefix('upstream-gateway-')}"
mode = "development"
listen = "{listen}:{PORTS[name]}"
allowed_peers = ["{peer}"]
database_url_env = "GATEWAY_DATABASE_URL"
local_kek_file = "kek"
allow_loopback_http = true
allow_uncommitted = false

[tls]
trust_domain = "aipay.test"
ca_file = "{ca}"
cert_file = "{certs}/tls.crt"
key_file = "{certs}/tls.key"
''')


def gateway_client_settings(name):
    prefix = "AIPAY_RECONCILIATION_" if GATEWAYS[name] == "reconciliation" else "AIPAY_"
    return {prefix + "UPSTREAM_GATEWAY_ADDRESS": f"127.0.0.1:{PORTS[name]}"}


def embedded_client_settings(root, peer):
    if peer == "payment":
        return {"AIPAY_PLUGIN_CREDENTIALS_FILE": root / "inputs/payment/plugins.json",
                "AIPAY_PLUGIN_EVIDENCE_DIRECTORY": root / "data/payment/evidence",
                "AIPAY_PLUGIN_TEST_ONLY_ALLOW_LOOPBACK": "true"}
    return {"AIPAY_RECONCILIATION_VERIFICATION_ALLOW_HTTP": "on",
            "AIPAY_RECONCILIATION_VERIFICATION_ALLOW_LOOPBACK": "on",
            "AIPAY_RECONCILIATION_SECRET_SEALER": "local",
            "AIPAY_RECONCILIATION_SECRET_KEY_FILE": root / "inputs/reconciliation/sealer.key"}


def switch_gateway_clients(root, plaintext):
    trade = root / "handoff/trade.json"
    if not trade.is_file():
        raise ValueError("UG-4 requires fresh prepare with gateway identities and databases (see dev/README.md)")
    plugins = root / "inputs/payment/plugins.json"
    if plaintext:
        # Retain the two embedded-mode keys across transport switches.
        evidence = root / "handoff/plaintext-evidence.key"
        sealer = root / "inputs/reconciliation/sealer.key"
        for key in (evidence, sealer):
            if not key.exists():
                write(key, secrets.token_bytes(32))
        shared = json.loads(trade.read_bytes())["shared"]
        dump(plugins, {"credentials": {"sim-md5-v1": {"secrets": {"shared": b64(shared.encode())}}},
                       "evidence_key": b64(evidence.read_bytes())})
    for name, peer in GATEWAYS.items():
        env = root / "env" / (peer + ".env")
        values = read_env(env)
        gateway, embedded = gateway_client_settings(name), embedded_client_settings(root, peer)
        remove, add = (gateway, embedded) if plaintext else (embedded, gateway)
        prefix = "AIPAY_" if peer == "payment" else "AIPAY_RECONCILIATION_"
        if plaintext:
            for suffix in ("UPSTREAM_GATEWAY_CALL_TIMEOUT", "UPSTREAM_GATEWAY_SERVER_NAME"):
                values.pop(prefix + suffix, None)
        else:
            suffixes = ("PLUGIN_EGRESS_PROXY", "PLUGIN_TEST_ONLY_ALLOW_PRIVATE", "PLUGIN_REQUEST_TIMEOUT") if peer == "payment" else (
                "VERIFICATION_PROXY", "VERIFICATION_TIMEOUT", "VERIFICATION_TEST_ONLY_ALLOW_PRIVATE")
            for suffix in suffixes:
                values.pop(prefix + suffix, None)
        for k in remove:
            values.pop(k, None)
        save_env(env, values | add)
    table = root / "inputs/iam/routes.json"
    current = json.loads(table.read_bytes())
    rules = [rule for rule in current if rule != TRADE_CREDENTIALS_ROUTE]
    dump(table, rules if plaintext else rules + [TRADE_CREDENTIALS_ROUTE])
    if not plaintext:
        plugins.unlink(missing_ok=True)


def native_deposit_inputs(root, admin, passwords):
    for name in DEPOSIT_SERVICES:
        (root / "logs" / name).mkdir(mode=0o700, exist_ok=True)
    password = passwords.setdefault("COLLECTION_DEV_DB_PASSWORD", secrets.token_hex(24))
    cert = root / "certs/collection"
    save_env(root / "env/devcollection.env", {
        "AIPAY_ENVIRONMENT": "development", "AIPAY_LOG_OUTPUT": "file", "AIPAY_DEVCOLLECTION_CHAIN_ID": "31337",
        "AIPAY_DATABASE_URL": database_url(admin, "collection_dev", password, "collection_dev", prefix=""),
        "AIPAY_GRPC_ADDR": f"127.0.0.1:{PORTS['devcollection']}", "AIPAY_GRPC_SERVER_NAME": "collection",
        "AIPAY_RPC_ALLOWED_PEERS": "ledger,reconciliation", "AIPAY_TLS_TRUST_DOMAIN": "aipay.test",
        "AIPAY_TLS_CA_FILE": root / "certs/ca.crt", "AIPAY_TLS_CERT_FILE": cert / "tls.crt",
        "AIPAY_TLS_KEY_FILE": cert / "tls.key", "AIPAY_SIGNING_BACKEND": "file",
        "AIPAY_SIGNING_KEY_ID": "collection-dev", "AIPAY_SIGNING_KEY_FILE": cert / "signing.pem",
        "AIPAY_DEVCOLLECTION_JWKS_FILE": root / "certs/public/collection.jwks",
    })
    save_env(root / "env/devchain.env", {"AIPAY_ENVIRONMENT": "development", "AIPAY_LOG_OUTPUT": "file",
             "AIPAY_DEVCHAIN_DATASET": root / "deposits/chain.json"})


def deposit_settings(root, name):
    marker = root / "deposits.enabled"
    if not marker.is_file():
        return {}
    if name == "ledger":
        delayed = {"AIPAY_LEDGER_COLLECTION_ADDR": "127.0.0.1:1"} if (root / "deposits.delay-collection").exists() else {}
        if (root / "deposits.delay-matches").exists():
            delayed["AIPAY_LEDGER_RECONCILIATION_ADDR"] = "127.0.0.1:1"
        return delayed | {"AIPAY_LEDGER_DEPOSITS": "on", "AIPAY_LEDGER_DEPOSIT_POLL_INTERVAL": "1s",
                "AIPAY_LEDGER_DEPOSIT_BATCH": "100"}
    if name == "reconciliation":
        return read_env(root / "deposits/reconciliation.env") | {"AIPAY_RECON_DEPOSITS": "on"}
    if name == "devchain":
        return {"AIPAY_DEVCHAIN_FINALIZED": marker.read_text().strip()}
    return {}


def address(peer, compose):
    if not compose:
        return f"127.0.0.1:{PORTS[peer]}"
    host = "upstream-sim" if peer in ("payment", "reconciliation") else peer
    return f"{host}:{PORTS[peer]}"


def ensure_report_key(root, key=None):
    key = key or root / "inputs/ledger/report.pem"
    public = root / "handoff/ledger-report-public.pem"
    if key.is_symlink() or public.is_symlink():
        raise ValueError("ledger report material must be a regular file")
    if key.exists():
        if not key.is_file() or (key.stat().st_mode & 0o777) != 0o600:
            raise ValueError("invalid ledger report key permissions")
        pem = key.read_bytes()
    else:
        if public.exists():
            raise ValueError("ledger report private key missing for published public key")
        pem = subprocess.check_output(["openssl", "genpkey", "-algorithm", "EC", "-pkeyopt",
                                       "ec_paramgen_curve:P-256"], stderr=subprocess.DEVNULL)
    spki = subprocess.check_output(["openssl", "pkey", "-pubout", "-passin", "pass:"], input=pem,
                                   stderr=subprocess.DEVNULL)
    der = base64.b64decode(b"".join(spki.splitlines()[1:-1]), validate=True)
    if (pem.count(b"-----BEGIN ") != 1 or not pem.startswith(b"-----BEGIN PRIVATE KEY-----") or
            not pem.rstrip().endswith(b"-----END PRIVATE KEY-----") or len(der) != 91 or
            not der.startswith(bytes.fromhex("3059301306072a8648ce3d020106082a8648ce3d03010703420004"))):
        raise ValueError("ledger report key must be a P-256 PKCS#8 key")
    if public.exists() and public.read_bytes() != spki:
        raise ValueError("ledger report public key mismatch")
    if not key.exists():
        write(key, pem)
    if not public.exists():
        write(public, spki)


def demo_settings(root, svc, compose):
    public = Path("/run/kaivo/public") if compose else root / "certs/public"
    if svc == "reconciliation":
        return {"AIPAY_RECONCILIATION_REFUND_OBJECTION_WINDOW_MIN": "10s"}
    if svc == "payment":
        return {"AIPAY_PAYMENT_REFUND_OBJECTION_WINDOW": "10s", "AIPAY_PAYMENT_REFUND_NOTICES_ENABLED": "true",
                "AIPAY_PAYMENT_EVENTS": "on", "AIPAY_LEDGER_RPC_ADDRESS": address("ledger", compose),
                "AIPAY_LEDGER_RPC_SERVER_NAME": "ledger",
                "AIPAY_LEDGER_EVENT_KEYS_FILE": str(public / "ledger.jwks")}
    if svc == "backend":
        return {"AIPAY_ACCOUNT_NOTICES_ENABLED": "true", "AIPAY_ACCOUNT_NOTICES_GRPC_ADDR": address("payment", compose),
                "AIPAY_ACCOUNT_NOTICES_SERVER_NAME": "payment", "AIPAY_PAYMENT_EVENT_KEYS_FILE": str(public / "payment.jwks"),
                "AIPAY_ACCOUNT_NOTICES_PULL_INTERVAL": "1s"}
    if svc == "ledger":
        inputs = Path("/run/kaivo/inputs") if compose else root / "inputs/ledger"
        return {"AIPAY_LEDGER_REPORT_KEY_ID": "ledger-report-dev", "AIPAY_LEDGER_REPORT_KEY_FILE": str(inputs / "report.pem"),
                "AIPAY_LEDGER_JOBS": "on", "AIPAY_LEDGER_JOB_INTERVAL": "2s"}
    return {}


def upgrade_demo(root, compose=False):
    def inputs(svc):
        return Path("/run/kaivo/inputs") if compose else root / "inputs" / svc

    public = Path("/run/kaivo/public") if compose else root / "certs/public"
    ledger = read_env(root / "env/ledger.env")
    configured_key = ledger.get("AIPAY_LEDGER_REPORT_KEY_FILE")
    if configured_key:
        path = Path(configured_key)
        if compose:
            path = root / "inputs/ledger" / path.relative_to(inputs("ledger"))
        if not path.is_absolute() or (not path.exists() and path.parent != root / "inputs/ledger"):
            raise ValueError("configured ledger report key must exist or use the ledger private input directory")
        ensure_report_key(root, path)
    else:
        ensure_report_key(root)
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
        "backend": {"AIPAY_RECONCILIATION_GRPC_ADDR": address("reconciliation", compose),
                    "AIPAY_HTTP_MAX_BODY_BYTES": "23068672", "AIPAY_TELEGRAM_KEY_MESSAGE_TTL": "10s",
                    "AIPAY_TELEGRAM_MONITOR_INTERVAL": "2s"},
        "ledger": {"AIPAY_LEDGER_PAYMENT_EVENTS": "on", "AIPAY_LEDGER_PAYMENT_ADDR": address("payment", compose),
                   "AIPAY_LEDGER_DEV_USD_RATES_FILE": str(inputs("ledger") / "usd-rates.json"),
                   "AIPAY_LEDGER_PAYMENT_SERVER_NAME": "payment",
                   "AIPAY_LEDGER_PAYMENT_JWKS_FILE": str(public / "payment.jwks")},
        "reconciliation": {},
        "payment": {"AIPAY_PAYMENT_DEV_SELLER_REVIEWS_FILE": str(inputs("payment") / "seller-reviews.json")},
    }
    for svc, additions in changes.items():
        path = root / "env" / (svc + ".env")
        values = read_env(path)
        if svc == "payment" and values.get("AIPAY_PAYMENT_DEV_SELLER_REVIEWS_FILE"):
            del additions["AIPAY_PAYMENT_DEV_SELLER_REVIEWS_FILE"]
        settings = demo_settings(root, svc, compose)
        if svc == "ledger":
            for name in ("AIPAY_LEDGER_REPORT_KEY_ID", "AIPAY_LEDGER_REPORT_KEY_FILE"):
                if values.get(name):
                    settings[name] = values[name]
        save_env(path, values | additions | settings)
    path = root / "env/notifier.env"
    values = read_env(path)
    if values.get("AIPAY_NOTIFIER_ALLOWED_HOSTS") == "127.0.0.1":
        save_env(path, values | {"AIPAY_NOTIFIER_ALLOWED_HOSTS": "localhost"})


def prepare(root, admin, cache, queue, compose=False):
    """Callers supply only the fixed stack directory, and set umask 077."""
    root.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    root.mkdir(mode=0o700)  # Exclusive and outside all repositories.
    try:
        listen = "0.0.0.0" if compose else "127.0.0.1"
        generate_inputs(root, listen + ":9080")
        ensure_report_key(root)
        passwords = {"STACK_ID": "kaivo-development-" + str(uuid.uuid4())}
        if not queue:
            queue_pass = secrets.token_hex(32)
            queue = f"redis://:{queue_pass}@127.0.0.1:6389"
            qdir = root / "data/queue-redis"
            qdir.mkdir()
            (root / "logs/queue-redis").mkdir()
            if any(c in str(qdir) for c in '"\\\r\n'):
                raise ValueError("unsupported Redis data directory name")
            write(qdir / "redis.conf", f'bind 127.0.0.1\nport 6389\ndir "{qdir}"\nrequirepass {queue_pass}\n'
                  'appendonly yes\nappendfsync everysec\nmaxmemory-policy noeviction\ndaemonize no\n')
        cp, qp = [url_parts(url, ("redis", "rediss")) for url in (cache, queue)]
        if (cp.hostname, cp.port or 6379) == (qp.hostname, qp.port or 6379):
            raise ValueError("cache and queue Redis require separate instances")
        for svc in OWNERS:
            passwords[svc.upper() + "_DB_PASSWORD"] = secrets.token_hex(24)
            if svc in APP_ROLES:
                passwords[svc.upper() + "_APP_PASSWORD"] = secrets.token_hex(24)
        gateway_inputs(root, admin, passwords, compose)
        if not compose:
            native_deposit_inputs(root, admin, passwords)
        save_env(root / "env/provision.env", passwords)
        for svc in SERVICES:
            # Containers mount only their own materials and the public registry.
            base = Path("/run/kaivo") if compose else root
            inputs = base / "inputs" if compose else base / "inputs" / svc
            cert = base / "identity" if compose else base / "certs" / svc
            ca = base / "ca.crt" if compose else base / "certs/ca.crt"
            public = base / "public" if compose else base / "certs/public"
            data = base / "data" if compose else base / "data" / svc
            log = "/app/logs" if compose else str(root / "logs" / svc)
            values = {"ENVIRONMENT": "development", "LOG_DIR": log}
            if compose:
                values.update(TRACE_ENDPOINT="http://collector:4317", TRACE_ALLOW_INSECURE="true", TRACE_ENVIRONMENT="local")
            if svc in OWNERS:
                pw = passwords[svc.upper() + "_DB_PASSWORD"]
                dsn = database_url(admin, svc, pw, svc)
                save_env(root / "env" / (svc + "-migrate.env"), {"AIPAY_DATABASE_URL": dsn})
                if svc == "iam":
                    seller_ceremony_env(root, dsn)
                if svc in APP_ROLES:
                    dsn = database_url(admin, svc + "_app", passwords[svc.upper() + "_APP_PASSWORD"], svc)
                values.update(DATABASE_URL=dsn, REDIS_URL=redis_db(cache, CACHE_DB[svc]),
                              TLS_CA_FILE=ca, TLS_CERT_FILE=cert / "tls.crt", TLS_KEY_FILE=cert / "tls.key",
                              TLS_TRUST_DOMAIN="aipay.test")
            if svc in PEERS:
                values.update(GRPC_ADDR=f"{listen}:{PORTS[svc]}", GRPC_SERVER_NAME=svc,
                              RPC_ALLOWED_PEERS=f"{svc},probe," + PEERS[svc], IAM_ASSERTION_KEYS_FILE=public / "iam.jwks",
                              SIGNING_BACKEND="file", SIGNING_KEY_ID=svc + "-dev", SIGNING_KEY_FILE=cert / "signing.pem")
            if svc in ("iam", "payment"):
                values.update(QUEUE_REDIS_URL=redis_db(queue, CACHE_DB[svc]), QUEUE_NAME="aipay." + svc)
            if svc == "iam":
                values.update(IAM_DATA_BACKEND="development", IAM_DATA_KEY=b64(secrets.token_bytes(32)),
                              IAM_EMAIL_DIRECTORY=data / "mail", IAM_ROUTES_FILE=inputs / "routes.json",
                              IAM_EPAY_SIGNER="local", IAM_EPAY_SIGNER_FILE=inputs / "epay.der", IAM_EPAY_SIGNER_KEY_ID="epay-dev",
                              IAM_EPAY_SIGNER_VALID_FROM=stamp(datetime.now(timezone.utc)), IAM_EPAY_SEALER="local",
                              IAM_EPAY_SEALER_FILE=inputs / "sealer.key", IAM_WEBAUTHN_RP_ID=RP, IAM_WEBAUTHN_ORIGINS=ORIGIN)
            elif svc == "ledger":
                values.update(LEDGER_JOBS="on", LEDGER_CHECKPOINT_KEY_ID="ledger-dev", LEDGER_ANCHOR_DIR=data / "anchors",
                              LEDGER_DEV_USD_RATES_FILE=inputs / "usd-rates.json",
                              LEDGER_PAYMENT_EVENTS="on", LEDGER_PAYMENT_ADDR=address("payment", compose),
                              LEDGER_PAYMENT_SERVER_NAME="payment", LEDGER_PAYMENT_JWKS_FILE=public / "payment.jwks",
                              LEDGER_APPROVAL_RP_ID=RP, LEDGER_APPROVAL_ORIGINS=ORIGIN, LEDGER_DEPOSITS="off",
                              LEDGER_COLLECTION_ADDR=("collection:9106" if compose else "127.0.0.1:9106"), LEDGER_COLLECTION_SERVER_NAME="collection",
                              LEDGER_COLLECTION_JWKS_FILE=public / "collection.jwks", LEDGER_RECONCILIATION_ADDR=address("reconciliation", compose),
                              LEDGER_RECONCILIATION_SERVER_NAME="reconciliation", LEDGER_RECONCILIATION_JWKS_FILE=public / "reconciliation.jwks")
            elif svc == "payment":
                values.update(RPC_MAX_MESSAGE_BYTES="16777216", IAM_RPC_ADDRESS=address("iam", compose),
                              IAM_EVENT_KEYS_FILE=public / "iam.jwks",
                              PAYMENT_DISPATCHER_ENABLED="true", PAYMENT_WORKER_ENABLED="true",
                              PAYMENT_APPROVAL_RP_ID=RP, PAYMENT_APPROVAL_ORIGINS=ORIGIN, PAYMENT_DEV_RATE_FILE=inputs / "rate.json",
                              PAYMENT_DEV_SELLER_REVIEWS_FILE=inputs / "seller-reviews.json", PAYMENT_DEV_RATE_MAX_AGE="10m", PLUGIN_ENABLED="true",
                              PLUGIN_TEST_ONLY_ALLOW_HTTP="true",
                              PLUGIN_CALLBACK_URL=f"http://{address('backend', compose)}/callback/{{channel_code}}",
                              PAYMENT_NOTIFICATION_IAM_ADDRESS=address("iam", compose), PAYMENT_NOTIFICATION_LOCAL_RSA_FILE=inputs / "epay.der")
            elif svc == "notifier":
                values.update(NOTIFIER_GRPC_ADDR=f"{listen}:9115", NOTIFIER_PAYMENT_ADDRESS=address("payment", compose),
                              NOTIFIER_TLS_CA_FILE=ca, NOTIFIER_TLS_CERT_FILE=cert / "tls.crt", NOTIFIER_TLS_KEY_FILE=cert / "tls.key",
                              NOTIFIER_TLS_TRUST_DOMAIN="aipay.test", NOTIFIER_TEST_ONLY_ALLOW_HTTP="true",
                              NOTIFIER_TEST_ONLY_ALLOW_LOOPBACK="true",
                              NOTIFIER_EGRESS_PROXY=os.getenv("AIPAY_NOTIFIER_EGRESS_PROXY", "http://127.0.0.1:3128"),
                              NOTIFIER_ALLOWED_HOSTS=os.getenv("AIPAY_NOTIFIER_ALLOWED_HOSTS", "localhost"))
            elif svc == "reconciliation":
                values.update(RECONCILIATION_JOBS="on", RECONCILIATION_AUTHORIZATION_VALID_FOR="5m",
                              LEDGER_RPC_ADDRESS=address("ledger", compose), PAYMENT_RPC_ADDRESS=address("payment", compose),
                              PAYMENT_EVENT_KEYS_FILE=public / "payment.jwks", RECONCILIATION_MARKET="on",
                              RECONCILIATION_MARKET_DEVELOPMENT_FILE=inputs / "market.json",
                              RECONCILIATION_COVERAGE_DEVELOPMENT_FILE=inputs / "coverage.json",
                              RECONCILIATION_VERIFICATION="on", RECONCILIATION_LATE_PAYMENT_WINDOW="5s",
                              RECONCILIATION_ADMIN="on", RECONCILIATION_ADMIN_PAYMENT_ADDRESS=address("payment", compose),
                              RECONCILIATION_ADMIN_RP_ID=RP, RECONCILIATION_ADMIN_ORIGINS=ORIGIN,
                              RECONCILIATION_DISPUTE_REGISTRY="on", RECONCILIATION_WEBAUTHN_RP_ID=RP, RECONCILIATION_WEBAUTHN_ORIGINS=ORIGIN,
                              RECONCILIATION_PLUGIN_CHANNELS='{"sim_form_md5_verify":"sim_form_md5","epay_v1_verify":"epay_v1"}', RECON_DEPOSITS="off",
                              RECON_COLLECTION_ADDR="collection:9106" if compose else "127.0.0.1:9106",
                              RECON_COLLECTION_SERVER_NAME="collection", RECON_COLLECTION_JWKS_FILE=public / "collection.jwks")
            elif svc == "backend":
                values.update(HTTP_ADDR=listen + ":8080", ADMIN_HTTP_ADDR=listen + ":8081", SELLER_HTTP_ADDR=listen + ":8082",
                              IAM_GRPC_ADDR=address("iam", compose), PAYMENT_GRPC_ADDR=address("payment", compose),
                              RECONCILIATION_GRPC_ADDR=address("reconciliation", compose), HTTP_MAX_BODY_BYTES="23068672",
                              TELEGRAM_MONITOR_INTERVAL="2s", TELEGRAM_KEY_MESSAGE_TTL="10s",
                              LEDGER_GRPC_ADDR=address("ledger", compose), PLATFORM_ORIGIN=ORIGIN, SELLER_ORIGIN="https://seller.aipay.test",
                              PORTAL_COOKIE_KEY=secrets.token_urlsafe(32), EPAY_V2_LOCAL_RSA_FILE=inputs / "epay.der",
                              TOTP_ENROLLMENT_ORIGIN="https://merchant.aipay.test", TELEGRAM_ENABLED="true",
                              TELEGRAM_WEBHOOK_URL="https://merchant.aipay.test/telegram/webhook", TELEGRAM_BOT_TOKEN_FILE=inputs / "bot-token",
                              TELEGRAM_WEBHOOK_SECRET=secrets.token_urlsafe(32), TELEGRAM_API_BASE_URL="http://127.0.0.1:9081")
            env = {"AIPAY_" + k: str(v) for k, v in values.items()}
            for name, peer in GATEWAYS.items():
                if peer == svc:
                    env.update(gateway_client_settings(name))
            if svc == "upstream-sim":
                env = {"UPSTREAM_SIM_CONFIG": str(inputs / "config.json")}
            elif svc == "cashier":
                env = {"CASHIER_SIM_HOST": "upstream-sim" if compose else "127.0.0.1", "CASHIER_LISTEN_HOST": listen,
                       "CASHIER_CERT": cert / "tls.crt", "CASHIER_KEY": cert / "tls.key"}
            env["AIPAY_LOG_OUTPUT"] = "file"
            save_env(root / "env" / (svc + ".env"), env | demo_settings(root, svc, compose))
        from verify import verify
        verify(root)
        write(root / "prepared", "1\n")
    except BaseException:
        shutil.rmtree(root)
        raise
