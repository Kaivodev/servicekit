"""Shared inputs for the native and Compose development stacks."""
import base64
from datetime import datetime, timedelta, timezone
import hashlib
import json
import os
from pathlib import Path
import secrets
import shutil
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
PORTS = {"iam": 9101, "ledger": 9102, "settlement": 9103, "reconciliation": 9104, "payment": 9105,
         "notifier": 9115, "upstream-sim": 9080, "cashier": 9443, "backend": 8080}
CACHE_DB = {"backend": 0, "iam": 1, "ledger": 2, "settlement": 3, "reconciliation": 4, "payment": 5}
PEERS = {"iam": "backend,payment,settlement", "ledger": "backend,payment,reconciliation,settlement",
         "payment": "backend,ledger,reconciliation,notifier", "reconciliation": "backend,ledger,settlement",
         "settlement": "backend"}
RP = "admin.aipay.test"
ORIGIN = "https://" + RP


def write(path, data):
    """Atomic replacement, including first creation. Never follow the destination."""
    data = data.encode() if isinstance(data, str) else data
    with tempfile.NamedTemporaryFile(dir=path.parent, delete=False) as f:
        try:
            f.write(data)
            f.flush()
            os.replace(f.name, path)
        finally:
            Path(f.name).unlink(missing_ok=True)


def dump(path, value):
    write(path, json.dumps(value, separators=(",", ":")) + "\n")


def save_env(path, values):
    if any(any(c in str(v) for c in "\x00\r\n") for v in values.values()):
        raise ValueError("invalid multiline environment value")
    write(path, "".join(f"{k}={v}\n" for k, v in values.items()))


def read_env(path):
    return dict(line.split("=", 1) for line in path.read_text().splitlines() if line)


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


def database_url(admin, owner, password, db):
    u = url_parts(admin, ("postgres", "postgresql"))
    # An admin DSN's identity/target must never override the service's URI.
    if any(k not in ("sslmode", "sslrootcert", "connect_timeout", "application_name")
           for k, _ in parse_qsl(u.query, keep_blank_values=True)):
        raise ValueError("unsupported PostgreSQL URL option (see dev/README.md)")
    host = u.netloc.rsplit("@", 1)[-1]
    return urlunsplit((u.scheme, f"{owner}:{quote(password, safe='')}@{host}", "/aipay_" + db, u.query, ""))


def redis_db(raw, index):
    u = url_parts(raw, ("redis", "rediss"))
    if any(k.lower() == "db" for k, _ in parse_qsl(u.query)):
        raise ValueError("select the Redis DB by URL path")
    return urlunsplit((u.scheme, u.netloc, "/" + str(index), u.query, ""))


def stamp(time):
    return time.isoformat().replace("+00:00", "Z")


def b64(data):
    return base64.b64encode(data).decode("ascii")


def refresh(root, now=None):
    now = now or datetime.now(timezone.utc)
    end = now.replace(second=0, microsecond=0)
    minute = end - timedelta(minutes=1)
    key = "dev-" + minute.strftime("%Y%m%dT%H%MZ")
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
    dump(market_file, records)
    dump(market_file.with_name("coverage.json"), dict(covered=True, as_of=stamp(now), expires_at=stamp(now + timedelta(hours=1))))
    dump(root / "inputs/payment/rate.json", rate)


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


def generate_inputs(root, sim_listen):
    for svc in SERVICES:
        for parent in ("inputs", "logs", "data"):
            (root / parent / svc).mkdir(parents=True, mode=0o700)
    for directory in ("env", "handoff", "data/iam/mail", "data/ledger/anchors", "data/payment/evidence"):
        (root / directory).mkdir(mode=0o700)
    ids = ",".join((*PEERS, "backend", "notifier", "collection", "probe", "cashier"))
    subprocess.run(["go", "run", "-mod=readonly", "./cmd/devcert", "--services", ids,
                    "--signing-services", ",".join((*PEERS, "collection")),
                    "--out", str(root / "certs")], env=os.environ | {"GOWORK": "off"}, cwd=LIBRARY, check=True)
    inputs = root / "inputs"
    write(inputs / "iam/sealer.key", secrets.token_bytes(32))
    write(inputs / "reconciliation/sealer.key", secrets.token_bytes(32))
    # IAM, backend and payment use the same platform RSA key for EPay V2.
    rsa = subprocess.check_output(["openssl", "genpkey", "-algorithm", "RSA", "-pkeyopt", "rsa_keygen_bits:2048"],
                                  stderr=subprocess.DEVNULL)
    der = subprocess.check_output(["openssl", "pkcs8", "-topk8", "-nocrypt", "-outform", "DER"], input=rsa)
    for svc in ("iam", "backend", "payment"):
        write(inputs / svc / "epay.der", der)
    write(root / "handoff/platform-public.pem", subprocess.check_output(["openssl", "pkey", "-pubout"], input=rsa))
    payment_secret, query_secret = secrets.token_hex(32), secrets.token_hex(32)
    dump(inputs / "payment/plugins.json", {"credentials": {"sim-md5-v1": {"secrets": {"shared": b64(payment_secret.encode())}}},
                                         "evidence_key": b64(secrets.token_bytes(32))})
    dump(root / "handoff/query.json", {"query_key": query_secret})
    dump(inputs / "upstream-sim/config.json", dict(environment="test", listen=sim_listen, base_url="https://127.0.0.1:9443",
         control_token=secrets.token_urlsafe(32), accounts=[dict(id="md5-demo", style="form-md5",
         shared_secret=payment_secret, query_shared_secret=query_secret)]))
    dump(inputs / "iam/routes.json", routes())
    write(inputs / "backend/bot-token", "10001:" + secrets.token_urlsafe(32))
    refresh(root)


def prepare(root, admin, cache, queue, compose=False):
    """Callers supply only the fixed stack directory, and set umask 077."""
    root.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    root.mkdir(mode=0o700)  # Exclusive and outside all repositories.
    try:
        listen = "0.0.0.0" if compose else "127.0.0.1"
        generate_inputs(root, listen + ":9080")
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
            def address(peer):
                if not compose:
                    return f"127.0.0.1:{PORTS[peer]}"
                # The two WASM hosts share the simulator's network namespace.
                host = "upstream-sim" if peer in ("payment", "reconciliation") else peer
                return f"{host}:{PORTS[peer]}"
            values = {"ENVIRONMENT": "development", "LOG_DIR": log}
            if compose:
                values.update(TRACE_ENDPOINT="http://collector:4317", TRACE_ALLOW_INSECURE="true", TRACE_ENVIRONMENT="local")
            if svc in OWNERS:
                pw = passwords[svc.upper() + "_DB_PASSWORD"]
                dsn = database_url(admin, svc, pw, svc)
                save_env(root / "env" / (svc + "-migrate.env"), {"AIPAY_DATABASE_URL": dsn})
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
                              LEDGER_APPROVAL_RP_ID=RP, LEDGER_APPROVAL_ORIGINS=ORIGIN, LEDGER_DEPOSITS="off",
                              LEDGER_COLLECTION_ADDR=("collection:9106" if compose else "127.0.0.1:9106"), LEDGER_COLLECTION_SERVER_NAME="collection",
                              LEDGER_COLLECTION_JWKS_FILE=public / "collection.jwks", LEDGER_RECONCILIATION_ADDR=address("reconciliation"),
                              LEDGER_RECONCILIATION_SERVER_NAME="reconciliation", LEDGER_RECONCILIATION_JWKS_FILE=public / "reconciliation.jwks")
            elif svc == "payment":
                values.update(RPC_MAX_MESSAGE_BYTES="16777216", PAYMENT_EVENTS="on", IAM_RPC_ADDRESS=address("iam"),
                              IAM_EVENT_KEYS_FILE=public / "iam.jwks", LEDGER_RPC_ADDRESS=address("ledger"),
                              PAYMENT_DISPATCHER_ENABLED="true", PAYMENT_WORKER_ENABLED="true",
                              PAYMENT_APPROVAL_RP_ID=RP, PAYMENT_APPROVAL_ORIGINS=ORIGIN, PAYMENT_DEV_RATE_FILE=inputs / "rate.json",
                              PAYMENT_DEV_RATE_MAX_AGE="10m", PLUGIN_ENABLED="true", PLUGIN_CREDENTIALS_FILE=inputs / "plugins.json",
                              PLUGIN_EVIDENCE_DIRECTORY=data / "evidence", PLUGIN_TEST_ONLY_ALLOW_HTTP="true",
                              PLUGIN_TEST_ONLY_ALLOW_LOOPBACK="true", PLUGIN_CALLBACK_URL=f"http://{address('backend')}/callback/sim_form_md5",
                              PAYMENT_NOTIFICATION_IAM_ADDRESS=address("iam"), PAYMENT_NOTIFICATION_LOCAL_RSA_FILE=inputs / "epay.der")
            elif svc == "notifier":
                values.update(NOTIFIER_GRPC_ADDR=f"{listen}:9115", NOTIFIER_PAYMENT_ADDRESS=address("payment"),
                              NOTIFIER_TLS_CA_FILE=ca, NOTIFIER_TLS_CERT_FILE=cert / "tls.crt", NOTIFIER_TLS_KEY_FILE=cert / "tls.key",
                              NOTIFIER_TLS_TRUST_DOMAIN="aipay.test", NOTIFIER_TEST_ONLY_ALLOW_HTTP="true",
                              NOTIFIER_TEST_ONLY_ALLOW_LOOPBACK="true",
                              NOTIFIER_EGRESS_PROXY=os.getenv("AIPAY_NOTIFIER_EGRESS_PROXY", "http://127.0.0.1:3128"),
                              NOTIFIER_ALLOWED_HOSTS=os.getenv("AIPAY_NOTIFIER_ALLOWED_HOSTS", "127.0.0.1"))
            elif svc == "reconciliation":
                values.update(RECONCILIATION_JOBS="on", RECONCILIATION_AUTHORIZATION_VALID_FOR="5m",
                              LEDGER_RPC_ADDRESS=address("ledger"), PAYMENT_RPC_ADDRESS=address("payment"),
                              PAYMENT_EVENT_KEYS_FILE=public / "payment.jwks", RECONCILIATION_MARKET="on",
                              RECONCILIATION_MARKET_DEVELOPMENT_FILE=inputs / "market.json",
                              RECONCILIATION_COVERAGE_DEVELOPMENT_FILE=inputs / "coverage.json",
                              RECONCILIATION_VERIFICATION="on", RECONCILIATION_VERIFICATION_ALLOW_HTTP="on",
                              RECONCILIATION_VERIFICATION_ALLOW_LOOPBACK="on", RECONCILIATION_LATE_PAYMENT_WINDOW="5s",
                              RECONCILIATION_SECRET_SEALER="local", RECONCILIATION_SECRET_KEY_FILE=inputs / "sealer.key",
                              RECONCILIATION_ADMIN="on", RECONCILIATION_ADMIN_PAYMENT_ADDRESS=address("payment"),
                              RECONCILIATION_ADMIN_RP_ID=RP, RECONCILIATION_ADMIN_ORIGINS=ORIGIN,
                              RECONCILIATION_DISPUTE_REGISTRY="on", RECONCILIATION_WEBAUTHN_RP_ID=RP, RECONCILIATION_WEBAUTHN_ORIGINS=ORIGIN,
                              RECONCILIATION_PLUGIN_CHANNELS='{"sim_form_md5_verify":"sim_form_md5"}', RECON_DEPOSITS="off",
                              RECON_COLLECTION_ADDR="collection:9106" if compose else "127.0.0.1:9106",
                              RECON_COLLECTION_SERVER_NAME="collection", RECON_COLLECTION_JWKS_FILE=public / "collection.jwks")
            elif svc == "backend":
                values.update(HTTP_ADDR=listen + ":8080", ADMIN_HTTP_ADDR=listen + ":8081", SELLER_HTTP_ADDR=listen + ":8082",
                              IAM_GRPC_ADDR=address("iam"), PAYMENT_GRPC_ADDR=address("payment"),
                              LEDGER_GRPC_ADDR=address("ledger"), PLATFORM_ORIGIN=ORIGIN, SELLER_ORIGIN="https://seller.aipay.test",
                              PORTAL_COOKIE_KEY=secrets.token_urlsafe(32), EPAY_V2_LOCAL_RSA_FILE=inputs / "epay.der",
                              TOTP_ENROLLMENT_ORIGIN="https://merchant.aipay.test", TELEGRAM_ENABLED="true",
                              TELEGRAM_WEBHOOK_URL="https://merchant.aipay.test/telegram/webhook", TELEGRAM_BOT_TOKEN_FILE=inputs / "bot-token",
                              TELEGRAM_WEBHOOK_SECRET=secrets.token_urlsafe(32), TELEGRAM_API_BASE_URL="http://127.0.0.1:9081")
            env = {"AIPAY_" + k: str(v) for k, v in values.items()}
            if svc == "upstream-sim":
                env = {"UPSTREAM_SIM_CONFIG": str(inputs / "config.json")}
            elif svc == "cashier":
                env = {"CASHIER_SIM_HOST": "upstream-sim" if compose else "127.0.0.1", "CASHIER_LISTEN_HOST": listen,
                       "CASHIER_CERT": cert / "tls.crt", "CASHIER_KEY": cert / "tls.key"}
            save_env(root / "env" / (svc + ".env"), env)
        from verify import verify
        verify(root)
        write(root / "prepared", "1\n")
    except BaseException:
        shutil.rmtree(root)
        raise
