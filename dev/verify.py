"""Offline checks on a prepared stack. OpenSSL output stays inside the verifier."""
import base64
import json
import stat
import subprocess

from stack_config import APP_ROLES, PEERS, SERVICES, read_env


def check(ok, message):
    if not ok:
        raise ValueError(message)


def openssl(*args, data=None):
    return subprocess.run(["openssl", *args], input=data, check=True, capture_output=True).stdout


def verify(root):
    certs = root / "certs"
    for directory in ("env", "inputs", "handoff", "certs"):
        for path in (root / directory).rglob("*"):
            check(not path.is_symlink() and stat.S_IMODE(path.stat().st_mode) == (0o700 if path.is_dir() else 0o600),
                  "invalid permissions in prepared stack")
    for name in (*PEERS, "backend", "notifier", "collection", "probe", "cashier"):
        cert = certs / name / "tls.crt"
        for purpose in ("sslclient", "sslserver"):
            openssl("verify", "-CAfile", certs / "ca.crt", "-purpose", purpose, "-verify_hostname", name, cert)
        san = openssl("x509", "-in", cert, "-noout", "-ext", "subjectAltName").decode().splitlines()[-1]
        check("URI:spiffe://aipay.test/service/" + name in [v.strip() for v in san.split(",")], "wrong TLS identity")
        check(openssl("pkey", "-in", certs / name / "tls.key", "-pubout") ==
              openssl("x509", "-in", cert, "-pubkey", "-noout"), "TLS key mismatch")
    for name in (*PEERS, "collection"):
        jwk, = json.loads((certs / "public" / (name + ".jwks")).read_text())["keys"]
        check((jwk["kid"], jwk["kty"], jwk["crv"]) == (name + "-dev", "EC", "P-256") and "d" not in jwk,
              "invalid public signing registry")
        xy = b"".join(base64.urlsafe_b64decode(jwk[k] + "=") for k in ("x", "y"))
        # RFC 5480 P-256 SPKI, uncompressed SEC1 point, followed by fixed-width X and Y.
        spki = bytes.fromhex("3059301306072a8648ce3d020106082a8648ce3d03010703420004") + xy
        check(openssl("pkey", "-in", certs / name / "signing.pem", "-pubout", "-outform", "DER") == spki,
              "public signing registry does not match private key")
    for name in ("iam", "backend", "payment"):
        check(openssl("pkey", "-inform", "DER", "-in", root / "inputs" / name / "epay.der", "-pubout") ==
              (root / "handoff/platform-public.pem").read_bytes(), "EPay signer mismatch")
    for name in SERVICES:
        env = read_env(root / "env" / (name + ".env"))
        if name in APP_ROLES:
            check(name + "_app:" in env["AIPAY_DATABASE_URL"], "runtime role mismatch")
        if name == "notifier":
            check(not any(k.startswith(("AIPAY_DATABASE", "AIPAY_QUEUE", "AIPAY_SIGNING", "AIPAY_PLUGIN"))
                          for k in env), "unexpected notifier credentials")
    sim = json.loads((root / "inputs/upstream-sim/config.json").read_text())["accounts"][0]
    payment = json.loads((root / "inputs/payment/plugins.json").read_text())["credentials"]["sim-md5-v1"]
    readonly = json.loads((root / "handoff/query.json").read_text())["query_key"]
    check(sim["shared_secret"] == base64.b64decode(payment["secrets"]["shared"]).decode() and
          sim["query_shared_secret"] == readonly and readonly != sim["shared_secret"], "simulator credential mismatch")
