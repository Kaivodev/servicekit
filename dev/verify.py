"""Offline checks on a prepared stack. OpenSSL output stays inside the verifier."""
import base64
import json
import re
import stat
import subprocess
import tomllib
from urllib.parse import urlsplit

from stack_config import APP_ROLES, GATEWAYS, PEERS, SERVICES, TOKEN_ISSUER, read_env


def check(ok, message):
    if not ok:
        raise ValueError(message)


def openssl(*args, data=None):
    return subprocess.run(["openssl", *args], input=data, check=True, capture_output=True).stdout


def epay_handoff(accounts):
    epay = [a for a in accounts if a["id"] == "epay-demo"]
    check(len(epay) == 1 and epay[0].get("style") == "epay-v1" and epay[0].get("pid") == 1001,
          "invalid EPay simulator account")
    key = epay[0].get("shared_secret")
    check(isinstance(key, str) and re.fullmatch(r"[A-Za-z0-9]{32}", key), "invalid EPay simulator key")
    return {"merchant_key": key}


def verify_gateway_transport(root):
    mode = "plaintext" if (root / "transport.plaintext").is_file() else "mtls"
    for name, peer in GATEWAYS.items():
        path = root / "inputs" / name / "gateway.toml"
        config = tomllib.loads(path.read_text())
        check(config.get("role") == name.removeprefix("upstream-gateway-") and config.get("allowed_peers") == [peer],
              f"{name} role or caller mismatch")
        check(config.get("transport", "mtls") == mode, f"{name} transport does not match {mode}")
        if mode == "mtls":
            tls = config.get("tls")
            check(isinstance(tls, dict) and all(tls.get(k) for k in ("trust_domain", "ca_file", "cert_file", "key_file"))
                  and "service_token" not in config, f"{name} requires mTLS authentication settings")
        else:
            token = config.get("service_token")
            check("tls" not in config and isinstance(token, dict) and token.get("issuer") == TOKEN_ISSUER and
                  "issuer_file" not in token and token.get("service_namespaces") == {peer: "local"} and
                  isinstance(token.get("jwks_file"), str) and
                  (path.parent / token["jwks_file"]).resolve() == (root / "token-issuer/jwks.json").resolve(),
                  f"{name} service token settings do not match the local issuer")


def verify(root):
    verify_gateway_transport(root)
    certs = root / "certs"
    for directory in ("env", "inputs", "handoff", "certs"):
        for path in (root / directory).rglob("*"):
            check(not path.is_symlink() and stat.S_IMODE(path.stat().st_mode) == (0o700 if path.is_dir() else 0o600),
                  "invalid permissions in prepared stack")
    for name in (*PEERS, *GATEWAYS, "backend", "notifier", "collection", "probe", "cashier"):
        cert = certs / name / "tls.crt"
        for purpose in ("sslclient", "sslserver"):
            openssl("verify", "-CAfile", certs / "ca.crt", "-purpose", purpose, "-verify_hostname", name, cert)
        san = openssl("x509", "-in", cert, "-noout", "-ext", "subjectAltName").decode().splitlines()[-1]
        uris = [v.strip() for v in san.split(",") if v.strip().startswith("URI:")]
        check(uris == ["URI:spiffe://aipay.test/service/" + name], "wrong TLS identity")
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
    payment_env = read_env(root / "env/payment.env")
    check(urlsplit(payment_env["AIPAY_PLUGIN_CALLBACK_URL"]).path == "/callback/{channel_code}"
          and payment_env["AIPAY_PLUGIN_CALLBACK_URL"].count("{channel_code}") == 1, "invalid callback template")
    channels = json.loads(read_env(root / "env/reconciliation.env")["AIPAY_RECONCILIATION_PLUGIN_CHANNELS"])
    check(all(channels.get(code + "_verify") == code for code in ("sim_form_md5", "epay_v1")),
          "missing verification plugin mapping")
    accounts = json.loads((root / "inputs/upstream-sim/config.json").read_text())["accounts"]
    sim = accounts[0]
    check(sim["id"] == "md5-demo" and sim["style"] == "form-md5", "missing primary form-md5 account")
    check(epay_handoff(accounts) == json.loads((root / "handoff/epay.json").read_bytes()),
          "EPay handoff credential mismatch")
    shared = json.loads((root / "handoff/trade.json").read_bytes())["shared"]
    readonly = json.loads((root / "handoff/query.json").read_text())["query_key"]
    check(sim["shared_secret"] == shared and
          sim["query_shared_secret"] == readonly and readonly != sim["shared_secret"], "simulator credential mismatch")
