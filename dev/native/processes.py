"""A private control socket per service. Only the parent signals its own child."""
import http.client
import json
import os
from pathlib import Path
import shutil
import signal
import socket
import ssl
import subprocess
import sys
import time

import telemetry

from stack_config import DEPOSIT_SERVICES, LIBRARY, PORTS, SERVICES, deposit_settings, read_env, write


def service_env(root, name):
    # In particular do not inherit admin DSNs, module tokens or another service's keys.
    env = {k: os.environ[k] for k in ("PATH", "LANG", "TZ", "TMPDIR") if k in os.environ}
    if name not in ("queue-redis", *telemetry.PROCESSES):
        owner = "ledger" if name == "ledger-reader" else name
        env.update(read_env(root / "env" / (owner + ".env")))
        env.update(deposit_settings(root, owner))
        env["AIPAY_LOG_OUTPUT"] = "stdout" if (root / "logs.stdout").exists() else "file"
        if name != "cashier":
            env.update(telemetry.environment(root))
    if name == "ledger-reader":
        env.update(AIPAY_GRPC_ADDR="127.0.0.1:9122", AIPAY_LEDGER_JOBS="off",
                   AIPAY_LEDGER_PAYMENT_EVENTS="off", AIPAY_LOG_DIR=str(root / "logs/ledger-reader"))
    if name == "devcollection":
        env["AIPAY_DEVCOLLECTION_OVERLAP_FILE"] = str(root / "demo/overlap.json")
    return env


def services(root):
    deposits = DEPOSIT_SERVICES if (root / "deposits.enabled").is_file() else ()
    managed = telemetry.PROCESSES if telemetry.state(root)["mode"] == "local" else ()
    return managed + (("queue-redis",) if (root / "data/queue-redis/redis.conf").exists() else ()) + deposits + SERVICES


def command(root, name):
    if name in telemetry.PROCESSES:
        return telemetry.command(root, name)
    if name == "cashier":
        return [sys.executable, "-B", str(LIBRARY / "dev/cashier.py")]
    if name == "queue-redis":
        return ["redis-server", str(root / "data/queue-redis/redis.conf")]
    if name in DEPOSIT_SERVICES:
        return [str(root / "bin" / ("kaivo-" + name)), "serve"]
    binary = root / "bin" / {"notifier": "payment", "ledger-reader": "ledger"}.get(name, name)
    args = {"notifier": ["notifier"], "upstream-sim": []}.get(name, ["serve"])
    return [str(binary), *args]


def health(root, name):
    env = service_env(root, name)
    try:
        if name == "otelcol":
            with socket.create_connection(("127.0.0.1", 4317), timeout=3):
                return True
        if name == "prometheus":
            conn = http.client.HTTPConnection("127.0.0.1", 9090, timeout=3)
            try:
                conn.request("GET", "/-/ready")
                return conn.getresponse().status == 200
            finally:
                conn.close()
        if name == "devchain":
            conn = http.client.HTTPConnection("127.0.0.1", PORTS[name], timeout=3)
            try:
                conn.request("POST", "/", '{"jsonrpc":"2.0","id":1,"method":"eth_chainId","params":[]}')
                response = conn.getresponse()
                return response.status == 200 and json.load(response).get("result") == "0x7a69"
            finally:
                conn.close()
        if name == "devcollection":
            # The controller owns the probe. The server never receives ledger keys.
            env = {k: v for k, v in env.items() if k.startswith(("AIPAY_GRPC_", "AIPAY_TLS_")) or
                   k in ("AIPAY_ENVIRONMENT", "AIPAY_DEVCOLLECTION_CHAIN_ID")}
            env.update(AIPAY_TLS_CERT_FILE=str(root / "certs/ledger/tls.crt"),
                       AIPAY_TLS_KEY_FILE=str(root / "certs/ledger/tls.key"))
        if name == "cashier":
            tls = ssl.create_default_context(cafile=str(root / "certs/ca.crt"))
            conn = http.client.HTTPSConnection("127.0.0.1", PORTS[name], context=tls, timeout=3)
        elif name in ("backend", "upstream-sim"):
            conn = http.client.HTTPConnection("127.0.0.1", PORTS[name], timeout=3)
        if name in ("backend", "upstream-sim", "cashier"):
            try:
                conn.request("GET", "/health/ready" if name == "backend" else "/healthz")
                return conn.getresponse().status == 200
            finally:
                conn.close()
        if name == "queue-redis":
            from urllib.parse import urlsplit
            password = urlsplit(read_env(root / "env/iam.env")["AIPAY_QUEUE_REDIS_URL"]).password
            result = subprocess.run(["redis-cli", "-h", "127.0.0.1", "-p", "6389", "PING"], timeout=3,
                                    env=env | {"REDISCLI_AUTH": password}, capture_output=True)
            return result.returncode == 0 and result.stdout.strip() == b"PONG"
        probe = command(root, name)[:1] + (["notifier"] if name == "notifier" else []) + ["healthcheck"]
        return subprocess.run(probe, env=env, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                              stderr=subprocess.DEVNULL, timeout=6).returncode == 0
    except (OSError, ValueError, subprocess.TimeoutExpired, http.client.HTTPException):
        return False


def request(name, action):
    # Controller and supervisors use the private run/ as cwd (short AF_UNIX paths on macOS).
    with socket.socket(socket.AF_UNIX) as client:
        client.settimeout(30)
        try:
            client.connect(name + ".sock")
        except (FileNotFoundError, ConnectionRefusedError):
            return None
        client.sendall(action.encode() + b"\n")
        with client.makefile("rb") as reply:
            return reply.readline(64).strip().decode()


def shutdown(child):
    if child.poll() is None:
        child.terminate()
        try:
            child.wait(timeout=20)
        except subprocess.TimeoutExpired:
            child.kill()
            child.wait()


def supervise(root, name):
    endpoint = Path(name + ".sock")
    pidfile = Path(name + ".pid")
    # up/down hold the controller lock. A live socket is never unlinked by up.
    stopping = False

    def stop_signal(_sig, _frame):
        nonlocal stopping
        stopping = True

    signal.signal(signal.SIGTERM, stop_signal)
    signal.signal(signal.SIGINT, stop_signal)
    with socket.socket(socket.AF_UNIX) as server:
        server.bind(str(endpoint))
        try:
            server.listen(4)
            server.settimeout(0.25)
            child = subprocess.Popen(command(root, name), cwd=root, env=service_env(root, name))
            try:
                write(pidfile, str(child.pid) + "\n")
                while not stopping and child.poll() is None:
                    try:
                        client, _ = server.accept()
                    except socket.timeout:
                        continue
                    with client:
                        client.settimeout(2)
                        try:
                            with client.makefile("rb") as query:
                                action = query.readline(16)
                            if action == b"stop\n":
                                shutdown(child)
                                stopping = True
                                client.sendall(b"stopped\n")
                            elif action == b"pid\n":
                                client.sendall(f"{child.pid}\n".encode())
                        except (OSError, TimeoutError):
                            pass
            finally:
                shutdown(child)
        finally:
            pidfile.unlink(missing_ok=True)
            endpoint.unlink(missing_ok=True)


def start(root, name):
    if request(name, "pid"):
        if health(root, name):
            return False
        raise RuntimeError(f"{name} is running but unready; inspect its logs")
    ports = [9122 if name == "ledger-reader" else PORTS.get(name, 6389)] + ([8081, 8082] if name == "backend" else [])
    for port in ports:
        with socket.socket() as probe:
            probe.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            try:
                probe.bind(("127.0.0.1", port))
            except OSError as exc:
                raise RuntimeError(f"{name}: listener {port} unavailable") from exc
    if name == "queue-redis" and not all(shutil.which(p) for p in ("redis-server", "redis-cli")):
        raise RuntimeError("managed queue requires redis-server and redis-cli")
    Path(name + ".sock").unlink(missing_ok=True)
    # The supervisor receives only its service's settings and reads no PID to send a signal.
    with (root / "logs" / name / "process.log").open("ab") as log:
        worker = subprocess.Popen([sys.executable, "-B", str(Path(__file__).with_name("stack.py")), "_run", name],
                                  cwd=root / "run", stdin=subprocess.DEVNULL, stdout=log, stderr=log, start_new_session=True,
                                  env={k: os.environ[k] for k in ("PATH", "LANG", "TZ", "TMPDIR") if k in os.environ})
    try:
        until = time.monotonic() + 60
        while worker.poll() is None and time.monotonic() < until:
            if request(name, "pid") and health(root, name) and worker.poll() is None:
                print(f"{name} ready", flush=True)
                return worker
            time.sleep(0.25)
        raise RuntimeError(f"{name} failed readiness; inspect logs/{name}/")
    except BaseException:
        shutdown(worker)
        raise


def stop(name):
    reply = request(name, "stop")
    if reply is not None and reply != "stopped":
        raise RuntimeError(f"{name}: could not confirm stop")
    # The parent removes the socket after replying, before a subsequent start.
    if reply:
        deadline = time.monotonic() + 3
        while Path(name + ".sock").exists() and time.monotonic() < deadline:
            time.sleep(0.02)
        if Path(name + ".sock").exists():
            raise RuntimeError(f"{name}: supervisor has not exited")
