"""Offline kubectl with a multi-word wrapper, real sockets and redaction sentinels."""
import base64
import json
import os
from pathlib import Path
import socket
import sys
import time

args = sys.argv[1:]
assert args.pop(0) == "wrapper"
root = Path(os.environ["DEMO_TEST_ROOT"])
with (root / "calls").open("a") as calls:
    print(json.dumps(args), file=calls)
if args[0] == "apply":
    assert args == ["apply", "--server-side", "--field-manager=kaivo-staging-market", "--force-conflicts", "-f", "-"]
    assert sys.stdin.buffer.read() == b"---\nmarket stream\n"
    sys.exit(int(os.getenv("FAIL_APPLY", "0")))
assert args.pop(0) == "-n"
ns, verb, *args = args
def cm_path(name):
    return root / (ns + "_" + name + ".json")


if verb == "rollout":
    assert args[0] in ("restart", "status") and args[1].startswith("deployment/")
    assert (args[2:] == ["--timeout=180s"]) == (args[0] == "status")
    if args[0] == "status" and args[1] == os.getenv("FAIL_ROLLOUT"):
        sys.exit(1)
elif verb == "port-forward":
    assert args[:2] == ["--address", "127.0.0.1"]
    if args[2] == os.getenv("FAIL_FORWARD"):
        sys.exit(1)
    listeners = []
    for mapping in args[3:]:
        local, remote = map(int, mapping.split(":"))
        sock = socket.socket()
        sock.bind(("127.0.0.1", local))
        sock.listen(8)
        listeners.append(sock)
        print(f"Forwarding from 127.0.0.1:{local} -> {remote}", flush=True)
    time.sleep(90)
elif verb == "get":
    if args[0] == "deployment":
        spec = json.loads((Path(__file__).parent / "deployment.json").read_text().replace('"iam"', json.dumps(args[1])))
        print(json.dumps(spec))
    elif args[0] == "pod":
        print(os.getenv("POD_PHASE", "Succeeded"))
    elif args[0] == "secret":
        value = os.environ["DEMO_TEST_VALUE"]
        print(json.dumps({"data": {key:base64.b64encode(value.encode()).decode() for key in ("uri","bot-token","telegram-webhook-secret")}}))
    elif args[:2] == ["configmap","backend-config"]:
        print(json.dumps({"data":{"AIPAY_TELEGRAM_WEBHOOK_URL":"https://merchant.aipay.test/telegram/webhook"}}))
    elif args[0] == "configmap" and args[1] in ("ledger-config", "payment-config", "reconciliation-config"):
        print(json.dumps({"data":{"AIPAY_ENVIRONMENT":os.getenv("TEST_STAGE_ENV", "development")}}))
    elif args[0] == "configmap" and args[1] in ("payment-inputs", "deposit-dataset", "reconciliation-deposits"):
        path = cm_path(args[1])
        if path.exists():
            print(path.read_text())
        elif "--ignore-not-found" not in args:
            sys.exit(1)
    elif args[0] == "configmap":
        print(json.dumps({"data": {key:"fresh" for key in ("rate.json","coverage.json","market.json","key")}}))
    else:
        sys.exit(2)
elif verb == "create":
    pod = json.load(sys.stdin)
    if pod["kind"] == "ConfigMap":
        path = cm_path(pod["metadata"]["name"])
        assert pod["metadata"]["namespace"] == ns and not path.exists()
        pod["metadata"]["resourceVersion"] = "1"
        path.write_text(json.dumps(pod))
        sys.exit(0)
    assert pod["kind"] == "Pod" and pod["metadata"]["namespace"] == ns
    (root / "pod").write_text(json.dumps(pod))
elif verb == "patch":
    assert args == ["configmap", args[1], "--type=merge", "--patch-file=/dev/stdin"]
    path = cm_path(args[1])
    cm = json.loads(path.read_text())
    patch = json.load(sys.stdin)
    assert set(patch) == {"metadata", "data"}
    assert patch["metadata"]["resourceVersion"] == cm["metadata"]["resourceVersion"]
    if args[1] == "payment-inputs":
        assert set(patch["data"]) == {"seller-reviews.json"}
    cm["metadata"]["resourceVersion"] = str(int(cm["metadata"]["resourceVersion"]) + 1)
    if os.getenv("REVIEW_CONFLICT") and cm["metadata"]["resourceVersion"] == "2":
        cm["data"]["seller-reviews.json"] = os.environ["REVIEW_CONFLICT"]
        path.write_text(json.dumps(cm))
        sys.exit(1)
    cm["data"].update(patch["data"])
    path.write_text(json.dumps(cm))
elif verb == "delete":
    assert args[1] == json.loads((root / "pod").read_text())["metadata"]["name"]
elif verb == "logs":
    print("private-pod-log-sentinel")
else:
    print("private-kubectl-error-sentinel", file=sys.stderr)
    sys.exit(2)
