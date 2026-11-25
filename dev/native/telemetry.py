"""Optional metrics pipeline managed by the native process stack."""
import ipaddress
import json
import os
from pathlib import Path
import re
import shutil
from urllib.parse import urlsplit

from stack_config import dump, write

PROCESSES = ("otelcol", "prometheus")
LOCAL_ENDPOINT = "http://127.0.0.1:4317"

COLLECTOR = """receivers:
  otlp:
    protocols:
      grpc:
        endpoint: 127.0.0.1:4317
processors:
  memory_limiter:
    check_interval: 1s
    limit_mib: 128
    spike_limit_mib: 32
  batch: {}
exporters:
  otlphttp:
    metrics_endpoint: http://127.0.0.1:9090/api/v1/otlp/v1/metrics
service:
  telemetry:
    metrics:
      level: none
  pipelines:
    metrics:
      receivers: [otlp]
      processors: [memory_limiter, batch]
      exporters: [otlphttp]
"""
PROMETHEUS = """otlp:
  promote_resource_attributes: [deployment.environment.name, kaivo.domain]
scrape_configs: []
"""


def endpoint_parts(value):
    # urlsplit accepts whitespace, unbracketed junk after IPv6 and empty query
    # delimiters. Only accept an authority explicitly ending in a TCP port.
    match = re.fullmatch(r"https?://(\[[0-9a-fA-F:.]+\]|[a-zA-Z0-9.-]+):[0-9]+", value)
    try:
        if match:
            parsed = urlsplit(value)
            host = parsed.hostname
            if host and parsed.port and (match[1].startswith("[") or
                    all(re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", label)
                        for label in host.removesuffix(".").split("."))):
                return parsed
    except ValueError:
        pass
    raise ValueError("metrics endpoint requires http(s)://host:port")


def binary(variable, candidates):
    override = os.getenv(variable)
    for name in ([override] if override else candidates):
        path = shutil.which(name)
        if path:
            return str(Path(path).resolve())
    raise ValueError(f"install {' or '.join(candidates)} or set {variable} to its executable")


def state(root):
    path = root / "telemetry.json"
    return json.loads(path.read_text()) if path.exists() else {"mode": "off"}


def configure(root, mode, endpoint=None):
    config = {"mode": mode}
    if mode == "on":
        if endpoint is not None:
            endpoint_parts(endpoint)
            config = {"mode": "external", "endpoint": endpoint}
        else:
            config = {"mode": "local", "endpoint": LOCAL_ENDPOINT,
                      "otelcol": binary("AIPAY_DEV_OTELCOL_BIN", ("otelcol-contrib", "otelcol")),
                      "prometheus": binary("AIPAY_DEV_PROMETHEUS_BIN", ("prometheus",))}
            directory = root / "telemetry"
            for path in (directory, root / "data/prometheus", *(root / "logs" / p for p in PROCESSES)):
                path.mkdir(mode=0o700, parents=True, exist_ok=True)
            write(directory / "collector.yaml", COLLECTOR)
            write(directory / "prometheus.yaml", PROMETHEUS)
    dump(root / "telemetry.json", config)


def environment(root):
    config = state(root)
    if config["mode"] == "off":
        return {}
    values = {"AIPAY_METRICS_ENDPOINT": config["endpoint"], "AIPAY_METRICS_ENVIRONMENT": "local",
              # The export timeout must stay below the interval (observability v0.4.0).
              "AIPAY_METRICS_INTERVAL": "5s", "AIPAY_METRICS_EXPORT_TIMEOUT": "3s"}
    if config["mode"] == "external":
        url = endpoint_parts(config["endpoint"])
        try:
            address = ipaddress.ip_address(url.hostname)
            loopback = (getattr(address, "ipv4_mapped", None) or address).is_loopback
        except ValueError:
            loopback = url.hostname.rstrip(".") == "localhost"
        if url.scheme == "http" and not loopback:
            values["AIPAY_METRICS_ALLOW_INSECURE"] = "true"
    return values


def command(root, name):
    executable = state(root)[name]
    if name == "otelcol":
        return [executable, "--config", str(root / "telemetry/collector.yaml")]
    return [executable, "--config.file=" + str(root / "telemetry/prometheus.yaml"),
            "--storage.tsdb.path=" + str(root / "data/prometheus"), "--storage.tsdb.retention.time=2d",
            "--web.listen-address=127.0.0.1:9090", "--web.enable-otlp-receiver"]
