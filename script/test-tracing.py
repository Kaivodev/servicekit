#!/usr/bin/env python3
"""Run integration tests with isolated native PostgreSQL and Redis.
Optional --collector/--jaeger binaries also verify Collector -> Jaeger queries.
No container engine, existing database, persistent credential or global install.
"""
import argparse
import os
from pathlib import Path
import shutil
import socket
import subprocess
import tempfile
import time

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument('--postgres-bin', type=Path, default=Path('/opt/homebrew/opt/postgresql@18/bin'))
parser.add_argument('--collector', type=Path)
parser.add_argument('--jaeger', type=Path)
parser.add_argument('--workspace', action='store_true', help='use sibling modules during development')
parser.add_argument('--run', default='.')
parser.add_argument('--backend', action='store_true', help='also verify sibling gateway storage against these disposable stores')
a = parser.parse_args()
if bool(a.collector) != bool(a.jaeger):
    parser.error('--collector and --jaeger must be provided together')
repo = Path(__file__).resolve().parents[1]
redis = shutil.which('redis-server')
if not redis:
    parser.error('redis-server is required')
for name in ('initdb', 'pg_ctl'):
    if not (a.postgres_bin/name).is_file():
        parser.error(f'missing PostgreSQL binary: {name}')

def port():
    with socket.socket() as sock:
        sock.bind(('127.0.0.1', 0))
        return sock.getsockname()[1]

def ready(number):
    try:
        with socket.create_connection(('127.0.0.1', number), timeout=.1):
            return True
    except OSError:
        return False

def run(command, **kw):
    result = subprocess.run([str(x) for x in command], capture_output=True, text=True, timeout=60, **kw)
    if result.returncode:
        raise RuntimeError(f'{Path(str(command[0])).name} failed: {result.stdout}{result.stderr}')

with tempfile.TemporaryDirectory(prefix='aipay-trace-test-') as temp:
    root = Path(temp); os.chmod(root, 0o700)
    env = {k:v for k,v in os.environ.items() if not k.startswith('AIPAY_')}
    env['GOWORK'] = str(repo.parent/'go.work') if a.workspace else 'off'
    pg_port, redis_port = port(), port()
    env['AIPAY_TEST_DATABASE_URL'] = f'postgres://postgres@127.0.0.1:{pg_port}/postgres?sslmode=disable'
    env['AIPAY_TEST_REDIS_URL'] = f'redis://127.0.0.1:{redis_port}/0'
    processes = []; logs = []; pg_started = False
    def start(command, label, number):
        log = open(root/(label+'.log'), 'wb'); logs.append(log)
        process = subprocess.Popen([str(x) for x in command], env=env, stdout=log, stderr=subprocess.STDOUT)
        processes.append(process)
        deadline = time.monotonic()+15
        while not ready(number):
            if process.poll() is not None or time.monotonic()>deadline:
                log.flush()
                raise RuntimeError(f'{label} failed: '+(root/(label+'.log')).read_text())
            time.sleep(.1)
    try:
        run([a.postgres_bin/'initdb','-D',root/'pg','-U','postgres','--auth=trust','--no-locale','--encoding=UTF8'])
        run([a.postgres_bin/'pg_ctl','-D',root/'pg','-l',root/'pg.log','-o',f'-h 127.0.0.1 -p {pg_port} -k {root}','-w','start']); pg_started=True
        start([redis,'--bind','127.0.0.1','--port',redis_port,'--save','','--appendonly','no','--dir',root], 'redis', redis_port)
        if a.collector:
            collector, jaeger, query, query_grpc = port(), port(), port(), port()
            env.update(AIPAY_COLLECTOR_ADDR=f'127.0.0.1:{collector}',AIPAY_JAEGER_OTLP_ADDR=f'127.0.0.1:{jaeger}',AIPAY_JAEGER_QUERY_ADDR=f'127.0.0.1:{query}',AIPAY_JAEGER_QUERY_GRPC_ADDR=f'127.0.0.1:{query_grpc}',AIPAY_TEST_OTLP_TARGET=f'127.0.0.1:{collector}',AIPAY_TEST_JAEGER_URL=f'http://127.0.0.1:{query}')
            for binary, config in ((a.jaeger,'jaeger'),(a.collector,'collector')):
                run([binary,'validate','--config',repo/'dev'/(config+'.yaml')],env=env)
            start([a.jaeger,'--config',repo/'dev/jaeger.yaml'],'jaeger',query)
            start([a.collector,'--config',repo/'dev/collector.yaml'],'collector',collector)
        result = subprocess.run(['go','test','-race','-count=1','-tags=integration','-run',a.run,'-v','./internal/integration/...'],cwd=repo,env=env,timeout=180)
        if result.returncode:
            raise SystemExit(result.returncode)
        if a.backend:
            result = subprocess.run(['go','test','-race','-count=1','-tags=integration','./internal/integration/...'],cwd=repo.parent/'backend',env=env,timeout=120)
            if result.returncode:
                raise SystemExit(result.returncode)
        print('isolated tracing/queue integration passed'+(' including Collector and Jaeger query' if a.collector else ''),flush=True)
    finally:
        for process in reversed(processes):
            if process.poll() is None:
                process.terminate()
                try: process.wait(timeout=5)
                except subprocess.TimeoutExpired: process.kill(); process.wait()
        if pg_started:
            subprocess.run([a.postgres_bin/'pg_ctl','-D',root/'pg','-m','immediate','-w','stop'],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,timeout=15)
        for log in logs: log.close()
