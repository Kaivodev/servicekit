#!/usr/bin/env python3
"""Build/run four sibling services against freshly initialized, loopback-only stores.
Requires native PostgreSQL (initdb/pg_ctl/psql) and Redis binaries; never uses a
configured business database. All databases, certificates and logs are temporary.
"""
import argparse
import json
import os
from pathlib import Path
import shutil
import signal
import socket
import subprocess
import tempfile
import time

SERVICES = ('iam', 'ledger', 'settlement', 'reconciliation')
p = argparse.ArgumentParser(description=__doc__)
p.add_argument('--workspace', type=Path, default=Path(__file__).resolve().parents[2])
p.add_argument('--use-workspace', action='store_true', help='use local sibling modules instead of published versions')
p.add_argument('--postgres-bin', type=Path, default=Path(os.environ.get('AIPAY_POSTGRES_BIN', '/opt/homebrew/opt/postgresql@18/bin')))
a = p.parse_args()
workspace = a.workspace.resolve()
for name in (*SERVICES, 'servicekit'):
    if not (workspace / name / 'go.mod').is_file():
        p.error(f'missing workspace module: {name}')
for binary in ('initdb', 'pg_ctl', 'psql'):
    if not (a.postgres_bin / binary).is_file():
        p.error(f'missing PostgreSQL binary: {binary}; set --postgres-bin')
redis_binary = shutil.which('redis-server')
if not redis_binary:
    p.error('redis-server is required')


def port():
    with socket.socket() as s:
        s.bind(('127.0.0.1', 0))
        return s.getsockname()[1]


def socket_ready(number):
    try:
        with socket.create_connection(('127.0.0.1', number), timeout=.1):
            return True
    except OSError:
        return False


def run(args, **kw):
    result = subprocess.run([str(x) for x in args], stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, timeout=kw.pop('timeout', 90), **kw)
    if result.returncode:
        # Child errors may contain test connection strings; keep artifacts private.
        raise RuntimeError(f'{Path(str(args[0])).name} {args[1] if len(args)>1 else ""} failed (exit {result.returncode})')
    return result.stdout


def wait_until(check, label, timeout=15):
    end = time.monotonic() + timeout
    while time.monotonic() < end:
        if check():
            return
        time.sleep(.1)
    raise RuntimeError(f'timeout: {label}')


with tempfile.TemporaryDirectory(prefix='aipay-runtime-test-') as temp:
    root = Path(temp)
    os.chmod(root, 0o700)
    pg_port, redis_port = port(), port()
    pg_started = False
    redis_process = None
    processes = {}
    outputs = []
    envs = {}
    env = os.environ.copy()
    # Do not inherit any deployed service configuration or module workspace.
    for key in list(env):
        if key.startswith('AIPAY_'):
            del env[key]
    env['GOWORK'] = str(workspace / 'go.work') if a.use_workspace else 'off'
    pg = a.postgres_bin
    def psql(sql, database='postgres'):
        return run([pg/'psql', '-X', '-v', 'ON_ERROR_STOP=1', '-h', '127.0.0.1', '-p', str(pg_port), '-U', 'postgres', '-d', database, '-Atc', sql])
    def start_redis():
        log = open(root/'redis-output.log', 'ab'); outputs.append(log)
        return subprocess.Popen([redis_binary, '--bind', '127.0.0.1', '--port', str(redis_port), '--save', '', '--appendonly', 'no', '--dir', str(root)], stdout=log, stderr=subprocess.STDOUT)
    def health(name):
        return subprocess.run([root/f'aipay-{name}', 'healthcheck'], env=envs[name], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=4).returncode == 0
    def start_service(name):
        log = open(root/f'{name}-output.log', 'ab'); outputs.append(log)
        return subprocess.Popen([root/f'aipay-{name}', 'serve'], env=envs[name], stdout=log, stderr=subprocess.STDOUT)
    def rejected(name, args, options):
        result = subprocess.run([root/f'aipay-{name}', *args], env=options, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=8)
        if result.returncode == 0:
            raise RuntimeError(f'{name} accepted invalid startup/migration')
        if b'postgres://' in result.stdout or b'never-log-this' in result.stdout:
            raise RuntimeError('connection credential exposed in process output')
    try:
        run([pg/'initdb', '-D', root/'postgres', '-U', 'postgres', '--auth=trust', '--no-locale', '--encoding=UTF8'])
        run([pg/'pg_ctl', '-D', root/'postgres', '-l', root/'postgres.log', '-o', f'-h 127.0.0.1 -p {pg_port} -k {root}', '-w', 'start'])
        pg_started = True
        redis_process = start_redis()
        wait_until(lambda: redis_process.poll() is None and socket_ready(redis_port), 'Redis start')
        psql('CREATE DATABASE servicekit_test')
        testenv = env | {'AIPAY_TEST_DATABASE_URL':f'postgres://postgres@127.0.0.1:{pg_port}/servicekit_test?sslmode=disable', 'AIPAY_TEST_REDIS_URL':f'redis://127.0.0.1:{redis_port}/0', 'GOWORK':'off'}
        result = subprocess.run(['go', 'test', '-race', '-tags=integration', './internal/integration/...'], cwd=workspace/'servicekit', env=testenv, text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=120)
        print(result.stdout, end='', flush=True)
        if result.returncode:
            raise RuntimeError('servicekit storage integration failed')
        run(['go', 'run', './cmd/devcert', '--out', root/'certs'], cwd=workspace/'servicekit', env=env)
        print('isolated storage and certificate generation passed', flush=True)
        for name in SERVICES:
            run(['go', 'build', '-o', root/f'aipay-{name}', '.'], cwd=workspace/name, env=env)
            data = json.loads(run([root/f'aipay-{name}', 'version']))
            if data['service'] != name:
                raise RuntimeError('incorrect binary version identity')
            psql(f'CREATE ROLE aipay_{name} LOGIN')
            psql(f'CREATE DATABASE aipay_{name} OWNER aipay_{name}')
            envs[name] = env | {
                'AIPAY_DATABASE_URL':f'postgres://aipay_{name}@127.0.0.1:{pg_port}/aipay_{name}?sslmode=disable',
                'AIPAY_REDIS_URL':f'redis://127.0.0.1:{redis_port}/0',
                'AIPAY_GRPC_ADDR':f'127.0.0.1:{port()}',
                'AIPAY_RPC_ALLOWED_PEERS':f'backend,probe,{name}',
                'AIPAY_TLS_CERT_FILE':str(root/'certs'/name/'tls.crt'),
                'AIPAY_TLS_KEY_FILE':str(root/'certs'/name/'tls.key'),
                'AIPAY_TLS_CA_FILE':str(root/'certs'/'ca.crt'),
                'AIPAY_TLS_TRUST_DOMAIN':'aipay.test',
                'AIPAY_LOG_DIR':str(root/'logs'/name),
                # Deliberately unavailable collector must not affect startup/readiness.
                'AIPAY_TRACE_ENDPOINT':f'http://127.0.0.1:{port()}',
                'AIPAY_TRACE_EXPORT_TIMEOUT':'100ms', 'AIPAY_TRACE_BATCH_INTERVAL':'10ms',
                'AIPAY_TRACE_SHUTDOWN_TIMEOUT':'100ms',
                'AIPAY_HEALTH_INTERVAL':'100ms', 'AIPAY_HEALTH_TIMEOUT':'250ms',
                'AIPAY_RPC_CALL_TIMEOUT':'500ms', 'AIPAY_STARTUP_TIMEOUT':'2s', 'AIPAY_SHUTDOWN_TIMEOUT':'2s',
            }
            rejected(name, ['serve'], envs[name])  # no migration yet
            run([root/f'aipay-{name}', 'migrate', 'up'], env=envs[name])
            run([root/f'aipay-{name}', 'migrate', 'up'], env=envs[name])
            processes[name] = start_service(name)
            wait_until(lambda n=name: health(n), f'{name} readiness')
            print(f'{name}: migrate, start, mTLS health and version passed', flush=True)
        rejected('ledger', ['migrate', 'up'], envs['ledger'] | {'AIPAY_DATABASE_URL':envs['iam']['AIPAY_DATABASE_URL']})
        rejected('ledger', ['serve'], envs['ledger'] | {'AIPAY_DATABASE_URL':envs['iam']['AIPAY_DATABASE_URL']})
        rejected('iam', ['serve'], envs['iam'])  # occupied listener
        rejected('iam', ['serve'], envs['iam'] | {'AIPAY_TLS_CERT_FILE':str(root/'certs'/'ledger'/'tls.crt'), 'AIPAY_TLS_KEY_FILE':str(root/'certs'/'ledger'/'tls.key')})
        # Ownership isolation and failed-startup cleanup leave just the live pool.
        connections = int(psql("SELECT count(*) FROM pg_stat_activity WHERE application_name='aipay-iam'"))
        if connections > 4:
            raise RuntimeError('failed startup leaked PostgreSQL pools')
        run([root/'aipay-iam', 'migrate', 'down'], env=envs['iam'])
        wait_until(lambda: not health('iam'), 'schema loss readiness')
        run([root/'aipay-iam', 'migrate', 'up'], env=envs['iam'])
        wait_until(lambda: health('iam'), 'schema restored readiness')
        redis_process.terminate(); redis_process.wait(timeout=5)
        for name in SERVICES:
            wait_until(lambda n=name: not health(n), f'{name} Redis outage readiness')
        redis_process = start_redis()
        for name in SERVICES:
            wait_until(lambda n=name: health(n), f'{name} Redis recovery readiness')
        run([pg/'pg_ctl', '-D', root/'postgres', '-m', 'fast', '-w', 'stop']); pg_started=False
        for name in SERVICES:
            wait_until(lambda n=name: not health(n), f'{name} PostgreSQL outage readiness')
        start = time.monotonic()
        for process in processes.values():
            process.send_signal(signal.SIGTERM)
        for name, process in processes.items():
            if process.wait(timeout=5) != 0:
                raise RuntimeError(f'{name} graceful shutdown failed')
        if time.monotonic()-start > 5:
            raise RuntimeError('shutdown exceeded process budget')
        for log in (root/'logs').rglob('*.log'):
            for line in log.read_text().splitlines():
                json.loads(line)
                if 'postgres://' in line:
                    raise RuntimeError('database URL leaked into logs')
        print('four-process isolation, startup failure cleanup, schema/Redis/PostgreSQL readiness, unavailable collector and SIGTERM passed', flush=True)
    finally:
        for process in processes.values():
            if process.poll() is None:
                process.terminate()
                try: process.wait(timeout=4)
                except subprocess.TimeoutExpired: process.kill(); process.wait()
        if redis_process and redis_process.poll() is None:
            redis_process.terminate(); redis_process.wait(timeout=5)
        if pg_started:
            subprocess.run([pg/'pg_ctl', '-D', root/'postgres', '-m', 'immediate', '-w', 'stop'], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=15)
        for output in outputs:
            output.close()
