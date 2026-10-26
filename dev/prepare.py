#!/usr/bin/env python3
"""Prepare disposable local development credentials, certificates and log paths."""
import argparse
import fcntl
import json
import os
from pathlib import Path
import secrets
import shutil
import subprocess

library=Path(__file__).resolve().parents[1]
workspace=library.parent
output=workspace/'.local'/'dev'
parser=argparse.ArgumentParser(description=__doc__)
parser.add_argument('--add-queue-credentials',action='store_true',help='append only the missing queue password to an existing stack.env')
args=parser.parse_args()
if args.add_queue_credentials:
    descriptor=os.open(output/'stack.env',os.O_RDWR|os.O_APPEND|os.O_NOFOLLOW)
    with os.fdopen(descriptor,'r+') as target:
        fcntl.flock(target,fcntl.LOCK_EX)
        if os.fstat(target.fileno()).st_mode & 0o077:
            raise RuntimeError('stack.env must be private (0600)')
        existing=target.read()
        if not any(line.startswith('QUEUE_REDIS_PASSWORD=') for line in existing.splitlines()):
            target.write(('' if existing.endswith('\n') else '\n')+'QUEUE_REDIS_PASSWORD='+json.dumps(secrets.token_hex(24))+'\n')
    print('Queue credential is present; existing database passwords and certificates preserved.')
    raise SystemExit(0)
output.parent.mkdir(exist_ok=True,mode=0o700)
output.mkdir(mode=0o700)  # Deliberately refuse to overwrite existing state.
try:
    env=os.environ|{'GOWORK':'off'}
    subprocess.run(['go','run','./cmd/devcert','--out',str(output/'certs')],cwd=library,env=env,check=True)
    values={'AIPAY_DEV_DIR':str(output),'AIPAY_DEV_UID':str(os.getuid()),'AIPAY_DEV_GID':str(os.getgid()),'POSTGRES_PASSWORD':secrets.token_hex(24),'REDIS_PASSWORD':secrets.token_hex(24),'QUEUE_REDIS_PASSWORD':secrets.token_hex(24)}
    for service in ('iam','ledger','settlement','reconciliation'):
        values[service.upper()+'_DB_PASSWORD']=secrets.token_hex(24)
        (output/'logs'/service).mkdir(parents=True,mode=0o700)
    descriptor=os.open(output/'stack.env',os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600)
    with os.fdopen(descriptor,'w') as target:
        for key,value in values.items():target.write(f'{key}={json.dumps(value)}\n')
except BaseException:
    shutil.rmtree(output)
    raise
print('Prepared local development credentials, certificates and log directories.')
print('Run: docker compose --env-file ../.local/dev/stack.env -f dev/compose.yaml up -d --build')
