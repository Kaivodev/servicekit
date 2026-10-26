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
SERVICES=('iam','payment','ledger','settlement','reconciliation')
parser=argparse.ArgumentParser(description=__doc__)
parser.add_argument('--add-missing-credentials',action='store_true',help='append only missing passwords and log directories to an existing stack')
parser.add_argument('--add-queue-credentials',action='store_true',help=argparse.SUPPRESS)  # Earlier name, kept for existing instructions.
args=parser.parse_args()
if args.add_missing_credentials or args.add_queue_credentials:
    keys=('QUEUE_REDIS_PASSWORD',*(service.upper()+'_DB_PASSWORD' for service in SERVICES))
    descriptor=os.open(output/'stack.env',os.O_RDWR|os.O_APPEND|os.O_NOFOLLOW)
    with os.fdopen(descriptor,'r+') as target:
        fcntl.flock(target,fcntl.LOCK_EX)
        if os.fstat(target.fileno()).st_mode & 0o077:
            raise RuntimeError('stack.env must be private (0600)')
        existing=target.read()
        present={line.split('=',1)[0] for line in existing.splitlines()}
        added=[key for key in keys if key not in present]
        if added:
            target.write(('' if existing.endswith('\n') else '\n')+''.join(f'{key}={json.dumps(secrets.token_hex(24))}\n' for key in added))
    for service in SERVICES:
        (output/'logs'/service).mkdir(mode=0o700,exist_ok=True)
    print(f"Appended {', '.join(added) or 'nothing'}; existing passwords and certificates preserved.")
    # The initialized PostgreSQL volume and certificate set predate any added service.
    if any(key.endswith('_DB_PASSWORD') for key in added):
        print('Create the matching database roles in the existing PostgreSQL volume; see dev/README.md.')
    if missing:=[service for service in SERVICES if not (output/'certs'/service).is_dir()]:
        print('Certificates lack', ', '.join(missing)+'; regenerate them as described in dev/README.md.')
    raise SystemExit(0)
output.parent.mkdir(exist_ok=True,mode=0o700)
output.mkdir(mode=0o700)  # Deliberately refuse to overwrite existing state.
try:
    env=os.environ|{'GOWORK':'off'}
    subprocess.run(['go','run','./cmd/devcert','--out',str(output/'certs')],cwd=library,env=env,check=True)
    values={'AIPAY_DEV_DIR':str(output),'AIPAY_DEV_UID':str(os.getuid()),'AIPAY_DEV_GID':str(os.getgid()),'POSTGRES_PASSWORD':secrets.token_hex(24),'REDIS_PASSWORD':secrets.token_hex(24),'QUEUE_REDIS_PASSWORD':secrets.token_hex(24)}
    for service in SERVICES:
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
