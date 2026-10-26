#!/usr/bin/env python3
"""Prepare disposable local development credentials, certificates and log paths."""
import json
import os
from pathlib import Path
import secrets
import shutil
import subprocess

library=Path(__file__).resolve().parents[1]
workspace=library.parent
output=workspace/'.local'/'dev'
output.parent.mkdir(exist_ok=True,mode=0o700)
output.mkdir(mode=0o700)  # Deliberately refuse to overwrite existing state.
try:
    env=os.environ|{'GOWORK':'off'}
    subprocess.run(['go','run','./cmd/devcert','--out',str(output/'certs')],cwd=library,env=env,check=True)
    values={'AIPAY_DEV_DIR':str(output),'AIPAY_DEV_UID':str(os.getuid()),'AIPAY_DEV_GID':str(os.getgid()),'POSTGRES_PASSWORD':secrets.token_hex(24),'REDIS_PASSWORD':secrets.token_hex(24)}
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
