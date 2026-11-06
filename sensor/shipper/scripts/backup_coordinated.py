#!/usr/bin/env python3
"""Candidate encrypted Sentinel queue/state backup. Not installed or scheduled.

Requires reviewed shipper image SHA-256 as argv[1]. That image must have been
started after the coordinated-lock release; install/rollout handles this gate.
Never log or persist captured telemetry in plaintext.
"""
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile
from datetime import datetime, timezone

CONTAINER = 'sensor-sentinel-shipper-1'
PATH_IN_REPO = '/application-state/sentinel-coordinated.tar.gz'
MAX_BYTES = 128 * 1024 * 1024
VALIDATE = "import json,sys;from sentinel_shipper.recovery_capture import validate_snapshot;print(json.dumps(validate_snapshot(sys.stdin.buffer.read())))"

def run(argv, data=None):
    result=subprocess.run(argv,input=data,capture_output=True,timeout=600)
    if result.returncode:
        raise RuntimeError('command failed: '+Path(argv[0]).name)
    return result.stdout

def verify_image(expected):
    if not re.fullmatch(r'sha256:[0-9a-f]{64}',expected):
        raise ValueError('invalid approved image')
    image=run(['docker','inspect','--format','{{.Image}}',CONTAINER]).decode().strip()
    if image != expected:
        raise ValueError('running shipper is not the approved recovery image')

def validate(data):
    if len(data)>MAX_BYTES:
        raise ValueError('archive too large')
    summary=json.loads(run(['docker','exec','-i',CONTAINER,'python','-c',VALIDATE],data=data))
    if summary.get('sqlite_integrity')!='ok' or summary.get('replay')!='manual-review-only':
        raise ValueError('offline validation failed')
    return summary

def backup(expected):
    verify_image(expected)
    data=run(['docker','exec',CONTAINER,'python','-m','sentinel_shipper.recovery_capture'])
    verify_image(expected)
    summary=validate(data)
    digest=hashlib.sha256(data).hexdigest()
    wrapper=str(Path.home()/'scripts/restic-b2.sh')
    out=run([wrapper,'--json','backup','--stdin','--stdin-filename',PATH_IN_REPO,'--tag','sentinel-coordinated'],data=data)
    records=[x for line in out.splitlines() if line for x in [json.loads(line)] if x.get('message_type')=='summary']
    if len(records)!=1 or not re.fullmatch('[0-9a-f]{8,64}',records[0].get('snapshot_id','')):
        raise ValueError('snapshot identity')
    snapshot=records[0]['snapshot_id']
    restored=run([wrapper,'dump',snapshot,PATH_IN_REPO,'--no-lock'])
    if hashlib.sha256(restored).hexdigest()!=digest:
        raise ValueError('restored hash differs')
    verify_image(expected)
    restored_summary=validate(restored)
    if restored_summary!=summary:
        raise ValueError('restored summary differs')
    return {'status':'verified','snapshot':snapshot,'bytes':len(data),'sha256':digest,'summary':summary,'image':expected,'finished':datetime.now(timezone.utc).isoformat()}

def main():
    if len(sys.argv)!=2:
        print('expected approved shipper image digest',file=sys.stderr);return 2
    result={'status':'failed'}
    try:
        with open('/tmp/restic-b2.lock','a') as lock:
            fcntl.flock(lock,fcntl.LOCK_EX)
            result=backup(sys.argv[1])
    except (OSError,RuntimeError,ValueError,subprocess.SubprocessError) as exc:
        result['error']=type(exc).__name__
    dest=Path.home()/'logs/sentinel-coordinated-backup.json'
    with tempfile.NamedTemporaryFile(mode='w',dir=dest.parent,delete=False) as f:
        json.dump(result,f);f.write('\n');tmp=Path(f.name)
    os.chmod(tmp,0o600);os.replace(tmp,dest)
    print(json.dumps(result));return 0 if result['status']=='verified' else 1
if __name__=='__main__': sys.exit(main())
