#!/usr/bin/env python3
"""Back up Sentinel's local SQLite state through encrypted restic stdin.

This does not capture the live queue or windows and makes no point-in-time claim
about those independent files. No database bytes are written to local disk.
"""
import datetime
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import sqlite3
import subprocess
import sys
import tempfile

MAX_BYTES = 64 * 1024 * 1024
CONTAINER = 'sensor-sentinel-shipper-1'
TABLES = {'devices', 'device_countries', 'debounce', 'ip_map', 'features', 'device_shipped'}
CAPTURE = r'''import sqlite3,sys
s=sqlite3.connect('file:/var/lib/sentinel/state/state.db?mode=ro',uri=True,timeout=5)
m=sqlite3.connect(':memory:')
try:
    if s.execute('PRAGMA page_count').fetchone()[0]*s.execute('PRAGMA page_size').fetchone()[0]>64*1024*1024: raise ValueError('size')
    s.backup(m,pages=128,sleep=0.05)
    if m.execute('PRAGMA integrity_check').fetchall()!=[('ok',)]: raise ValueError('integrity')
    data=m.serialize()
    if len(data)<100 or len(data)>64*1024*1024 or not data.startswith(b'SQLite format 3\x00'): raise ValueError('header')
    sys.stdout.buffer.write(data[:18]+bytes((1,1))+data[20:])
finally:
    m.close();s.close()
'''

def check(data):
    if len(data)<100 or len(data)>MAX_BYTES or not data.startswith(b'SQLite format 3\x00'):
        raise ValueError('invalid sqlite snapshot')
    db=sqlite3.connect(':memory:')
    try:
        db.deserialize(data)
        if db.execute('PRAGMA integrity_check').fetchall()!=[('ok',)]: raise ValueError('integrity')
        tables={row[0] for row in db.execute("SELECT name FROM sqlite_master WHERE type='table'")}
        if not TABLES <= tables: raise ValueError('unexpected schema')
    finally:
        db.close()

def run(args, data=None, timeout=600):
    p=subprocess.run(args,input=data,stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=timeout)
    if p.returncode: raise RuntimeError('command failed: '+Path(args[0]).name)
    return p.stdout

def backup():
    wrapper=str(Path.home()/'scripts/restic-b2.sh')
    data=run(['docker','exec',CONTAINER,'python','-c',CAPTURE],timeout=180)
    check(data)
    digest=hashlib.sha256(data).hexdigest()
    out=run([wrapper,'--json','backup','--stdin','--stdin-filename','/application-state/sentinel-state.db','--tag','application-sqlite','--tag','sentinel-state'],data=data)
    summaries=[x for line in out.splitlines() if line for x in [json.loads(line)] if x.get('message_type')=='summary']
    if len(summaries)!=1 or not re.fullmatch('[0-9a-f]{8,64}',summaries[0].get('snapshot_id','')): raise ValueError('snapshot identity')
    sid=summaries[0]['snapshot_id']
    restored=run([wrapper,'dump',sid,'/application-state/sentinel-state.db','--no-lock'])
    if hashlib.sha256(restored).hexdigest()!=digest: raise ValueError('restored hash')
    check(restored)
    return {'status':'verified','snapshot':sid,'bytes':len(data),'sha256':digest,'sqlite_integrity':'ok','queue_windows':'not captured','finished':datetime.datetime.now(datetime.timezone.utc).isoformat()}

def main():
    result={'status':'failed'}
    try:
        with open('/tmp/restic-b2.lock','a') as lock:
            fcntl.flock(lock,fcntl.LOCK_EX)
            result=backup()
    except (OSError,RuntimeError,ValueError,sqlite3.Error,subprocess.SubprocessError) as exc:
        result['error']=type(exc).__name__
    dest=Path.home()/'logs/sentinel-state-backup.json';dest.parent.mkdir(parents=True,exist_ok=True)
    with tempfile.NamedTemporaryFile(mode='w',dir=dest.parent,delete=False) as f:
        json.dump(result,f);f.write('\n'); temp=Path(f.name)
    os.chmod(temp,0o600);os.replace(temp,dest)
    print(json.dumps(result))
    return 0 if result['status']=='verified' else 1
if __name__=='__main__': sys.exit(main())
