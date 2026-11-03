import importlib.util
import json
from pathlib import Path
import sqlite3
from unittest import mock
import pytest

path=Path(__file__).resolve().parents[1]/'scripts/backup_state.py'
spec=importlib.util.spec_from_file_location('backup_state',path)
m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)

def db_bytes():
    db=sqlite3.connect(':memory:')
    for table in m.TABLES: db.execute('CREATE TABLE '+table+' (x INTEGER)')
    db.execute('INSERT INTO devices VALUES (1)');db.commit()
    b=db.serialize();db.close();return b

def test_verify_valid_and_wrong_schema():
    m.check(db_bytes())
    db=sqlite3.connect(':memory:');db.execute('CREATE TABLE unrelated (x)');data=db.serialize();db.close()
    with pytest.raises(ValueError): m.check(data)

def test_backup_uploads_and_verifies_exact_bytes_without_plaintext_file():
    data=db_bytes(); calls=[]
    def run(args,data=None,timeout=600):
        calls.append((args,data))
        if args[0]=='docker': return db_bytes()
        if 'backup' in args: return json.dumps({'message_type':'summary','snapshot_id':'abcdef12'}).encode()
        return db_bytes()
    with mock.patch.object(m,'run',side_effect=run): result=m.backup()
    assert result['status']=='verified' and result['queue_windows']=='not captured'
    assert calls[1][1]==data and calls[2][1] is None

def test_bad_restore_is_rejected():
    def run(args,data=None,timeout=600):
        if args[0]=='docker': return db_bytes()
        if 'backup' in args: return b'{"message_type":"summary","snapshot_id":"abcdef12"}'
        return b'bad'
    with mock.patch.object(m,'run',side_effect=run), pytest.raises(ValueError): m.backup()

def test_capture_real_wal_database(tmp_path):
    import subprocess, sys
    path=tmp_path/'source.db'
    db=sqlite3.connect(path)
    db.execute('PRAGMA journal_mode=WAL')
    for table in m.TABLES: db.execute('CREATE TABLE '+table+' (x INTEGER)')
    db.execute('INSERT INTO devices VALUES (42)');db.commit()
    program=m.CAPTURE.replace('/var/lib/sentinel/state/state.db',str(path))
    result=subprocess.run([sys.executable,'-c',program],capture_output=True,check=True)
    m.check(result.stdout)
    restored=sqlite3.connect(':memory:');restored.deserialize(result.stdout)
    assert restored.execute('SELECT x FROM devices').fetchone()==(42,)
    restored.close();db.close()
