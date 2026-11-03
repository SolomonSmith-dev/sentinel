import io
import json
import multiprocessing
import sqlite3
import tarfile
import time

from sentinel_shipper.recovery_capture import capture
from sentinel_shipper.recovery_lock import recovery_lock

def hold_lock(state, ready, release):
    with recovery_lock(state):
        ready.set()
        release.wait(3)

def test_capture_waits_for_shipper_and_restores_wal_queue_and_windows(tmp_path):
    state=tmp_path/'state';state.mkdir(); windows=tmp_path/'windows';windows.mkdir()
    (state/'queue').mkdir();(state/'quarantine').mkdir()
    (state/'queue'/'one.json').write_text('{"synthetic":true}')
    (state/'queue'/'incomplete.json.tmp').write_text('ignore')
    (windows/'100.ndjson').write_text('{"synthetic":true}\n')
    (windows/'101.ndjson.tmp').write_text('ignore')
    db=sqlite3.connect(state/'state.db');db.execute('PRAGMA journal_mode=WAL');db.execute('CREATE TABLE sample (x)');db.execute('INSERT INTO sample VALUES (42)');db.commit()
    ready=multiprocessing.Event();release=multiprocessing.Event()
    p=multiprocessing.Process(target=hold_lock,args=(state,ready,release));p.start();assert ready.wait(3)
    import threading
    result=[];t=threading.Thread(target=lambda: result.append(capture(state,windows)));t.start();time.sleep(.1);assert not result
    release.set();p.join(3);t.join(3);assert result and p.exitcode==0
    with tarfile.open(fileobj=io.BytesIO(result[0]),mode='r:gz') as tar:
        names=set(tar.getnames());assert names=={'manifest.json','state/state.db','state/queue/one.json','windows/100.ndjson'}
        manifest=json.load(tar.extractfile('manifest.json')); assert manifest['eve_continuity']=='not captured'
        recovered=sqlite3.connect(':memory:');recovered.deserialize(tar.extractfile('state/state.db').read());assert recovered.execute('SELECT x FROM sample').fetchone()==(42,);recovered.close()
    db.close()

def test_capture_rejects_symlink(tmp_path):
    state=tmp_path/'state';state.mkdir();(state/'queue').mkdir();windows=tmp_path/'windows';windows.mkdir()
    db=sqlite3.connect(state/'state.db');db.execute('CREATE TABLE sample (x)');db.commit();db.close()
    (state/'queue'/'bad.json').symlink_to(state/'state.db')
    import pytest
    with pytest.raises(ValueError): capture(state, windows)

def test_capture_fails_when_queue_or_windows_missing(tmp_path):
    import pytest
    state=tmp_path/'state';state.mkdir();windows=tmp_path/'windows';windows.mkdir()
    db=sqlite3.connect(state/'state.db');db.execute('CREATE TABLE sample (x)');db.commit();db.close()
    with pytest.raises(ValueError): capture(state,windows)
    (state/'queue').mkdir();windows.rmdir()
    with pytest.raises(ValueError): capture(state,windows)

def test_offline_validation_refuses_unsafe_archive_and_never_replays(tmp_path):
    import pytest
    from sentinel_shipper.recovery_capture import validate_snapshot
    state=tmp_path/'state';state.mkdir();(state/'queue').mkdir();windows=tmp_path/'windows';windows.mkdir()
    db=sqlite3.connect(state/'state.db');db.execute('CREATE TABLE sample (x)');db.commit();db.close()
    (state/'queue'/'unfinalized.json').write_text('{"windows":[]}')
    (state/'queue'/'finalized.json').write_text('{"sent_at":123,"windows":[]}')
    result=validate_snapshot(capture(state,windows))
    assert result['queued_items']==2 and result['replay']=='manual-review-only'
    buf=io.BytesIO()
    with tarfile.open(fileobj=buf,mode='w:gz') as tar:
        member=tarfile.TarInfo('../escape');member.size=0;tar.addfile(member,io.BytesIO())
    with pytest.raises(ValueError): validate_snapshot(buf.getvalue())

def test_capture_refuses_missing_or_stale_handshake(tmp_path):
    import pytest
    state=tmp_path/'state';state.mkdir();(state/'queue').mkdir();windows=tmp_path/'windows';windows.mkdir()
    db=sqlite3.connect(state/'state.db');db.execute('CREATE TABLE sample (x)');db.commit();db.close()
    with pytest.raises((OSError, ValueError)): capture(state,windows,require_handshake=True)
    (state/'recovery-protocol.json').write_text('{"protocol":1,"pid":999999,"start_ticks":"1","boot_id":"stale"}')
    with pytest.raises(ValueError): capture(state,windows,require_handshake=True)
