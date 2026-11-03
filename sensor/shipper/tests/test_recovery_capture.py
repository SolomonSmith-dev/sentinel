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

def test_eve_rotation_and_opaque_model_restore_offline(tmp_path):
    import os
    from sentinel_shipper.eve import EveTailer
    from sentinel_shipper.recovery_capture import validate_snapshot
    state=tmp_path/'state';state.mkdir();(state/'queue').mkdir();windows=tmp_path/'windows';windows.mkdir();eve_dir=tmp_path/'eve';eve_dir.mkdir()
    db=sqlite3.connect(state/'state.db');db.execute('CREATE TABLE sample (x)');db.commit();db.close()
    def event(sid):
        return (json.dumps({'event_type':'alert','timestamp':'2026-11-02T00:00:00.000000+0000','src_ip':'192.0.2.1','dest_ip':'8.8.8.8','alert':{'signature_id':sid,'signature':'synthetic','category':'test','severity':2}})+'\n').encode()
    prefix=event(10); rotated=eve_dir/'eve.json.1';rotated.write_bytes(prefix+event(11));current=eve_dir/'eve.json';current.write_bytes(event(12)+b'{"partial"')
    (state/'eve_offset.json').write_text(json.dumps({'inode':rotated.stat().st_ino,'offset':len(prefix)}))
    (state/'model.joblib').write_bytes(b'opaque-not-a-pickle')
    archive=capture(state,windows,eve=current)
    summary=validate_snapshot(archive);assert summary['eve_continuity']=='captured-offline-remap-required';assert summary['model']=='opaque-manual-review'
    isolated=tmp_path/'isolated';isolated.mkdir(mode=0o700)
    with tarfile.open(fileobj=io.BytesIO(archive),mode='r:gz') as t:
        cp=json.load(t.extractfile('eve/checkpoint.json'));assert cp['partial_last_line'] is True
        first=isolated/'eve.json.1';first.write_bytes(t.extractfile('eve/000000.ndjson').read());os.utime(first,(1,1))
        restored=isolated/'eve.json';restored.write_bytes(t.extractfile('eve/000001.ndjson').read())
        assert t.extractfile('state/model.joblib').read()==b'opaque-not-a-pickle'
    position=isolated/'offset.json';position.write_text(json.dumps({'inode':first.stat().st_ino,'offset':cp['offset']}))
    tailer=EveTailer(restored,position)
    assert [x.sid for x in tailer.read()]==[11];tailer.commit()
    assert [x.sid for x in tailer.read()]==[12];tailer.commit()
    assert tailer.read()==[]

def test_eve_missing_checkpoint_inode_fails_closed(tmp_path):
    import pytest
    state=tmp_path/'state';state.mkdir();(state/'queue').mkdir();windows=tmp_path/'windows';windows.mkdir();eve=tmp_path/'eve.json';eve.write_bytes(b'{}\n')
    db=sqlite3.connect(state/'state.db');db.execute('CREATE TABLE sample (x)');db.commit();db.close()
    (state/'eve_offset.json').write_text(json.dumps({'inode':eve.stat().st_ino+123456,'offset':0}))
    with pytest.raises(ValueError): capture(state,windows,eve=eve)
