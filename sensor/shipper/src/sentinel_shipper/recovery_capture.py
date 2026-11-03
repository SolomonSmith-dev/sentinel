"""Capture recoverable local Sentinel files under the shipper's shared lock.

Output is sensitive tar data: callers must pipe it directly to encrypted backup,
never a terminal or plaintext disk. EVE continuity and model are not included.
"""
from __future__ import annotations
import io
import json
import sqlite3
import sys
import tarfile
from pathlib import Path
from .recovery_lock import recovery_lock, check_handshake

MAX_BYTES = 128 * 1024 * 1024

def capture(state: Path, windows: Path, require_handshake: bool = False) -> bytes:
    contents = {}
    total = 0
    with recovery_lock(state):
        if require_handshake:
            check_handshake(state)
        src = sqlite3.connect((state / 'state.db').as_uri() + '?mode=ro', uri=True, timeout=5)
        db = sqlite3.connect(':memory:')
        try:
            pages = src.execute('PRAGMA page_count').fetchone()[0]
            size = src.execute('PRAGMA page_size').fetchone()[0]
            if pages * size > MAX_BYTES:
                raise ValueError('state too large')
            src.backup(db, pages=128, sleep=0.05)
            if db.execute('PRAGMA integrity_check').fetchall() != [('ok',)]:
                raise ValueError('state integrity')
            data = db.serialize()
            if not data.startswith(b'SQLite format 3\x00') or len(data) < 100:
                raise ValueError('invalid sqlite state')
            contents['state/state.db'] = data[:18] + bytes((1, 1)) + data[20:]
        finally:
            db.close()
            src.close()
        total = len(contents['state/state.db'])
        # Names are enumerated while the shipper cannot mutate them. Capture
        # publishes completed windows via atomic rename; later windows are not
        # part of this snapshot and temp files are never copied.
        if not (state / 'queue').is_dir() or not windows.is_dir():
            raise ValueError('required queue or windows missing')
        for root, pattern, prefix in ((state / 'queue', '*.json', 'state/queue'),
                                      (state / 'quarantine', '*.json', 'state/quarantine'),
                                      (state / 'quarantine', '*.reason', 'state/quarantine'),
                                      (windows, '*.ndjson', 'windows')):
            if not root.is_dir():
                continue
            for path in sorted(root.glob(pattern)):
                if path.is_symlink() or not path.is_file():
                    raise ValueError('unsupported source file')
                size = path.stat().st_size
                if total + size > MAX_BYTES:
                    raise ValueError('capture too large')
                contents[prefix + '/' + path.name] = path.read_bytes()
                total += len(contents[prefix + '/' + path.name])
                if total > MAX_BYTES:
                    raise ValueError('capture too large')
    # Build the archive after releasing the lock; no network or compression runs
    # inside the shipper's critical section.
    out = io.BytesIO()
    manifest = {'format': 1, 'queue_windows': 'coordinated-at-least-once',
                'eve_continuity': 'not captured', 'model': 'not captured',
                'entries': sorted(contents)}
    with tarfile.open(fileobj=out, mode='w:gz') as archive:
        for name, data in [('manifest.json', json.dumps(manifest).encode()), *sorted(contents.items())]:
            info = tarfile.TarInfo(name)
            info.size = len(data)
            info.mode = 0o600
            archive.addfile(info, io.BytesIO(data))
    return out.getvalue()

def validate_snapshot(blob: bytes) -> dict:
    """Validate offline only; never extract files or replay to a live sender."""
    if len(blob) > MAX_BYTES:
        raise ValueError('archive too large')
    files = {}
    total = 0
    with tarfile.open(fileobj=io.BytesIO(blob), mode='r:gz') as archive:
        for member in archive:
            name = member.name
            allowed = (name == 'manifest.json' or name == 'state/state.db' or
                       (name.startswith('state/queue/') and name.endswith('.json')) or
                       (name.startswith('state/quarantine/') and name.endswith(('.json', '.reason'))) or
                       (name.startswith('windows/') and name.endswith('.ndjson')))
            if not allowed or not member.isfile() or name in files or '..' in Path(name).parts or len(Path(name).parts) != (1 if name == 'manifest.json' else (2 if name in ('state/state.db',) or name.startswith('windows/') else 3)):
                raise ValueError('unsafe archive member')
            total += member.size
            if total > MAX_BYTES:
                raise ValueError('expanded archive too large')
            stream = archive.extractfile(member)
            if stream is None:
                raise ValueError('missing archive member')
            files[name] = stream.read()
    if 'manifest.json' not in files or 'state/state.db' not in files:
        raise ValueError('archive missing required data')
    manifest = json.loads(files['manifest.json'])
    if manifest.get('format') != 1 or set(manifest.get('entries', [])) != set(files) - {'manifest.json'}:
        raise ValueError('archive manifest differs')
    db = sqlite3.connect(':memory:')
    try:
        db.deserialize(files['state/state.db'])
        if db.execute('PRAGMA integrity_check').fetchall() != [('ok',)]:
            raise ValueError('recovered database integrity')
    finally:
        db.close()
    for name, data in files.items():
        if name.startswith(('state/queue/', 'state/quarantine/')) and name.endswith('.json'):
            if not isinstance(json.loads(data), dict):
                raise ValueError('invalid queued item')
    # Captured queue items are never automatically replayed. They may have been
    # accepted since capture or aged beyond ingest/idempotency limits.
    return {'entries': len(files) - 1, 'sqlite_integrity': 'ok',
            'queued_items': sum(n.startswith('state/queue/') for n in files),
            'replay': 'manual-review-only', 'eve_continuity': 'not captured',
            'model': 'not captured'}

def main() -> int:
    try:
        sys.stdout.buffer.write(capture(Path('/var/lib/sentinel/state'), Path('/var/lib/sentinel/windows'), require_handshake=True))
        return 0
    except (OSError, ValueError, sqlite3.Error):
        print('sentinel recovery capture failed', file=sys.stderr)
        return 1

if __name__ == '__main__':
    raise SystemExit(main())
