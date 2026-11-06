"""Capture recoverable local Sentinel files under the shipper's shared lock.

Output is sensitive tar data: callers must pipe it directly to encrypted backup,
never a terminal or plaintext disk. Restore remains isolated and manual.
"""
from __future__ import annotations
import io
import json
import os
import sqlite3
import sys
import tarfile
from pathlib import Path
from .recovery_lock import recovery_lock, check_handshake

MAX_BYTES = 128 * 1024 * 1024

def capture(state: Path, windows: Path, require_handshake: bool = False, eve: Path | None = None) -> bytes:
    contents = {}
    total = 0
    eve_status = 'not captured'
    model_status = 'not captured'
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
        model = state / 'model.joblib'
        if model.exists():
            if model.is_symlink() or not model.is_file() or total + model.stat().st_size > MAX_BYTES:
                raise ValueError('unsupported or oversized model')
            contents['state/model.joblib'] = model.read_bytes()
            total += len(contents['state/model.joblib'])
            if total > MAX_BYTES:
                raise ValueError('capture too large')
            model_status = 'opaque-manual-review'
        if eve is not None:
            checkpoint_path = state / 'eve_offset.json'
            if checkpoint_path.is_symlink() or not checkpoint_path.is_file() or checkpoint_path.stat().st_size > 4096:
                raise ValueError('EVE checkpoint missing')
            checkpoint = json.loads(checkpoint_path.read_bytes())
            inode, offset = checkpoint.get('inode'), checkpoint.get('offset')
            if not isinstance(inode, int) or not isinstance(offset, int) or inode < 1 or offset < 0:
                raise ValueError('invalid EVE checkpoint')
            candidates = sorted(eve.parent.glob(eve.name + '.[0-9]*'))
            if eve.exists():
                candidates.append(eve)
            stats = []
            for path in candidates:
                if path.is_symlink() or not path.is_file():
                    raise ValueError('unsupported EVE source')
                stats.append(path.stat())
            indices = [i for i, st in enumerate(stats) if st.st_ino == inode]
            if len(indices) != 1:
                raise ValueError('EVE checkpoint inode unavailable')
            first = indices[0]
            if offset > stats[first].st_size:
                raise ValueError('EVE checkpoint beyond end')
            selected = candidates[first:]
            for index, (path, st) in enumerate(zip(selected, stats[first:])):
                if total + st.st_size > MAX_BYTES:
                    raise ValueError('EVE capture too large')
                flags = os.O_RDONLY | getattr(os, 'O_NOFOLLOW', 0)
                fd = os.open(path, flags)
                try:
                    opened = os.fstat(fd)
                    if opened.st_ino != st.st_ino or opened.st_dev != st.st_dev or opened.st_size < st.st_size:
                        raise ValueError('EVE changed before read')
                    with os.fdopen(fd, 'rb', closefd=False) as stream:
                        data = stream.read(st.st_size)
                    if len(data) != st.st_size or os.fstat(fd).st_size < st.st_size:
                        raise ValueError('EVE truncated during read')
                    now = path.stat()
                    if path.is_symlink() or now.st_ino != st.st_ino or now.st_dev != st.st_dev:
                        raise ValueError('EVE rotated during capture')
                finally:
                    os.close(fd)
                if index == 0 and 0 < offset < len(data) and data[offset - 1:offset] != b'\n':
                    raise ValueError('EVE checkpoint is not a line boundary')
                name = f'eve/{index:06d}.ndjson'
                contents[name] = data
                total += len(data)
            checkpoint_copy = {'file': 'eve/000000.ndjson', 'offset': offset,
                               'source_inode': inode, 'files': len(selected),
                               'partial_last_line': bool(contents[f'eve/{len(selected)-1:06d}.ndjson']) and not contents[f'eve/{len(selected)-1:06d}.ndjson'].endswith(b'\n')}
            contents['eve/checkpoint.json'] = json.dumps(checkpoint_copy).encode()
            total += len(contents['eve/checkpoint.json'])
            if total > MAX_BYTES:
                raise ValueError('capture too large')
            eve_status = 'captured-offline-remap-required'
    # Build the archive after releasing the lock; no network or compression runs
    # inside the shipper's critical section.
    out = io.BytesIO()
    manifest = {'format': 1, 'queue_windows': 'coordinated-at-least-once',
                'eve_continuity': eve_status, 'model': model_status,
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
            allowed = (name == 'manifest.json' or name == 'state/state.db' or name == 'state/model.joblib' or name == 'eve/checkpoint.json' or (name.startswith('eve/') and name.endswith('.ndjson')) or
                       (name.startswith('state/queue/') and name.endswith('.json')) or
                       (name.startswith('state/quarantine/') and name.endswith(('.json', '.reason'))) or
                       (name.startswith('windows/') and name.endswith('.ndjson')))
            if not allowed or not member.isfile() or name in files or '..' in Path(name).parts or len(Path(name).parts) != (1 if name == 'manifest.json' else (2 if name in ('state/state.db', 'state/model.joblib', 'eve/checkpoint.json') or name.startswith(('windows/', 'eve/')) else 3)):
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
    eve_mode = manifest.get('eve_continuity')
    if eve_mode not in ('not captured', 'captured-offline-remap-required'):
        raise ValueError('unknown EVE capture mode')
    if eve_mode == 'not captured' and any(n.startswith('eve/') for n in files):
        raise ValueError('unexpected archived EVE')
    if eve_mode == 'captured-offline-remap-required':
        checkpoint = json.loads(files['eve/checkpoint.json'])
        first = checkpoint.get('file')
        if first != 'eve/000000.ndjson' or first not in files or not isinstance(checkpoint.get('offset'), int) or not 0 <= checkpoint['offset'] <= len(files[first]):
            raise ValueError('invalid archived EVE checkpoint')
        count = checkpoint.get('files')
        if not isinstance(count, int) or count < 1 or count > len(files) or {f'eve/{i:06d}.ndjson' for i in range(count)} != {n for n in files if n.startswith('eve/') and n.endswith('.ndjson')}:
            raise ValueError('archived EVE file count differs')
        offset = checkpoint['offset']
        if 0 < offset < len(files[first]) and files[first][offset - 1:offset] != b'\n':
            raise ValueError('archived EVE offset is not a line boundary')
    if manifest.get('model') not in ('not captured', 'opaque-manual-review') or (manifest.get('model') == 'opaque-manual-review') != ('state/model.joblib' in files):
        raise ValueError('model manifest differs')
    # Captured queue items are never automatically replayed. They may have been
    # accepted since capture or aged beyond ingest/idempotency limits.
    return {'entries': len(files) - 1, 'sqlite_integrity': 'ok',
            'queued_items': sum(n.startswith('state/queue/') for n in files),
            'replay': 'manual-review-only', 'eve_continuity': manifest['eve_continuity'],
            'model': manifest['model']}

def main() -> int:
    try:
        sys.stdout.buffer.write(capture(Path('/var/lib/sentinel/state'), Path('/var/lib/sentinel/windows'), require_handshake=True, eve=Path('/var/log/suricata/eve.json')))
        return 0
    except (OSError, ValueError, sqlite3.Error):
        print('sentinel recovery capture failed', file=sys.stderr)
        return 1

if __name__ == '__main__':
    raise SystemExit(main())
