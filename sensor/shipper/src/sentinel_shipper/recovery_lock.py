"""Cooperate with recovery capture across shipper ticks and sender drains."""
from contextlib import contextmanager
import fcntl
import time
from pathlib import Path

@contextmanager
def recovery_lock(state_dir: Path, timeout: float = 60):
    state_dir.mkdir(parents=True, exist_ok=True)
    with (state_dir / 'recovery.lock').open('a') as lock:
        deadline = time.monotonic() + timeout
        while True:
            try:
                fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
                break
            except BlockingIOError:
                if time.monotonic() >= deadline:
                    raise TimeoutError('recovery lock timeout')
                time.sleep(0.05)
        try:
            yield
        finally:
            fcntl.flock(lock, fcntl.LOCK_UN)

PROTOCOL = 1

def process_start_ticks(pid: int) -> str:
    # Fields after the last ')' start at Linux stat field 3; starttime is 22.
    raw = Path(f'/proc/{pid}/stat').read_text()
    return raw.rsplit(')', 1)[1].split()[19]

def write_handshake(state_dir: Path) -> None:
    import json, os, tempfile
    marker = {'protocol': PROTOCOL, 'pid': os.getpid(),
              'start_ticks': process_start_ticks(os.getpid()),
              'boot_id': Path('/proc/sys/kernel/random/boot_id').read_text().strip()}
    with tempfile.NamedTemporaryFile(mode='w', dir=state_dir, delete=False) as f:
        json.dump(marker, f); f.write('\n'); temporary = Path(f.name)
    os.chmod(temporary, 0o600)
    temporary.replace(state_dir / 'recovery-protocol.json')

def check_handshake(state_dir: Path) -> None:
    import json
    marker = json.loads((state_dir / 'recovery-protocol.json').read_text())
    if (marker.get('protocol') != PROTOCOL or marker.get('pid') != 1 or
        marker.get('start_ticks') != process_start_ticks(1) or
        marker.get('boot_id') != Path('/proc/sys/kernel/random/boot_id').read_text().strip()):
        raise ValueError('running shipper recovery handshake mismatch')
