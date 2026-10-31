import importlib.util
import os
from pathlib import Path

spec = importlib.util.spec_from_file_location("supervisor", Path(__file__).with_name("supervisor.py"))
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


def test_rename_preserves_inode_and_reopens(tmp_path):
    active = tmp_path / "eve.json"
    active.write_bytes(b"12345")
    inode = active.stat().st_ino
    retention = module.Retention(tmp_path, rotate_bytes=4)
    assert retention.rotate(lambda: active.write_bytes(b"new"))
    archive, = tmp_path.glob("eve.json.*")
    assert archive.stat().st_ino == inode
    assert archive.read_bytes() == b"12345"
    assert active.read_bytes() == b"new"


def test_retention_caps_bytes_and_age_and_warns(tmp_path, caplog):
    (tmp_path / "eve.json").write_bytes(b"live")
    for i in range(4):
        (tmp_path / f"eve.json.{i:04d}").write_bytes(b"12345")
    os.utime(tmp_path / "eve.json.0000", (1, 1))
    retention = module.Retention(tmp_path, max_bytes=10)
    assert retention.prune() == 2
    assert sum(p.stat().st_size for p in tmp_path.glob("eve.json.*")) == 10
    assert "lagging shipper may lose unread alerts" in caplog.text
    assert (tmp_path / "eve.json").read_bytes() == b"live"


def test_never_unlink_archive_awaiting_reopen(tmp_path):
    (tmp_path / "eve.json.0001").write_bytes(b"still open")
    retention = module.Retention(tmp_path, max_bytes=1)
    assert retention.prune() == 0
