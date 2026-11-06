import importlib.util
from pathlib import Path
from unittest import mock
import pytest

path=Path(__file__).resolve().parents[1]/'scripts/backup_coordinated.py'
spec=importlib.util.spec_from_file_location('backup_coordinated',path)
m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)

def test_image_identity_is_required():
    with pytest.raises(ValueError): m.verify_image('not-an-image')
    with mock.patch.object(m,'run',return_value=b'sha256:'+b'0'*64+b'\n'):
        with pytest.raises(ValueError): m.verify_image('sha256:'+'1'*64)

def test_restore_mismatch_fails():
    image='sha256:'+'1'*64
    def run(args,data=None):
        if args[:2]==['docker','inspect']: return (image+'\n').encode()
        if args[:2]==['docker','exec'] and '-m' in args: return b'private archive'
        if args[:2]==['docker','exec']: return b'{"sqlite_integrity":"ok","replay":"manual-review-only"}'
        if 'backup' in args: return b'{"message_type":"summary","snapshot_id":"abcdef12"}'
        return b'tampered'
    with mock.patch.object(m,'run',side_effect=run), pytest.raises(ValueError): m.backup(image)
