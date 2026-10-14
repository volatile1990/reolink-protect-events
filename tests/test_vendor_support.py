"""Integrity verification of release-local native dependencies; no native load."""
import hashlib
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from reolink_protect_events import vendor_support as vendor


def populate(root,files=None):
    files=files or {'PIL/__init__.py':b'__version__="11.3.0"\n','PIL/Image.py':b'fixture source\n',
                  'PIL/_imaging.cpython-39-aarch64-linux-gnu.so':b'\0nativebinary',
                  'pillow.libs/libjpeg.so':b'\0library'}
    for name,content in files.items():
        path=root/name;path.parent.mkdir(parents=True,exist_ok=True);path.write_bytes(content)
    manifest={'schemaVersion':1,'project':'pillow','version':'11.3.0','wheelSha256':'a'*64,
        'files':[{'path':name,'bytes':len(content),'sha256':hashlib.sha256(content).hexdigest()}
                 for name,content in sorted(files.items())]}
    (root/'integrity.json').write_text(json.dumps(manifest))
    return manifest


class VendorSupportTests(unittest.TestCase):
    def test_verified_inventory_and_binary_byte_preservation(self):
        with tempfile.TemporaryDirectory()as folder:
            root=Path(folder);manifest=populate(root)
            self.assertEqual(vendor.verify_vendor(root),manifest)
            self.assertEqual((root/'PIL/_imaging.cpython-39-aarch64-linux-gnu.so').read_bytes(),b'\0nativebinary')

    def test_modified_member_removed_member_and_extra_file_rejected(self):
        for mode in ('modified','removed','extra'):
            with self.subTest(mode=mode),tempfile.TemporaryDirectory()as folder:
                root=Path(folder);populate(root)
                if mode=='modified':(root/'PIL/Image.py').write_bytes(b'tampered source')
                elif mode=='removed':(root/'PIL/Image.py').unlink()
                else:(root/'PIL/extra.py').write_text('unverified source')
                with self.assertRaises(vendor.VendorError):vendor.verify_vendor(root)

    def test_nested_integrity_filename_is_not_an_inventory_exemption(self):
        with tempfile.TemporaryDirectory()as folder:
            root=Path(folder);populate(root);(root/'PIL/integrity.json').write_text('{"unverified":true}')
            with self.assertRaisesRegex(vendor.VendorError,'decoder_member_inventory_changed'):
                vendor.verify_vendor(root)

    def test_traversal_foreign_absolute_duplicate_and_invalid_project_rejected(self):
        for mode in ('traversal','foreign','absolute','duplicate','project','version'):
            with self.subTest(mode=mode),tempfile.TemporaryDirectory()as folder:
                root=Path(folder);manifest=populate(root)
                if mode=='traversal':manifest['files'][0]['path']='PIL/../../outside'
                elif mode=='foreign':manifest['files'][0]['path']='foreign/Image.py'
                elif mode=='absolute':manifest['files'][0]['path']='/PIL/Image.py'
                elif mode=='duplicate':manifest['files'].append(manifest['files'][0])
                elif mode=='project':manifest['project']='other'
                else:manifest['version']='12.0.0'
                (root/'integrity.json').write_text(json.dumps(manifest))
                with self.assertRaises(vendor.VendorError):vendor.verify_vendor(root)

    def test_native_file_budget_is_checked_before_reading_large_member(self):
        with tempfile.TemporaryDirectory()as folder:
            root=Path(folder);manifest=populate(root)
            target=root/'PIL/_imaging.cpython-39-aarch64-linux-gnu.so'
            with target.open('wb')as handle:handle.truncate(49*1024*1024)
            row=next(row for row in manifest['files']if row['path'].endswith('.so')and row['path'].startswith('PIL/'))
            row['bytes']=target.stat().st_size
            (root/'integrity.json').write_text(json.dumps(manifest))
            actual=Path.read_bytes
            def read(path):
                if path==target:self.fail('read before native file budget check')
                return actual(path)
            with patch.object(Path,'read_bytes',read),self.assertRaisesRegex(vendor.VendorError,'decoder_budget_exceeded'):
                vendor.verify_vendor(root)

    def test_symlink_member_is_rejected_without_loading_native_code(self):
        with tempfile.TemporaryDirectory()as folder:
            root=Path(folder);populate(root);target=root/'PIL/Image.py';actual=Path.is_symlink
            with patch.object(Path,'is_symlink',lambda path:True if path==target else actual(path)):
                with self.assertRaisesRegex(vendor.VendorError,'decoder_member_invalid'):vendor.verify_vendor(root)

    def test_integrity_failure_stops_before_any_import(self):
        with tempfile.TemporaryDirectory()as folder:
            package=Path(folder);root=package/'_vendor';root.mkdir();populate(root)
            (root/'PIL/Image.py').write_bytes(b'tampered')
            with patch.object(vendor,'__file__',str(package/'vendor_support.py')),patch.object(vendor,'_VERIFIED',False), \
                 patch.object(vendor.importlib,'import_module')as loader:
                with self.assertRaises(vendor.VendorError):vendor.ensure_pillow()
                loader.assert_not_called()


if __name__=='__main__':unittest.main()
