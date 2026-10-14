"""Release content/integrity boundaries and a real local SQLite journal backup."""
import hashlib
import io
import json
import os
from contextlib import closing
from pathlib import Path
import sqlite3
import stat
import tempfile
import time
import unittest
from unittest.mock import patch
import warnings
import zipfile

from reolink_protect_events.operations import release

# Importing the remote installer changes umask by design; isolate that effect.
previous_umask=os.umask(0o077)
from reolink_protect_events.operations import installer
os.umask(previous_umask)


def wheel(entries=None,duplicate=False):
    entries=entries or {'PIL/__init__.py':b'__version__="11.3.0"\r\n',
        'PIL/Image.py':b'fixture decoder source\r\n',
        'PIL/_imaging.cpython-39-aarch64-linux-gnu.so':b'\0\xffnative\r\n',
        'pillow.libs/libjpeg.so.62':b'\0\xfflibrary\r\n',
        'pillow-11.3.0.dist-info/licenses/LICENSE':b'license\n'}
    output=io.BytesIO()
    with zipfile.ZipFile(output,'w',zipfile.ZIP_DEFLATED)as archive:
        for name,content in entries.items():archive.writestr(name,content)
        if duplicate:
            with warnings.catch_warnings():
                warnings.simplefilter('ignore');archive.writestr('PIL/Image.py',b'again')
    return output.getvalue()


def manifest(content):
    return {'project':'pillow','version':'11.3.0','python':'cp39','architecture':'aarch64',
        'sha256':hashlib.sha256(content).hexdigest(),'bytes':len(content),
        'filename':'pillow-11.3.0-cp39-cp39-manylinux2014_aarch64.whl',
        'url':'https://files.pythonhosted.org/packages/fixture.whl'}


def package(entries=None,metadata=None,symlink=None,duplicate=False):
    entries=entries or {'reolink_protect_events/runtime.py':b'fixture runtime\n',
        'reolink_protect_events/operations/monitor.py':b'fixture monitor\n',
        'reolink_protect_events/_vendor/integrity.json':b'{}'}
    metadata=metadata or {'schemaVersion':1,'project':'reolink-protect-events','version':'1.0.0',
        'sourceRevision':'a'*40,'sourceSha256':'b'*64,
        'members':[{'path':name,'bytes':len(content),'sha256':hashlib.sha256(content).hexdigest()}
                   for name,content in sorted(entries.items())]}
    output=io.BytesIO()
    with zipfile.ZipFile(output,'w',zipfile.ZIP_DEFLATED)as archive:
        for name,content in entries.items():
            info=zipfile.ZipInfo(name);info.compress_type=zipfile.ZIP_DEFLATED
            info.external_attr=(stat.S_IFLNK|0o700 if name==symlink else stat.S_IFREG|0o600)<<16
            archive.writestr(info,content)
        archive.writestr('reolink_protect_events/release.json',json.dumps(metadata))
        if duplicate:
            with warnings.catch_warnings():
                warnings.simplefilter('ignore');archive.writestr('reolink_protect_events/runtime.py',b'again')
    data=output.getvalue()
    return data,hashlib.sha256(data).hexdigest()


class ReleaseTests(unittest.TestCase):
    def test_canonical_text_crlf_binary_unchanged(self):
        self.assertEqual(release.canonical(b'a\r\nb\r\n'),b'a\nb\n')
        for binary in (b'\xff\r\n',b'\0native\r\n',b'\x89PNG\r\n'):
            self.assertEqual(release.canonical(binary),binary)

    def test_member_traversal_absolute_windows_and_null_rejected(self):
        for name in ('../PIL/Image.py','PIL/../../Image.py','/PIL/Image.py',
                     'PIL\\Image.py','C:/PIL/Image.py','PIL/Image.py\0'):
            with self.subTest(name=name),self.assertRaises(release.ReleaseError):release.member_name(name)

    def test_pinned_wheel_digest_mismatch_fails_before_member_use(self):
        content=wheel()
        with tempfile.TemporaryDirectory()as folder:
            root=Path(folder);(root/'dependencies').mkdir()
            (root/'dependencies/pillow-cp39-aarch64.json').write_text(json.dumps(manifest(content)))
            with self.assertRaisesRegex(release.ReleaseError,'dependency_digest_mismatch'):
                release.dependency_bytes(root,downloader=lambda *_:content+b'bad')
            observed,actual=release.dependency_bytes(root,downloader=lambda *_:content)
            self.assertEqual(actual,content);self.assertEqual(observed['version'],'11.3.0')

    def test_native_wheel_layout_raw_binary_and_exact_integrity_members(self):
        content=wheel();members=release.vendor_members(manifest(content),content)
        prefix='reolink_protect_events/_vendor/'
        integrity=json.loads(members[prefix+'integrity.json'])
        self.assertEqual(members[prefix+'PIL/Image.py'],b'fixture decoder source\r\n')
        self.assertEqual(members[prefix+'PIL/_imaging.cpython-39-aarch64-linux-gnu.so'],b'\0\xffnative\r\n')
        self.assertEqual({row['path']for row in integrity['files']},
                         {name[len(prefix):]for name in members if name!=prefix+'integrity.json'})
        for row in integrity['files']:
            self.assertEqual(hashlib.sha256(members[prefix+row['path']]).hexdigest(),row['sha256'])

    def test_wheel_unknown_path_duplicate_missing_decoder_and_symlink_rejected(self):
        for content in (wheel({'../PIL/Image.py':b'x'}),wheel({'other/Image.py':b'x'}),
                        wheel(duplicate=True),wheel({'PIL/Image.py':b'x'})):
            with self.assertRaises(release.ReleaseError):release.vendor_members(manifest(content),content)
        output=io.BytesIO()
        with zipfile.ZipFile(output,'w')as archive:
            info=zipfile.ZipInfo('PIL/Image.py');info.external_attr=(stat.S_IFLNK|0o777)<<16
            archive.writestr(info,'/outside')
        with self.assertRaisesRegex(release.ReleaseError,'dependency_member_invalid'):
            release.vendor_members(manifest(output.getvalue()),output.getvalue())

    def test_wheel_budget_checked_before_decompression(self):
        info=zipfile.ZipInfo('PIL/large.so');info.file_size=49*1024*1024
        with patch.object(release.zipfile,'ZipFile')as archive:
            current=archive.return_value.__enter__.return_value;current.infolist.return_value=[info]
            with self.assertRaisesRegex(release.ReleaseError,'dependency_budget_exceeded'):
                release.vendor_members({'sha256':'a'*64},b'fixture')
            current.read.assert_not_called()

    def test_package_recursion_static_json_canonical_and_exact_declared_members(self):
        with tempfile.TemporaryDirectory()as folder:
            root=Path(folder);pkg=root/'reolink_protect_events';(pkg/'operations').mkdir(parents=True)
            (root/'compatibility').mkdir()
            (pkg/'__init__.py').write_bytes(b'__version__ = "1.0.0"\r\n')
            (pkg/'runtime.py').write_bytes(b'line one\r\nline two\r\n')
            (pkg/'operations/monitor.py').write_bytes(b'monitor\r\n')
            (root/'compatibility/contract.json').write_bytes(b'{"schemaVersion":1}\r\n')
            snapshot={'sourceRevision':'a'*40,'sourceDirty':False,'sourceSha256':'b'*64,'sourceFiles':4}
            with patch.object(release,'source_snapshot',return_value=snapshot):
                data,meta=release.build_package(root,include_dependency=False)
                other,other_meta=release.build_package(root,include_dependency=False)
            self.assertEqual(data,other);self.assertEqual(meta,other_meta)
            with zipfile.ZipFile(io.BytesIO(data))as archive:
                names=set(archive.namelist());actual=json.loads(archive.read('reolink_protect_events/release.json'))
                self.assertIn('reolink_protect_events/operations/monitor.py',names)
                self.assertIn('reolink_protect_events/compatibility/contract.json',names)
                self.assertEqual(archive.read('reolink_protect_events/runtime.py'),b'line one\nline two\n')
                self.assertEqual(names,{r['path']for r in actual['members']}|{'reolink_protect_events/release.json'})

    def test_static_json_symlink_is_rejected(self):
        with tempfile.TemporaryDirectory()as folder:
            root=Path(folder).resolve();pkg=root/'reolink_protect_events';pkg.mkdir();(root/'compatibility').mkdir()
            (pkg/'__init__.py').write_text('__version__ = "1.0.0"')
            target=root/'compatibility/contract.json';target.write_text('{}')
            actual=Path.is_symlink
            with patch.object(release,'source_snapshot',return_value={}), \
                 patch.object(Path,'is_symlink',lambda path:True if path==target else actual(path)):
                with self.assertRaisesRegex(release.ReleaseError,'release_symlink_invalid'):
                    release.build_package(root,include_dependency=False)


class InstallerVerificationTests(unittest.TestCase):
    def test_exact_package_members_hash_and_manifest_required(self):
        data,digest=package();members,meta=installer.verified_members(data,digest)
        self.assertEqual(len(members),len(meta['members'])+1)
        with self.assertRaisesRegex(RuntimeError,'package_digest_mismatch'):
            installer.verified_members(data,'0'*64)
        with self.assertRaisesRegex(RuntimeError,'package_inventory_invalid'):
            wrong,checksum=package(metadata={'schemaVersion':1,'project':'reolink-protect-events','members':[]})
            installer.verified_members(wrong,checksum)

    def test_member_tamper_duplicate_symlink_and_traversal_rejected(self):
        data,digest=package();_,meta=installer.verified_members(data,digest)
        changed=json.loads(json.dumps(meta));changed['members'][0]['sha256']='0'*64
        data,digest=package(metadata=changed)
        with self.assertRaisesRegex(RuntimeError,'package_member_changed'):installer.verified_members(data,digest)
        for data,digest in (package(duplicate=True),package(symlink='reolink_protect_events/runtime.py'),
                            package({'reolink_protect_events/../../outside':b'x'})):
            with self.assertRaises(RuntimeError):installer.verified_members(data,digest)

    def test_manifest_budget_is_checked_before_read(self):
        data,digest=package()
        actual=zipfile.ZipFile.read
        def guarded(archive,name,*args,**kwargs):
            if name=='reolink_protect_events/release.json':
                self.fail('Oversized ZIP metadata decompressed before budget validation')
            return actual(archive,name,*args,**kwargs)
        original=zipfile.ZipFile.infolist
        def declared(archive):
            infos=original(archive)
            next(info for info in infos if info.filename=='reolink_protect_events/release.json').file_size=17*1024*1024
            return infos
        with patch.object(zipfile.ZipFile,'infolist',declared),patch.object(zipfile.ZipFile,'read',guarded):
            with self.assertRaisesRegex(RuntimeError,'package_budget_exceeded'):
                installer.verified_members(data,digest)

    def test_sqlite_backup_uses_real_journal_filename_and_rollback_keeps_new_events(self):
        with tempfile.TemporaryDirectory()as folder:
            base=Path(folder);root=base/'events';root.mkdir();monitor=base/'monitor';monitor.mkdir()
            owner='a'*32;(monitor/'maintenance.json').write_text(json.dumps({'owner':owner}))
            unit=base/'events.service';unit.write_text('old events unit')
            monitor_unit=base/'monitor.service';monitor_unit.write_text('old monitor unit')
            (root/'config.json').write_text('{}');journal=root/'journal.sqlite3'
            with closing(sqlite3.connect(journal))as database:
                database.execute('CREATE TABLE fixture_events(sequence INTEGER)')
                database.execute('INSERT INTO fixture_events VALUES(7)')
                database.commit()
            archive,digest=package()
            def run(args):
                if args[:2]==['systemctl','start']and args[-1]==unit.name:
                    with closing(sqlite3.connect(journal))as database:
                        database.execute('INSERT INTO fixture_events VALUES(23)');database.commit()
                return 'active'
            health={'health':{'atMs':int(time.time()*1000)+100000,'mode':'native','healthy':True},
                    'monitor':{'active':True,'enabled':True}}
            with patch.object(installer,'root',root),patch.object(installer,'monitor_root',monitor), \
                 patch.object(installer,'unit',unit),patch.object(installer,'monitor_unit',monitor_unit), \
                 patch.object(installer,'service',unit.name),patch.object(installer,'secure'), \
                 patch.object(installer.os,'geteuid',return_value=0,create=True), \
                 patch.object(installer,'get_config',return_value={'bridges':[]}), \
                 patch.object(installer,'run',side_effect=run),patch.object(installer,'health',return_value=health), \
                 patch.object(installer,'state_of',side_effect=lambda _:{'active':True,'enabled':True}), \
                 patch.object(installer.subprocess,'run'):
                import base64
                result=installer.execute({'mode':'install','package':base64.b64encode(archive).decode(),
                                          'digest':digest,'owner':owner})
                self.assertTrue(result['journalBackedUp'])
                backups=list((root/'backups').iterdir());self.assertEqual(len(backups),1)
                with closing(sqlite3.connect(backups[0]/'journal.sqlite3'))as database:
                    self.assertEqual(database.execute('SELECT sequence FROM fixture_events').fetchall(),[(7,)])
                installer.restore(backups[0])
                with closing(sqlite3.connect(journal))as database:
                    self.assertIn((23,),database.execute('SELECT sequence FROM fixture_events').fetchall())
            self.assertEqual(unit.read_text(),'old events unit')


if __name__=='__main__':unittest.main()
