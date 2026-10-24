"""Fenced, renewable automatic maintenance; legacy/manual markers stay private.

An expired timestamp is never permission to race an active mutation. Orphans
are archived only after every known deployment/mutation lock is available.
Expired owner UUIDs cannot acquire or renew another lease.
"""
from contextlib import ExitStack, contextmanager
import os
from pathlib import Path
import re
import time

from .locking import process_lock
from .safety import need, private_path, read_json, write_json

TTL_MS = 180000
_FIXTURE_BOOT = 'fixture-' + str(os.getpid())


def identity():
    path=Path('/proc/sys/kernel/random/boot_id')
    return path.read_text().strip() if path.is_file() else _FIXTURE_BOOT


def _now():
    return int((time.clock_gettime(time.CLOCK_BOOTTIME)if hasattr(time,'CLOCK_BOOTTIME')else time.monotonic())*1000)


def _owner(owner):
    need(isinstance(owner,str) and re.fullmatch('[a-f0-9]{32}',owner),'maintenance_owner_invalid')


def _fsync_directory(path):
    if os.name=='nt':return
    fd=os.open(str(path),os.O_RDONLY|os.O_DIRECTORY|getattr(os,'O_NOFOLLOW',0))
    try:os.fsync(fd)
    finally:os.close(fd)


def status(root, *, monotonic_ms=None, boot_id=None):
    path=Path(root)/'maintenance.json'
    if not path.exists() and not path.is_symlink():return {'active':False,'automatic':False,'expired':False}
    result={'active':True,'automatic':False,'expired':False,'requiresReview':True}
    if path.is_symlink():return result
    if path.stat().st_nlink!=1:return result
    try:value=read_json(path)
    except Exception:return result
    owner=value.get('owner')
    if not isinstance(owner,str) or re.fullmatch('[a-f0-9]{32}',owner) is None:return result
    result['owner']=owner
    if value.get('schemaVersion')!=2 or value.get('mode')!='automatic':return result
    expires=value.get('expiresAtMonotonicMs');ttl=value.get('ttlMs')
    renewed=value.get('renewedMonotonicMs');boot=value.get('bootId')
    if not (type(expires)is int and type(renewed)is int and renewed>=0 and type(ttl)is int
            and 30000<=ttl<=600000 and expires==renewed+ttl and isinstance(boot,str) and 1<=len(boot)<=80):return result
    now=_now()if monotonic_ms is None else monotonic_ms
    current=identity()if boot_id is None else boot_id
    expired=boot!=current or now<renewed or now>=expires
    return {'active':True,'automatic':True,'expired':expired,'requiresReview':False,
            'owner':owner,'bootId':boot,'expiresAtMonotonicMs':expires}


def _retired(root):
    path=Path(root)/'retired-maintenance'
    private_path(path,directory=True)
    if not path.exists():path.mkdir(mode=0o700);_fsync_directory(path.parent)
    return private_path(path,directory=True)


def _mutation_paths(root):
    paths=[Path(root)/'mutation.lock']
    if Path(root)==Path('/srv/cameras/protect/state/monitor'):
        paths += [Path('/srv/cameras/protect/deployment.lock'),Path('/srv/cameras/bridges/.reolink-release.lock')]
    return paths


def _mutation_locks(stack,root):
    for path in _mutation_paths(root):
        private_path(path)
        stack.enter_context(process_lock(path))


def change(root, owner, enable, *, monotonic_ms=None, boot_id=None, ttl_ms=TTL_MS):
    _owner(owner);need(type(enable)is bool,'maintenance_enable_invalid')
    root=private_path(root,directory=True)
    if not root.exists():root.mkdir(parents=True,mode=0o700)
    need(type(ttl_ms)is int and 30000<=ttl_ms<=600000,'maintenance_ttl_invalid')
    now=_now()if monotonic_ms is None else monotonic_ms
    boot=identity()if boot_id is None else boot_id
    if enable:
        # A new explicit controller can recover a crash without waiting for
        # the next monitor sample. The same mutation locks still gate cleanup.
        reconcile(root,monotonic_ms=now,boot_id=boot)
    with process_lock(root/'maintenance-lease.lock'),ExitStack()as stack:
        path=root/'maintenance.json';state=status(root,monotonic_ms=now,boot_id=boot)
        tombstone=_retired(root)/(owner+'.json')
        need(not tombstone.exists()and not tombstone.is_symlink(),'maintenance_owner_expired')
        if state['active']:
            need(state.get('owner')==owner,'maintenance_owned_by_other_rollout')
            if state['automatic']:need(not state['expired'],'maintenance_owner_expired')
            elif enable:
                # An existing legacy/manual barrier is never silently promoted.
                return {'ok':True,'maintenance':True,'owner':owner,'manual':True,'requiresReview':True}
            if not enable:
                _mutation_locks(stack,root)
                path.unlink();_fsync_directory(root)
                return {'ok':True,'maintenance':False,'owner':owner}
        elif not enable:return {'ok':True,'maintenance':False,'owner':owner}
        else:
            # Fence against a recovery or deployment that entered before this
            # first lease. Renewal intentionally does not take mutation locks.
            _mutation_locks(stack,root)
            receipt=root/'recovery.json'
            need(not receipt.exists()or read_json(receipt).get('phase')=='complete',
                 'maintenance_pending_restoration')
        previous=read_json(path)if path.exists()else{}
        value={'schemaVersion':2,'mode':'automatic','owner':owner,'bootId':boot,
               'ttlMs':ttl_ms,'renewedMonotonicMs':now,'expiresAtMonotonicMs':now+ttl_ms,
               'atMs':previous.get('atMs',int(time.time()*1000)),'renewedAtMs':int(time.time()*1000)}
        write_json(path,value)
        return {'ok':True,'maintenance':True,'owner':owner,'automatic':True,'ttlMs':ttl_ms,
                'expiresAtMonotonicMs':now+ttl_ms}


def blocks(root, owner=None):
    value=status(root)
    if owner is None:return value['active']
    _owner(owner)
    return not value['active'] or value.get('owner')!=owner or value.get('expired')is True


@contextmanager
def mutation_guard(root, owner=None):
    """Hold across a whole mutating RPC so orphan cleanup cannot overlap it."""
    root=Path(root)
    with process_lock(root/'mutation.lock'):
        need(not blocks(root,owner),'maintenance_mutation_fenced')
        yield


def reconcile(root, *, monotonic_ms=None, boot_id=None, extra_locks=None):
    root=Path(root)
    result=status(root,monotonic_ms=monotonic_ms,boot_id=boot_id)
    if not result.get('automatic') or not result.get('expired'):return dict(result,orphanArchived=False)
    locks=_mutation_paths(root)
    if extra_locks:locks+=list(extra_locks)
    try:
        with process_lock(root/'maintenance-lease.lock'),ExitStack()as stack:
            current=status(root,monotonic_ms=monotonic_ms,boot_id=boot_id)
            if current!=result:return dict(current,orphanArchived=False)
            for path in locks:
                private_path(path)
                stack.enter_context(process_lock(path))
            path=root/'maintenance.json';raw=path.read_bytes();value=read_json(path)
            need(value.get('owner')==result['owner'],'maintenance_reconcile_drift')
            archive=_retired(root)/(result['owner']+'.json')
            need(not archive.exists()and not archive.is_symlink(),'maintenance_owner_already_retired')
            need(path.read_bytes()==raw,'maintenance_reconcile_drift')
            os.rename(path,archive);_fsync_directory(root);_fsync_directory(archive.parent)
            return {'active':False,'automatic':False,'expired':False,'orphanArchived':True,
                    'retiredOwner':result['owner']}
    except (OSError,RuntimeError):
        return dict(result,orphanArchived=False,waitingForMutation=True)
