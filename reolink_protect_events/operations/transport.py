"""Run shipped public operations through SSH stdin; retain private config remotely."""
import base64
import io
import json
from pathlib import Path
import re
import shlex
import subprocess
import zipfile
import threading
import time
from contextlib import contextmanager


def _lease_clock():
    # Include suspend time. CLOCK_MONOTONIC alone pauses during Linux suspend.
    if hasattr(time,'CLOCK_BOOTTIME'):return time.clock_gettime(time.CLOCK_BOOTTIME)
    if __import__('os').name=='nt':
        import ctypes
        function=ctypes.windll.kernel32.GetTickCount64
        function.restype=ctypes.c_ulonglong
        return function()/1000
    return time.monotonic()


BOOTSTRAP = r'''
import base64,importlib.abc,importlib.util,io,json,pathlib,sys,zipfile
bundle=json.load(sys.stdin)
archive=zipfile.ZipFile(io.BytesIO(base64.b64decode(bundle['sources'],validate=True)))
class Owned(importlib.abc.MetaPathFinder,importlib.abc.Loader):
 def find_spec(self,name,path=None,target=None):
  stem=name.replace('.','/')
  for member,package in ((stem+'/__init__.py',True),(stem+'.py',False)):
   if member in archive.namelist():
    spec=importlib.util.spec_from_loader(name,self,is_package=package);spec.origin='<owned>/'+member;return spec
 def create_module(self,spec):return None
 def exec_module(self,module):
  stem=module.__name__.replace('.','/')
  member=stem+'/__init__.py' if module.__spec__.submodule_search_locations is not None else stem+'.py'
  module.__file__='<owned>/'+member
  exec(compile(archive.read(member),module.__file__,'exec'),module.__dict__)
sys.meta_path.insert(0,Owned())
try:
 from reolink_protect_events.operations.safety import private_path,read_json
 request=bundle['request'];action=request['action']
 if action=='installer':
  from reolink_protect_events.operations.installer import execute
  if request['request'].get('mode')in('install','capture','rollback'):
   from reolink_protect_events.operations.maintenance_lease import mutation_guard
   if request['request'].get('owner')is None:raise RuntimeError('installer_requires_owned_maintenance')
   with mutation_guard(pathlib.Path('/data/reolink-protect-monitor'),request['request'].get('owner')):
    result=execute(request['request'])
  else:result=execute(request['request'])
 else:
  path=pathlib.Path(request.get('configPath','/data/reolink-protect-events/config.json'))
  if path.as_posix()!='/data/reolink-protect-events/config.json':raise RuntimeError('config_scope_invalid')
  marker=pathlib.Path('/data/reolink-protect-connector/server-architecture.json')
  if action=='compatibility' and (marker.exists() or marker.is_symlink()):
   path=pathlib.Path('/data/reolink-protect-connector/compatibility.json')
  config=read_json(private_path(path))
  if action=='compatibility':
   from reolink_protect_events.operations.compatibility import assess
   result=assess(config)
  elif action=='health':
   from reolink_protect_events.operations.media_health import run_once
   result=run_once(config,mode=request.get('mode','quick'),prior=request.get('prior'),camera_ids=request.get('cameraIds'))
  elif action=='recover':
   from reolink_protect_events.operations.recovery import rebuild
   from reolink_protect_events.operations.safety import ensure_root
   result=rebuild(config,ensure_root('/data/reolink-protect-monitor'),request['cameraId'],maintenance_owner=request.get('owner'))
  elif action=='monitor-status':
   from reolink_protect_events.operations.installer import state_of,monitor_root,monitor_unit
   result={'ok':True,'service':state_of(monitor_unit.name)}
   for name in ('health','state'):
    p=monitor_root/(name+'.json')
    if p.exists():result[name]=read_json(p)
  elif action=='event-evidence':
   from reolink_protect_events.operations.evidence import inspect
   result=inspect(config)
  else:raise RuntimeError('operation_action_invalid')
 print(json.dumps(result))
except Exception as error:
 print(json.dumps({'ok':False,'errorCode':getattr(error,'code','remote_operation_failed'),'errorType':type(error).__name__}))
'''


# Keep the new host paths in a separate dispatcher. A caller cannot select a
# config/state path, install an old UDM package, or fall back to the retired UDM
# journal when the server profile is selected.
SERVER_BOOTSTRAP = BOOTSTRAP[:BOOTSTRAP.index('try:\n from reolink_protect_events.operations.safety')] + r'''
try:
 from reolink_protect_events.operations.safety import private_path,read_json,ensure_root
 from reolink_protect_events.remote import settings
 request=bundle['request'];action=request['action']
 if 'configPath' in request:raise RuntimeError('server_config_override_forbidden')
 root=pathlib.Path('/srv/cameras/protect')
 config=read_json(private_path(root/'config/events.json'))
 remote=settings(config)
 if remote is None or remote['sshAlias']!='udm-protect':raise RuntimeError('server_remote_profile_required')
 if action=='health':
  from reolink_protect_events.operations.media_health import run_once
  result=run_once(config,mode=request.get('mode','quick'),prior=request.get('prior'),camera_ids=request.get('cameraIds'))
 elif action=='recover':
  from reolink_protect_events.operations.recovery import rebuild
  result=rebuild(config,ensure_root(root/'state/monitor'),request['cameraId'],maintenance_owner=request.get('owner'))
 elif action=='monitor-status':
  from reolink_protect_events.operations.installer import state_of
  result={'ok':True,'service':state_of('reolink-protect-media-monitor.service')}
  for name in ('health','state'):
   path=root/'state/monitor'/(name+'.json')
   if path.exists():result[name]=read_json(private_path(path))
 elif action=='event-evidence':
  from reolink_protect_events.operations.evidence import inspect
  result=inspect(config,root=root/'state/events')
 elif action=='installer' and request.get('request',{}).get('mode')=='maintenance':
  from reolink_protect_events.operations import installer
  installer.monitor_root=ensure_root(root/'state/monitor')
  value=request['request']
  if type(value.get('enable'))is not bool:raise RuntimeError('server_maintenance_enable_invalid')
  result=installer.maintenance(value['owner'],value['enable'])
 else:raise RuntimeError('server_operation_action_invalid')
 print(json.dumps(result))
except Exception as error:
 print(json.dumps({'ok':False,'errorCode':getattr(error,'code','server_operation_failed'),'errorType':type(error).__name__}))
'''


def source_bundle(repo):
    root = Path(repo).resolve()
    output = io.BytesIO()
    with zipfile.ZipFile(output, 'w', zipfile.ZIP_DEFLATED) as archive:
        for path in sorted((root / 'reolink_protect_events').rglob('*.py')):
            if '_vendor' in path.parts or '__pycache__' in path.parts:
                continue
            if path.is_symlink():
                raise ValueError('operation_source_symlink')
            archive.writestr(str(path.relative_to(root)).replace('\\', '/'), path.read_bytes())
    return base64.b64encode(output.getvalue()).decode()


def invoke(repo, host, request, timeout=150, sources=None):
    if not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_.-]{0,127}', host):
        raise ValueError('trusted_ssh_alias_required')
    payload = json.dumps({'sources': sources if sources is not None else source_bundle(repo), 'request': request})
    command = 'python3 -c ' + shlex.quote(BOOTSTRAP)
    response = subprocess.run(['ssh', '-o', 'BatchMode=yes', '-o', 'ConnectTimeout=10', '-o', 'StrictHostKeyChecking=yes', host, command],
                              input=payload, text=True, capture_output=True, timeout=timeout)
    try:
        result = json.loads(response.stdout)
    except (ValueError, TypeError):
        raise RuntimeError('operation_transport_failed') from None
    if response.returncode != 0 or not isinstance(result, dict) or type(result.get('ok')) is not bool:
        raise RuntimeError('operation_transport_failed')
    return result


def invoke_server(repo, host, request, timeout=180, sources=None):
    if host != 'heimserver':
        raise ValueError('heimserver_ssh_alias_required')
    payload = json.dumps({'sources': sources if sources is not None else source_bundle(repo), 'request': request})
    command = 'sudo -n python3 -B -c ' + shlex.quote(SERVER_BOOTSTRAP)
    try:
        response = subprocess.run(['ssh', '-T', '-oBatchMode=yes', '-oConnectTimeout=10',
                                   '-oStrictHostKeyChecking=yes', host, command],
                                  input=payload, text=True, stdout=subprocess.PIPE,
                                  stderr=subprocess.DEVNULL, timeout=timeout)
        if response.returncode != 0 or len(response.stdout) > 8 * 1024 * 1024:
            raise RuntimeError('server_operation_transport_failed')
        result = json.loads(response.stdout)
        if not isinstance(result, dict) or type(result.get('ok')) is not bool:
            raise RuntimeError('server_operation_transport_failed')
        return result
    except (OSError, subprocess.TimeoutExpired, ValueError, TypeError):
        raise RuntimeError('server_operation_transport_failed') from None


class MaintenanceLease:
    """Client heartbeat for the existing private automatic-maintenance RPC.

    send receives one public request, must enforce its own finite timeout, and
    never returns credentials. check() fences every later deployment step if a
    heartbeat becomes uncertain. stop(release=False) lets orphan reconciliation
    deal with an interrupted transaction instead of creating an endless marker.
    """
    def __init__(self,send,owner,*,interval_seconds=30,progress_timeout_seconds=300,clock=None):
        if not isinstance(owner,str)or re.fullmatch('[a-f0-9]{32}',owner)is None:
            raise ValueError('maintenance_owner_invalid')
        if type(interval_seconds)not in(int,float)or not 0<interval_seconds<=60:
            raise ValueError('maintenance_heartbeat_interval_invalid')
        if type(progress_timeout_seconds)not in(int,float)or not 0<progress_timeout_seconds<=7200:
            raise ValueError('maintenance_progress_timeout_invalid')
        self.send=send;self.owner=owner;self.interval=interval_seconds
        self.stopping=threading.Event();self.failure=None;self.thread=None
        self.clock=clock or _lease_clock
        self.progress_timeout=progress_timeout_seconds
        self.confirmed_until=None;self.progress_until=None;self.activities=[]
        self.state_lock=threading.Lock()

    def _fence(self,code):
        if self.failure is None:self.failure=code
        self.stopping.set()
        raise RuntimeError(self.failure)

    def _valid(self,*,initial=False,allow_stopped=False):
        if self.failure is not None:raise RuntimeError(self.failure)
        if self.stopping.is_set()and not allow_stopped:raise RuntimeError('maintenance_lease_closed')
        now=self.clock()
        if not initial:
            if self.confirmed_until is None or now>=self.confirmed_until:self._fence('maintenance_confirmation_expired')
            deadline=min(item[1]for item in self.activities)if self.activities else self.progress_until
            if deadline is None or now>=deadline:self._fence('maintenance_controller_progress_stalled')
        return now

    def _request(self,enabled,*,initial=False):
        with self.state_lock:
            began=self._valid(initial=initial,allow_stopped=not enabled)
        value=self.send({'action':'installer','request':{'mode':'maintenance','owner':self.owner,'enable':enabled}})
        if not isinstance(value,dict)or value.get('ok')is not True or value.get('manual')is True:
            if isinstance(value,dict)and value.get('errorCode')in('maintenance_owner_expired',
                    'maintenance_pending_restoration','maintenance_owned_by_other_rollout'):
                raise RuntimeError(value['errorCode'])
            raise RuntimeError('automatic_maintenance_lease_failed')
        if enabled:
            ttl=value.get('ttlMs',180000)
            if type(ttl)is not int or not 30000<=ttl<=600000:raise RuntimeError('maintenance_confirmation_invalid')
            deadline=began+ttl/1000-min(5,ttl/10000)
            with self.state_lock:
                self._valid(initial=initial)
                if self.clock()>=deadline:self._fence('maintenance_confirmation_expired')
                self.confirmed_until=deadline
                if initial:self.progress_until=self.clock()+self.progress_timeout
        return value

    def start(self):
        if self.thread is not None:self.check();return {'ok':True,'maintenance':True,'owner':self.owner}
        value=self._request(True,initial=True)
        def heartbeat():
            while not self.stopping.wait(self.interval):
                try:self._request(True)
                except Exception:
                    if not self.stopping.is_set():
                        self.failure=self.failure or'maintenance_heartbeat_failed';self.stopping.set()
                    return
        self.thread=threading.Thread(target=heartbeat,name='maintenance-heartbeat',daemon=True)
        self.thread.start();return value

    def check(self):
        with self.state_lock:
            now=self._valid();self.progress_until=now+self.progress_timeout

    @contextmanager
    def activity(self,timeout_seconds):
        """A finite known RPC can renew only until its actual operation limit."""
        if type(timeout_seconds)not in(int,float)or not 1<=timeout_seconds<=7200:
            raise ValueError('maintenance_activity_timeout_invalid')
        self.check();token=object()
        with self.state_lock:self.activities.append((token,self.clock()+timeout_seconds+5))
        try:yield self
        finally:
            with self.state_lock:
                if not self.activities or self.activities[-1][0]is not token:self._fence('maintenance_activity_order_invalid')
                _,deadline=self.activities.pop()
                if self.clock()>=deadline:self._fence('maintenance_controller_progress_stalled')
                self.progress_until=self.clock()+self.progress_timeout
            self.check()

    def stop(self,*,release=True):
        if release:
            with self.state_lock:self._valid()
        self.stopping.set()
        if self.thread is not None:self.thread.join(timeout=35)
        if self.thread is not None and self.thread.is_alive():
            raise RuntimeError('maintenance_heartbeat_not_stopped')
        if release:return self._request(False)
        return {'ok':True,'maintenance':True,'owner':self.owner,'renewalStopped':True}

    def __enter__(self):self.start();return self
    def __exit__(self,kind,error,traceback):
        if kind is not None:self.stop(release=False)
        else:
            try:self.check()
            except Exception:
                self.stop(release=False);raise
            self.stop()
