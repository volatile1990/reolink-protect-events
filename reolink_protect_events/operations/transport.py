"""Run shipped public operations through SSH stdin; retain private config remotely."""
import base64
import io
import json
from pathlib import Path
import re
import shlex
import subprocess
import zipfile


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
  result=execute(request['request'])
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
