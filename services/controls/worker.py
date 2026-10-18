"""Private Unix-socket proxy. Camera secrets stay in the root-owned host config."""
import argparse
import base64
import http.server
import json
import os
from pathlib import Path
import re
import socketserver
import stat
import urllib.error
import urllib.request
import urllib.parse

CONFIG = Path('/etc/reolink-protect-controls/config.json')
SOCKET = Path('/run/reolink-protect-controls/controls.sock')
HOSTS = {'192.168.30.' + str(i) for i in range(210, 216)}


class ControlError(Exception):
    def __init__(self, code, status=400):
        self.code, self.status = code, status


def load_config(path=None):
    path = CONFIG if path is None else Path(path)
    info = path.stat()
    if path.is_symlink() or info.st_uid != 0 or stat.S_IMODE(info.st_mode) & 0o077:
        raise ControlError('private_config_required', 503)
    value = json.loads(path.read_text())
    bridges = value.get('bridges')
    if not isinstance(bridges, list) or len(bridges) != 6 or {b.get('host') for b in bridges} != HOSTS:
        raise ControlError('unexpected_camera_scope', 503)
    if len({b.get('cameraId') for b in bridges}) != 6:
        raise ControlError('unexpected_camera_scope', 503)
    for bridge in bridges:
        if not re.fullmatch('[a-f0-9]{24}', bridge.get('cameraId', '')) or not all(isinstance(bridge.get(k), str) and bridge[k] for k in ('username','password')) or ':' in bridge['username']:
            raise ControlError('invalid_private_config', 503)
    return {b['cameraId']: b for b in bridges}


def validate_job(job, bridges):
    if not isinstance(job, dict) or set(job) != {'cameraId','host','method','resource','body','queryType'}:
        raise ControlError('invalid_control_request')
    bridge = bridges.get(job['cameraId'])
    if not bridge or bridge['host'] != job['host']:
        raise ControlError('camera_identity_mismatch', 403)
    method, resource, body = job['method'], job['resource'], job['body']
    if method not in ('GET','POST') or not isinstance(resource,str) or not re.fullmatch('[a-z][a-z0-9_-]{0,63}',resource):
        raise ControlError('invalid_control_request')
    selector=job['queryType']
    if selector is not None and (method!='GET' or not isinstance(selector,str) or not re.fullmatch('[a-z][a-z0-9_-]{0,31}',selector)):
        raise ControlError('invalid_control_selector')
    if method == 'GET':
        if body is not None: raise ControlError('invalid_control_request')
    elif resource in ('capabilities','state') or not isinstance(body,dict) or set(body) != {'values'} or not isinstance(body['values'],dict):
        raise ControlError('invalid_control_request')
    if len(json.dumps(body).encode()) > 70000: raise ControlError('control_request_too_large')
    return bridge


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        return None


def dispatch(job, bridges, opener=None):
    bridge = validate_job(job, bridges)
    headers = {'Authorization':'Basic ' + base64.b64encode((bridge['username']+':'+bridge['password']).encode()).decode(),
               'Content-Type':'application/json', 'X-Reolink-Control-Intent':'user'}
    data = None if job['method'] == 'GET' else json.dumps(job['body']).encode()
    query='' if job['queryType'] is None else '?type='+urllib.parse.quote(job['queryType'],safe='')
    req = urllib.request.Request('http://'+bridge['host']+':8080/control/'+job['resource']+query,data=data,headers=headers,method=job['method'])
    op = opener or urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect())
    try:
        with op.open(req,timeout=70) as response:
            raw = response.read(262145)
            if len(raw)>262144: raise ControlError('camera_control_response_too_large',502)
            result=json.loads(raw)
            if not isinstance(result,dict): raise ControlError('invalid_camera_control_response',502)
            # Bridge endpoint is a projected, dedicated control contract, never a raw camera API.
            if job['method']=='GET' and job['resource'] in ('state','capabilities') and result.get('schemaVersion')!=1: raise ControlError('control_schema_mismatch',502)
            return result
    except urllib.error.HTTPError as exc:
        raise ControlError('camera_control_rejected',exc.code if exc.code in (400,403,404,409,422,503) else 502) from None
    except (OSError, ValueError, urllib.error.URLError):
        raise ControlError('camera_control_unavailable',503) from None


def stream_listen(job, bridges, handler):
    bridge=validate_job(job,bridges)
    if job['method']!='GET' or job['resource']!='listen' or job['queryType'] is not None:
        raise ControlError('invalid_audio_request')
    headers={'Authorization':'Basic '+base64.b64encode((bridge['username']+':'+bridge['password']).encode()).decode()}
    req=urllib.request.Request('http://'+bridge['host']+':8080/control/listen',headers=headers)
    op=urllib.request.build_opener(urllib.request.ProxyHandler({}),NoRedirect())
    try:
        with op.open(req,timeout=20) as response:
            if response.headers.get('Content-Type','').split(';')[0]!='audio/aac':
                raise ControlError('invalid_camera_audio_response',502)
            handler.send_response(200);handler.send_header('Content-Type','audio/aac');handler.send_header('Cache-Control','no-store')
            handler.send_header('Connection','close');handler.end_headers();handler.audio_started=True
            handler.close_connection=True
            while True:
                data=response.read1(8192)
                if not data:break
                handler.wfile.write(data);handler.wfile.flush()
    except urllib.error.HTTPError as exc:
        raise ControlError('camera_audio_unavailable',exc.code if exc.code in (401,404,429,503)else 502)from None
    except (OSError,urllib.error.URLError):
        if not getattr(handler,'audio_started',False):raise ControlError('camera_audio_unavailable',503)from None


class Handler(http.server.BaseHTTPRequestHandler):
    def log_message(self,*args): pass

    def do_POST(self):
        status=200
        try:
            if self.path != '/control' or self.headers.get('Transfer-Encoding'): raise ControlError('invalid_control_request')
            size=int(self.headers.get('Content-Length','0'))
            if not 1<=size<=80000: raise ControlError('invalid_control_request')
            job=json.loads(self.rfile.read(size))
            if isinstance(job,dict)and job.get('resource')=='listen':
                stream_listen(job,self.server.bridges,self);return
            value=dispatch(job,self.server.bridges)
        except ControlError as exc: status=exc.status;value={'ok':False,'error':exc.code}
        except Exception: status=503;value={'ok':False,'error':'camera_control_unavailable'}
        data=json.dumps(value,ensure_ascii=False).encode()
        self.send_response(status);self.send_header('Content-Type','application/json');self.send_header('Content-Length',str(len(data)));self.end_headers();self.wfile.write(data)


class Server(socketserver.ThreadingMixIn, getattr(socketserver, 'UnixStreamServer', socketserver.TCPServer)):
    daemon_threads=True
    def get_request(self):
        connection,address=super().get_request()
        connection.settimeout(75)
        return connection,address


def numeric_identity(value):
    if not re.fullmatch(r'[0-9]+', str(value)) or not 0 <= int(value) < 4294967295:
        raise argparse.ArgumentTypeError('numeric Unix uid/gid required')
    return int(value)


def private_mode(value):
    if not re.fullmatch(r'(?:0o)?[0-7]{3,4}', str(value)):
        raise argparse.ArgumentTypeError('octal permission mode required')
    result = int(value, 8)
    if result > 0o777 or result & 0o007:
        raise argparse.ArgumentTypeError('mode must deny access to other users')
    return result


def arguments(argv=None, environ=None):
    env = os.environ if environ is None else environ
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--config', type=Path, default=env.get('REOLINK_CONTROLS_CONFIG', str(CONFIG)))
    parser.add_argument('--socket', type=Path, default=env.get('REOLINK_CONTROLS_SOCKET', str(SOCKET)))
    parser.add_argument('--socket-uid', type=numeric_identity,
                        default=env.get('REOLINK_CONTROLS_SOCKET_UID', str(getattr(os, 'geteuid', lambda: 0)())))
    parser.add_argument('--socket-gid', type=numeric_identity,
                        default=env.get('REOLINK_CONTROLS_SOCKET_GID', str(getattr(os, 'getegid', lambda: 0)())))
    parser.add_argument('--socket-dir-mode', type=private_mode, default=env.get('REOLINK_CONTROLS_SOCKET_DIR_MODE', '0750'))
    parser.add_argument('--socket-mode', type=private_mode, default=env.get('REOLINK_CONTROLS_SOCKET_MODE', '0660'))
    return parser.parse_args(argv)


def serve(options, server_factory=Server):
    os.umask(0o077)
    bridges=load_config(options.config)
    endpoint=options.socket
    if not endpoint.is_absolute() or not options.config.is_absolute():
        raise RuntimeError('absolute_runtime_paths_required')
    endpoint.parent.mkdir(mode=options.socket_dir_mode,exist_ok=True)
    if endpoint.parent.is_symlink() or not endpoint.parent.is_dir():
        raise RuntimeError('unexpected_socket_directory')
    os.chown(endpoint.parent,options.socket_uid,options.socket_gid)
    os.chmod(endpoint.parent,options.socket_dir_mode)
    if endpoint.exists() or endpoint.is_symlink():
        if endpoint.is_symlink() or not stat.S_ISSOCK(endpoint.lstat().st_mode):
            raise RuntimeError('unexpected_socket_path')
        endpoint.unlink()
    with server_factory(str(endpoint),Handler) as server:
        server.bridges=bridges
        os.chown(endpoint,options.socket_uid,options.socket_gid)
        os.chmod(endpoint,options.socket_mode)
        server.serve_forever()


def main(argv=None):
    serve(arguments(argv))


if __name__=='__main__': main()
