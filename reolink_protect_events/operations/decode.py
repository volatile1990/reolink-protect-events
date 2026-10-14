"""Local real video/audio decodes of existing bridge and Protect recordings.

The UDM only reads private configuration and exports recorded bytes. Private
SSH output, media, SDP and decoder logs stay in RAM; reports contain projections.
All subprocesses, streams, HTTP bodies and concurrent viewers are bounded.
"""
import asyncio
import base64
import http.server
import json
import math
import os
from pathlib import Path
import re
import shutil
import subprocess
import threading
import time
import urllib.parse

from .safety import HOSTS, OperationError, error_code, need
from .rtsp_proxy import BoundedLines, Progress, RtspProxy, Warnings

MAX_MEDIA_BYTES = 64 * 1024 * 1024
MAX_PRIVATE_JSON = 262144
MAX_LOG_BYTES = 131072
EXPORT_SECONDS = 20
DEFAULT_CONFIG = '/data/reolink-protect-events/config.json'


def _creation_options():
    return {'creationflags': subprocess.CREATE_NO_WINDOW} if os.name == 'nt' else {}


def _process_env():
    # Local RAM media must never be sent to a process-wide HTTP proxy.
    result = {key:value for key,value in os.environ.items()
              if key.lower() not in ('http_proxy','https_proxy','all_proxy','no_proxy')}
    result['no_proxy'] = '127.0.0.1,localhost'
    return result


def _duration(value):
    need(type(value) in (int, float) and math.isfinite(value) and 3 <= value <= 5,
         'decode_duration_invalid')
    return float(value)


def _executable(value, name):
    found = shutil.which(value or name)
    need(found is not None and Path(found).is_file(), 'local_' + name + '_unavailable')
    return str(Path(found).resolve())


async def _read_capped(reader, limit):
    chunks, size = [], 0
    while True:
        chunk = await reader.read(min(65536, limit + 1 - size))
        if not chunk:
            return b''.join(chunks)
        size += len(chunk)
        need(size <= limit, 'subprocess_output_limit')
        chunks.append(chunk)


async def _run_bytes(command, *, input_data=None, timeout, stdout_limit, stderr_limit=MAX_LOG_BYTES):
    """No shell, bounded capture and total wait including pipe drains."""
    process, tasks = None, []
    try:
        process = await asyncio.create_subprocess_exec(*command,
            stdin=asyncio.subprocess.PIPE if input_data is not None else asyncio.subprocess.DEVNULL,
            stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE,
            limit=65536, env=_process_env(), **_creation_options())
        async def write():
            if input_data is not None:
                process.stdin.write(input_data)
                await process.stdin.drain()
                process.stdin.close()
        tasks = [asyncio.create_task(_read_capped(process.stdout, stdout_limit)),
                 asyncio.create_task(_read_capped(process.stderr, stderr_limit)),
                 asyncio.create_task(write()), asyncio.create_task(process.wait())]
        try:
            output, errors, _, code = await asyncio.wait_for(asyncio.gather(*tasks), timeout)
        except asyncio.TimeoutError:
            raise OperationError('subprocess_total_deadline') from None
        return code, output, errors
    except OperationError:
        raise
    except Exception:
        raise OperationError('subprocess_failed') from None
    finally:
        if process is not None and process.returncode is None:
            try:
                process.kill()
                await asyncio.wait_for(process.wait(), 2)
            except (ProcessLookupError, OSError, asyncio.TimeoutError):
                pass
        for task in tasks:
            if not task.done():
                task.cancel()
        if tasks:
            await asyncio.gather(*tasks, return_exceptions=True)


def _ssh_command(alias):
    need(isinstance(alias, str) and re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_.-]{0,79}', alias),
         'ssh_alias_invalid')
    return ['ssh', '-T', '-o', 'BatchMode=yes', '-o', 'ConnectTimeout=10', '-o',
            'StrictHostKeyChecking=yes', alias, 'python3 -']


# Public helper sources are carried through stdin. This works before upgrading
# an older installation which has no operations package; no repository outside
# this installed package or machine-specific sibling script is imported.
_REMOTE_COMMON = r'''
import base64,http.client,json,pathlib,re,sys,time,types,urllib.parse,xml.etree.ElementTree as ET
payload=json.loads(base64.b64decode(INPUT))
for name in ('reolink_protect_events','reolink_protect_events.operations'):
 module=types.ModuleType(name);module.__path__=[];sys.modules[name]=module
for name,source in payload['helpers']:
 module=types.ModuleType(name);module.__package__=name.rsplit('.',1)[0];sys.modules[name]=module
 exec(compile(source,'<public-helper>','exec'),module.__dict__)
from reolink_protect_events.http_deadline import get_bytes,_DeadlineSocket
from reolink_protect_events.operations.safety import need,read_json,private_path,validate_config,OperationError
from reolink_protect_events.operations.http import owner_headers,protect_json,bridge_metrics
from reolink_protect_events.operations.protect import selected_cameras,qualities

def context():
 path=payload['configPath'];need(path in ('/data/reolink-protect-events/config.json','/data/reolink-bridge-events/config.json'),'decode_config_path_invalid')
 config=read_json(path,limit=262144);validate_config(config)
 release=payload.get('remoteRelease')
 if release is not None:
  need(isinstance(release,str)and re.fullmatch('/data/reolink-protect-events/releases/[a-f0-9]{16,64}',release),'decode_release_path_invalid')
  path=private_path(release,directory=True);need(path.is_dir(),'decode_release_unavailable')
 bootstrap=protect_json(config,'/api/bootstrap');cameras=selected_cameras(config,bootstrap)
 wanted=payload['ips'];need(isinstance(wanted,list)and wanted and len(set(wanted))==len(wanted),'decode_scope_invalid')
 rows=[c for c in cameras if c['host']in wanted];need(len(rows)==len(wanted),'decode_scope_invalid')
 return config,rows

def uri_for(bridge,profile):
 soap=('<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope" xmlns:m="http://www.onvif.org/ver10/media/wsdl" xmlns:tt="http://www.onvif.org/ver10/schema"><s:Body><m:GetStreamUri><m:StreamSetup><tt:Stream>RTP-Unicast</tt:Stream><tt:Transport><tt:Protocol>RTSP</tt:Protocol></tt:Transport></m:StreamSetup><m:ProfileToken>'+profile+'</m:ProfileToken></m:GetStreamUri></s:Body></s:Envelope>').encode()
 token=base64.b64encode((bridge['username']+':'+bridge['password']).encode()).decode()
 connection=http.client.HTTPConnection(bridge['host'],8080,timeout=5);deadline=time.monotonic()+5;sock=None
 try:
  connection.connect();sock=connection.sock;connection.sock=_DeadlineSocket(sock,deadline)
  connection.request('POST','/onvif/media_service',body=soap,headers={'Authorization':'Basic '+token,'Content-Type':'application/soap+xml'})
  with connection.getresponse()as response:
   raw=response.read(65537);need(response.status==200 and len(raw)<=65536 and b'<!DOCTYPE'not in raw.upper(),'decode_onvif_response_invalid')
 finally:
  connection.close()
  if sock is not None:sock.close()
 uri=ET.fromstring(raw).findtext('.//{http://www.onvif.org/ver10/schema}Uri');url=urllib.parse.urlsplit(uri)
 need(url.scheme=='rtsp'and url.hostname==bridge['host']and url.port==8554 and url.username is None and not url.fragment,'decode_onvif_uri_scope')
 return uri

def discover():
 config,cameras=context();bridges={b['cameraId']:b for b in config['bridges']};out=[];now=int(time.time()*1000)
 for camera in cameras:
  bridge=bridges[camera['id']];streams=bridge_metrics(bridge).get('streams',[])
  need(isinstance(streams,list)and 1<=len(streams)<=8,'decode_source_profiles_invalid')
  by={s.get('profile'):s for s in streams if isinstance(s,dict)and s.get('profile')in ('main','sub')}
  expected={'main'}|({'sub'}if len(qualities(camera))==2 else set());need(set(by)==expected,'decode_source_profiles_changed')
  channels={c['id']:c for c in camera['channels']if c.get('enabled')is True}
  stats=camera.get('stats',{}).get('video',{})
  for quality,key,channel in qualities(camera):
   profile='main'if quality=='high'else'sub';stream=by[profile];c=channels[channel]
   codec={'H265':'hevc','H264':'h264'}.get(stream.get('codec'));width=stream.get('width');height=stream.get('height')
   need(codec is not None and type(width)is int and type(height)is int and 16<=width<=16384 and 16<=height<=16384,'decode_source_metadata_invalid')
   need((width,height)==(c.get('width'),c.get('height')),'decode_source_dimensions_changed')
   recording_end=stats.get(key,camera.get(key));recording_start=stats.get('recordingStart',camera.get('recordingStart'))
   need(type(recording_end)is int and -5000<=now-recording_end<=120000,'decode_recording_index_stale')
   end=recording_end-payload['lagSeconds']*1000;start=end-20000
   need(type(recording_start)is int and recording_start<=start<end<=now,'decode_recording_range_unavailable')
   if payload.get('notBeforeMs')is not None:need(start>=payload['notBeforeMs'],'decode_new_recording_pending')
   out.append({'host':bridge['host'],'cameraId':camera['id'],'profile':profile,'quality':quality,'channel':channel,
    'url':uri_for(bridge,profile),'username':bridge['username'],'password':bridge['password'],
    'expectedCodec':codec,'expectedWidth':width,'expectedHeight':height,'startMs':start,'endMs':end})
 return {'ok':True,'profiles':out}

def export():
 config,cameras=context();p=payload['profile'];camera=next((c for c in cameras if c['id']==p['cameraId']and c['host']==p['host']),None)
 need(camera is not None,'decode_camera_mapping_changed')
 expected=[q for q in qualities(camera)if q[0]==p['quality']and q[2]==p['channel']];need(len(expected)==1,'decode_export_profile_scope')
 start,end=p['startMs'],p['endMs'];now=int(time.time()*1000)
 need(type(start)is int and type(end)is int and end-start==20000 and 0<start<end<=now,'decode_export_time_scope')
 stats=camera.get('stats',{}).get('video',{});recording_end=stats.get(expected[0][1],camera.get(expected[0][1]))
 need(type(recording_end)is int and end<=recording_end,'decode_recording_range_unavailable')
 if payload.get('notBeforeMs')is not None:need(start>=payload['notBeforeMs'],'decode_new_recording_pending')
 path='/api/video/export?'+urllib.parse.urlencode({'camera':camera['id'],'start':start,'end':end,'channel':p['channel']})
 status,content=get_bytes('http://127.0.0.1:7080'+path,owner_headers(config),timeout=35,limit=67108864)
 need(status==200 and content and b'ftyp'in content[:64],'decode_export_rejected')
 sys.stdout.buffer.write(content);sys.stdout.buffer.flush()

try:
 if payload['action']=='discover':print(json.dumps(discover(),separators=(',',':')))
 elif payload['action']=='export':export()
 else:raise OperationError('decode_action_invalid')
except Exception as error:
 code=error.code if isinstance(error,OperationError)else'decode_remote_read_failed'
 target=sys.stderr if payload.get('action')=='export'else sys.stdout
 target.write(json.dumps({'ok':False,'errorCode':code},separators=(',',':')))
 raise SystemExit(2)
'''


def _remote_source(payload):
    package = Path(__file__).resolve().parents[1]
    helpers = [('reolink_protect_events.http_deadline', package / 'http_deadline.py')]
    helpers += [('reolink_protect_events.operations.' + name, package / 'operations' / (name + '.py'))
                for name in ('safety', 'http', 'protect')]
    value = dict(payload, helpers=[(name, path.read_text(encoding='utf-8')) for name, path in helpers])
    encoded = base64.b64encode(json.dumps(value, separators=(',', ':')).encode()).decode()
    return _REMOTE_COMMON.replace('INPUT', repr(encoded)).encode()


def _public_profile(value):
    return {key: value[key] for key in ('host', 'cameraId', 'profile', 'quality', 'channel')}


def _remote_error(raw, fallback):
    try:
        value=json.loads(raw)
        code=value.get('errorCode')if isinstance(value,dict)and value.get('ok')is False else None
        if isinstance(code,str)and re.fullmatch(r'[a-z0-9_]{1,96}',code):
            return code
    except (ValueError,UnicodeError):
        pass
    return fallback


def _private_profiles(response, selected):
    need(isinstance(response, dict) and response.get('ok') is True and set(response) == {'ok', 'profiles'},
         'decode_discovery_failed')
    rows = response['profiles'];expected = {(host, profile) for host in selected
        for profile in (('main',) if host.endswith('.215') else ('main', 'sub'))}
    need(isinstance(rows, list) and len(rows) == len(expected), 'decode_profile_coverage_invalid')
    required = {'host', 'cameraId', 'profile', 'quality', 'channel', 'url', 'username', 'password',
                'expectedCodec', 'expectedWidth', 'expectedHeight', 'startMs', 'endMs'}
    identities = set()
    for row in rows:
        need(isinstance(row, dict) and set(row) == required, 'decode_private_payload_scope')
        need((row['host'], row['profile']) in expected, 'decode_profile_coverage_invalid')
        need(re.fullmatch(r'[a-f0-9]{24}', row['cameraId'] or '') is not None, 'decode_camera_identity_invalid')
        need((row['quality'], row['channel']) == (('high', 0) if row['profile'] == 'main' else ('low', 2)),
             'decode_profile_mapping_invalid')
        need(row['expectedCodec'] in ('h264', 'hevc') and all(type(row[k]) is int and 16 <= row[k] <= 16384
             for k in ('expectedWidth', 'expectedHeight')), 'decode_expected_metadata_invalid')
        need(type(row['startMs']) is int and type(row['endMs']) is int and row['endMs']-row['startMs']==20000,
             'decode_export_time_scope')
        for key in ('username', 'password', 'url'):
            need(isinstance(row[key], str) and 0 < len(row[key]) <= 8192 and not any(c in row[key] for c in '\r\n\0'),
                 'decode_private_payload_invalid')
        need(':' not in row['username'], 'decode_private_payload_invalid')
        parsed = urllib.parse.urlsplit(row['url'])
        need(parsed.scheme == 'rtsp' and parsed.hostname == row['host'] and parsed.port == 8554
             and parsed.username is None and parsed.fragment == '' and parsed.path.startswith('/'), 'decode_rtsp_scope_invalid')
        identities.add((row['host'], row['profile']))
    need(identities == expected, 'decode_profile_coverage_invalid')
    return rows


class MemoryVideo(http.server.BaseHTTPRequestHandler):
    """Only a bounded RAM MP4, loopback binding and strict one-range support."""
    protocol_version = 'HTTP/1.1'
    def log_message(self, *_):
        pass
    def setup(self):
        self.request.settimeout(3)
        super().setup()
    def do_GET(self):
        if self.path != '/recording.mp4':
            self.send_error(404);return
        data = self.server.video
        start, end, partial = 0, len(data)-1, False
        raw = self.headers.get('Range')
        if raw is not None:
            match = re.fullmatch(r'bytes=(\d{1,12})-(\d{0,12})', raw)
            if not match:
                self.send_error(416);return
            start = int(match[1]);end = min(end, int(match[2])) if match[2] else end;partial = True
            if not 0 <= start <= end:
                self.send_error(416);return
        self.send_response(206 if partial else 200)
        self.send_header('Content-Type', 'video/mp4')
        self.send_header('Content-Length', str(end-start+1))
        self.send_header('Accept-Ranges', 'bytes')
        self.send_header('Connection', 'close')
        if partial:self.send_header('Content-Range', 'bytes %d-%d/%d' % (start,end,len(data)))
        self.end_headers();self.close_connection=True
        try:
            for index in range(start,end+1,65536):
                self.wfile.write(data[index:min(index+65536,end+1)])
        except (OSError, TimeoutError):
            pass


class _MemoryServer(http.server.ThreadingHTTPServer):
    daemon_threads = True
    block_on_close = False
    request_queue_size = 4
    def __init__(self, content):
        need(isinstance(content, bytes) and 0 < len(content) <= MAX_MEDIA_BYTES, 'decode_media_size_limit')
        self.video = content
        super().__init__(('127.0.0.1', 0), MemoryVideo)
        self.thread = threading.Thread(target=self.serve_forever, kwargs={'poll_interval': .05}, daemon=True)
        self.thread.start()
    @property
    def url(self):
        return 'http://127.0.0.1:' + str(self.server_port) + '/recording.mp4'
    def close(self):
        self.shutdown();self.server_close();self.thread.join(timeout=1);self.video=b''


def timeline_comparison(video, audio):
    try:
        starts = [float(row['start_time']) for row in (video,audio)]
        spans = [float(row['duration']) for row in (video,audio)]
        need(all(math.isfinite(v) for v in starts+spans) and min(spans) > 0, 'decode_track_timing_invalid')
    except (KeyError, TypeError, ValueError):
        raise OperationError('decode_track_timing_invalid') from None
    start_delta=abs(starts[0]-starts[1]);end_delta=abs(starts[0]+spans[0]-starts[1]-spans[1])
    return {'audioVideoStartDeltaSeconds':round(start_delta,6),'audioVideoEndDeltaSeconds':round(end_delta,6),
            'audioVideoDurationDeltaSeconds':round(abs(spans[0]-spans[1]),6),
            'deliveredTimelineDurationsCompatible':max(start_delta,end_delta)<=.35,
            'captureSynchronizationMeasured':False}


def _project_streams(raw):
    need(isinstance(raw,dict) and isinstance(raw.get('streams'),list) and 1<=len(raw['streams'])<=8,
         'decode_probe_metadata_invalid')
    result=[]
    for row in raw['streams']:
        need(isinstance(row,dict) and row.get('codec_type')in ('video','audio')
             and row.get('codec_name')in ('h264','hevc','aac'),'decode_probe_metadata_invalid')
        value={'codec_type':row['codec_type'],'codec_name':row['codec_name']}
        for key in ('width','height','channels'):
            if key in row:
                need(type(row[key])is int and 0<row[key]<=16384,'decode_probe_metadata_invalid')
                value[key]=row[key]
        if 'sample_rate'in row:
            rate=str(row['sample_rate']);need(re.fullmatch(r'[0-9]{1,6}',rate)and 0<int(rate)<=384000,'decode_probe_metadata_invalid')
            value['sample_rate']=rate
        for key in ('start_time','duration'):
            if key in row:
                text=str(row[key]);need(re.fullmatch(r'-?[0-9]{1,8}(?:\.[0-9]{1,12})?',text),'decode_probe_metadata_invalid')
                number=float(text);need(math.isfinite(number)and abs(number)<=86400,'decode_probe_metadata_invalid')
                value[key]=text
        if 'avg_frame_rate'in row:
            text=str(row['avg_frame_rate']);need(re.fullmatch(r'[0-9]{1,10}/[0-9]{1,10}',text),'decode_probe_metadata_invalid')
            value['avg_frame_rate']=text
        result.append(value)
    return result


class DecodeLogs:
    def __init__(self):
        self.progress=Progress();self.warnings=Warnings();self.dimensions=set();self.video_frames=0
        self.first_pts=None;self.last_pts=None;self.timestamp_errors=0
    def line(self,line):
        self.progress.line(line)
        if 'Parsed_showinfo' in line and re.search(r'\bn:\s*\d+',line):
            match=re.search(r'\bs:(\d{1,5})x(\d{1,5})\b',line)
            pts=re.search(r'\bpts_time:([-+0-9.eE]+)',line)
            if match and pts:
                try:
                    value=float(pts[1]);need(math.isfinite(value),'decode_frame_pts_invalid')
                    self.dimensions.add((int(match[1]),int(match[2])));self.video_frames+=1
                    if self.first_pts is None:self.first_pts=value
                    if self.last_pts is not None and value<self.last_pts-.001:self.timestamp_errors+=1
                    self.last_pts=value
                except (ValueError,OperationError):
                    self.timestamp_errors+=1
        if any(level in line for level in ('[warning]','[error]','[fatal]','[panic]')) or line.lower().startswith('last message repeated'):
            self.warnings.line(line)


def _decode_command(exe,url,duration,*,rtsp=False):
    command=[exe,'-hide_banner','-loglevel','level+info','-nostdin','-threads','1','-filter_threads','1']
    if rtsp:command+=['-rtsp_transport','tcp','-timeout','10000000']
    else:command+=['-rw_timeout','10000000','-protocol_whitelist','http,tcp']
    command+=['-i',url,'-map','0:v:0','-an','-t',str(duration),'-vf','showinfo=checksum=0',
        '-enc_time_base','demux','-fps_mode','passthrough','-f','null','-',
        '-map','0:a:0','-vn','-t',str(duration),'-c:a','pcm_s16le','-f','s16le','pipe:1',
        '-progress','pipe:2','-nostats']
    return command


async def _decode_av(exe,url,duration,expected,audio,*,rtsp=False):
    logs=DecodeLogs();lines=BoundedLines(logs.line);process=None;tasks=[];pcm_bytes=0
    code=None;failure=None;expired=False;began=time.monotonic()
    async def count_pcm(reader):
        nonlocal pcm_bytes
        while True:
            chunk=await reader.read(4096)
            if not chunk:return
            pcm_bytes+=len(chunk)
            need(pcm_bytes<=2*1024*1024,'decode_pcm_budget')
    async def drain(reader):
        size=0
        while True:
            chunk=await reader.read(4096)
            if not chunk:lines.finish();return
            size+=len(chunk);need(size<=2*1024*1024,'decode_log_budget');lines.feed(chunk)
    try:
        process=await asyncio.create_subprocess_exec(*_decode_command(exe,url,duration,rtsp=rtsp),
            stdin=asyncio.subprocess.DEVNULL,stdout=asyncio.subprocess.PIPE,stderr=asyncio.subprocess.PIPE,
            limit=65536,env=_process_env(),**_creation_options())
        tasks=[asyncio.create_task(count_pcm(process.stdout)),asyncio.create_task(drain(process.stderr)),
               asyncio.create_task(process.wait())]
        try:
            _,_,code=await asyncio.wait_for(asyncio.gather(*tasks),duration+10)
        except asyncio.TimeoutError:
            expired=True;failure='decode_total_deadline'
    except Exception as error:
        failure=error_code(error,'local_decode_failed')
    finally:
        if process is not None and process.returncode is None:
            try:process.kill();await asyncio.wait_for(process.wait(),2)
            except (ProcessLookupError,OSError,asyncio.TimeoutError):pass
        for task in tasks:
            if not task.done():task.cancel()
        if tasks:await asyncio.gather(*tasks,return_exceptions=True)
    rate,channels=audio.get('sampleRate'),audio.get('channels')
    samples=pcm_bytes//(2*channels) if type(channels)is int and 1<=channels<=8 else 0
    audio_seconds=samples/rate if type(rate)is int and rate>0 else 0
    span=logs.last_pts-logs.first_pts if logs.first_pts is not None and logs.last_pts is not None else 0
    valid_audio=audio.get('codec')=='aac' and rate==16000 and channels==1
    dimensions_match=logs.dimensions=={(expected['expectedWidth'],expected['expectedHeight'])}
    completed=(failure is None and code==0 and logs.progress.ended and logs.video_frames>0
        and span>=duration-.5 and audio_seconds>=duration-.5 and pcm_bytes%(2*max(1,channels or 1))==0)
    clean=completed and valid_audio and dimensions_match and not logs.timestamp_errors
    clean=clean and not bool(logs.warnings.categories) and not lines.overlong
    return {'ok':clean,'realVideoDecode':logs.video_frames>0,'realAudioDecode':samples>0,
        'videoFrames':logs.video_frames,'reportedVideoFrames':logs.progress.frames,
        'decodedVideoSpanSeconds':round(span,6),'decodedPcmSampleFrames':samples,
        'decodedAudioSeconds':round(audio_seconds,6),'pcmBytesCountedAndDiscarded':pcm_bytes,
        'decodedDimensions':[list(pair)for pair in sorted(logs.dimensions)],'expectedDimensionsMatch':dimensions_match,
        'expectedAudioMatch':valid_audio,'requestedSeconds':duration,'decoderExitCode':code,
        'progressEnd':logs.progress.ended,'hardTimerExpired':expired,'completedRequestedMediaDuration':completed,
        'warningCategories':dict(logs.warnings.categories),'decodedTimestampErrors':logs.timestamp_errors,
        'overlongLogLinesDiscarded':lines.overlong,'cleanDecode':clean,
        'runtimeSeconds':round(time.monotonic()-began,3),'errorCode':failure}


async def _rtsp_decode(profile,exe,duration):
    metadata={}
    def inspect(body):
        for line in body.decode('ascii').splitlines():
            match=re.fullmatch(r'a=rtpmap:\d+ (H264|H265|MPEG4-GENERIC)/(\d+)(?:/(\d+))?',line,re.I)
            if not match:continue
            codec=match[1].upper()
            if codec in ('H264','H265'):
                metadata.update(videoCodec={'H264':'h264','H265':'hevc'}[codec],videoClock=int(match[2]))
            else:metadata.update(audioCodec='aac',audioSampleRate=int(match[2]),audioChannels=int(match[3]or'1'))
    endpoint=urllib.parse.urlsplit(profile['url'])
    proxy=RtspProxy(endpoint,8554,profile['username'],profile['password'],inspect_sdp=inspect)
    result=None
    try:
        local_url=await proxy.start()
        # SDP is received while the decoder runs. The mapping deliberately has
        # live properties rather than copying empty pre-DESCRIBE metadata.
        class Audio:
            def get(self,key):return metadata.get({'codec':'audioCodec','sampleRate':'audioSampleRate','channels':'audioChannels'}[key])
        result=await _decode_av(exe,local_url,duration,profile,Audio(),rtsp=True)
        await proxy.close()
        proxy.finish_process(result['completedRequestedMediaDuration'])
        result.update(sdpMetadata=metadata,rtspProxy=proxy.result())
        result['ok']=result['ok']and metadata.get('videoCodec')==profile['expectedCodec']and not proxy.errors
        return dict(_public_profile(profile),**result)
    except Exception as error:
        return dict(_public_profile(profile),ok=False,errorCode=error_code(error,'rtsp_decode_failed'))
    finally:
        await proxy.close()


async def _recorded_decode(profile,exe,probe,duration,ssh,payload):
    row=dict(_public_profile(profile),startMs=profile['startMs'],endMs=profile['endMs'],requestedExportSeconds=20,ok=False)
    server=None;content=None
    try:
        request=dict(payload,action='export',profile={key:profile[key]for key in ('host','cameraId','quality','channel','startMs','endMs')})
        code,content,errors=await _run_bytes(ssh,input_data=_remote_source(request),timeout=45,stdout_limit=MAX_MEDIA_BYTES)
        need(code==0,_remote_error(errors,'decode_recording_export_failed'))
        need(content and b'ftyp'in content[:64],'decode_recording_export_failed')
        row['exportBytes']=len(content);server=_MemoryServer(content);content=None
        args=[probe,'-v','error','-rw_timeout','10000000','-protocol_whitelist','http,tcp','-show_entries',
              'stream=codec_type,codec_name,width,height,sample_rate,channels,start_time,duration,avg_frame_rate',
              '-of','json',server.url]
        code,raw,errors=await _run_bytes(args,timeout=15,stdout_limit=262144)
        need(code==0 and not errors.strip(),'decode_recording_probe_failed')
        streams=_project_streams(json.loads(raw));row['streams']=streams
        videos=[s for s in streams if s.get('codec_type')=='video'];audios=[s for s in streams if s.get('codec_type')=='audio']
        need(len(videos)==1 and len(audios)==1,'decode_recording_tracks_invalid')
        video,audio=videos[0],audios[0]
        metadata_match=(video.get('codec_name')==profile['expectedCodec'] and
            (video.get('width'),video.get('height'))==(profile['expectedWidth'],profile['expectedHeight']))
        row['videoMetadataPreserved']=metadata_match;row.update(timeline_comparison(video,audio))
        need(float(video['duration'])>=19 and float(audio['duration'])>=19,'decode_recording_export_too_short')
        actual_audio={'codec':audio.get('codec_name'),'sampleRate':int(audio.get('sample_rate',0)), 'channels':audio.get('channels')}
        result=await _decode_av(exe,server.url,duration,profile,actual_audio)
        row['decode']=result;row['ok']=result['ok']and metadata_match and row['deliveredTimelineDurationsCompatible']
        return row
    except Exception as error:
        return dict(row,errorCode=error_code(error,'recorded_decode_failed'))
    finally:
        if server is not None:server.close()
        content=None


def _coverage(profiles,rows):
    expected={(p['host'],p['quality'])for p in profiles}
    checked={(r['host'],r['quality'])for r in rows}
    successful={(r['host'],r['quality'])for r in rows if r.get('ok')is True}
    return {'expectedRequested':len(expected),'checked':len(checked),'passed':len(successful),
        'expectedFull':11,'allRequested':checked==expected and successful==expected,
        'allEleven':len(expected)==11 and checked==expected and successful==expected}


def run_full_decodes(ssh_alias='unifi-dream-machine', *, config_path=DEFAULT_CONFIG, remote_release=None,
                     ips=None, ffmpeg=None, ffprobe=None, duration=5, recording_lag_seconds=30, not_before_ms=None):
    """Return a projected read-only real-decode gate; missing tools never pass.

    A subset can pass its explicitly requested scope, but UPDATE must also
    require both profile coverage `allEleven` flags and `realDecodes`.
    `not_before_ms` requires the entire fresh 20 s recorded clip after activation.
    No synthetic events, media files, configuration changes or concurrent viewers.
    """
    report={'schemaVersion':1,'atMs':int(time.time()*1000),'ok':False,'realDecodes':False,
        'readOnly':True,'mediaPersisted':False,'credentialsPrinted':False,'handsetPlaybackVerified':False,
        'maxConcurrentViewers':1,'rtsp':[],'recordings':[]}
    for key in ('rtspProfileCoverage','recordedProfileCoverage'):
        report[key]={'expectedRequested':0,'checked':0,'passed':0,'expectedFull':11,'allRequested':False,'allEleven':False}
    profiles=[]
    try:
        duration=_duration(duration);ssh=_ssh_command(ssh_alias)
        need(config_path in (DEFAULT_CONFIG,'/data/reolink-bridge-events/config.json'),'decode_config_path_invalid')
        need(remote_release is None or isinstance(remote_release,str) and
             re.fullmatch(r'/data/reolink-protect-events/releases/[a-f0-9]{16,64}',remote_release), 'decode_release_path_invalid')
        selected=sorted(HOSTS) if not ips else list(ips)
        need(1<=len(selected)<=6 and len(set(selected))==len(selected) and set(selected)<=HOSTS,'decode_scope_invalid')
        need(type(recording_lag_seconds)is int and 1<=recording_lag_seconds<=120,'decode_recording_lag_invalid')
        need(not_before_ms is None or type(not_before_ms)is int and 0<not_before_ms<=int(time.time()*1000),
             'decode_not_before_invalid')
        exe=_executable(ffmpeg,'ffmpeg')
        sibling=Path(exe).with_name('ffprobe.exe'if os.name=='nt'else'ffprobe')
        probe=_executable(ffprobe or (str(sibling)if sibling.is_file()else None),'ffprobe')
        payload={'action':'discover','configPath':config_path,'remoteRelease':remote_release,'ips':selected,
                 'lagSeconds':recording_lag_seconds,'notBeforeMs':not_before_ms}
        async def execute():
            nonlocal profiles
            code,raw,_=await _run_bytes(ssh,input_data=_remote_source(payload),timeout=150,stdout_limit=MAX_PRIVATE_JSON)
            need(code==0,_remote_error(raw,'decode_discovery_failed'))
            profiles=_private_profiles(json.loads(raw),selected)
            for profile in profiles:
                report['rtsp'].append(await _rtsp_decode(profile,exe,duration))
                report['recordings'].append(await _recorded_decode(profile,exe,probe,duration,ssh,payload))
        asyncio.run(execute())
        report['rtspProfileCoverage']=_coverage(profiles,report['rtsp'])
        report['recordedProfileCoverage']=_coverage(profiles,report['recordings'])
        report['realDecodes']=bool(profiles) and all(r.get('realVideoDecode')is True and r.get('realAudioDecode')is True
            for r in report['rtsp']) and all(r.get('decode',{}).get('realVideoDecode')is True and
                r.get('decode',{}).get('realAudioDecode')is True for r in report['recordings'])
        report['ok']=report['realDecodes'] and report['rtspProfileCoverage']['allRequested']and report['recordedProfileCoverage']['allRequested']
        report['newRecordingGateRequired']=not_before_ms is not None
        report['recordingClipsAfterMs']=not_before_ms
        report['limitation']='Short real decode and delivered track timeline check; sensor capture synchronization and handset playback are not measured.'
    except Exception as error:
        report['errorCode']=error_code(error,'full_decode_failed')
    finally:
        profiles.clear()
    return report
