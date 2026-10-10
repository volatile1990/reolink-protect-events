#!/usr/bin/env python3
"""Read-only native classification/Find Anything verification through trusted SSH.

Credentials and complete camera/bootstrap payloads stay on the console. This
tool performs only GET requests and BEGIN READ ONLY catalog/event queries. It
never uploads events, changes settings, executes DS notifications, or stores
images/video. Its output is a sparse JSON audit suitable for a deployment check.
"""
import argparse
import base64
import json
import re
import subprocess


REMOTE = r'''
import hashlib,json,os,pathlib,re,ssl,subprocess,urllib.error,urllib.parse,urllib.request
config_path=pathlib.Path('/data/reolink-protect-events/config.json')
if os.geteuid()!=0 or config_path.is_symlink() or config_path.stat().st_mode&0o077:
 raise RuntimeError('private_root_configuration_required')
cfg=json.loads(config_path.read_text())
headers={'X-UserId':cfg['protectUserId'],'X-UserRole':'owner','X-UserPermissionMask':'64',
 'X-UserPermissions':'65535','X-Internal-Use':'true','Content-Type':'application/json'}
class NoRedirect(urllib.request.HTTPRedirectHandler):
 def redirect_request(self,*args): raise RuntimeError('redirect_rejected')
op=urllib.request.build_opener(urllib.request.ProxyHandler({}),NoRedirect(),
 urllib.request.HTTPSHandler(context=ssl._create_unverified_context()))
def jpeg_dimensions(raw):
 if raw[:2]!=b'\xff\xd8' or raw[-2:]!=b'\xff\xd9': return None
 pos=2
 while pos<len(raw):
  if raw[pos]!=0xff: return None
  while pos<len(raw) and raw[pos]==0xff: pos+=1
  if pos>=len(raw): return None
  marker=raw[pos];pos+=1
  if marker in (0xda,0xd9): return None
  if marker==0x01 or 0xd0<=marker<=0xd8: continue
  if pos+2>len(raw): return None
  size=int.from_bytes(raw[pos:pos+2],'big')
  if size<2 or pos+size>len(raw): return None
  if marker in (0xc0,0xc1,0xc2,0xc3,0xc5,0xc6,0xc7,0xc9,0xca,0xcb,0xcd,0xce,0xcf):
   if size<8: return None
   height=int.from_bytes(raw[pos+3:pos+5],'big')
   width=int.from_bytes(raw[pos+5:pos+7],'big')
   return {'width':width,'height':height} if width>0 and height>0 else None
  pos+=size
 return None

def get(path,binary=False):
 req=urllib.request.Request('https://127.0.0.1:7443'+path,headers=headers,method='GET')
 try:
  with op.open(req,timeout=15) as r:
   raw=r.read(10000001)
   if len(raw)>10000000: raise RuntimeError('response_limit')
   if binary:
    dimensions=jpeg_dimensions(raw)
    return {'status':r.status,'bytes':len(raw),'sha256':hashlib.sha256(raw).hexdigest(),'contentType':r.headers.get('Content-Type'),
     'isJpeg':dimensions is not None,'dimensions':dimensions}
   return {'status':r.status,'body':json.loads(raw)}
 except urllib.error.HTTPError as e: return {'status':e.code,'body':None}
def text(value): return "convert_from(decode('"+str(value).encode().hex()+"','hex'),'UTF8')"
def sql(query):
 p=subprocess.run(['runuser','-u','postgres','--','psql','-h','/run/postgresql','-p','5433','-d','unifi-protect','-w','-X','-q','-At','-v','ON_ERROR_STOP=1'],input='BEGIN READ ONLY;\nSET LOCAL statement_timeout=\'10s\';\n'+query+'\nROLLBACK;\n',encoding='utf-8',stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=20)
 if p.returncode: raise RuntimeError('readonly_database_query_failed')
 for line in reversed(p.stdout.splitlines()):
  try: return json.loads(line)
  except ValueError: pass
 raise RuntimeError('database_json_missing')
eid=text(event_id)
event_result=get('/api/events/'+event_id)
event=event_result.get('body') or {}
if event_result['status']!=200: print(json.dumps({'ok':False,'eventId':event_id,'eventStatus':event_result['status']}));raise SystemExit(1)
camera=event.get('camera')
if camera_ids and camera not in camera_ids: raise RuntimeError('event_camera_scope_mismatch')
if not isinstance(camera,str) or not re.fullmatch('[0-9a-f]{24}',camera): raise RuntimeError('invalid_event_camera')
start=event['start']-1000
end=max(event.get('end') or event['start'],event['start'])+1000
metadata=event.get('metadata') or {}
own=metadata.get('reolinkProtectEvents') or {}
expected_types=sorted(set(expected_classes))
event_summary={'id':event.get('id'),'camera':camera,'type':event.get('type'),'start':event.get('start'),'end':event.get('end'),'score':event.get('score'),'smartDetectTypes':event.get('smartDetectTypes'),
 'classificationOrigin':own.get('classificationOrigin'),'confidenceAvailable':own.get('confidenceAvailable'),'spatialTrackAvailable':own.get('spatialTrackAvailable'),'adapterVirtualZone':own.get('adapterVirtualZone'),
 'historicalImport':(own.get('provenance') or {}).get('historicalImport',False),'endIsTimeoutEstimate':(own.get('provenance') or {}).get('endIsTimeoutEstimate',False)}
def search(kind,confidence):
 query=urllib.parse.urlencode([('start',start),('end',end),('labels[]','camera:'+camera),('labels[]','smartDetectType:'+kind),('minConfidence',confidence),('limit',50),('orderDirection','asc')])
 result=get('/api/detection-search?'+query)
 body=result.get('body') or {}
 found=next((e for e in body.get('events',[]) if e.get('id')==event_id),None)
 thumbs=(found or {}).get('metadata',{}).get('detectedThumbnails',[])
 return {'class':kind,'minConfidence':confidence,'status':result['status'],'found':found is not None,'resultCount':len(body.get('events',[])),
  'objectIds':[t.get('objectId') for t in thumbs if t.get('type')==kind],
  'inventedConfidencePresent':any('confidence' in t for t in thumbs)}
searches=[search(kind,confidence) for kind in ('person','vehicle','animal') for confidence in (30,95)]
query=urllib.parse.urlencode([('start',start),('end',end),('cameras',camera),('types','smartDetectZone'),('limit',100)])
events=get('/api/events?'+query)
event_list=events.get('body') or []
if isinstance(event_list,dict): event_list=event_list.get('events',[])
event_filter={'status':events['status'],'found':any(e.get('id')==event_id for e in event_list)}
boot_result=get('/api/bootstrap')
boot=boot_result.get('body') or {}
targets=set(camera_ids or [camera])
camera_status=[]
for c in boot.get('cameras',[]):
 if c.get('id') in targets:
  flags=c.get('featureFlags') or {}
  camera_status.append({'id':c.get('id'),'isThirdPartyCamera':c.get('isThirdPartyCamera'),'hasSmartDetect':flags.get('hasSmartDetect'),'smartDetectTypes':flags.get('smartDetectTypes'),
   'zoneIds':[z.get('id') for z in c.get('smartDetectZones',[])],'recordingMode':(c.get('recordingSettings') or {}).get('mode'),
   'recordingEnd':((c.get('stats') or {}).get('video') or {}).get('recordingEnd')})
tables=['events','smartDetectObjects','smartDetectRaws','smartDetectTracks','smartDetectObjectAreas','labels','detectionLabels','thumbnails','cameras']
table_sql=','.join(text(t) for t in tables)
graph=sql("""SELECT json_build_object(
 'readOnly',current_setting('transaction_read_only'),
 'tablesPresent',COALESCE((SELECT json_agg(table_name ORDER BY table_name) FROM information_schema.tables WHERE table_schema='public' AND table_name IN ("""+table_sql+""")),'[]'::json),
 'eventRows',(SELECT count(*) FROM events WHERE id="""+eid+"""),
 'objects',COALESCE((SELECT json_agg(json_build_object('id',id,'type',type,'eventId',"eventId",'cameraId',"cameraId",'detectedAt',"detectedAt",'confidenceKeyPresent',attributes::jsonb?'confidence','spatialCoordPresent',attributes::jsonb?'coord','adapterVirtualZone',attributes::jsonb->'adapterVirtualZone')) FROM "smartDetectObjects" WHERE "eventId"="""+eid+"""),'[]'::json),
 'tracks',COALESCE((SELECT json_agg(json_build_object('id',id,'samples',json_array_length(payload))) FROM "smartDetectTracks" WHERE "eventId"="""+eid+"""),'[]'::json),
 'thumbnails',COALESCE((SELECT json_agg(json_build_object('id',id,'bytes',octet_length(content),'width',width,'height',height,'timestamp',timestamp,'isFullfov',"isFullfov")) FROM thumbnails WHERE "eventId"="""+eid+"""),'[]'::json),
 'detectionLabels',COALESCE((SELECT json_agg(json_build_object('objectId',dl."objectId",'names',(SELECT json_agg(l.name ORDER BY l.name) FROM labels l WHERE l.lid=ANY(dl.labels)))) FROM "detectionLabels" dl WHERE dl."eventId"="""+eid+"""),'[]'::json),
 'spatialAreaRows',(SELECT count(*) FROM "smartDetectObjectAreas" a JOIN "smartDetectObjects" o ON o.id=a."smartDetectObjectId" WHERE o."eventId"="""+eid+"""),
 'rawTrackRowsAtStart',(SELECT count(*) FROM "smartDetectRaws" WHERE "cameraId"="""+text(camera)+""" AND timestamp="""+str(event['start'])+"""),
 'locked',(SELECT locked FROM events WHERE id="""+eid+"""),
 'deleted',(SELECT "deletedAt" IS NOT NULL FROM events WHERE id="""+eid+"""),
 'foreignKeys',COALESCE((SELECT json_agg(json_build_object('table',r.relname,'name',p.conname,'definition',pg_get_constraintdef(p.oid))) FROM pg_constraint p JOIN pg_class r ON r.oid=p.conrelid JOIN pg_namespace n ON n.oid=r.relnamespace WHERE p.contype='f' AND n.nspname='public' AND r.relname IN ("""+table_sql+""")),'[]'::json));""")
thumb_result=get('/api/events/'+event_id+'/thumbnail?isFullfov=true',binary=True)
timeline_thumb_result=get('/api/events/'+event_id+'/thumbnail?w=48&h=48',binary=True)
timeline_explicit_result=get('/api/events/'+event_id+'/thumbnail?w=48&h=48&isFullfov=false',binary=True)
tracks_result=get('/api/events/'+event_id+'/smartDetectTrack')
tracks_body=tracks_result.get('body') or {}
tracks_summary={'status':tracks_result['status'],'samples':len(tracks_body.get('payload',[])),'event':tracks_body.get('event'),'camera':tracks_body.get('camera')}
objects=graph.get('objects',[])
positive=all(s['status']==200 and s['found'] for s in searches if s['class'] in expected_types)
negative=all(s['status']==200 and not s['found'] for s in searches if s['class'] not in expected_types)
true_graph=(graph['eventRows']==1 and sorted(o['type'] for o in objects)==expected_types and graph['spatialAreaRows']==0 and all(not o['confidenceKeyPresent'] and not o['spatialCoordPresent'] for o in objects))
def valid_thumbnail(result): return result.get('status')==200 and result.get('bytes',0)>0 and result.get('isJpeg') is True
thumbnail_paths_valid=all(valid_thumbnail(result) for result in (thumb_result,timeline_thumb_result,timeline_explicit_result))
ok=(positive and negative and true_graph and event.get('type')=='smartDetectZone' and sorted(event.get('smartDetectTypes',[]))==expected_types and graph['readOnly']=='on' and event_filter['found'] and not graph['deleted'] and thumbnail_paths_valid)
print(json.dumps({'ok':ok,'event':event_summary,'eventApiStatus':event_result['status'],'eventFilteredApi':event_filter,'searchFilters':searches,'graph':graph,
 'thumbnailApi':thumb_result,'timelineThumbnailApi':timeline_thumb_result,'timelineThumbnailExplicitApi':timeline_explicit_result,
 'thumbnailPathsValid':thumbnail_paths_valid,'tracksApi':tracks_summary,'protectVersion':boot.get('nvr',{}).get('version'),'cameras':camera_status,
 'limits':{'spatialTracksExpected':False,'confidenceExpected':False,'apiGETOnly':True,'databaseReadOnly':True,'imagesOrVideoSaved':False}}))
raise SystemExit(0 if ok else 1)
'''


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--event-id", required=True)
    parser.add_argument("--camera-id", action="append", default=[])
    parser.add_argument("--expected-class", choices=("person", "vehicle", "animal"), action="append", default=[])
    parser.add_argument("--ssh-alias", default="unifi-dream-machine")
    args = parser.parse_args()
    for value in [args.event_id] + args.camera_id:
        if not re.fullmatch(r"[a-f0-9]{24}", value):
            parser.error("Event and camera IDs must be 24 lowercase hex characters")
    encoded = base64.b64encode(REMOTE.encode("utf-8")).decode("ascii")
    values = "event_id=" + repr(args.event_id) + "\ncamera_ids=" + repr(args.camera_id) + "\nexpected_classes=" + repr(args.expected_class or ["person"]) + "\n"
    script = values + "import base64\nexec(base64.b64decode(" + repr(encoded) + "))\n"
    result = subprocess.run(["ssh", "-o", "BatchMode=yes", "-o", "ConnectTimeout=10", "-o", "StrictHostKeyChecking=yes",
                            args.ssh_alias, "python3 -"], input=script, encoding="utf-8", stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE, timeout=180, shell=False)
    if result.stdout:
        # The remote script deliberately emits only sparse projected JSON.
        print(result.stdout.strip())
    else:
        print(json.dumps({"ok": False, "error": "readonly_verification_failed", "exit": result.returncode}))
    return result.returncode


if __name__ == "__main__":
    raise SystemExit(main())
