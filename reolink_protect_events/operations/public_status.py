"""Only fixed diagnostic codes cross the private-monitor boundary."""
import json
import os
from pathlib import Path
import re
import stat
import tempfile

from .safety import need

ALERT_CODES=frozenset(('maintenance_requires_review','recovery_requires_review',
    'recovery_restoration_pending','recorder_repair_budget_exhausted','source_unhealthy',
    'native_media_requires_attention','monitor_sample_failed','maintenance_expired_mutation_active'))
STATES=frozenset(('maintenance','starting','attention','healthy','verifying','degraded'))


def projection(report):
    alerts=[]
    for value in report.get('alerts',[]):
        if not isinstance(value,dict)or value.get('code')not in ALERT_CODES:continue
        row={'code':value['code'],'actionRequired':value.get('actionRequired')is True}
        cid=value.get('cameraId')
        if isinstance(cid,str)and re.fullmatch('[a-f0-9]{24}',cid):row['cameraId']=cid
        alerts.append(row)
    failed=report.get('errorCode')is not None
    if failed:alerts.append({'code':'monitor_sample_failed','actionRequired':True})
    return {'schemaVersion':1,'atMs':report.get('atMs')if type(report.get('atMs'))is int else 0,
            'completedAtMs':report.get('completedAtMs')if type(report.get('completedAtMs'))is int else 0,
            'state':report.get('state')if report.get('state')in STATES else'attention',
            'actionRequired':failed or report.get('actionRequired')is True,'alerts':alerts}


def write(path,report):
    path=Path(path)
    need(path.name=='monitor.json'and path.parent.is_dir(),'public_monitor_path_invalid')
    for current in (path,*path.parents):
        need(not current.is_symlink(),'public_monitor_symlink')
        if not current.exists():continue
        info=current.stat()
        sticky=current!=path and stat.S_ISDIR(info.st_mode)and bool(info.st_mode&stat.S_ISVTX)
        if os.name!='nt':
            need(info.st_uid in(0,os.geteuid())and(sticky or not info.st_mode&0o022),'public_monitor_unsafe_path')
        if current==path:need(stat.S_ISREG(info.st_mode)and info.st_nlink==1,'public_monitor_unsafe_file')
    data=(json.dumps(projection(report),sort_keys=True,separators=(',',':'))+'\n').encode()
    fd,name=tempfile.mkstemp(prefix='.monitor-public-',dir=path.parent)
    try:
        with os.fdopen(fd,'wb')as f:
            if os.name!='nt':os.fchmod(f.fileno(),0o644)
            f.write(data);f.flush();os.fsync(f.fileno())
        os.replace(name,path)
        if os.name!='nt':
            directory=os.open(path.parent,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
            try:os.fsync(directory)
            finally:os.close(directory)
    finally:
        if os.path.exists(name):os.unlink(name)
