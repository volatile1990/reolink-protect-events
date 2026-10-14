"""Read genuine imported events and selected thumbnail metadata, without media files."""
import json
from contextlib import closing
from pathlib import Path
import sqlite3
from ..http_deadline import get_bytes
from ..native import _jpeg_size, sql_text
from .http import protect_json
from .safety import private_path, read_json


def inspect(config, root='/data/reolink-protect-events'):
    root = Path(root)
    health = read_json(private_path(root / 'health.json'))
    path = private_path(root / 'journal.sqlite3')
    with closing(sqlite3.connect('file:' + str(path) + '?mode=ro', uri=True, timeout=10)) as db:
        db.execute('PRAGMA query_only=ON')
        counts = dict(db.execute('SELECT class,COUNT(*) FROM intervals WHERE delivered_revision>0 GROUP BY class'))
        columns = {r[1] for r in db.execute('PRAGMA table_info(media)')}
        selections = []
        if 'selection' in columns:
            rows = db.execute('SELECT i.id,i.camera,i.class,i.start,i.end,m.selection FROM intervals i JOIN media m ON m.event_id=i.id WHERE m.done=1 AND m.selection IS NOT NULL ORDER BY i.start DESC LIMIT 12').fetchall()
            for eid, camera, cls, start, end, raw in rows:
                selected = json.loads(raw)
                if selected.get('automaticSelected') is not True:
                    continue
                event = protect_json(config, '/api/events/' + eid)
                own = (event.get('metadata') or {}).get('reolinkProtectEvents') or {}
                genuine = own.get('owner') == 'reolink-protect-events' and event.get('camera') == camera
                headers = {'X-UserId': config['protectUserId'], 'X-UserRole': 'owner', 'X-UserPermissionMask': '64',
                           'X-UserPermissions': '65535', 'X-Internal-Use': 'true'}
                code, image = get_bytes('https://127.0.0.1:7443/api/events/' + eid + '/thumbnail?isFullfov=true',
                                        headers, timeout=10, limit=2097152)
                dimensions = _jpeg_size(image) if code == 200 else None
                selections.append({'eventId': eid, 'cameraId': camera, 'class': cls, 'startMs': start, 'endMs': end,
                                   'genuineImportedEvent': genuine, 'selection': selected,
                                   'protectThumbnailAvailable': dimensions is not None,
                                   'thumbnailDimensions': dimensions, 'thumbnailBytes': len(image) if dimensions else 0})
                if len(selections) >= 3:
                    break
    return {'ok': health.get('healthy') is True and bool(counts), 'readOnly': True,
            'importedIntervalsByClass': counts, 'automaticThumbnails': selections,
            'automaticThumbnailProven': any(r['genuineImportedEvent'] and r['protectThumbnailAvailable']
                                          and r['selection'].get('decodedCandidates', 0) >= 2 for r in selections),
            'mediaPersisted': False}
