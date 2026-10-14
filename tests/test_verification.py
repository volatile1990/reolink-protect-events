import ast
import copy
import importlib.util
from pathlib import Path
import unittest

from reolink_protect_events.verification import verify_checks

EVENT = '1' * 24
CAMERA = '2' * 24


def report():
    image = {'status': 200, 'isJpeg': True, 'bytes': 200, 'dimensions': {'width': 10, 'height': 10}}
    return {'event': {'id': EVENT, 'camera': CAMERA, 'type': 'smartDetectZone', 'start': 100000,
        'score': None, 'smartDetectTypes': ['person'], 'owner': 'reolink-protect-events', 'schemaVersion': 1,
        'classificationOrigin': 'camera', 'confidenceAvailable': False, 'spatialTrackAvailable': False, 'adapterVirtualZone': True},
        'eventApiStatus': 200, 'bootstrapApiStatus': 200, 'protectVersion': '7.3.70',
        'eventFilteredApi': {'status': 200, 'found': True},
        'cameras': [{'id': CAMERA, 'isThirdPartyCamera': True, 'isPairedWithAiPort': False,
                     'hasSmartDetect': True, 'smartDetectTypes': ['person', 'vehicle', 'animal'], 'zoneIds': [1]}],
        'searchFilters': [{'class': kind, 'minConfidence': confidence, 'status': 200,
                          'found': kind == 'person', 'inventedConfidencePresent': False}
                         for kind in ('person', 'vehicle', 'animal') for confidence in (30, 95)],
        'tracksApi': {'status': 200, 'samples': 0, 'event': EVENT, 'camera': CAMERA},
        'thumbnailApi': dict(image), 'timelineThumbnailApi': dict(image), 'timelineThumbnailExplicitApi': dict(image),
        'graph': {'readOnly': 'on', 'eventRows': 1, 'deleted': False, 'spatialAreaRows': 0,
                  'objects': [{'id': '3' * 24, 'type': 'person', 'eventId': EVENT, 'cameraId': CAMERA,
                               'detectedAt': 100000, 'confidenceKeyPresent': False, 'spatialCoordPresent': False, 'adapterVirtualZone': True}],
                  'tracks': [{'id': '4' * 24, 'samples': 0}],
                  'thumbnails': [{'isFullfov': full, 'bytes': 200, 'width': 10, 'height': 10, 'timestamp': 100000} for full in (None, True)]}}


class VerificationTests(unittest.TestCase):
    def test_complete_known_good_graph_passes(self):
        checks = verify_checks(report(), EVENT, ['person'], [CAMERA])
        self.assertTrue(all(checks.values()), checks)

    def test_previously_ignored_failures_are_rejected_individually(self):
        for name, mutate in (
            ('version', lambda r: r.update(protectVersion='new version')),
            ('bootstrap', lambda r: r.update(bootstrapApiStatus=503)),
            ('eventApi', lambda r: r['event'].update(id='5' * 24)),
            ('sourceOwnership', lambda r: r['event'].update(owner='other integration')),
            ('sourceOwnership', lambda r: r['event'].update(classificationOrigin='inferred')),
            ('truthfulSource', lambda r: r['event'].update(score=90)),
            ('cameraFeatures', lambda r: r['cameras'][0].update(hasSmartDetect=False)),
            ('cameraFeatures', lambda r: r['cameras'][0].update(isPairedWithAiPort=True)),
            ('cameraFeatures', lambda r: r['cameras'][0].update(zoneIds=[])),
            ('tracks', lambda r: r['tracksApi'].update(status=404)),
            ('tracks', lambda r: r['tracksApi'].update(event='5' * 24)),
            ('tracks', lambda r: r['tracksApi'].update(samples=1)),
            ('eventFilter', lambda r: r['eventFilteredApi'].update(status=500)),
            ('graph', lambda r: r['graph']['objects'][0].update(confidenceKeyPresent=True)),
            ('graph', lambda r: r['graph']['objects'][0].update(cameraId='5' * 24)),
            ('thumbnailPaths', lambda r: r['timelineThumbnailApi'].update(status=404)),
            ('thumbnailPaths', lambda r: r['thumbnailApi'].update(dimensions={'width': 0, 'height': 10})),
            ('thumbnailGraph', lambda r: r['graph'].update(thumbnails=[])),
        ):
            with self.subTest(check=name):
                value = report()
                mutate(value)
                checks = verify_checks(value, EVENT, ['person'], [CAMERA])
                self.assertFalse(checks[name], checks)

    def test_missing_camera_and_empty_search_cannot_pass_vacuously(self):
        value = report()
        self.assertFalse(verify_checks(value, EVENT, ['person'], [CAMERA, '5' * 24])['eventCameraScope'])
        value['searchFilters'] = []
        self.assertFalse(verify_checks(value, EVENT, ['person'], [CAMERA])['searchFilters'])
        value['cameras'] = []
        self.assertFalse(verify_checks(value, EVENT, ['person'], [CAMERA])['cameraFeatures'])

    def test_actual_tool_invokes_full_checks_and_has_valid_remote_source(self):
        path = Path(__file__).resolve().parents[1] / 'tools/verify_native.py'
        spec = importlib.util.spec_from_file_location('native_verify_test', path)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        parsed = ast.parse(module.REMOTE)
        names = {node.func.id for node in ast.walk(parsed) if isinstance(node, ast.Call) and isinstance(node.func, ast.Name)}
        self.assertIn('verify_checks', names)


if __name__ == '__main__':
    unittest.main()
