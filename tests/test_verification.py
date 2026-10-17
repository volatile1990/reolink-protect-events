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


def group_report():
    result = report()
    result['event'].update(end=115000, smartDetectTypes=['person', 'vehicle'],
        sourceUnionVersion=1, sourceTypes=['frigate', 'reolink'], classificationOrigin='mixed',
        source='reolink-and-frigate', mergePolicy='camera_visual_positive_overlap', objectIdentityMatched=False,
        identityStart=100000, visualGroupVersion=1, groupIdentityStart=100000, activationMs=99000,
        groupMaxSpanMs=120000, classIntervalsComplete=True,
        classIntervals={'vehicle': [{'start': 100000, 'end': 115000}],
                        'person': [{'start': 107000, 'end': 110000}]})
    result['graph']['objects'][0]['detectedAt'] = 107000
    car = dict(result['graph']['objects'][0], id='5' * 24, type='vehicle', detectedAt=100000)
    result['graph']['objects'].append(car)
    for search in result['searchFilters']:
        search['found'] = search['class'] in ('person', 'vehicle')
        # The first true image precedes the person. Search correctness does not
        # depend on fabricating a later person's detectedThumbnail image.
        search['objectIds'] = []
    return result


class VerificationTests(unittest.TestCase):
    def test_complete_known_good_graph_passes(self):
        checks = verify_checks(report(), EVENT, ['person'], [CAMERA])
        self.assertTrue(all(checks.values()), checks)

    def test_truthful_external_and_mixed_union_sources_are_verified(self):
        for types, origin, source in ((["frigate"], "external-model", "frigate-object-detection"),
                                      (["frigate", "reolink"], "mixed", "reolink-and-frigate")):
            value = report()
            value["event"].update(sourceUnionVersion=1, sourceTypes=types, classificationOrigin=origin,
                                  source=source, mergePolicy="camera_class_time_union", objectIdentityMatched=False)
            self.assertTrue(all(verify_checks(value, EVENT, ["person"], [CAMERA]).values()))
            value["event"]["classificationOrigin"] = "camera"
            self.assertFalse(verify_checks(value, EVENT, ["person"], [CAMERA])["sourceOwnership"])

    def test_group_verifies_both_classes_at_their_actual_times_without_person_image(self):
        checks = verify_checks(group_report(), EVENT, ['person', 'vehicle'], [CAMERA])
        self.assertEqual(len(checks), 14)
        self.assertTrue(all(checks.values()), checks)
        value = group_report()
        value['event']['end'] = None
        value['event']['classIntervals']['vehicle'][0]['end'] = None
        value['graph']['thumbnails'][0]['timestamp'] = 140000
        value['graph']['thumbnails'][1]['timestamp'] = 140000
        self.assertTrue(all(verify_checks(value, EVENT, ['person', 'vehicle'], [CAMERA]).values()))

    def test_group_does_not_accept_event_start_as_later_class_detection_time(self):
        value = group_report()
        value['graph']['objects'][0]['detectedAt'] = value['event']['start']
        self.assertFalse(verify_checks(value, EVENT, ['person', 'vehicle'], [CAMERA])['graph'])
        value = report()
        value['graph']['objects'][0]['detectedAt'] += 1
        self.assertFalse(verify_checks(value, EVENT, ['person'], [CAMERA])['graph'])

    def test_group_protocol_and_complete_class_intervals_fail_closed(self):
        for change in (
                {'visualGroupVersion': True}, {'visualGroupVersion': 2}, {'sourceUnionVersion': True},
                {'classIntervalsComplete': False}, {'classIntervals': {}}, {'groupIdentityStart': 100001},
                {'activationMs': 100001}, {'groupMaxSpanMs': 300001},
                {'classIntervals': {'vehicle': [{'start': 100000, 'end': 115000}]}},
                {'classIntervals': {'vehicle': [{'start': 100000, 'end': 115000}],
                                    'person': [{'start': 99000, 'end': 110000}]}},
                {'classIntervals': {'vehicle': [{'start': 100000, 'end': 115000}],
                                    'person': [{'start': 107000, 'end': 116000}]}},
                {'classIntervals': {'vehicle': [{'start': 100000, 'end': 115000}],
                                    'person': [{'start': 107000, 'end': None}]}},
                {'classIntervals': {'vehicle': [{'start': 100000, 'end': 115000}],
                                    'person': [{'start': 107000, 'end': 109000}, {'start': 108000, 'end': 110000}]}},
                {'mergePolicy': 'camera_class_time_union'}):
            value = group_report()
            value['event'].update(change)
            with self.subTest(change=change):
                checks = verify_checks(value, EVENT, ['person', 'vehicle'], [CAMERA])
                self.assertFalse(checks['sourceOwnership'], checks)

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
        for field in ('identityStart', 'visualGroupVersion', 'groupIdentityStart', 'activationMs',
                      'groupMaxSpanMs', 'classIntervalsComplete', 'classIntervals'):
            self.assertIn("'" + field + "':provenance.get('" + field + "')", module.REMOTE)


if __name__ == '__main__':
    unittest.main()
