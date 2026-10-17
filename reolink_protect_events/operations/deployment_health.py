"""Narrow Events-only acceptance of a pinned, pre-existing Frigate outage.

This never changes runtime health or suppresses its dependency failure. The
default installer gate remains strict unless this explicit contract is supplied.
"""
import hashlib
import json
import re


_ERROR_COUNTERS = ('nativeImportErrors', 'replayGaps', 'replayLostPushes',
                   'sourceClockRegressions', 'frigatePossibleHistoryGaps',
                   'frigateMissingActiveEvents', 'expiredThumbnailWindows')
_CONTRACT_KEYS = {'schemaVersion', 'expectedConfigSha256',
                  'expectedDeploymentSha256', 'expectedFailureSha256'}


def _need(condition, code):
    if not condition:
        raise RuntimeError('existing_frigate_' + code)


def _integer(value):
    return type(value) is int and value >= 0


def _scope(config):
    bridges = config.get('bridges', [])
    _need(isinstance(bridges, list) and len(bridges) == 6
          and all(isinstance(row, dict) for row in bridges), 'scope_invalid')
    cameras = [row.get('cameraId') for row in bridges]
    _need(all(isinstance(camera, str) and re.fullmatch('[a-f0-9]{24}', camera)
              for camera in cameras) and len(set(cameras)) == 6, 'scope_invalid')
    frigate = config.get('frigate')
    mapping = frigate.get('cameraMap') if isinstance(frigate, dict) else None
    _need(isinstance(mapping, dict) and len(mapping) == 6
          and set(mapping.values()) == set(cameras), 'scope_invalid')
    return sorted(cameras)


def _core(config, value, now_ms, started_ms=None):
    cameras = _scope(config)
    _need(isinstance(value, dict), 'health_invalid')
    at = value.get('atMs')
    _need(_integer(at) and -5000 <= now_ms - at <= 30000
          and (started_ms is None or at > started_ms), 'health_not_fresh')
    _need(value.get('mode') == 'native' and value.get('nativeReady') is True
          and 'nativeError' in value and value['nativeError'] is None
          and value.get('workerStopped') is not True, 'native_not_ready')
    age = value.get('nativeWorkerAgeMs')
    _need(_integer(age) and age <= 30000, 'worker_not_fresh')
    bridges = value.get('bridges')
    _need(isinstance(bridges, dict) and set(bridges) == set(cameras), 'bridge_scope_changed')
    for camera in cameras:
        row = bridges[camera]
        _need(isinstance(row, dict), 'bridge_not_ready')
        seen = row.get('lastSuccessMs')
        _need(_integer(seen) and -5000 <= now_ms - seen <= 30000
              and (started_ms is None or seen > started_ms)
              and type(row.get('consecutiveErrors')) is int and row['consecutiveErrors'] == 0
              and type(row.get('sourceBacklog')) is int and row['sourceBacklog'] == 0
              and not row.get('errorType'), 'bridge_not_ready')
    for name in ('pending', 'retryIntervals', 'pendingThumbnails', 'failedThumbnails'):
        _need(type(value.get(name)) is int and value[name] == 0, 'outbox_not_ready')
    _need(value.get('thumbnailErrorReasons') == {}, 'thumbnail_errors')
    counters = value.get('counters')
    _need(isinstance(counters, dict) and _integer(value.get('importErrors')), 'counters_invalid')
    errors = {name: counters.get(name, 0) for name in _ERROR_COUNTERS}
    _need(all(_integer(number) for number in errors.values()), 'counters_invalid')
    errors['importErrors'] = value['importErrors']
    return cameras, errors


def _failures(value, cameras, now_ms, prior=None):
    _need(value.get('healthy') is False and value.get('captureHealthy') is False
          and value.get('frigateHealthy') is False, 'failure_not_present')
    rows = value.get('frigate')
    _need(isinstance(rows, dict) and set(rows) == set(cameras), 'failure_scope_changed')
    result = []
    for camera in cameras:
        row = rows[camera]
        _need(isinstance(row, dict) and row.get('errorType') == 'ConnectionRefusedError'
              and _integer(row.get('consecutiveErrors')) and row['consecutiveErrors'] >= 1,
              'failure_changed')
        seen = row.get('lastSuccessMs')
        if prior is None:
            _need(_integer(seen) and seen > 0 and now_ms - seen > 30000,
                  'failure_not_preexisting')
        else:
            # A newly started Runtime has no successful Frigate timestamp yet.
            # A different timestamp would instead describe a new outage.
            _need(seen is None or seen == prior[camera], 'failure_changed')
        result.append({'cameraId': camera, 'errorType': 'ConnectionRefusedError',
                       'lastSuccessMs': seen})
    return result


def _projection(config, value, now_ms):
    cameras, errors = _core(config, value, now_ms)
    return {'schemaVersion': 1, 'kind': 'all-six-frigate-connection-refused',
            'cameraIds': cameras, 'failures': _failures(value, cameras, now_ms),
            'errorCounters': errors}


def _digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(',', ':')).encode()).hexdigest()


def failure_fingerprint(config, value, *, now_ms):
    """Fingerprint only stable, independently validated outage evidence."""
    return _digest(_projection(config, value, now_ms))


def validate_contract(contract):
    """Validate the opt-in schema even on an idempotent resume."""
    _need(isinstance(contract, dict) and set(contract) == _CONTRACT_KEYS
          and type(contract.get('schemaVersion')) is int and contract['schemaVersion'] == 1,
          'contract_invalid')
    for name in _CONTRACT_KEYS - {'schemaVersion'}:
        _need(isinstance(contract[name], str) and re.fullmatch('[a-f0-9]{64}', contract[name]),
              'contract_invalid')


def prepare_baseline(config, value, contract, *, config_sha256, deployment_sha256, now_ms):
    """Validate the request against server-read files and current raw health."""
    validate_contract(contract)
    _need(contract['expectedConfigSha256'] == config_sha256, 'configuration_CAS_mismatch')
    _need(contract['expectedDeploymentSha256'] == deployment_sha256, 'deployment_CAS_mismatch')
    projection = _projection(config, value, now_ms)
    _need(contract['expectedFailureSha256'] == _digest(projection), 'failure_CAS_mismatch')
    return projection


def accept(config, value, baseline, *, started_ms, now_ms):
    """Accept fresh native Events work without rewriting overall health."""
    cameras, errors = _core(config, value, now_ms, started_ms)
    _need(cameras == baseline['cameraIds'] and errors == baseline['errorCounters'],
          'errors_or_scope_changed')
    if value.get('healthy') is True:
        rows = value.get('frigate')
        _need(value.get('captureHealthy') is True and value.get('frigateHealthy') is True
              and isinstance(rows, dict) and set(rows) == set(cameras), 'failure_scope_changed')
        for row in rows.values():
            seen = row.get('lastSuccessMs')
            _need(_integer(seen) and -5000 <= now_ms - seen <= 30000
                  and type(row.get('consecutiveErrors')) is int and row['consecutiveErrors'] == 0
                  and not row.get('errorType'), 'failure_changed')
        return 'healthy'
    _failures(value, cameras, now_ms,
              prior={row['cameraId']: row['lastSuccessMs'] for row in baseline['failures']})
    return 'events-native-ready-existing-frigate-failure'
