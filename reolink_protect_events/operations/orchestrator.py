"""One guarded update of the user's two repositories, with resumable host receipts."""
import base64
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import time
import uuid
from .decode import EXPORT_WINDOW_SECONDS, run_full_decodes
from .release import build_package, source_snapshot
from .locking import process_lock
from .transport import invoke, source_bundle

IPS = ['192.168.30.' + str(i) for i in range(210, 216)]


class UpdateError(RuntimeError):
    pass


def need(value, code):
    if not value:
        raise UpdateError(code)


def load_module(path, name):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


def save(path, value):
    temporary = path.with_name(path.name + '.' + uuid.uuid4().hex)
    with temporary.open('x', encoding='utf-8') as f:
        os.chmod(temporary, 0o600)
        json.dump(value, f, indent=2)
        f.flush()
        os.fsync(f.fileno())
    os.replace(temporary, path)


def gate_decode(report, full=True):
    need(report.get('ok') is True and report.get('realDecodes') is True, 'real_media_decode_failed')
    key = 'allEleven' if full else 'allRequested'
    need(all(report.get(kind, {}).get(key) is True for kind in ('rtspProfileCoverage', 'recordedProfileCoverage')),
         'real_media_decode_coverage_failed')


class Backend:
    def __init__(self, bridge_repo, events_repo, connector, host='unifi-dream-machine', ffmpeg=None, ffprobe=None,
                 dependency_cache=None, progress=None):
        self.bridge_repo = Path(bridge_repo).resolve()
        self.events_repo = Path(events_repo).resolve()
        self.connector = connector
        self.host = host
        self.ffmpeg = ffmpeg
        self.ffprobe = ffprobe
        self.cache = dependency_cache
        self.progress = progress or (lambda value: print(json.dumps(value), flush=True))
        self.bridge_manifest = load_module(self.bridge_repo / 'tools/release_manifest.py', 'owned_bridge_manifest')
        self.nas_cli = load_module(self.bridge_repo / 'tools/deploy/cli.py', 'owned_bridge_deploy')
        self.operation_sources = source_bundle(self.events_repo)
        self.verification_sources = self.operation_sources
        self.nas_sources = self.nas_cli.source_bundle()

    def current_sources(self):
        bridge = self.bridge_manifest.manifest(self.bridge_repo, canonical=True)
        events = source_snapshot(self.events_repo, require_clean=True)
        need(not bridge['sourceDirty'] and not events['sourceDirty'], 'clean_committed_sources_required')
        return {'bridge': bridge, 'events': events}

    def freeze(self, directory):
        sources = self.current_sources()
        archive = directory / 'bridge-source.zip'
        temporary_archive = directory / ('bridge-source-' + uuid.uuid4().hex + '.zip')
        need(not archive.is_symlink(), 'frozen_source_path_invalid')
        self.bridge_manifest.archive_sources(self.bridge_manifest.source_files(self.bridge_repo), temporary_archive, canonical=True)
        os.replace(temporary_archive, archive)
        data, manifest = build_package(self.events_repo, cache=self.cache, require_clean=True)
        (directory / 'events-package.zip').write_bytes(data)
        save(directory / 'operation-sources.json', {'events': self.operation_sources, 'bridge': self.nas_sources})
        return {'sources': sources, 'archiveSha256': hashlib.sha256(archive.read_bytes()).hexdigest(), 'eventsManifest': manifest,
                'operationSourcesSha256': hashlib.sha256((directory / 'operation-sources.json').read_bytes()).hexdigest()}

    def tests(self):
        rows = []
        for repo, folder in ((self.bridge_repo, 'tests/tools'), (self.events_repo, 'tests')):
            result = subprocess.run([sys.executable, '-m', 'unittest', 'discover', '-s', folder], cwd=repo,
                                    capture_output=True, text=True, timeout=240)
            # Test failure details remain captured; public receipts expose only status/count.
            need(result.returncode == 0, 'offline_contract_tests_failed')
            import re
            count = re.search(r'Ran (\d+) tests?', result.stderr)
            rows.append({'repository': repo.name, 'passed': True, 'tests': int(count[1]) if count else None})
        return {'ok': True, 'results': rows}

    def cached_build(self, directory, frozen):
        """Reuse only an exact-source, successful isolated artifact audit.

        The NAS plan subsequently checks the immutable image ID, tag and source
        labels again before recording a baseline or changing any camera.
        """
        required = frozen['sources']['bridge']
        siblings = sorted((p for p in directory.parent.iterdir() if p.is_dir() and not p.is_symlink()
                           and len(p.name) == 32 and all(c in '0123456789abcdef' for c in p.name)),
                          key=lambda p: p.stat().st_mtime, reverse=True)
        for path in siblings[:24]:
            receipt = path / 'update.json'
            if path == directory or receipt.is_symlink() or not receipt.is_file() or receipt.stat().st_size > 16 * 1024 * 1024:
                continue
            try:
                state = json.loads(receipt.read_text(encoding='utf-8'))
                value = state['evidence']['isolated-build-and-hardware-tests']
                release = value['release']
                flags = ('ok', 'testsPassed', 'testedApplicationDllIdentical', 'cleanupConfirmed', 'productionInventoryPreserved', 'kernelProcessLimitVerified')
                if not all(value.get(k) is True for k in flags):
                    continue
                if any(release.get(k) != required[k] for k in ('sourceSha256', 'sourceRevision', 'version')):
                    continue
                if release.get('archiveSha256') != frozen['archiveSha256']:
                    continue
                result = dict(value)
                result['buildCacheReceipt'] = str(receipt)
                result['buildCacheReused'] = True
                return result
            except (KeyError, ValueError, OSError, TypeError):
                continue
        return None

    def nas(self, payload):
        return self.nas_cli.invoke(payload, self.connector, sources=self.nas_sources)

    def udm(self, request, timeout=180):
        if request.get('action') == 'health' and request.get('mode') == 'full':
            timeout = max(timeout, 300)
        readonly = request.get('action') in ('compatibility', 'health', 'event-evidence', 'monitor-status')
        return invoke(self.events_repo, self.host, request, timeout=timeout,
                      sources=self.verification_sources if readonly else self.operation_sources)

    def decode(self, ips=None, not_before_ms=None):
        if not_before_ms is not None:
            # Entire export window must precede the thirty-second index lag.
            self.wait_until(not_before_ms + (EXPORT_WINDOW_SECONDS + 30 + 2) * 1000)
        while True:
            value = run_full_decodes(self.host, ips=ips, ffmpeg=self.ffmpeg, ffprobe=self.ffprobe,
                                     not_before_ms=not_before_ms)
            # Recording-index progress is a readiness condition. Its scoped
            # discovery fails before opening a viewer, so waiting does not hide
            # a failed payload decode or introduce concurrent readers.
            if not_before_ms is None or value.get('errorCode') != 'decode_new_recording_pending':
                return value
            now = int(time.time() * 1000)
            if now >= not_before_ms + 180000:
                return value
            self.progress({'stage': 'waiting-for-recording-index', 'reason': 'new-recording-not-indexed-yet'})
            self.wait_until(min(now + 20000, not_before_ms + 180000))

    def wait_until(self, timestamp):
        while int(time.time() * 1000) < timestamp:
            self.progress({'stage': 'waiting-for-recording-index', 'remainingSeconds': max(1, (timestamp - int(time.time() * 1000)) // 1000)})
            time.sleep(min(20, max(0.05, (timestamp - int(time.time() * 1000)) / 1000)))


class Update:
    def __init__(self, backend, directory, resume=False):
        self.backend = backend
        self.directory = Path(directory).resolve()
        self.path = self.directory / 'update.json'
        if resume:
            need(self.path.is_file() and not self.path.is_symlink(), 'resume_receipt_required')
            self.state = json.loads(self.path.read_text(encoding='utf-8'))
            need(self.state.get('schemaVersion') == 1 and self.state.get('status') in ('running', 'failed'), 'resume_state_invalid')
            if 'frozen' in self.state:
                path = self.directory / 'operation-sources.json'
                need(path.is_file() and not path.is_symlink(), 'frozen_operation_sources_missing')
                data = path.read_bytes()
                need(hashlib.sha256(data).hexdigest() == self.state['frozen']['operationSourcesSha256'], 'frozen_operation_sources_changed')
                sources = json.loads(data)
                self.backend.operation_sources, self.backend.nas_sources = sources['events'], sources['bridge']
                self.state['resumedVerificationSources'] = self.backend.current_sources()['events']
            else:
                need(not self.state['completed'] and not self.state.get('maintenanceIntent') and not self.state.get('maintenanceActive')
                     and not self.state.get('installIntent') and not self.state.get('baseline'), 'incomplete_freeze_state_invalid')
        else:
            need(not self.directory.exists(), 'fresh_update_directory_required')
            self.directory.mkdir(parents=True, mode=0o700)
            self.state = {'schemaVersion': 1, 'owner': uuid.uuid4().hex, 'status': 'running', 'completed': [], 'evidence': {}}
            self.persist()

    def persist(self):
        self.state['atMs'] = int(time.time() * 1000)
        save(self.path, self.state)

    def step(self, name, operation):
        if name in self.state['completed']:
            return self.state['evidence'][name]
        self.backend.progress({'stage': name, 'status': 'running'})
        value = operation()
        if not isinstance(value, dict) or value.get('ok') is not True:
            self.state['evidence'][name + '-failed'] = value if isinstance(value, dict) else {'ok': False, 'errorCode': 'invalid_operation_result'}
            self.persist()
            raise UpdateError(name + '_failed')
        self.state['evidence'][name] = value
        self.state['completed'].append(name)
        self.persist()
        self.backend.progress({'stage': name, 'status': 'passed'})
        return value

    def maintenance(self, enabled, recovery=False):
        if enabled and not recovery:
            self.check_sources()
        self.state['maintenanceIntent'] = enabled
        self.persist()
        result = self.backend.udm({'action': 'installer', 'request': {'mode': 'maintenance', 'owner': self.state['owner'], 'enable': enabled}})
        need(result.get('ok') is True, 'maintenance_change_failed')
        self.state['maintenanceActive'] = enabled
        self.persist()
        return result

    def check_sources(self):
        current = self.backend.current_sources()
        for project in ('bridge', 'events'):
            expected = self.state['frozen']['sources'][project]
            need(all(current[project][key] == expected[key] for key in ('sourceRevision', 'sourceSha256')),
                 'sources_changed_since_release_freeze')

    def health(self, camera_ids=None):
        result = self.backend.udm({'action': 'health', 'mode': 'full', 'cameraIds': camera_ids})
        if result.get('ok') is True:
            need(result.get('fullActiveCoverage') is True if camera_ids is None else
                 sorted(result.get('activeProbeCameraIds', [])) == sorted(camera_ids), 'native_active_probe_coverage_failed')
            return result
        # One scoped repair per camera/release, only for healthy input and a native failure.
        if camera_ids:
            rows = {r['cameraId']: r for r in result.get('cameras', [])}
            need(all(row.get('ok') is True for cid, row in rows.items() if cid not in camera_ids),
                 'unrelated_camera_health_failed')
            for cid in camera_ids:
                row = rows.get(cid, {})
                need(row.get('ok') is False, 'target_failure_not_confirmed')
                need(row.get('sourceHealthy') is True, 'source_unhealthy_no_recorder_repair')
                attempts = self.state.setdefault('repairAttempts', [])
                need(cid not in attempts, 'release_recorder_repair_limit')
                attempts.append(cid)
                self.state['evidence']['repair-trigger-' + cid] = row
                self.persist()  # Charge the attempt before an ambiguous remote dispatch.
                repair = self.backend.udm({'action': 'recover', 'cameraId': cid, 'owner': self.state['owner']}, timeout=300)
                self.state['evidence']['repair-' + cid] = repair
                self.persist()
                need(repair.get('ok') is True and repair.get('restoredOriginalTcp') is True, 'native_recorder_repair_failed')
            checked = self.backend.udm({'action': 'health', 'mode': 'full', 'cameraIds': camera_ids})
            need(sorted(checked.get('activeProbeCameraIds', [])) == sorted(camera_ids), 'native_active_probe_coverage_failed')
            return checked
        return result

    def rollback(self):
        self.maintenance(True, recovery=True)
        results = []
        if self.state.get('installIntent'):
            observed = self.backend.udm({'action': 'installer', 'request': {'mode': 'status'}})
            need(observed.get('ok') is True, 'rollback_events_inventory_failed')
            digest = observed.get('deployment', {}).get('sha256')
            candidate = self.state['frozen']['eventsManifest']['packageSha256']
            if digest == candidate:
                results.append(self.backend.udm({'action': 'installer', 'request': {'mode': 'rollback', 'expectedDigest': candidate}}, timeout=240))
            else:
                need(digest == self.state['installIntent']['previousDigest'], 'rollback_events_deployment_drift')
        if self.state.get('baseline') and self.state.get('release'):
            status = self.backend.nas({'mode': 'resume', 'baseline': self.state['baseline'], 'release': self.state['release']})
            need(status.get('ok') is True, 'rollback_inventory_guard_failed')
            restored = self.backend.nas({'mode': 'rollback-all', 'baseline': self.state['baseline'], 'release': self.state['release'],
                                         'expected': status['bridges']})
            need(restored.get('ok') is True, 'bridge_rollback_failed')
            results.append(restored)
        need(all(r.get('ok') is True for r in results), 'release_rollback_failed')
        need(all(self.state['evidence'].get('repair-' + cid, {}).get('restoredOriginalTcp') is True
                 for cid in self.state.get('repairAttempts', [])), 'recorder_original_settings_unverified')
        health = self.backend.udm({'action': 'health', 'mode': 'full'}, timeout=180)
        self.state['evidence']['rollback-native-media'] = health
        self.persist()
        decoded = self.backend.decode()
        self.state['evidence']['rollback-real-decodes'] = decoded
        self.persist()
        gate_decode(decoded)
        need(health.get('ok') is True and health.get('fullActiveCoverage') is True, 'rollback_native_media_failed')
        return {'ok': True, 'restored': results, 'health': health, 'decode': decoded, 'journalPreserved': True}

    def run(self):
        lock = self.directory / 'controller.lock'
        lease = process_lock(lock)
        lease.__enter__()
        try:
            if self.state['status'] == 'failed' and (self.state.get('maintenanceActive') or self.state.get('maintenanceIntent')):
                self.state['rollback'] = self.rollback()
                self.maintenance(False)
                self.state['status'] = 'rolled-back'
                self.persist()
                return {'ok': False, 'status': 'rolled-back', 'receipt': str(self.path), 'rollback': self.state['rollback']}
            if 'frozen' not in self.state:
                self.state['frozen'] = self.backend.freeze(self.directory)
                self.persist()
            self.check_sources()
            self.step('offline-tests', self.backend.tests)
            self.step('compatibility-before', lambda: self.backend.udm({'action': 'compatibility'}))
            self.step('native-media-before', lambda: self.health())
            self.step('real-decode-before', self._full_decode)
            def build():
                frozen = self.state['frozen']
                cached = getattr(self.backend, 'cached_build', lambda *_: None)(self.directory, frozen)
                if cached is not None:
                    return cached
                return self.backend.nas({'mode': 'build', 'archiveBase64': base64.b64encode((self.directory / 'bridge-source.zip').read_bytes()).decode(),
                    'archiveSha256': frozen['archiveSha256'], 'sourceManifest': frozen['sources']['bridge'],
                    'imageTag': 'reolink-bridge:managed-' + frozen['sources']['bridge']['sourceSha256'][:12] + '-' + self.state['owner'][:8]})
            result = self.step('isolated-build-and-hardware-tests', build)
            need(result.get('productionInventoryPreserved') is True and result.get('cleanupConfirmed') is True, 'build_isolation_not_proven')
            self.state['release'] = result['release']
            self.check_sources()
            self.maintenance(True)
            if 'baseline' not in self.state:
                plan = self.backend.nas({'mode': 'plan', 'release': self.state['release']})
                need(plan.get('ok') is True and len(plan['bridges']) == 6, 'bridge_plan_failed')
                self.state['baseline'] = plan['baseline']
                self.state['evidence']['plan'] = plan
                self.persist()
            status = self.backend.nas({'mode': 'resume', 'baseline': self.state['baseline'], 'release': self.state['release']})
            need(status.get('ok') is True, 'bridge_resume_failed')
            for ip in IPS:
                name = 'camera-' + ip
                if name in self.state['completed']:
                    continue
                if ip in status['pendingIps']:
                    self.check_sources()
                    status = self.backend.nas({'mode': 'apply', 'baseline': self.state['baseline'], 'ip': ip,
                                               'release': self.state['release'], 'expected': status['bridges']})
                    need(status.get('ok') is True, 'bridge_apply_failed')
                    self.state.setdefault('activations', {})[ip] = int(time.time() * 1000)
                    self.persist()
                activation = self.state.setdefault('activations', {}).setdefault(ip, int(time.time() * 1000))
                self.persist()
                row = next(r for r in self.state['evidence']['native-media-before']['cameras'] if r['host'] == ip)
                def verify(ip=ip, cid=row['cameraId'], activation=activation):
                    health = self.health([cid])
                    self.state['evidence'][name + '-health'] = health
                    self.persist()
                    need(health.get('ok') is True, 'camera_native_media_failed')
                    decoded = self.backend.decode([ip], not_before_ms=activation)
                    self.state['evidence'][name + '-decode'] = decoded
                    self.persist()
                    gate_decode(decoded, full=False)
                    return {'ok': True, 'health': health, 'decode': decoded, 'afterActivationMs': activation}
                self.step(name, verify)
                status = self.backend.nas({'mode': 'resume', 'baseline': self.state['baseline'], 'release': self.state['release']})
                need(status.get('ok') is True, 'bridge_resume_failed')
            self.step('bridge-final-receipt', lambda: self.backend.nas({'mode': 'final', 'baseline': self.state['baseline'],
                       'release': self.state['release'], 'expected': status['bridges']}))
            self.step('compatibility-before-events', lambda: self.backend.udm({'action': 'compatibility'}))
            self.check_sources()
            package = (self.directory / 'events-package.zip').read_bytes()
            need(hashlib.sha256(package).hexdigest() == self.state['frozen']['eventsManifest']['packageSha256'], 'events_package_changed')
            if not self.state.get('installIntent'):
                current = self.backend.udm({'action': 'installer', 'request': {'mode': 'status'}})
                need(current.get('ok') is True, 'events_preinstall_inventory_failed')
                self.state['installIntent'] = {'previousDigest': current.get('deployment', {}).get('sha256')}
                self.persist()
            self.step('install-events', lambda: self.backend.udm({'action': 'installer', 'request': {'mode': 'install',
                'package': base64.b64encode(package).decode(), 'digest': self.state['frozen']['eventsManifest']['packageSha256'],
                'owner': self.state['owner']}}, timeout=300))
            self.step('compatibility-after', lambda: self.backend.udm({'action': 'compatibility'}))
            self.step('native-media-after', lambda: self.health())
            self.step('real-decode-after', self._full_decode)
            self.step('genuine-event-evidence', lambda: self.backend.udm({'action': 'event-evidence'}))
            self.maintenance(False)
            self.state['status'] = 'complete'
            self.persist()
            return {'ok': True, 'status': 'complete', 'receipt': str(self.path), 'bridgeRelease': self.state['release'],
                    'eventsVersion': self.state['frozen']['eventsManifest']['version'], 'allCameras': True}
        except Exception as error:
            self.state['status'] = 'failed'
            self.state['errorCode'] = str(error) if isinstance(error, UpdateError) else 'update_operation_failed'
            self.state['errorType'] = type(error).__name__
            self.persist()
            if self.state.get('maintenanceActive') or self.state.get('maintenanceIntent'):
                try:
                    self.state['rollback'] = self.rollback()
                    self.maintenance(False)
                    self.state['status'] = 'rolled-back'
                except Exception as rollback_error:
                    self.state['rollback'] = {'ok': False, 'errorCode': 'rollback_verification_failed', 'errorType': type(rollback_error).__name__}
                    # Keep owned maintenance on an unresolved transaction; resume explicitly.
                self.persist()
            return {'ok': False, 'status': self.state['status'], 'errorCode': self.state['errorCode'],
                    'rollback': self.state.get('rollback'), 'receipt': str(self.path)}
        finally:
            lease.__exit__(None, None, None)

    def _full_decode(self):
        value = self.backend.decode()
        gate_decode(value)
        return value
