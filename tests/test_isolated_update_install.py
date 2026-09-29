"""Opt-in full Sparkle installation via the candidate model and worker.

PROXYPILOT_TEST_ISOLATED_INSTALLER=1 python3 -m unittest discover -s tests -p test_isolated_update_install.py -v

Only fresh user-owned test bundles and ephemeral keys; no privileged installer,
real app/profile, production feed or Keychain. Automated choices replace only
the UI driver; download, signature checks, installation and relaunch are real.
"""
from functools import partial
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
import hashlib
import os
import plistlib
import re
import shutil
import signal
import subprocess
import sys
import tempfile
import threading
import time
import unittest
import uuid
import zipfile
from test_update_quiescence import inert_proxy_model_source

ROOT = Path(__file__).resolve().parents[1]
SPARKLE = ROOT / 'vendor/sparkle-2.9.6'
FRAMEWORK = SPARKLE / 'Sparkle.xcframework/macos-arm64_x86_64/Sparkle.framework'


class Handler(SimpleHTTPRequestHandler):
    def do_GET(self):
        self.server.requests.append(self.path)
        if self.path == '/appcast.xml' and self.server.mode == 'native-network' and self.server.requests.count(self.path) == 1:
            self.send_error(503, 'Disposable test network failure')
            return
        if self.path == '/update.zip' and self.server.mode == 'native-cancel-download':
            payload = (Path(self.directory) / 'update.zip').read_bytes()
            self.send_response(200)
            self.send_header('Content-Length', str(len(payload)))
            self.end_headers()
            try:
                self.wfile.write(payload[:1024]); self.wfile.flush()
                # Keep the actual download window available for a human/CUA
                # cancellation. Cleanup can interrupt this fixture-only delay.
                self.server.stop_transfer.wait(120)
                self.wfile.write(payload[1024:])
            except (BrokenPipeError, ConnectionResetError):
                pass
            return
        if self.path == '/appcast.xml' and getattr(self.server, 'release_feeds', None):
            feeds = self.server.release_feeds
            events = self.server.host_events.read_text() if self.server.host_events.exists() else ''
            index = 1 if len(feeds) > 1 and self.server.next_feed_trigger in events else 0
            payload = feeds[index].read_bytes()
            self.send_response(200)
            self.send_header('Content-Type', 'application/xml')
            self.send_header('Content-Length', str(len(payload)))
            self.end_headers()
            self.wfile.write(payload)
            return
        super().do_GET()

    def log_message(self, *args):
        pass


class IsolatedInstallFixture:
    full_app = False

    @classmethod
    def frontend_sources(cls, build, proxy_model):
        return ['-D', 'ISOLATED_UPDATER', str(ROOT / 'app/update-worker/IsolatedUpdates.swift'), str(proxy_model), str(ROOT / 'tests/isolated-update-install/Frontend.swift')]

    def prepare_environment(self, work, mode): return None
    def configure_bundle(self, app, work, mode): pass
    def observe_running(self, work, events): pass
    def verify_environment(self, app, work, mode, events): pass

    @staticmethod
    def run_command(command, timeout=90):
        result = subprocess.run(command, capture_output=True, text=True, timeout=timeout)
        if result.returncode:
            raise AssertionError(result.stdout + result.stderr)
        return result.stdout

    @classmethod
    def setUpClass(cls):
        cls.compiled = tempfile.TemporaryDirectory(prefix='proxypilot-isolated-install-build-')
        cls.addClassCleanup(cls.compiled.cleanup)
        build = Path(cls.compiled.name)
        original = (ROOT / 'app/update-worker/UpdateWorker.swift').read_text()
        admission = 'VPNUpdateAdmission.inspectSystem()'
        if original.count(admission) != 1: raise AssertionError('Admission boundary changed')
        cls_source = original.replace(admission, '''VPNUpdateAdmission.inspect(
            applicationSupport: (UpdateWorker.enclosingHost()!.object(forInfoDictionaryKey: "TestDirectory") as! String) + "/admission/support",
            launchDaemons: (UpdateWorker.enclosingHost()!.object(forInfoDictionaryKey: "TestDirectory") as! String) + "/admission/daemons")''')
        if not getattr(cls, 'native_preview', False):
            cls_source = cls_source.replace('private var driver: SPUStandardUserDriver!', 'private var driver: SPUUserDriver!')
            cls_source = cls_source.replace('driver = SPUStandardUserDriver(hostBundle: host, delegate: self)',
                                        'driver = InstallDriver(host: host, delegate: self)')
            if cls_source == original or 'driver = SPUStandardUserDriver(' in cls_source:
                raise AssertionError('Test UI driver was not substituted')
        else:
            probes = {
                'try updater.start()': '''NativeProbe.observeActivation()
        try updater.start()
        if host.object(forInfoDictionaryKey: "TestMode") as? String == "native-background" {
            precondition(updater.automaticallyChecksForUpdates)
            NativeProbe.record("background-start")
            updater.checkForUpdatesInBackground()
        }''',
                'availableVersion = update.displayVersionString; publish()': '''NativeProbe.record("found user=\\(state.userInitiated) shown=\\(handleShowingUpdate)")
        if !state.userInitiated { NativeProbe.quietWindowCheck() }
        availableVersion = update.displayVersionString; publish()''',
                'func standardUserDriverWillFinishUpdateSession() {': 'func standardUserDriverWillFinishUpdateSession() {\n        NativeProbe.record("native-finished")',
                'func updater(_ updater: SPUUpdater, didAbortWithError error: Error) {': 'func updater(_ updater: SPUUpdater, didAbortWithError error: Error) {\n        NativeProbe.error(error)',
                'case .check:': 'case .check:\n            NativeProbe.manualCheck = true',
            }
            for needle, replacement in probes.items():
                if cls_source.count(needle) != 1: raise AssertionError('Native observation hook changed: ' + needle)
                cls_source = cls_source.replace(needle, replacement)
        source = build / 'Worker.swift'
        source.write_text(cls_source)
        # The released model is an immutable regression fixture, not a rewrite
        # of the current code pretending to be the previous version.
        snapshot = (ROOT / 'tests/isolated-update-install/LegacyUpdates-1.5.1.swift').read_text()
        old_source = snapshot.split('// ORIGINAL_SOURCE\n', 1)[1].rstrip() + '\n'
        if hashlib.sha256(old_source.encode()).hexdigest() != '7e28f62a0b9a7bc4bde5bf66ec5e87e239f66c2f9ea5de99fe9f057847731539':
            raise AssertionError('Pinned 1.5.1 updater fixture changed')
        legacy = build / 'LegacyUpdates.swift'
        legacy.write_text(old_source.replace('SPUStandardUpdaterController', 'LegacyUIAdapter'))
        proxy_model = build / 'ProxyModel.swift'
        proxy_model.write_text(inert_proxy_model_source())
        common = [str(ROOT / 'app/update-worker/UpdateWire.swift'), str(ROOT / 'app/update-worker/UpdateChannel.swift'),
                  str(ROOT / 'app/update-worker/VPNUpdateAdmission.swift')]
        for name, extras in [
            ('Frontend', cls.frontend_sources(build, proxy_model)),
            ('Worker', ['-D', 'UPDATE_WORKER_TESTING', '-F', str(FRAMEWORK.parent), '-framework', 'Sparkle',
                        '-Xlinker', '-rpath', '-Xlinker', '@executable_path/../Frameworks',
                        str(ROOT / 'app/update-worker/JointRelaunchSentinel.swift'), str(source),
                        str(ROOT / 'tests/isolated-update-install/Driver.swift'), str(ROOT / 'tests/isolated-update-install/NativeProbe.swift')]),
            ('LegacyFrontend', ['-D', 'LEGACY_UPDATER_TESTING', '-F', str(FRAMEWORK.parent), '-framework', 'Sparkle',
                                '-Xlinker', '-rpath', '-Xlinker', '@executable_path/../Frameworks', str(legacy),
                                str(ROOT / 'tests/isolated-update-install/LegacyUIAdapter.swift'),
                                str(ROOT / 'tests/isolated-update-install/Driver.swift'),
                                str(proxy_model),
                                str(ROOT / 'tests/isolated-update-install/Frontend.swift')])]:
            slices = []
            for arch in ('arm64', 'x86_64'):
                binary = build / f'{name}-{arch}'
                parsing = [] if name == 'Frontend' and cls.full_app else ['-parse-as-library']
                cls.run_command(['swiftc', *parsing, '-target', f'{arch}-apple-macosx11.0',
                                 '-module-cache-path', str(build / 'ModuleCache'), *common, *extras, '-o', str(binary)], timeout=180)
                slices.append(str(binary))
            cls.run_command(['lipo', '-create', *slices, '-output', str(build / name)])
        generator = build / 'key.swift'
        generator.write_text('''import Foundation
import CryptoKit
let key = Curve25519.Signing.PrivateKey()
try key.rawRepresentation.base64EncodedString().write(toFile: CommandLine.arguments[1], atomically: false, encoding: .utf8)
print(key.publicKey.rawRepresentation.base64EncodedString())
''')
        cls.run_command(['swiftc', '-module-cache-path', str(build / 'ModuleCache'), str(generator), '-o', str(build / 'key')])

    @staticmethod
    def matching_processes(work, identifier):
        rows = subprocess.run(['ps', '-axo', 'pid=,command='], capture_output=True, text=True, check=True).stdout.splitlines()
        matches = []
        for row in rows:
            fields = row.strip().split(None, 1)
            if len(fields) == 2 and (str(work) in fields[1] or identifier in fields[1]):
                matches.append((int(fields[0]), fields[1]))
        return matches

    def scenario(self, mode):
        with tempfile.TemporaryDirectory(prefix='proxypilot-isolated-install-') as directory:
            work = Path(directory).resolve()
            identifier = 'kz.documentolog.proxypilot.workercheck.' + uuid.uuid4().hex
            server = ThreadingHTTPServer(('127.0.0.1', 0), partial(Handler, directory=str(work)))
            server.requests = []
            server.mode = mode
            server.stop_transfer = threading.Event()
            threading.Thread(target=server.serve_forever, daemon=True).start()
            process = None
            environment = None
            try:
                (work / 'admission/support').mkdir(parents=True)
                (work / 'admission/daemons').mkdir()
                environment = self.prepare_environment(work, mode)
                versions = ['1.5.1', '1.5.2', '1.5.3'] if mode in ('migration', 'repeat') else ['1.0.0', '2.0.0']
                is_legacy = mode == 'migration'
                app = work / 'installed/ProxyPilot Install TEST.app'
                worker = app / 'Contents/Helpers/ProxyPilot Updater.app'
                (app / 'Contents/MacOS').mkdir(parents=True)
                (worker / 'Contents/MacOS').mkdir(parents=True)
                (worker / 'Contents/Frameworks').mkdir()
                self.run_command(['ditto', str(FRAMEWORK), str(worker / 'Contents/Frameworks/Sparkle.framework')])
                binary = app / 'Contents/MacOS/Frontend'
                shutil.copy2(Path(self.compiled.name) / ('LegacyFrontend' if is_legacy else 'Frontend'), binary)
                shutil.copy2(Path(self.compiled.name) / 'Worker', worker / 'Contents/MacOS/ProxyPilotUpdater')
                seed = work / 'ephemeral-key'
                seed.touch(mode=0o600)
                public = self.run_command([str(Path(self.compiled.name) / 'key'), str(seed)]).strip()
                info = dict(CFBundleIdentifier=identifier, CFBundleExecutable='Frontend', CFBundleName='ProxyPilot Install TEST',
                            CFBundlePackageType='APPL', CFBundleVersion=versions[0], CFBundleShortVersionString=versions[0],
                            LSMinimumSystemVersion='11.0', LSUIElement=True,
                            SUFeedURL=f'http://127.0.0.1:{server.server_port}/appcast.xml', SUPublicEDKey=public,
                            SUEnableAutomaticChecks=False, SUAutomaticallyUpdate=False, SUAllowsAutomaticUpdates=False,
                            SURequireSignedFeed=True, SUVerifyUpdateBeforeExtraction=True, SUSignedFeedFailureExpirationInterval=0,
                            TestDirectory=str(work), TestMode=mode, TestInitialVersion=versions[0], TestFinalVersion=versions[-1])
                worker_info = dict(CFBundleIdentifier=identifier + '.updater', CFBundleExecutable='ProxyPilotUpdater',
                                   CFBundleName='ProxyPilot Updater TEST', CFBundlePackageType='APPL',
                                   CFBundleVersion='999.0.0', CFBundleShortVersionString='999.0.0', LSMinimumSystemVersion='11.0',
                                   LSUIElement=True, NSAppTransportSecurity={'NSAllowsArbitraryLoads': True})
                (app / 'Contents/Info.plist').write_bytes(plistlib.dumps(info))
                (worker / 'Contents/Info.plist').write_bytes(plistlib.dumps(worker_info))
                self.configure_bundle(app, work, mode)
                info = plistlib.loads((app / 'Contents/Info.plist').read_bytes())
                self.run_command(['codesign', '--force', '--sign', '-', str(worker)])
                self.run_command(['codesign', '--force', '--sign', '-', '--options', 'runtime,hard,kill', str(app)])
                self.run_command(['codesign', '--verify', '--deep', '--strict', str(app)])
                if is_legacy: self.assertIn('Sparkle.framework', self.run_command(['otool', '-L', str(binary)]))
                else: self.assertNotIn('Sparkle.framework', self.run_command(['otool', '-L', str(binary)]))
                server.release_feeds = []
                server.host_events = work / 'host.events'
                server.next_feed_trigger = f'relaunched {versions[1]} preferences-preserved'
                archives = []
                for version in versions[1:]:
                    new_app = work / f'new-{version}/ProxyPilot Install TEST.app'
                    new_app.parent.mkdir()
                    shutil.copytree(app, new_app, symlinks=True)
                    shutil.copy2(Path(self.compiled.name) / 'Frontend', new_app / 'Contents/MacOS/Frontend')
                    (new_app / 'Contents/Info.plist').write_bytes(plistlib.dumps(dict(info, CFBundleVersion=version, CFBundleShortVersionString=version)))
                    self.run_command(['codesign', '--force', '--sign', '-', '--options', 'runtime,hard,kill', str(new_app)])
                    archive = work / (f'update-{version}.zip' if len(versions) > 2 else 'update.zip')
                    archives.append(archive)
                    self.run_command(['ditto', '-c', '-k', '--sequesterRsrc', '--keepParent', str(new_app), str(archive)])
                    signature = self.run_command([str(SPARKLE / 'bin/sign_update'), '--ed-key-file', str(seed), str(archive)]).strip()
                    feed = work / f'appcast-{version}.xml'
                    feed.write_text(f'''<?xml version="1.0"?><rss version="2.0" xmlns:sparkle="http://www.andymatuschak.org/xml-namespaces/sparkle"><channel><title>Disposable TEST</title><item>
<title>{version}</title><sparkle:version>{version}</sparkle:version><sparkle:shortVersionString>{version}</sparkle:shortVersionString>
<description><![CDATA[<h2>Test update</h2><p>English release notes for a disposable test only.</p>]]></description>
<enclosure url="http://127.0.0.1:{server.server_port}/{archive.name}" type="application/octet-stream" {signature}/>
</item></channel></rss>''')
                    self.run_command([str(SPARKLE / 'bin/sign_update'), '--ed-key-file', str(seed), str(feed)])
                    server.release_feeds.append(feed)
                if is_legacy:
                    # Reproduce the old layout/signing without launching the
                    # real 1.5.1 app, its CLI, or any production preferences.
                    shutil.rmtree(app / 'Contents/Helpers')
                    (app / 'Contents/Frameworks').mkdir()
                    self.run_command(['ditto', str(FRAMEWORK), str(app / 'Contents/Frameworks/Sparkle.framework')])
                    self.run_command(['codesign', '--force', '--sign', '-', '--options', '0', str(app)])
                    self.run_command(['codesign', '--verify', '--deep', '--strict', str(app)])
                if mode in ('corrupt', 'native-corrupt'):
                    archive = archives[0]
                    data = bytearray(archive.read_bytes())
                    self.assertEqual(data[:4], b'PK\x03\x04')
                    # Change only a local-header DOS timestamp: keep the ZIP
                    # readable/CRC-valid, but invalidate the Ed25519 signature.
                    data[10] ^= 1; archive.write_bytes(data)
                    with zipfile.ZipFile(archive) as changed:
                        self.assertIsNone(changed.testzip())
                original_info = hashlib.sha256((app / 'Contents/Info.plist').read_bytes()).hexdigest()
                host_log, worker_log = work / 'host.events', work / 'worker.events'
                with (work / 'console.log').open('w+') as log:
                    process = subprocess.Popen([str(binary)], stdout=log, stderr=subprocess.STDOUT, start_new_session=True)
                    installing = mode in ('install', 'native', 'migration', 'repeat', 'vpn-retry')
                    if mode.startswith('native'):
                        print(f'NATIVE PREVIEW WORKER: {worker}', flush=True)
                        print(f'HOST: {app}\nIDENTIFIER: {identifier}', flush=True)
                    deadline = time.monotonic() + (185 if mode.startswith('native') else 65)
                    while time.monotonic() < deadline:
                        events = host_log.read_text() if host_log.exists() else ''
                        self.observe_running(work, events)
                        if installing and f'relaunched {versions[-1]} preferences-preserved' in events:
                            break
                        if not installing and process.poll() is not None:
                            break
                        if 'timeout' in events or 'worker-unavailable' in events:
                            break
                        time.sleep(0.1)
                    host_events = host_log.read_text() if host_log.exists() else ''
                    worker_events = worker_log.read_text() if worker_log.exists() else ''
                    log.seek(0)
                    evidence = f'{host_events}\nWORKER:\n{worker_events}\n{log.read()}'
                    self.assertNotIn('timeout', host_events, evidence)
                    self.assertNotIn('worker-unavailable', host_events, evidence)
                    if installing:
                        for version in versions[1:]: self.assertIn(f'relaunched {version} preferences-preserved', host_events, evidence)
                        self.assertEqual(host_events.splitlines().count('prepare'), len(versions) - 1, evidence)
                        self.assertEqual(host_events.splitlines().count('commands-drained state-preserved'), len(versions) - 1, evidence)
                        self.assertEqual(plistlib.loads((app / 'Contents/Info.plist').read_bytes())['CFBundleVersion'], versions[-1])
                        self.assertFalse((app / 'Contents/Frameworks').exists())
                        self.assertTrue((app / 'Contents/Helpers/ProxyPilot Updater.app').is_dir())
                        self.assertNotIn('Sparkle.framework', self.run_command(['otool', '-L', str(binary)]))
                        if len(versions) > 2:
                            hosts = [int(pid) for pid in re.findall(r'launched [0-9.]+ pid=(\d+)', host_events)]
                            drivers = [int(pid) for pid in re.findall(r'driver-start pid=(\d+)', worker_events)]
                            self.assertEqual(len(set(hosts)), 3, evidence)
                            self.assertEqual(len(drivers), 2, evidence)
                            self.assertEqual(drivers[0] == hosts[0], is_legacy, evidence)
                            self.assertNotEqual(drivers[1], hosts[1], evidence)
                    else:
                        self.assertIn('idle', host_events, evidence)
                        self.assertNotIn('prepare', host_events, evidence)
                        self.assertNotIn('relaunched 2.0.0', host_events, evidence)
                        self.assertEqual(hashlib.sha256((app / 'Contents/Info.plist').read_bytes()).hexdigest(), original_info)
                    if mode in ('corrupt', 'native-corrupt'):
                        # Sparkle may wrap SUSignatureError in SUValidationError
                        # and SUInstallationError across the installer boundary.
                        self.assertTrue(any(f'error SUSparkleErrorDomain {code}' in worker_events for code in (3001, 3002)), evidence)
                    if mode.startswith('cancel-'): self.assertIn(mode, worker_events, evidence)
                    admission_mode = mode.removeprefix('native-')
                    if mode in ('cancel-offer', 'native-cancel-offer', 'native-network', 'native-background', 'quit') or admission_mode in ('vpn-present', 'vpn-unknown'): self.assertNotIn('/update.zip', server.requests)
                    else:
                        for archive in archives: self.assertIn('/' + archive.name, server.requests)
                    self.assertTrue(set(server.requests) <= {'/appcast.xml', *( '/' + archive.name for archive in archives)}, server.requests)
                    if admission_mode.startswith('vpn-'):
                        code = 2 if admission_mode == 'vpn-unknown' else 1
                        self.assertIn(f'error kz.documentolog.proxypilot.update-admission {code}', worker_events, evidence)
                        self.assertIn('/appcast.xml', server.requests)
                        if admission_mode == 'vpn-retry':
                            self.assertEqual(host_events.splitlines().count('check'), 2, evidence)
                            self.assertIn('retry-enabled', host_events, evidence)
                            self.assertLess(worker_events.index('error kz.documentolog'), worker_events.index('found 2.0.0'))
                        else:
                            self.assertFalse(any(line.startswith('found ') for line in worker_events.splitlines()), evidence)
                            self.assertNotIn('download', worker_events, evidence)
                            self.assertNotIn('ready', worker_events, evidence)
                    if mode == 'native-network':
                        self.assertIn('retry-enabled', host_events, evidence)
                        self.assertEqual(host_events.splitlines().count('check'), 2, evidence)
                        self.assertGreaterEqual(server.requests.count('/appcast.xml'), 2)
                        self.assertIn('error ', worker_events, evidence)
                    if mode == 'native-background':
                        self.assertIn('background-state badge=2.0.0 no-presentation', host_events, evidence)
                        self.assertIn('manual-background-check', host_events, evidence)
                        self.assertIn('found user=false shown=false', worker_events, evidence)
                        self.assertIn('background-visible-windows=0 active=false', worker_events, evidence)
                        self.assertNotIn('native-focus background', worker_events, evidence)
                        self.assertIn('native-focus manual', worker_events, evidence)
                        self.assertIn('present', host_events.splitlines(), evidence)
                    self.run_command(['codesign', '--verify', '--deep', '--strict', str(app)])
                    self.verify_environment(app, work, mode, host_events)
                    # Assert natural cleanup before any emergency teardown.
                    deadline = time.monotonic() + 10
                    while self.matching_processes(work, identifier) and time.monotonic() < deadline:
                        time.sleep(0.1)
                    self.assertEqual(self.matching_processes(work, identifier), [], evidence)
                    if mode.startswith('native'): print(f'{mode}: PASSED; no test processes remain\n{evidence}', flush=True)
            finally:
                # Only processes belonging to this unique disposable path/id.
                # Never broad killall/pkill against Sparkle or ProxyPilot.
                try:
                    for stop in (signal.SIGTERM, signal.SIGKILL):
                        for pid, _ in self.matching_processes(work, identifier):
                            try: os.kill(pid, stop)
                            except ProcessLookupError: pass
                        deadline = time.monotonic() + 5
                        while self.matching_processes(work, identifier) and time.monotonic() < deadline:
                            time.sleep(0.1)
                        if not self.matching_processes(work, identifier): break
                    if process is not None: process.wait(timeout=5)
                    self.assertEqual(self.matching_processes(work, identifier), [], 'Disposable test processes did not stop')
                finally:
                    try:
                        server.stop_transfer.set(); server.shutdown(); server.server_close()
                        for domain in (identifier, identifier + '.updater'):
                            subprocess.run(['defaults', 'delete', domain], capture_output=True)
                    finally:
                        if environment is not None: environment.close()


@unittest.skipUnless(sys.platform == 'darwin' and os.environ.get('PROXYPILOT_TEST_ISOLATED_INSTALLER') == '1',
                     'opt-in isolated disposable app installation')
class IsolatedUpdateInstallTests(IsolatedInstallFixture, unittest.TestCase):
    def test_hardened_host_updates_and_relaunches(self): self.scenario('install')
    def test_cancel_before_download_keeps_old_app(self): self.scenario('cancel-offer')
    def test_cancel_before_relaunch_prevents_deferred_install(self): self.scenario('cancel-ready')
    def test_modified_archive_is_rejected_before_prepare(self): self.scenario('corrupt')
    def test_migrate_released_model_then_update_again(self): self.scenario('migration')
    def test_two_successive_isolated_updates(self): self.scenario('repeat')


if __name__ == '__main__':
    import argparse
    parser = argparse.ArgumentParser(description='Disposable native update window; complete within three minutes.')
    parser.add_argument('--native-preview', action='store_true', required=True)
    # The stock native ready window has no cancellation control. Use `install`
    # to inspect that stage and finish via Install and Relaunch. The separate
    # automated cancel-ready test exercises the API, not a native button.
    parser.add_argument('--scenario', choices=['install', 'cancel-offer', 'cancel-download', 'network', 'corrupt', 'background'], default='install')
    args = parser.parse_args()
    IsolatedUpdateInstallTests.native_preview = True
    IsolatedUpdateInstallTests.setUpClass()
    try:
        IsolatedUpdateInstallTests().scenario('native' if args.scenario == 'install' else 'native-' + args.scenario)
    finally:
        IsolatedUpdateInstallTests.doClassCleanups()
