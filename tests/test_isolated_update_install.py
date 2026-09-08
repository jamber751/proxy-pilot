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

ROOT = Path(__file__).resolve().parents[1]
SPARKLE = ROOT / 'vendor/sparkle-2.9.6'
FRAMEWORK = SPARKLE / 'Sparkle.xcframework/macos-arm64_x86_64/Sparkle.framework'


class Handler(SimpleHTTPRequestHandler):
    def do_GET(self):
        self.server.requests.append(self.path)
        super().do_GET()

    def log_message(self, *args):
        pass


@unittest.skipUnless(sys.platform == 'darwin' and os.environ.get('PROXYPILOT_TEST_ISOLATED_INSTALLER') == '1',
                     'opt-in isolated disposable app installation')
class IsolatedUpdateInstallTests(unittest.TestCase):
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
        cls_source = original
        if not getattr(cls, 'native_preview', False):
            cls_source = original.replace('private var driver: SPUStandardUserDriver!', 'private var driver: SPUUserDriver!')
            cls_source = cls_source.replace('driver = SPUStandardUserDriver(hostBundle: host, delegate: self)',
                                        'driver = InstallDriver(host: host, delegate: self)')
            if cls_source == original or 'driver = SPUStandardUserDriver(' in cls_source:
                raise AssertionError('Test UI driver was not substituted')
        source = build / 'Worker.swift'
        source.write_text(cls_source)
        common = [str(ROOT / 'app/update-worker/UpdateWire.swift'), str(ROOT / 'app/update-worker/UpdateChannel.swift')]
        for name, extras in [
            ('Frontend', ['-D', 'ISOLATED_UPDATER', str(ROOT / 'app/update-worker/IsolatedUpdates.swift'), str(ROOT / 'tests/isolated-update-install/Frontend.swift')]),
            ('Worker', ['-D', 'UPDATE_WORKER_TESTING', '-F', str(FRAMEWORK.parent), '-framework', 'Sparkle',
                        '-Xlinker', '-rpath', '-Xlinker', '@executable_path/../Frameworks', str(source), str(ROOT / 'tests/isolated-update-install/Driver.swift')])]:
            slices = []
            for arch in ('arm64', 'x86_64'):
                binary = build / f'{name}-{arch}'
                cls.run_command(['swiftc', '-parse-as-library', '-target', f'{arch}-apple-macosx11.0', *common, *extras, '-o', str(binary)])
                slices.append(str(binary))
            cls.run_command(['lipo', '-create', *slices, '-output', str(build / name)])
        generator = build / 'key.swift'
        generator.write_text('''import Foundation
import CryptoKit
let key = Curve25519.Signing.PrivateKey()
try key.rawRepresentation.base64EncodedString().write(toFile: CommandLine.arguments[1], atomically: false, encoding: .utf8)
print(key.publicKey.rawRepresentation.base64EncodedString())
''')
        cls.run_command(['swiftc', str(generator), '-o', str(build / 'key')])

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
            threading.Thread(target=server.serve_forever, daemon=True).start()
            process = None
            try:
                app = work / 'installed/ProxyPilot Install TEST.app'
                worker = app / 'Contents/Helpers/ProxyPilot Updater.app'
                (app / 'Contents/MacOS').mkdir(parents=True)
                (worker / 'Contents/MacOS').mkdir(parents=True)
                (worker / 'Contents/Frameworks').mkdir()
                self.run_command(['ditto', str(FRAMEWORK), str(worker / 'Contents/Frameworks/Sparkle.framework')])
                binary = app / 'Contents/MacOS/Frontend'
                shutil.copy2(Path(self.compiled.name) / 'Frontend', binary)
                shutil.copy2(Path(self.compiled.name) / 'Worker', worker / 'Contents/MacOS/ProxyPilotUpdater')
                seed = work / 'ephemeral-key'
                seed.touch(mode=0o600)
                public = self.run_command([str(Path(self.compiled.name) / 'key'), str(seed)]).strip()
                info = dict(CFBundleIdentifier=identifier, CFBundleExecutable='Frontend', CFBundleName='ProxyPilot Install TEST',
                            CFBundlePackageType='APPL', CFBundleVersion='1.0.0', CFBundleShortVersionString='1.0.0',
                            LSMinimumSystemVersion='11.0', LSUIElement=True,
                            SUFeedURL=f'http://127.0.0.1:{server.server_port}/appcast.xml', SUPublicEDKey=public,
                            SUEnableAutomaticChecks=False, SUAutomaticallyUpdate=False, SUAllowsAutomaticUpdates=False,
                            SURequireSignedFeed=True, SUVerifyUpdateBeforeExtraction=True, SUSignedFeedFailureExpirationInterval=0,
                            TestDirectory=str(work), TestMode=mode)
                worker_info = dict(CFBundleIdentifier=identifier + '.updater', CFBundleExecutable='ProxyPilotUpdater',
                                   CFBundleName='ProxyPilot Updater TEST', CFBundlePackageType='APPL',
                                   CFBundleVersion='999.0.0', CFBundleShortVersionString='999.0.0', LSMinimumSystemVersion='11.0',
                                   LSUIElement=True, NSAppTransportSecurity={'NSAllowsArbitraryLoads': True})
                (app / 'Contents/Info.plist').write_bytes(plistlib.dumps(info))
                (worker / 'Contents/Info.plist').write_bytes(plistlib.dumps(worker_info))
                self.run_command(['codesign', '--force', '--sign', '-', str(worker)])
                self.run_command(['codesign', '--force', '--sign', '-', '--options', 'runtime,hard,kill', str(app)])
                self.run_command(['codesign', '--verify', '--deep', '--strict', str(app)])
                self.assertNotIn('Sparkle.framework', self.run_command(['otool', '-L', str(binary)]))
                new_app = work / 'new/ProxyPilot Install TEST.app'
                new_app.parent.mkdir()
                shutil.copytree(app, new_app, symlinks=True)
                (new_app / 'Contents/Info.plist').write_bytes(plistlib.dumps(dict(info, CFBundleVersion='2.0.0', CFBundleShortVersionString='2.0.0')))
                self.run_command(['codesign', '--force', '--sign', '-', '--options', 'runtime,hard,kill', str(new_app)])
                archive = work / 'update.zip'
                self.run_command(['ditto', '-c', '-k', '--sequesterRsrc', '--keepParent', str(new_app), str(archive)])
                signature = self.run_command([str(SPARKLE / 'bin/sign_update'), '--ed-key-file', str(seed), str(archive)]).strip()
                feed = work / 'appcast.xml'
                feed.write_text(f'''<?xml version="1.0"?><rss version="2.0" xmlns:sparkle="http://www.andymatuschak.org/xml-namespaces/sparkle"><channel><title>Disposable TEST</title><item>
<title>2.0.0</title><sparkle:version>2.0.0</sparkle:version><sparkle:shortVersionString>2.0.0</sparkle:shortVersionString>
<description><![CDATA[<h2>Test update</h2><p>English release notes for a disposable test only.</p>]]></description>
<enclosure url="http://127.0.0.1:{server.server_port}/update.zip" type="application/octet-stream" {signature}/>
</item></channel></rss>''')
                self.run_command([str(SPARKLE / 'bin/sign_update'), '--ed-key-file', str(seed), str(feed)])
                if mode == 'corrupt':
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
                    installing = mode in ('install', 'native')
                    if mode == 'native':
                        print(f'NATIVE PREVIEW WORKER: {worker}', flush=True)
                        print(f'HOST: {app}\nIDENTIFIER: {identifier}', flush=True)
                    deadline = time.monotonic() + (185 if mode == 'native' else 48)
                    while time.monotonic() < deadline:
                        events = host_log.read_text() if host_log.exists() else ''
                        if installing and 'relaunched 2.0.0 preferences-preserved' in events:
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
                        self.assertIn('relaunched 2.0.0 preferences-preserved', host_events, evidence)
                        self.assertEqual(host_events.splitlines().count('prepare'), 1, evidence)
                        self.assertEqual(plistlib.loads((app / 'Contents/Info.plist').read_bytes())['CFBundleVersion'], '2.0.0')
                    else:
                        self.assertIn('idle', host_events, evidence)
                        self.assertNotIn('prepare', host_events, evidence)
                        self.assertNotIn('relaunched 2.0.0', host_events, evidence)
                        self.assertEqual(hashlib.sha256((app / 'Contents/Info.plist').read_bytes()).hexdigest(), original_info)
                    if mode == 'corrupt':
                        # Sparkle may wrap SUSignatureError in SUValidationError
                        # and SUInstallationError across the installer boundary.
                        self.assertTrue(any(f'error SUSparkleErrorDomain {code}' in worker_events for code in (3001, 3002)), evidence)
                    if mode.startswith('cancel-'): self.assertIn(mode, worker_events, evidence)
                    if mode == 'cancel-offer': self.assertNotIn('/update.zip', server.requests)
                    else: self.assertIn('/update.zip', server.requests)
                    self.assertTrue(all(path in ('/appcast.xml', '/update.zip') for path in server.requests), server.requests)
                    self.run_command(['codesign', '--verify', '--deep', '--strict', str(app)])
                    # Assert natural cleanup before any emergency teardown.
                    deadline = time.monotonic() + 10
                    while self.matching_processes(work, identifier) and time.monotonic() < deadline:
                        time.sleep(0.1)
                    self.assertEqual(self.matching_processes(work, identifier), [], evidence)
                    if mode == 'native': print('NATIVE INSTALL/RELAUNCH PASSED; no test processes remain', flush=True)
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
                    server.shutdown(); server.server_close()
                    for domain in (identifier, identifier + '.updater'):
                        subprocess.run(['defaults', 'delete', domain], capture_output=True)

    def test_hardened_host_updates_and_relaunches(self): self.scenario('install')
    def test_cancel_before_download_keeps_old_app(self): self.scenario('cancel-offer')
    def test_cancel_before_relaunch_prevents_deferred_install(self): self.scenario('cancel-ready')
    def test_modified_archive_is_rejected_before_prepare(self): self.scenario('corrupt')


if __name__ == '__main__':
    import argparse
    parser = argparse.ArgumentParser(description='Disposable native update window; complete within three minutes.')
    parser.add_argument('--native-preview', action='store_true', required=True)
    parser.parse_args()
    IsolatedUpdateInstallTests.native_preview = True
    IsolatedUpdateInstallTests.setUpClass()
    try:
        IsolatedUpdateInstallTests().scenario('native')
    finally:
        IsolatedUpdateInstallTests.doClassCleanups()
