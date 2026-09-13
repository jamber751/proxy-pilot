"""Candidate UpdateModel + real out-of-process Sparkle, stopped before native UI.

Unique host preferences, signed loopback feed, no package download/installation,
no real application/VPN, no production signing keys. Both binaries are Universal.
"""
from functools import partial
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
import plistlib
import shutil
import subprocess
import sys
import tempfile
import threading
import unittest
import uuid
import xml.etree.ElementTree as ET

ROOT = Path(__file__).resolve().parents[1]
FRAMEWORK = ROOT / 'vendor/sparkle-2.9.6/Sparkle.xcframework/macos-arm64_x86_64/Sparkle.framework'
FEED = ROOT / 'dist/updates/appcast.xml'


class Handler(SimpleHTTPRequestHandler):
    requests = []

    def do_GET(self):
        self.requests.append(self.path)
        super().do_GET()

    def log_message(self, *args):
        pass


@unittest.skipUnless(sys.platform == 'darwin' and FRAMEWORK.exists() and FEED.exists(), 'macOS and signed local feed required')
class IsolatedUpdatesTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp = tempfile.TemporaryDirectory(prefix='proxypilot-worker-check-')
        cls.addClassCleanup(cls.temp.cleanup)
        cls.work = Path(cls.temp.name)
        cls.server = ThreadingHTTPServer(('127.0.0.1', 0), partial(Handler, directory=str(cls.work)))
        threading.Thread(target=cls.server.serve_forever, daemon=True).start()
        cls.addClassCleanup(cls.server.server_close)
        cls.addClassCleanup(cls.server.shutdown)
        cls.app = cls.work / 'ProxyPilot Worker TEST.app'
        cls.worker = cls.app / 'Contents/Helpers/ProxyPilot Updater.app'
        cls.binary = cls.app / 'Contents/MacOS/Frontend'
        cls.worker_binary = cls.worker / 'Contents/MacOS/ProxyPilotUpdater'
        cls.binary.parent.mkdir(parents=True)
        cls.worker_binary.parent.mkdir(parents=True)
        (cls.worker / 'Contents/Frameworks').mkdir()
        cls.run_command(['ditto', str(FRAMEWORK), str(cls.worker / 'Contents/Frameworks/Sparkle.framework')])
        item = ET.fromstring(FEED.read_bytes()).find('./channel/item')
        namespace = '{http://www.andymatuschak.org/xml-namespaces/sparkle}'
        cls.version = item.findtext(namespace + 'version')
        cls.display_version = item.findtext(namespace + 'shortVersionString') or cls.version
        cls.identifier = 'kz.documentolog.proxypilot.workercheck.' + uuid.uuid4().hex
        for domain in (cls.identifier, cls.identifier + '.updater'):
            cls.addClassCleanup(subprocess.run, ['defaults', 'delete', domain], capture_output=True)
        cls.info = dict(
            CFBundleIdentifier=cls.identifier, CFBundleExecutable='Frontend', CFBundleName='ProxyPilot Worker TEST',
            CFBundlePackageType='APPL', CFBundleVersion=cls.version, CFBundleShortVersionString=cls.version,
            LSMinimumSystemVersion='11.0', SUFeedURL=f'http://127.0.0.1:{cls.server.server_port}/appcast.xml',
            SUPublicEDKey=(ROOT / 'app/updater-public-key.txt').read_text().strip(),
            SUEnableAutomaticChecks=False, SUAutomaticallyUpdate=False, SUAllowsAutomaticUpdates=False,
            SURequireSignedFeed=True, SUVerifyUpdateBeforeExtraction=True, SUSignedFeedFailureExpirationInterval=0,
            TestMarker=str(cls.work / 'first-crash'), TestDirectory=str(cls.work))
        (cls.work / 'admission/support').mkdir(parents=True)
        (cls.work / 'admission/daemons').mkdir()
        worker_info = dict(CFBundleIdentifier=cls.identifier + '.updater', CFBundleExecutable='ProxyPilotUpdater',
                           CFBundleName='ProxyPilot Updater TEST', CFBundlePackageType='APPL',
                           CFBundleVersion='999.0.0', CFBundleShortVersionString='999.0.0', LSMinimumSystemVersion='11.0',
                           NSAppTransportSecurity={'NSAllowsArbitraryLoads': True})
        (cls.worker / 'Contents/Info.plist').write_bytes(plistlib.dumps(worker_info))
        # Stop at the standard driver's presentation callbacks, before a window,
        # release notes or package can be fetched. The real manual-check path,
        # signatures, model, preference storage and transport remain in use.
        source = (ROOT / 'app/update-worker/UpdateWorker.swift').read_text()
        admission = 'VPNUpdateAdmission.inspectSystem()'
        if source.count(admission) != 1: raise AssertionError('Admission boundary changed')
        source = source.replace(admission, '''VPNUpdateAdmission.inspect(
            applicationSupport: (UpdateWorker.enclosingHost()!.object(forInfoDictionaryKey: "TestDirectory") as! String) + "/admission/support",
            launchDaemons: (UpdateWorker.enclosingHost()!.object(forInfoDictionaryKey: "TestDirectory") as! String) + "/admission/daemons")''')
        source = source.replace('if handleShowingUpdate { channel.send(.present) }',
                                'if handleShowingUpdate { precondition(state.userInitiated); channel.send(.present); usleep(150_000); exit(0) }')
        source = source.replace('func standardUserDriverWillShowModalAlert() { channel.send(.present) }',
                                'func standardUserDriverWillShowModalAlert() { if availableVersion == nil { availableVersion = "TEST_ERROR" }; publish(); channel.send(.present); usleep(150_000); exit(0) }')
        source += '''
extension UpdateWorker {
    func updaterDidNotFindUpdate(_ updater: SPUUpdater, error: Error) { availableVersion = "TEST_CURRENT" }
}
@main enum TestWorker {
    static func main() throws {
        guard let host = UpdateWorker.enclosingHost(),
              let feed = host.object(forInfoDictionaryKey: "SUFeedURL") as? String,
              let url = URL(string: feed), url.host == "127.0.0.1", url.scheme == "http" else { exit(64) }
        let mode = host.object(forInfoDictionaryKey: "TestMode") as? String
        if mode == "failure" { exit(71) }
        if mode == "retry" {
            let marker = host.object(forInfoDictionaryKey: "TestMarker") as! String
            if !FileManager.default.fileExists(atPath: marker) { try Data().write(to: URL(fileURLWithPath: marker)); exit(71) }
        }
        let app = NSApplication.shared
        app.setActivationPolicy(.accessory)
        if let mode = mode, mode.hasPrefix("handoff-") {
            let scripted = HandoffWorker(mode: mode)
            try scripted.start()
            DispatchQueue.main.asyncAfter(deadline: .now() + 19) { exit(3) }
            withExtendedLifetime(scripted) { app.run() }
            return
        }
        let worker = UpdateWorker()
        try worker.start(host: host)
        DispatchQueue.main.asyncAfter(deadline: .now() + 19) { exit(3) }
        withExtendedLifetime(worker) { app.run() }
    }
}
'''
        test_worker = cls.work / 'Worker.swift'
        test_worker.write_text(source)
        common = [str(ROOT / 'app/update-worker/UpdateWire.swift'), str(ROOT / 'app/update-worker/UpdateChannel.swift'),
                  str(ROOT / 'app/update-worker/VPNUpdateAdmission.swift')]
        for name, output, extra in [
            ('Frontend', cls.binary, ['-D', 'ISOLATED_UPDATER', str(ROOT / 'app/update-worker/IsolatedUpdates.swift'), str(ROOT / 'tests/isolated_updates_frontend.swift')]),
            ('Worker', cls.worker_binary, ['-D', 'UPDATE_WORKER_TESTING', '-F', str(FRAMEWORK.parent), '-framework', 'Sparkle', '-Xlinker', '-rpath', '-Xlinker', '@executable_path/../Frameworks', str(test_worker), str(ROOT / 'tests/isolated_updates_handoff_worker.swift')])]:
            slices = []
            for arch in ('arm64', 'x86_64'):
                binary = cls.work / f'{name}-{arch}'
                cls.run_command(['swiftc', '-parse-as-library', '-target', f'{arch}-apple-macosx11.0',
                                 '-module-cache-path', str(cls.work / 'ModuleCache'), *common, *extra, '-o', str(binary)])
                slices.append(str(binary))
            cls.run_command(['lipo', '-create', *slices, '-output', str(output)])
        cls.run_command(['codesign', '--force', '--sign', '-', str(cls.worker)])

    @staticmethod
    def run_command(args):
        result = subprocess.run(args, capture_output=True, text=True, timeout=90)
        if result.returncode:
            raise AssertionError(result.stdout + result.stderr)
        return result

    def probe(self, mode='manual', expected='TEST_CURRENT', version=None, feed='valid'):
        Handler.requests.clear()
        target = self.work / 'appcast.xml'
        if feed == 'missing':
            target.unlink(missing_ok=True)
        else:
            data = FEED.read_bytes()
            target.write_bytes(data if feed == 'valid' else data.replace(b'ProxyPilot', b'ProxyPiloX'))
        self.info.update(TestMode=mode, TestExpected=expected, CFBundleVersion=version or self.version,
                         CFBundleShortVersionString=version or self.version)
        (self.app / 'Contents/Info.plist').write_bytes(plistlib.dumps(self.info))
        self.run_command(['codesign', '--force', '--sign', '-', '--options', 'runtime,hard,kill', str(self.app)])
        self.run_command(['codesign', '--verify', '--deep', '--strict', str(self.app)])
        result = subprocess.run([str(self.binary)], capture_output=True, text=True, timeout=22)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        if mode in ('manual', 'retry'):
            self.assertTrue(Handler.requests)
            self.assertTrue(all(path == '/appcast.xml' for path in Handler.requests), Handler.requests)
            self.assertIn('RESULT ' + expected, result.stdout)
        elif mode in ('preview', 'failure') or mode.startswith('handoff-'):
            self.assertEqual(Handler.requests, [])
        return result.stdout

    def test_manual_current_version(self): self.probe()
    def test_manual_new_host_version_not_worker_version(self): self.probe(expected=self.display_version, version='1.0.0')
    def test_manual_network_failure(self): self.probe(expected='TEST_ERROR', feed='missing')
    def test_tampered_feed_is_rejected(self): self.probe(expected='TEST_ERROR', feed='tampered')
    def test_preview_does_not_launch_updater(self): self.assertIn('PREVIEW_DISABLED', self.probe(mode='preview'))
    def test_child_failure_offers_retry(self): self.assertIn('RETRY_AVAILABLE', self.probe(mode='failure'))
    def test_retry_launches_fresh_child_and_completes_check(self): self.probe(mode='retry')
    def test_relaunch_completion_is_sent_only_once(self):
        self.assertIn('HANDOFF HANDOFF_OK', self.probe(mode='handoff-good', expected='HANDOFF_OK'))
    def test_aborted_relaunch_invalidates_late_completion(self):
        self.assertIn('HANDOFF ABORT_OK', self.probe(mode='handoff-abort', expected='ABORT_OK'))
    def test_duplicate_relaunch_request_is_rejected(self):
        self.assertIn('HANDOFF_REJECTED', self.probe(mode='handoff-duplicate'))
    def test_relaunch_without_update_session_is_rejected(self):
        self.assertIn('HANDOFF_REJECTED', self.probe(mode='handoff-unsolicited'))

    def test_automatic_preference_stays_with_host_and_survives_restart(self):
        self.assertIn('PREFERENCE true', self.probe(mode='preferences', expected='true'))
        self.assertIn('PREFERENCE false', self.probe(mode='preferences', expected='false'))
        result = self.run_command(['defaults', 'read', self.identifier, 'SUEnableAutomaticChecks'])
        self.assertEqual(result.stdout.strip(), '0')

    def test_frontend_has_no_sparkle_dependency(self):
        self.assertNotIn('Sparkle.framework', self.run_command(['otool', '-L', str(self.binary)]).stdout)
        self.assertIn('Sparkle.framework', self.run_command(['otool', '-L', str(self.worker_binary)]).stdout)
