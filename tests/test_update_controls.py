"""Drive the production UpdateModel.check(), not Sparkle's information-only API.

Use a unique disposable app and signed loopback feed. Stop at the native driver's
presentation callback: no package download, installation or real proxy access.
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


@unittest.skipUnless(sys.platform == 'darwin' and FRAMEWORK.exists() and FEED.exists(), 'signed local release required')
class ManualUpdateTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        item = ET.fromstring(FEED.read_bytes()).find('./channel/item')
        namespace = '{http://www.andymatuschak.org/xml-namespaces/sparkle}'
        cls.version = item.findtext(namespace + 'version')
        cls.display_version = item.findtext(namespace + 'shortVersionString') or cls.version
        if not cls.version:
            raise RuntimeError('Signed fixture feed has no version')
        cls.temp = tempfile.TemporaryDirectory(prefix='proxypilot-manual-check-')
        cls.work = Path(cls.temp.name)
        cls.server = ThreadingHTTPServer(('127.0.0.1', 0), partial(Handler, directory=str(cls.work)))
        threading.Thread(target=cls.server.serve_forever, daemon=True).start()
        cls.app = cls.work / 'ProxyPilot Check TEST.app'
        macos = cls.app / 'Contents/MacOS'
        macos.mkdir(parents=True)
        frameworks = cls.app / 'Contents/Frameworks'
        frameworks.mkdir()
        subprocess.run(['ditto', str(FRAMEWORK), str(frameworks / 'Sparkle.framework')], check=True)
        cls.info = dict(
            CFBundleIdentifier='kz.documentolog.proxypilot.manualtest.' + uuid.uuid4().hex,
            CFBundleExecutable='Check', CFBundleName='ProxyPilot Check TEST',
            CFBundleDisplayName='ProxyPilot Check TEST', CFBundlePackageType='APPL',
            CFBundleVersion=cls.version, CFBundleShortVersionString=cls.display_version,
            TestFeedVersion=cls.display_version,
            SUFeedURL=f'http://127.0.0.1:{cls.server.server_port}/appcast.xml',
            SUPublicEDKey=(ROOT / 'app/updater-public-key.txt').read_text().strip(),
            SUEnableAutomaticChecks=False, SUAutomaticallyUpdate=False, SUAllowsAutomaticUpdates=False,
            SURequireSignedFeed=True, SUVerifyUpdateBeforeExtraction=True, SUSignedFeedFailureExpirationInterval=0,
            NSAppTransportSecurity={'NSAllowsArbitraryLoads': True},  # Loopback fixture only.
        )
        source = (ROOT / 'app/Updates.swift').read_text().split('\nstruct UpdatesView:', 1)[0]
        source = source.replace('if handleShowingUpdate { onPresent?() }',
                                'if handleShowingUpdate { onPresent?(); precondition(state.userInitiated); finish("UPDATE") }')
        source = source.replace('func standardUserDriverWillShowModalAlert() { onPresent?() }',
                                'func standardUserDriverWillShowModalAlert() { onPresent?(); finish(outcome) }')
        (cls.work / 'Updates.swift').write_text(source)
        (cls.work / 'main.swift').write_text('''import AppKit
import Sparkle
let app = NSApplication.shared
app.setActivationPolicy(.accessory)
let model = UpdateModel()
var outcome = "ERROR"
var presentations = 0
var requested = false
func finish(_ result: String) {
    precondition(requested && presentations >= 2, "Manual check did not present its result")
    if result == "UPDATE" { precondition(model.availableVersion == Bundle.main.object(forInfoDictionaryKey: "TestFeedVersion") as? String) }
    print(result)
    exit(0)
}
extension UpdateModel {
    func updaterDidNotFindUpdate(_ updater: SPUUpdater, error: Error) { outcome = "CURRENT" }
}
model.onPresent = { presentations += 1 }
let preview = CommandLine.arguments.contains("preview")
model.start(preview: preview)
if preview {
    model.check()
    precondition(!model.canCheck && !model.sessionInProgress && presentations == 0)
    precondition(model.checkTitle == "Недоступно в превью")
    print("PREVIEW_DISABLED"); exit(0)
}
let timer = Timer.scheduledTimer(withTimeInterval: 0.05, repeats: true) { timer in
    guard model.canCheck else { return }
    timer.invalidate()
    precondition(model.checkTitle == "Проверить обновления")
    requested = true
    model.check()
    precondition(model.sessionInProgress, "Click did not start a Sparkle session")
    print("CHECK_STARTED")
}
DispatchQueue.main.asyncAfter(deadline: .now() + 12) { print("TIMEOUT"); exit(3) }
app.run()
''')
        cls.binary = macos / 'Check'
        built = subprocess.run(['swiftc', '-module-cache-path', str(ROOT / 'app/build/ModuleCache'),
                                '-F', str(FRAMEWORK.parent), '-framework', 'Sparkle',
                                '-Xlinker', '-rpath', '-Xlinker', '@executable_path/../Frameworks',
                                str(cls.work / 'main.swift'), str(cls.work / 'Updates.swift'), '-o', str(cls.binary)],
                               capture_output=True, text=True)
        if built.returncode:
            raise RuntimeError(built.stderr)

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()
        subprocess.run(['defaults', 'delete', cls.info['CFBundleIdentifier']], capture_output=True)
        cls.temp.cleanup()

    def probe(self, expected, version=None, feed=True, preview=False):
        cls = type(self)
        version = version or cls.version
        Handler.requests.clear()
        if feed:
            (cls.work / 'appcast.xml').write_bytes(FEED.read_bytes())
        else:
            (cls.work / 'appcast.xml').unlink(missing_ok=True)
        cls.info.update(CFBundleVersion=version, CFBundleShortVersionString=version)
        (cls.app / 'Contents/Info.plist').write_bytes(plistlib.dumps(cls.info))
        subprocess.run(['codesign', '--force', '--sign', '-', str(cls.app)], check=True, capture_output=True)
        result = subprocess.run([str(cls.binary)] + (['preview'] if preview else []),
                                capture_output=True, text=True, timeout=15)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn(expected, result.stdout)
        if preview:
            self.assertEqual(Handler.requests, [])
        else:
            self.assertTrue(Handler.requests)
            self.assertTrue(all(path.startswith('/appcast.xml') for path in Handler.requests))

    def test_manual_check_presents_current_version(self):
        self.probe('CURRENT')

    def test_manual_check_presents_new_version(self):
        self.probe('UPDATE', version='1.0.0')

    def test_manual_check_presents_network_failure(self):
        self.probe('ERROR', feed=False)

    def test_preview_is_explicitly_unavailable_and_makes_no_request(self):
        self.probe('PREVIEW_DISABLED', preview=True)


class PreviewIdentityTests(unittest.TestCase):
    def test_fixture_cannot_inherit_production_display_name(self):
        script = (ROOT / 'tests/preview_updates.py').read_text()
        self.assertIn("info['CFBundleDisplayName'] = 'ProxyPilot — ТЕСТОВЫЙ МАКЕТ'", script)
