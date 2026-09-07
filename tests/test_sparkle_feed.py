"""Exercise the real Sparkle framework against a signed feed over loopback.

Run after make-dmg.sh + app/sign-update.sh. No install, download, or user proxy
configuration is performed. The disposable host has its own bundle identifier.
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


class QuietHandler(SimpleHTTPRequestHandler):
    def log_message(self, *args):
        pass


@unittest.skipUnless(sys.platform == 'darwin' and FRAMEWORK.exists() and FEED.exists(), 'signed local release required')
class SparkleFeedTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp = tempfile.TemporaryDirectory(prefix='proxypilot-feed-test-')
        cls.work = Path(cls.temp.name)
        cls.feed = cls.work / 'appcast.xml'
        cls.feed.write_bytes(FEED.read_bytes())
        cls.server = ThreadingHTTPServer(('127.0.0.1', 0), partial(QuietHandler, directory=str(cls.work)))
        threading.Thread(target=cls.server.serve_forever, daemon=True).start()
        cls.app = cls.work / 'Update Check Test.app'
        macos = cls.app / 'Contents/MacOS'
        macos.mkdir(parents=True)
        frameworks = cls.app / 'Contents/Frameworks'
        frameworks.mkdir()
        subprocess.run(['ditto', str(FRAMEWORK), str(frameworks / 'Sparkle.framework')], check=True)
        source = cls.work / 'main.swift'
        source.write_text('''import AppKit
import Sparkle
final class Check: NSObject, SPUUpdaterDelegate {
    var found = false
    func updater(_ updater: SPUUpdater, didFindValidUpdate item: SUAppcastItem) { found = true }
    func updater(_ updater: SPUUpdater, didFinishUpdateCycleFor updateCheck: SPUUpdateCheck, error: Error?) {
        if found && error == nil { print("VALID_UPDATE"); exit(0) }
        print("REJECTED_OR_UNAVAILABLE"); exit(2)
    }
}
let app = NSApplication.shared
app.setActivationPolicy(.accessory)
let delegate = Check()
let controller = SPUStandardUpdaterController(startingUpdater: false, updaterDelegate: delegate, userDriverDelegate: nil)
controller.startUpdater()
DispatchQueue.main.asyncAfter(deadline: .now() + 0.2) { controller.updater.checkForUpdateInformation() }
DispatchQueue.main.asyncAfter(deadline: .now() + 15) { print("TIMEOUT"); exit(3) }
app.run()
''')
        cls.binary = macos / 'UpdateCheck'
        result = subprocess.run(['swiftc', '-module-cache-path', str(ROOT / 'app/build/ModuleCache'),
                                 '-F', str(FRAMEWORK.parent), '-framework', 'Sparkle',
                                 '-Xlinker', '-rpath', '-Xlinker', '@executable_path/../Frameworks',
                                 str(source), '-o', str(cls.binary)], capture_output=True, text=True)
        if result.returncode:
            raise RuntimeError(result.stderr)
        cls.info = dict(
            CFBundleIdentifier='kz.documentolog.proxypilot.feedtest.' + uuid.uuid4().hex,
            CFBundleExecutable='UpdateCheck', CFBundleName='Update Check Test', CFBundlePackageType='APPL',
            CFBundleVersion='1.0.0', CFBundleShortVersionString='1.0.0',
            SUFeedURL=f'http://127.0.0.1:{cls.server.server_port}/appcast.xml',
            SUPublicEDKey=(ROOT / 'app/updater-public-key.txt').read_text().strip(),
            SUEnableAutomaticChecks=False, SUAutomaticallyUpdate=False, SUAllowsAutomaticUpdates=False,
            SURequireSignedFeed=True, SUVerifyUpdateBeforeExtraction=True, SUSignedFeedFailureExpirationInterval=0,
            # TEST ONLY: production uses HTTPS without ATS exceptions.
            NSAppTransportSecurity={'NSAllowsArbitraryLoads': True},
        )
        (cls.app / 'Contents/Info.plist').write_bytes(plistlib.dumps(cls.info))
        subprocess.run(['codesign', '--force', '--sign', '-', str(cls.app)], check=True, capture_output=True)

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()
        subprocess.run(['defaults', 'delete', cls.info['CFBundleIdentifier']], capture_output=True)
        cls.temp.cleanup()

    def probe(self):
        return subprocess.run([str(self.binary)], capture_output=True, text=True, timeout=20)

    def test_signed_feed_accepted_by_sparkle(self):
        self.feed.write_bytes(FEED.read_bytes())
        result = self.probe()
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn('VALID_UPDATE', result.stdout)

    def test_embedded_release_notes_are_formatted_html(self):
        description = ET.fromstring(FEED.read_bytes()).find('./channel/item/description')
        self.assertIsNotNone(description)
        self.assertNotIn(description.get('{http://www.andymatuschak.org/xml-namespaces/sparkle}format'),
                         ['plain-text', 'markdown'])
        notes = description.text or ''
        self.assertEqual(notes.strip(), (ROOT / '.github/update-notes.html').read_text().strip())
        self.assertIn('<h2>Что нового</h2>', notes)
        self.assertEqual(notes.count('<li>'), 4)
        for unwanted in ['### ', 'Install.command', '<script', '<iframe', '<img', 'src=']:
            self.assertNotIn(unwanted, notes)

    def test_modified_feed_rejected_by_sparkle(self):
        self.feed.write_bytes(FEED.read_bytes().replace(b'ProxyPilot', b'ProxyPiloX'))
        result = self.probe()
        self.assertEqual(result.returncode, 2, result.stdout + result.stderr)
        self.assertIn('REJECTED_OR_UNAVAILABLE', result.stdout)

    def test_unreachable_feed_finishes_without_update(self):
        self.feed.unlink(missing_ok=True)
        result = self.probe()
        self.assertEqual(result.returncode, 2, result.stdout + result.stderr)
