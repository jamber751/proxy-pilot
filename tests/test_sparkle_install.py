"""Opt-in real ad-hoc Sparkle install/relaunch in a disposable .app.

PROXYPILOT_TEST_INSTALLER=1 python3 -m unittest discover -s tests -p test_sparkle_install.py -v
Uses an ephemeral test signing key, loopback server and fake app only.
"""
from functools import partial
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
import os
import plistlib
import shutil
import subprocess
import sys
import tempfile
import threading
import time
import unittest
import uuid

ROOT = Path(__file__).resolve().parents[1]
SPARKLE = ROOT / 'vendor/sparkle-2.9.6'
FRAMEWORK = SPARKLE / 'Sparkle.xcframework/macos-arm64_x86_64/Sparkle.framework'

DRIVER = r'''
import AppKit
import Sparkle
let marker = URL(fileURLWithPath: Bundle.main.object(forInfoDictionaryKey: "TestMarker") as! String)
if Bundle.main.object(forInfoDictionaryKey: "CFBundleVersion") as? String == "2.0.0" {
    try Data("relaunched 2.0.0".utf8).write(to: marker)
    exit(0)
}
final class Driver: NSObject, SPUUserDriver {
    func show(_ request: SPUUpdatePermissionRequest, reply: @escaping (SUUpdatePermissionResponse) -> Void) {
        reply(SUUpdatePermissionResponse(automaticUpdateChecks: false, sendSystemProfile: false))
    }
    func showUserInitiatedUpdateCheck(cancellation: @escaping () -> Void) {}
    func showUpdateFound(with appcastItem: SUAppcastItem, state: SPUUserUpdateState, reply: @escaping (SPUUserUpdateChoice) -> Void) { reply(.install) }
    func showUpdateReleaseNotes(with downloadData: SPUDownloadData) {}
    func showUpdateReleaseNotesFailedToDownloadWithError(_ error: Error) {}
    func showUpdateNotFoundWithError(_ error: Error, acknowledgement: @escaping () -> Void) { print(error); exit(2) }
    func showUpdaterError(_ error: Error, acknowledgement: @escaping () -> Void) { print(error); exit(3) }
    func showDownloadInitiated(cancellation: @escaping () -> Void) {}
    func showDownloadDidReceiveExpectedContentLength(_ expectedContentLength: UInt64) {}
    func showDownloadDidReceiveData(ofLength length: UInt64) {}
    func showDownloadDidStartExtractingUpdate() {}
    func showExtractionReceivedProgress(_ progress: Double) {}
    func showReady(toInstallAndRelaunch reply: @escaping (SPUUserUpdateChoice) -> Void) { reply(.install) }
    func showInstallingUpdate(withApplicationTerminated applicationTerminated: Bool, retryTerminatingApplication: @escaping () -> Void) {}
    func showUpdateInstalledAndRelaunched(_ relaunched: Bool, acknowledgement: @escaping () -> Void) { acknowledgement() }
    func dismissUpdateInstallation() {}
}
let app = NSApplication.shared
app.setActivationPolicy(.accessory)
let driver = Driver()
let updater = SPUUpdater(hostBundle: Bundle.main, applicationBundle: Bundle.main, userDriver: driver, delegate: nil)
try updater.start()
updater.checkForUpdates()
DispatchQueue.main.asyncAfter(deadline: .now() + 40) { print("TIMEOUT"); exit(4) }
app.run()
'''


class Quiet(SimpleHTTPRequestHandler):
    def log_message(self, *args):
        pass


@unittest.skipUnless(sys.platform == 'darwin' and os.environ.get('PROXYPILOT_TEST_INSTALLER') == '1', 'opt-in disposable app installation')
class SparkleInstallTests(unittest.TestCase):
    def test_adhoc_install_and_relaunch(self):
        with tempfile.TemporaryDirectory(prefix='proxypilot-installer-test-') as directory:
            work = Path(directory)
            server = ThreadingHTTPServer(('127.0.0.1', 0), partial(Quiet, directory=directory))
            threading.Thread(target=server.serve_forever, daemon=True).start()
            bundle_id = 'kz.documentolog.proxypilot.installtest.' + uuid.uuid4().hex
            process = None
            try:
                app = work / 'installed/Update Test.app'
                (app / 'Contents/MacOS').mkdir(parents=True)
                (app / 'Contents/Frameworks').mkdir()
                subprocess.run(['ditto', str(FRAMEWORK), str(app / 'Contents/Frameworks/Sparkle.framework')], check=True)
                seed = work / 'test-key'
                seed.touch(mode=0o600)
                generator = work / 'key.swift'
                generator.write_text('''import Foundation
import CryptoKit
let key = Curve25519.Signing.PrivateKey()
try key.rawRepresentation.base64EncodedString().write(toFile: CommandLine.arguments[1], atomically: false, encoding: .utf8)
print(key.publicKey.rawRepresentation.base64EncodedString())
''')
                public = subprocess.run(['swift', '-module-cache-path', str(ROOT / 'app/build/ModuleCache'), str(generator), str(seed)],
                                        check=True, capture_output=True, text=True).stdout.strip()
                source = work / 'main.swift'
                source.write_text(DRIVER)
                binary = app / 'Contents/MacOS/UpdateTest'
                result = subprocess.run(['swiftc', '-module-cache-path', str(ROOT / 'app/build/ModuleCache'),
                                         '-F', str(FRAMEWORK.parent), '-framework', 'Sparkle',
                                         '-Xlinker', '-rpath', '-Xlinker', '@executable_path/../Frameworks',
                                         str(source), '-o', str(binary)], capture_output=True, text=True)
                self.assertEqual(result.returncode, 0, result.stderr)
                marker = work / 'relaunch-result'
                info = dict(CFBundleIdentifier=bundle_id, CFBundleExecutable='UpdateTest', CFBundleName='Update Test',
                            CFBundlePackageType='APPL', CFBundleVersion='1.0.0', CFBundleShortVersionString='1.0.0',
                            SUFeedURL=f'http://127.0.0.1:{server.server_port}/appcast.xml', SUPublicEDKey=public,
                            SUEnableAutomaticChecks=False, SUAllowsAutomaticUpdates=False,
                            SURequireSignedFeed=True, SUVerifyUpdateBeforeExtraction=True,
                            SUSignedFeedFailureExpirationInterval=0, TestMarker=str(marker),
                            NSAppTransportSecurity={'NSAllowsArbitraryLoads': True})
                (app / 'Contents/Info.plist').write_bytes(plistlib.dumps(info))
                subprocess.run(['codesign', '--force', '--sign', '-', str(app)], check=True, capture_output=True)
                new_app = work / 'new/Update Test.app'
                new_app.parent.mkdir()
                shutil.copytree(app, new_app, symlinks=True)
                new_info = dict(info, CFBundleVersion='2.0.0', CFBundleShortVersionString='2.0.0')
                (new_app / 'Contents/Info.plist').write_bytes(plistlib.dumps(new_info))
                subprocess.run(['codesign', '--force', '--sign', '-', str(new_app)], check=True, capture_output=True)
                archive = work / 'update.zip'
                subprocess.run(['ditto', '-c', '-k', '--sequesterRsrc', '--keepParent', str(new_app), str(archive)], check=True)
                signed = subprocess.run([str(SPARKLE / 'bin/sign_update'), '--ed-key-file', str(seed), str(archive)],
                                        check=True, capture_output=True, text=True).stdout.strip()
                feed = work / 'appcast.xml'
                feed.write_text(f'''<?xml version="1.0"?><rss version="2.0" xmlns:sparkle="http://www.andymatuschak.org/xml-namespaces/sparkle"><channel><title>Test</title><item>
<title>2.0.0</title><sparkle:version>2.0.0</sparkle:version><sparkle:shortVersionString>2.0.0</sparkle:shortVersionString>
<enclosure url="http://127.0.0.1:{server.server_port}/update.zip" type="application/octet-stream" {signed}/>
</item></channel></rss>''')
                subprocess.run([str(SPARKLE / 'bin/sign_update'), '--ed-key-file', str(seed), str(feed)], check=True, capture_output=True)
                with (work / 'run.log').open('w+') as log:
                    process = subprocess.Popen([str(binary)], stdout=log, stderr=subprocess.STDOUT)
                    end = time.monotonic() + 50
                    while not marker.exists() and time.monotonic() < end:
                        if process.poll() not in (None, 0):
                            break
                        time.sleep(0.1)
                    log.seek(0)
                    self.assertTrue(marker.exists(), log.read())
                    self.assertEqual(marker.read_text(), 'relaunched 2.0.0')
                installed = plistlib.loads((app / 'Contents/Info.plist').read_bytes())
                self.assertEqual(installed['CFBundleVersion'], '2.0.0')
                subprocess.run(['codesign', '--verify', '--deep', '--strict', str(app)], check=True, capture_output=True)
            finally:
                if process is not None and process.poll() is None:
                    process.terminate()
                    process.wait(timeout=5)
                server.shutdown()
                server.server_close()
                subprocess.run(['defaults', 'delete', bundle_id], capture_output=True)
