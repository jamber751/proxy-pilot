"""Update policy, Ed25519 artifact validation and non-mutating relaunch checks."""
from pathlib import Path
import json
import shutil
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]


@unittest.skipUnless(sys.platform == 'darwin' and shutil.which('swiftc'), 'macOS Swift required')
class UpdateSignatureTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp = tempfile.TemporaryDirectory(prefix='proxypilot-signature-test-')
        cls.work = Path(cls.temp.name)
        cls.verifier = cls.work / 'verify'
        cache = ROOT / 'app/build/ModuleCache'
        subprocess.run(['swiftc', '-module-cache-path', str(cache), str(ROOT / 'app/verify-update.swift'),
                        '-o', str(cls.verifier)], check=True, capture_output=True)
        fixture = cls.work / 'fixture.swift'
        fixture.write_text('''import Foundation
import CryptoKit
let key = Curve25519.Signing.PrivateKey()
let other = Curve25519.Signing.PrivateKey()
let data = Data("fixture archive".utf8)
let result = ["key": key.publicKey.rawRepresentation.base64EncodedString(),
              "other": other.publicKey.rawRepresentation.base64EncodedString(),
              "signature": try key.signature(for: data).base64EncodedString()]
print(String(data: try JSONSerialization.data(withJSONObject: result), encoding: .utf8)!)
''')
        result = subprocess.run(['swift', '-module-cache-path', str(cache), str(fixture)],
                                capture_output=True, text=True, check=True)
        cls.keys = json.loads(result.stdout)

    @classmethod
    def tearDownClass(cls):
        cls.temp.cleanup()

    def verify(self, data=b'fixture archive', key=None, signature=None, version='1.5.0', url=None, length=15):
        archive, key_file, feed = [self.work / name for name in ['archive.zip', 'public.txt', 'appcast.xml']]
        archive.write_bytes(data)
        key_file.write_text(key or self.keys['key'])
        signature = signature or self.keys['signature']
        url = url or 'https://github.com/jamber751/proxy-pilot/releases/download/v1.5.0/ProxyPilot-1.5.0.zip'
        feed.write_text(f'''<?xml version="1.0"?><rss xmlns:sparkle="http://www.andymatuschak.org/xml-namespaces/sparkle"><channel><item>
<sparkle:version>{version}</sparkle:version>
<enclosure url="{url}" length="{length}" sparkle:edSignature="{signature}"/>
</item></channel></rss>''')
        return subprocess.run([str(self.verifier), str(key_file), str(archive), str(feed), '1.5.0'],
                              capture_output=True, text=True).returncode

    def test_valid_signature(self):
        self.assertEqual(self.verify(), 0)

    def test_reject_modified_archive(self):
        self.assertNotEqual(self.verify(data=b'Fixture archive'), 0)

    def test_reject_wrong_signing_key(self):
        self.assertNotEqual(self.verify(key=self.keys['other']), 0)

    def test_reject_missing_or_invalid_signature(self):
        self.assertNotEqual(self.verify(signature='invalid'), 0)

    def test_reject_metadata_mismatch(self):
        for changed in [{'version': '1.4.0'}, {'length': 99}, {'url': 'http://example.com/update.zip'}]:
            with self.subTest(changed=changed):
                self.assertNotEqual(self.verify(**changed), 0)


class UpdatePolicyTests(unittest.TestCase):
    def test_build_security_defaults(self):
        build = (ROOT / 'app/build.sh').read_text()
        package = (ROOT / 'make-dmg.sh').read_text()
        for key in ['SUVerifyUpdateBeforeExtraction', 'SURequireSignedFeed', 'SUEnableAutomaticChecks']:
            self.assertIn(f'<key>{key}</key> <true/>', build)
        for key in ['SUAutomaticallyUpdate', 'SUAllowsAutomaticUpdates', 'SUEnableSystemProfiling']:
            self.assertIn(f'<key>{key}</key> <false/>', build)
        self.assertIn('<key>CFBundleVersion</key>         <string>$VERSION</string>', build)
        self.assertIn('<key>SUScheduledCheckInterval</key> <integer>86400</integer>', build)
        self.assertIn('<key>SUSignedFeedFailureExpirationInterval</key> <integer>0</integer>', build)
        self.assertIn('ISOLATED_UPDATER="${PROXYPILOT_ISOLATED_UPDATER:-1}"', build)
        self.assertIn('SIGN_FLAGS=(--options runtime,hard,kill)', build)
        self.assertIn('BUILD_ROOT=$(mktemp -d /tmp/proxypilot-app-build.XXXXXX)', package)
        self.assertIn('codesign --force --sign - --options runtime,hard,kill', package)

    @unittest.skipUnless(sys.platform == 'darwin' and shutil.which('swiftc'), 'macOS Swift required')
    def test_relaunch_preserves_preview_state_and_can_be_cancelled(self):
        source = (ROOT / 'app/main.swift').read_text().split('\nstruct PowerStyle:', 1)[0]
        checks = '''
let model = ProxyModel(preview: true)
model.state = ProxyState(configured: true, enabled: true, running: "socks", system_proxy: true, selected: "socks")
var ready = false
model.prepareForUpdate { ready = true }
precondition(model.busy && !ready)
let end = Date().addingTimeInterval(3)
while !ready && Date() < end { RunLoop.main.run(until: Date().addingTimeInterval(0.01)) }
precondition(ready && model.busy)
precondition(model.state?.enabled == true && model.state?.selected == "socks")
model.cancelUpdatePreparation()
precondition(!model.busy && model.state?.running == "socks")
print("relaunch checks passed")
'''
        with tempfile.TemporaryDirectory(prefix='proxypilot-relaunch-') as directory:
            script, binary = Path(directory) / 'main.swift', Path(directory) / 'test'
            script.write_text(source + checks)
            built = subprocess.run(['swiftc', '-module-cache-path', str(ROOT / 'app/build/ModuleCache'),
                                    str(script), '-o', str(binary)], capture_output=True, text=True)
            self.assertEqual(built.returncode, 0, built.stderr)
            result = subprocess.run([str(binary)], capture_output=True, text=True, timeout=10)
            self.assertEqual(result.returncode, 0, result.stderr)
