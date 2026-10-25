"""Distribution requirement and isolated preflight fragments; never Installer."""
from pathlib import Path
import importlib.util
import os
import plistlib
import shutil
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = ('app/vpn-package/preinstall', 'app/vpn-package/first-install-preinstall',
           'app/vpn-rescue/preinstall')
VERSION_COMMAND = '/usr/bin/env -i PATH=/usr/bin:/bin:/usr/sbin:/sbin /usr/bin/sw_vers -productVersion'


def preflight_fragment(relative):
    source = (ROOT / relative).read_text()
    start = source.index('# Reject unsupported systems')
    end = source.index('PACKAGE_ROOT=', start)
    return source[start:end]


class MinimumMacOSTests(unittest.TestCase):
    def test_bundle_and_updater_declare_the_same_requirement(self):
        source = (ROOT / 'app/build.sh').read_text()
        self.assertIn('LSMinimumSystemVersion=12.0', source)
        self.assertIn('<key>LSMinimumSystemVersion</key>  <string>12.0</string>', source)
        ci = (ROOT / '.github/workflows/ci.yml').read_text()
        self.assertIn('Print :LSMinimumSystemVersion', ci)
        self.assertGreaterEqual(ci.count('= "12.0"'), 2)

    def test_all_preflights_check_system_before_any_payload_execution(self):
        fragments = [preflight_fragment(name) for name in SCRIPTS]
        self.assertEqual(len(set(fragments)), 1)
        for name in SCRIPTS:
            source = (ROOT / name).read_text()
            self.assertLess(source.index('SYSTEM_VERSION='), source.index('PACKAGE_ROOT='))
            self.assertLess(source.index('SYSTEM_VERSION='), source.index('exec /usr/bin/env'))
            self.assertIn(VERSION_COMMAND, source)

    @unittest.skipUnless(shutil.which('zsh'), 'zsh required')
    def test_old_and_malformed_versions_never_reach_payload_but_supported_versions_do(self):
        # Execute ONLY the actual OS fragment with a fake version provider.
        # No root guard is bypassed in a real script and no payload is executed.
        with tempfile.TemporaryDirectory(prefix='pp-minimum-os-') as folder:
            folder = Path(folder)
            stub = folder / 'version-provider'
            stub.write_text('#!/bin/sh\nprintf "%s" "$FAKE_MACOS_VERSION"\n')
            stub.chmod(0o700)
            script = folder / 'fragment.zsh'
            fragment = preflight_fragment(SCRIPTS[0]).replace(VERSION_COMMAND, '"$VERSION_PROVIDER"')
            script.write_text('set -euo pipefail\n' + fragment + '\nprintf reached > "$MARKER"\n')
            marker = folder / 'payload-reached'
            for version, accepted in [('10.16', False), ('11.7.10', False), ('12.0', True),
                                      ('12.7.6', True), ('13.0', True), ('26.1', True),
                                      ('', False), ('not-an-os', False), ('12SECRET.0', False),
                                      ('9999.0', False), ('11\n12.0', False)]:
                marker.unlink(missing_ok=True)
                with self.subTest(version=version):
                    environment = dict(os.environ, VERSION_PROVIDER=str(stub),
                                       FAKE_MACOS_VERSION=version, MARKER=str(marker))
                    result = subprocess.run(['zsh', '-f', str(script)], env=environment,
                                            capture_output=True, text=True, timeout=5)
                    self.assertEqual(result.returncode, 0 if accepted else 77, result.stderr)
                    self.assertEqual(marker.exists(), accepted)

    def test_packager_rejects_stale_minimum_even_with_valid_identity(self):
        spec = importlib.util.spec_from_file_location('minimum_package', ROOT / 'app/vpn-package/package.py')
        package = importlib.util.module_from_spec(spec); spec.loader.exec_module(package)
        with tempfile.TemporaryDirectory(prefix='pp-minimum-plist-') as folder:
            app = Path(folder) / 'ProxyPilot.app'; (app / 'Contents').mkdir(parents=True)
            info = dict(CFBundleIdentifier='kz.documentolog.proxypilot', CFBundleVersion='1.6.0',
                        CFBundleShortVersionString='1.6.0', CFBundleExecutable='ProxyPilot',
                        ProxyPilotVPNInstaller=True)
            for version in ['11.0', '12.0', '13.0']:
                info['LSMinimumSystemVersion'] = version
                (app / 'Contents/Info.plist').write_bytes(plistlib.dumps(info))
                if version == '12.0': self.assertEqual(package.version_of(app), '1.6.0')
                else:
                    with self.assertRaises(ValueError): package.version_of(app)

    def test_direct_app_and_updater_launches_are_gated_before_normal_roles(self):
        main = (ROOT / 'app/main.swift').read_text()
        guard = main.index('operatingSystemVersion.majorVersion < 12')
        self.assertLess(guard, main.index('if let status = VPNPasswordWorker.runIfRequested('))
        self.assertLess(guard, main.index('let app = NSApplication.shared'))
        worker = (ROOT / 'app/update-worker/UpdateWorker.swift').read_text()
        self.assertLess(worker.index('operatingSystemVersion.majorVersion >= 12'),
                        worker.index('let app = NSApplication.shared'))

    def test_release_verifier_requires_appcast_and_bundle_minimum_match(self):
        source = (ROOT / 'app/verify-release-candidate.sh').read_text()
        self.assertIn('"$ASSETS/appcast.xml" <<\'PY\'', source)
        self.assertIn("info.get('LSMinimumSystemVersion') != '12.0'", source)
        self.assertIn("minimums[0].text != '12.0'", source)
        for relative in ('app/vpn-package/package.py', 'app/vpn-rescue/package.py'):
            text = (ROOT / relative).read_text()
            self.assertIn("'--min-os-version', '12.0'", text)
            self.assertNotIn("'--min-os-version', '11.0'", text)

    def test_actual_release_metadata_gate_rejects_incompatible_or_ambiguous_feed(self):
        # Run the verifier's metadata block alone. No mount, executable,
        # signing, publication or other shell step is run by this test.
        source = (ROOT / 'app/verify-release-candidate.sh').read_text()
        block = source.split('"$ASSETS/appcast.xml" <<\'PY\'\n', 1)[1].split('\nPY\n', 1)[0]
        with tempfile.TemporaryDirectory(prefix='pp-minimum-feed-') as folder:
            folder = Path(folder)
            fields = [('metadata', 'version=1.6.0\nfrom-sequence=139\nto-sequence=140\n'),
                      ('candidate', 'version=1.6.0\nsequence=140\n'),
                      ('previous', 'sequence=139\n'), ('sequence', '140\n')]
            for name, content in fields: (folder / name).write_text(content)
            info = dict(CFBundleVersion='1.6.0', CFBundleShortVersionString='1.6.0',
                        ProxyPilotVPNReleaseSequence=140, LSMinimumSystemVersion='12.0')
            valid = '<sparkle:minimumSystemVersion>12.0</sparkle:minimumSystemVersion>'
            for requirement, accepted in [(valid, True), ('', False),
                    (valid.replace('12.0', '11.0'), False),
                    (valid.replace('12.0', '13.0'), False),
                    (valid + valid, False), (valid.replace('sparkle:', ''), False)]:
                (folder / 'feed').write_text('<rss xmlns:sparkle="http://www.andymatuschak.org/xml-namespaces/sparkle"><channel><item>' + requirement + '</item></channel></rss>')
                (folder / 'info').write_bytes(plistlib.dumps(info))
                result = subprocess.run([sys.executable, '-c', block, '1.6.0',
                    *[str(folder / name) for name in ('metadata', 'candidate', 'previous', 'info', 'sequence', 'feed')]],
                    capture_output=True, text=True, timeout=5)
                self.assertEqual(result.returncode == 0, accepted, result.stderr)
            (folder / 'feed').write_text('<rss xmlns:sparkle="http://www.andymatuschak.org/xml-namespaces/sparkle"><channel>' + valid + '</channel></rss>')
            info['LSMinimumSystemVersion'] = '11.0'
            (folder / 'info').write_bytes(plistlib.dumps(info))
            result = subprocess.run([sys.executable, '-c', block, '1.6.0',
                *[str(folder / name) for name in ('metadata', 'candidate', 'previous', 'info', 'sequence', 'feed')]],
                capture_output=True, text=True, timeout=5)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn('requires macOS 12', result.stderr)


if __name__ == '__main__': unittest.main()
