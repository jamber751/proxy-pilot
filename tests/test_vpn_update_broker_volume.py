"""Actual readonly second-filesystem acceptance; disposable root GHA only."""
import os
from pathlib import Path
import platform
import plistlib
import re
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]


@unittest.skipUnless(sys.platform == 'darwin' and os.getuid() == os.geteuid() == 0
                     and os.environ.get('GITHUB_ACTIONS') == 'true'
                     and os.environ.get('PROXYPILOT_VM_ROOT_TESTS') == '1',
                     'Explicit disposable root CI only; never mount locally')
class VPNUpdateBrokerVolumeRootTests(unittest.TestCase):
    root_vm_fixture = True

    def sealed_cdhash(self, app, arch):
        verified = subprocess.run(['/usr/bin/codesign', '--verify', '--deep', '--strict', str(app)],
                                  capture_output=True, text=True, timeout=30)
        self.assertEqual(verified.returncode, 0, 'synthetic bundle seal verification failed')
        described = subprocess.run(['/usr/bin/codesign', '-d', '--verbose=4', '--arch', arch, str(app)],
                                   capture_output=True, text=True, timeout=30)
        self.assertEqual(described.returncode, 0, 'synthetic bundle identity inspection failed')
        match = re.search(r'^CDHash=([0-9a-f]{40})$', described.stderr, re.MULTILINE)
        self.assertIsNotNone(match, 'synthetic bundle identity missing')
        self.assertRegex(described.stderr, r'flags=0x10302\(.*runtime.*\)')
        return match.group(1)

    def test_actual_readonly_dmg_copies_without_clone_support(self):
        with tempfile.TemporaryDirectory(prefix='pp-broker-volume-', dir='/private/tmp') as folder:
            root = Path(folder); root.chmod(0o700)
            source = root / 'source'; source.mkdir(mode=0o700)
            resources = source / 'ProxyPilot.app/Contents/Resources'
            resources.mkdir(parents=True)
            (resources / 'payload').write_bytes(b'public synthetic volume fixture' * 10000)
            os.symlink('payload', resources / 'current')
            arch = 'arm64' if platform.machine() == 'arm64' else 'x86_64'
            app = source / 'ProxyPilot.app'
            executable = app / 'Contents/MacOS/ProxyPilot'
            executable.parent.mkdir()
            (app / 'Contents/Info.plist').write_bytes(plistlib.dumps({
                'CFBundleExecutable': 'ProxyPilot', 'CFBundleIdentifier': 'com.proxypilot.fixture.volume',
                'CFBundleName': 'ProxyPilot', 'CFBundlePackageType': 'APPL',
                'CFBundleVersion': '1', 'CFBundleShortVersionString': '1.0',
                'LSMinimumSystemVersion': '11.0',
            }))
            compiled_app = subprocess.run(['/usr/bin/clang', '-target', arch + '-apple-macosx11.0',
                                           '-x', 'c', '-', '-o', str(executable)],
                                          input='int main(void) { return 0; }\n',
                                          capture_output=True, text=True, timeout=60)
            self.assertEqual(compiled_app.returncode, 0, 'synthetic bundle compilation failed')
            for name in ['vpn-helper', 'vpn-engine', 'vpn-release.manifest', 'vpn-release.sig',
                         'vpn-previous-release.manifest', 'vpn-previous-release.sig',
                         'vpn-update-transition', 'vpn-update-transition.sig']:
                (source / name).write_bytes(('synthetic ' + name).encode())
            for path in [source] + list(source.rglob('*')):
                os.lchown(path, 501, 20)
                if not path.is_symlink(): path.chmod(0o755 if path.is_dir() or path == executable else 0o644)
            signed = subprocess.run(['/usr/bin/codesign', '--sign', '-', '--timestamp=none',
                                     '--options', 'runtime,hard,kill', str(app)],
                                    capture_output=True, text=True, timeout=30)
            self.assertEqual(signed.returncode, 0, 'synthetic bundle ad-hoc signing failed')
            # Ownership is not sealed content. Keep all source nodes ordinary-owned.
            for path in [app] + list(app.rglob('*')): os.lchown(path, 501, 20)
            expected_cdhash = self.sealed_cdhash(app, arch)
            (root / 'private').mkdir(mode=0o700)
            mount = root / 'mount'; mount.mkdir(mode=0o700)
            binary = root / 'checks'
            arch = 'arm64' if platform.machine() == 'arm64' else 'x86_64'
            compiled = subprocess.run(['swiftc', '-target', arch + '-apple-macosx11.0',
                                       str(ROOT / 'app/vpn-helper/VPNUpdateBrokerInbox.swift'),
                                       str(ROOT / 'tests/vpn_update_broker_volume_checks.swift'),
                                       '-o', str(binary)], capture_output=True, text=True, timeout=120)
            self.assertEqual(compiled.returncode, 0, compiled.stderr)
            image = root / 'fixture.dmg'
            created = subprocess.run(['/usr/bin/hdiutil', 'create', '-quiet', '-srcfolder', str(source),
                                      '-fs', 'HFS+', '-format', 'UDRO', str(image)],
                                     capture_output=True, text=True, timeout=90)
            self.assertEqual(created.returncode, 0, created.stderr)
            attached = False
            try:
                result = subprocess.run(['/usr/bin/hdiutil', 'attach', '-readonly', '-nobrowse',
                                         '-mountpoint', str(mount), str(image)],
                                        capture_output=True, text=True, timeout=90)
                self.assertEqual(result.returncode, 0, result.stderr)
                attached = True
                self.assertEqual(self.sealed_cdhash(mount / 'ProxyPilot.app', arch), expected_cdhash)
                checked = subprocess.run([str(binary), folder], capture_output=True, text=True, timeout=30)
                self.assertEqual(checked.returncode, 0, checked.stdout + checked.stderr)
                self.assertEqual(checked.stdout.strip(), 'readonly cross-volume inbox passed')
                publications = list((root / 'private').glob('inbox-*'))
                self.assertEqual(len(publications), 1)
                self.assertEqual(self.sealed_cdhash(publications[0] / 'ProxyPilot.app', arch), expected_cdhash)
                self.assertEqual(os.readlink(publications[0] / 'ProxyPilot.app/Contents/Resources/current'), 'payload')
            finally:
                if attached:
                    result = subprocess.run(['/usr/bin/hdiutil', 'detach', '-quiet', str(mount)],
                                            capture_output=True, text=True, timeout=60)
                    self.assertEqual(result.returncode, 0, result.stderr)


if __name__ == '__main__': unittest.main()
