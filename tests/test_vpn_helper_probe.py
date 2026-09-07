"""Build/inspect disposable packages and real anonymous XPC; never install a service."""
import json
from pathlib import Path
import os
import plistlib
import shutil
import subprocess
import sys
import tempfile
import unittest
import xml.etree.ElementTree as ET

ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / 'tests/vpn-helper-probe'
LABEL = 'kz.documentolog.proxypilot.vpn-probe'


@unittest.skipUnless(sys.platform == 'darwin' and shutil.which('swiftc'), 'macOS Swift required')
class VPNHelperProbeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temporary = tempfile.TemporaryDirectory(prefix='proxypilot-helper-probe-test-')
        cls.directory = Path(cls.temporary.name)
        cls.packages = cls.directory / 'packages'
        result = subprocess.run(['zsh', str(SOURCE / 'build.sh'), str(cls.packages)],
                                text=True, capture_output=True, timeout=150)
        if result.returncode:
            cls.temporary.cleanup()
            raise AssertionError(result.stdout + result.stderr)

    @classmethod
    def tearDownClass(cls):
        cls.temporary.cleanup()

    def run_tool(self, *arguments, code=0, timeout=15):
        result = subprocess.run(list(map(str, arguments)), capture_output=True, text=True, timeout=timeout)
        self.assertEqual(result.returncode, code, result.stdout + result.stderr)
        return result.stdout

    def binary(self, version):
        return self.packages / f'stage-{version}/Library/PrivilegedHelperTools' / LABEL

    def test_universal_ad_hoc_versions_and_no_privileged_operations(self):
        for version in ['0.0.1', '0.0.2']:
            binary = self.binary(version)
            self.assertEqual(set(self.run_tool('/usr/bin/lipo', '-archs', binary).split()),
                             {'arm64', 'x86_64'})
            self.run_tool('/usr/bin/codesign', '--verify', '--strict', binary)
            metadata = json.loads(self.run_tool(binary, '--describe'))
            self.assertEqual(metadata['buildVersion'], version)
            self.assertEqual(metadata['protocolVersion'], 1)
            self.assertEqual(metadata['effectiveUserID'], os.geteuid())
            self.assertEqual(metadata['privilegedOperations'], [])
            for arch in ['arm64', 'x86_64']:
                commands = self.run_tool('/usr/bin/otool', '-arch', arch, '-l', binary)
                self.assertRegex(commands, r'minos 11\.0')

    def test_real_anonymous_xpc_compatible_incompatible_and_reconnect(self):
        for version in ['0.0.1', '0.0.2']:
            for _ in range(2):
                self.assertIn('checks passed', self.run_tool(self.binary(version), '--self-test', timeout=30))

    def test_command_surface_and_non_root_daemon_rejection(self):
        binary = self.binary('0.0.1')
        self.run_tool(binary, code=64)
        self.run_tool(binary, '--connect', code=64)
        self.run_tool(binary, '--serve', '/tmp/profile.ovpn', code=64)
        if os.geteuid() != 0:
            self.run_tool(binary, '--serve', code=77)

    def test_missing_installed_service_is_an_error_not_connected(self):
        present = subprocess.run(['/bin/launchctl', 'print', f'system/{LABEL}'],
                                 capture_output=True, timeout=5).returncode == 0
        if present:
            self.skipTest('An explicitly installed probe exists; do not contact it in isolated tests')
        self.run_tool(self.binary('0.0.1'), '--check-installed', code=69, timeout=10)

    def test_packages_contain_only_fixed_inert_payload(self):
        for version in ['0.0.1', '0.0.2']:
            expanded = self.directory / f'expanded-{version}'
            self.run_tool('/usr/sbin/pkgutil', '--expand-full',
                          self.packages / f'ProxyPilot-VPN-Probe-{version}.pkg', expanded)
            info = ET.parse(expanded / 'PackageInfo').getroot()
            self.assertEqual(info.attrib['identifier'], LABEL)
            self.assertEqual(info.attrib['version'], version)
            self.assertEqual(info.attrib['install-location'], '/')
            self.assertEqual(info.attrib['minimumSystemVersion'], '11.0')
            payload = expanded / 'Payload'
            self.assertFalse(any(path.is_symlink() for path in payload.rglob('*')))
            files = {str(path.relative_to(payload)) for path in payload.rglob('*') if path.is_file()}
            self.assertEqual(files, {f'Library/LaunchDaemons/{LABEL}.plist',
                                     f'Library/PrivilegedHelperTools/{LABEL}'})
            with (payload / f'Library/LaunchDaemons/{LABEL}.plist').open('rb') as source:
                daemon = plistlib.load(source)
            self.assertEqual(daemon['Label'], LABEL)
            self.assertEqual(daemon['ProgramArguments'], [f'/Library/PrivilegedHelperTools/{LABEL}', '--serve'])
            self.assertEqual(daemon['MachServices'], {LABEL: True})
            self.assertEqual(daemon['UserName'], 'root')
            self.assertNotIn('RunAtLoad', daemon)
            self.assertNotIn('KeepAlive', daemon)
            self.assertNotIn('StandardOutPath', daemon)
            self.run_tool('/usr/bin/codesign', '--verify', '--strict',
                          payload / f'Library/PrivilegedHelperTools/{LABEL}')
            bom = self.run_tool('/usr/bin/lsbom', '-f', '-l', expanded / 'Bom')
            entries = {}
            for line in bom.splitlines():
                fields = line.split('\t')
                self.assertEqual(fields[2], '0/0', line)
                entries[fields[0]] = fields[1]
            # BOM also includes AppleDouble metadata records for directory xattrs;
            # inspect the two actual files, not those metadata records, as files.
            self.assertEqual(entries[f'./Library/LaunchDaemons/{LABEL}.plist'], '100644')
            self.assertEqual(entries[f'./Library/PrivilegedHelperTools/{LABEL}'], '100755')

    def test_uninstall_has_no_payload_and_only_our_files(self):
        expanded = self.directory / 'expanded-remove'
        self.run_tool('/usr/sbin/pkgutil', '--expand-full',
                      self.packages / 'Remove-ProxyPilot-VPN-Probe.pkg', expanded)
        info = ET.parse(expanded / 'PackageInfo').getroot()
        self.assertEqual(info.attrib['identifier'], LABEL + '.remove')
        self.assertEqual(info.attrib['minimumSystemVersion'], '11.0')
        self.assertFalse((expanded / 'Payload').exists())
        script = (expanded / 'Scripts/postinstall').read_text()
        removal = next(line for line in script.splitlines() if line.startswith('/bin/rm '))
        self.assertEqual(removal.split(), ['/bin/rm', '-f', '--',
                         f'/Library/LaunchDaemons/{LABEL}.plist', f'/Library/PrivilegedHelperTools/{LABEL}'])
        self.assertNotIn('pro.proxypilot.vpn', script)

    def test_installer_scripts_reject_unprivileged_execution(self):
        if os.geteuid() == 0:
            self.skipTest('Never execute installation scripts as root in isolated tests')
        for name in ['install/preinstall', 'install/postinstall', 'remove/postinstall']:
            self.run_tool('zsh', '-n', SOURCE / name)
            self.run_tool('zsh', SOURCE / name, 'probe.pkg', '/', '/', code=77)

    def test_build_refuses_existing_or_relative_output(self):
        self.run_tool('zsh', SOURCE / 'build.sh', self.packages, code=73)
        self.run_tool('zsh', SOURCE / 'build.sh', '.', code=64)


if __name__ == '__main__':
    unittest.main()
