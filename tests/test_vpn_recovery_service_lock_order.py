"""Current recovery must acquire Service lifecycle before touching store state.

Only a signed synthetic helper and ordinary-user temporary directories are used.
This suite never probes/registers a launchd domain or starts a service.
"""
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
HELPER = ROOT / 'app/vpn-helper'


@unittest.skipUnless(sys.platform == 'darwin' and os.getuid() == os.geteuid()
                     and os.getuid() >= 500 and shutil.which('swiftc'), 'ordinary macOS user required')
class VPNRecoveryServiceLockOrderTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp = tempfile.TemporaryDirectory(prefix='pp-recovery-lock-order-')
        cls.addClassCleanup(cls.temp.cleanup)
        cls.work = Path(cls.temp.name)
        sources = [ROOT / 'app/VPNConfiguration.swift', ROOT / 'app/VPNProfileImporter.swift']
        sources += [path for path in sorted(HELPER.glob('*.swift')) if path.name != 'ServiceMain.swift']
        sources.append(ROOT / 'tests/vpn_recovery_service_lock_order_checks.swift')
        # Compile both slices from one immutable input graph while independent
        # agents may edit inactive rescue-only source in the shared checkout.
        captured = {path: path.read_bytes() for path in sources}
        frozen = cls.work / 'Sources'
        for path, data in captured.items():
            target = frozen / path.relative_to(ROOT)
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(data)
        if any(path.read_bytes() != data for path, data in captured.items()):
            raise AssertionError('Source changed during recovery test snapshot capture')
        if set(path for path in HELPER.glob('*.swift') if path.name != 'ServiceMain.swift') != set(
                path for path in sources if path.parent == HELPER):
            raise AssertionError('Helper source graph changed during snapshot capture')
        sources = [frozen / path.relative_to(ROOT) for path in sources]
        flags = ['-D', 'VPN_RECOVERY_DAEMON_TESTING', '-D', 'VPN_HELPER_READINESS_TESTING',
                 '-D', 'VPN_APPLICATION_DESTINATION_TESTING']
        slices = []
        for arch in ('arm64', 'x86_64'):
            output = cls.work / ('driver-' + arch)
            built = subprocess.run(['/usr/bin/swiftc', '-parse-as-library', *flags, '-target',
                                    arch + '-apple-macosx11.0', *map(str, sources), '-o', str(output)],
                                   capture_output=True, text=True, timeout=300)
            if built.returncode: raise AssertionError(built.stdout + built.stderr)
            slices.append(str(output))
        cls.driver = cls.work / 'driver'
        subprocess.run(['/usr/bin/lipo', '-create', *slices, '-output', str(cls.driver)], check=True)
        cls.driver.chmod(0o700)
        subprocess.run(['/usr/bin/codesign', '--force', '--sign', '-', '--options', 'runtime,hard,kill',
                        '--identifier', 'kz.documentolog.proxypilot.vpn-helper', str(cls.driver)], check=True)
        cls.pins = []
        for arch in ('arm64', 'x86_64'):
            result = subprocess.run(['/usr/bin/codesign', '-d', '--verbose=4', '--arch', arch, str(cls.driver)],
                                    capture_output=True, text=True, check=True)
            cls.pins.append(re.search(r'^CDHash=([a-f0-9]{40})$', result.stderr, re.M)[1])

    def check_held_service(self, record):
        with tempfile.TemporaryDirectory(prefix='pp-recovery-lock-case-') as temp:
            os.chmod(temp, 0o700)
            result = subprocess.run([str(self.driver), temp, *self.pins, record],
                                    capture_output=True, text=True, timeout=30)
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assertEqual(result.stdout.strip(), 'status:75 releaseLock:absent state:unchanged callbacks:none')

    def test_busy_service_does_not_create_store_lock_or_read_selected_state(self): self.check_held_service('clean')
    def test_busy_service_does_not_even_parse_malformed_selected_state(self): self.check_held_service('malformed')


if __name__ == '__main__': unittest.main()
