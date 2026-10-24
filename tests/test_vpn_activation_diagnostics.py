"""Pure native diagnostics + fixture-owned ordinary files. No real logger sink,
root, system services, Keychain or user settings are exercised.
"""
from pathlib import Path
import os
import platform
import shutil
import subprocess
import sys
import tempfile
import unittest

import test_vpn_rescue_system_vm as vm
from test_vpn_launchd import COMPONENTS, IMPORTER, HELPER, ROOT


class ActivationDiagnosticParserTests(unittest.TestCase):
    def line(self, role='helper', stage='selection', event='failure', category='storeBusy', elapsed='lt250'):
        return f'ProxyPilot VPN activation role: {role}; stage: {stage}; event: {event}; category: {category}; elapsed: {elapsed}'

    def test_closed_parser_rejects_unknown_fields_paths_and_arbitrary_output(self):
        rows = [self.line(), 'PRIVATE /path credential', self.line(role='PRIVATE'),
                self.line(stage='private'), self.line(event='private'), self.line(category='private'),
                self.line(elapsed='999999'), self.line() + ' PRIVATE']
        self.assertEqual(vm.activation_tokens(chr(10).join(rows)), ['helper:selection:failure:storeBusy:lt250'])

    def test_reader_only_uses_known_regular_private_single_link_files(self):
        with tempfile.TemporaryDirectory(prefix='pp-activation-logs-') as temporary:
            root = Path(temporary); root.chmod(0o700)
            helper = root / 'helper.log'; helper.write_text(self.line() + chr(10) + 'PRIVATE'); helper.chmod(0o600)
            recovery = root / 'recovery.log'; recovery.write_text(self.line(role='finalizer')); recovery.chmod(0o600)
            self.assertEqual(vm.activation_log_diagnostics(root, os.geteuid(), (0, 0)), {'record': 'changed'})
            result = vm.activation_log_diagnostics(root, os.geteuid())
            self.assertEqual(result['helper.log']['events'], ['helper:selection:failure:storeBusy:lt250'])
            self.assertNotIn('PRIVATE', repr(result))
            helper.chmod(0o640)
            self.assertEqual(vm.activation_log_diagnostics(root, os.geteuid())['helper.log']['record'], 'unsafe')
            helper.chmod(0o600); link = root / 'extra'; os.link(helper, link)
            self.assertEqual(vm.activation_log_diagnostics(root, os.geteuid())['helper.log']['record'], 'unsafe')
            link.unlink(); helper.unlink(); helper.symlink_to(recovery)
            self.assertEqual(vm.activation_log_diagnostics(root, os.geteuid())['helper.log']['record'], 'unreadable')
            helper.unlink(); helper.write_text((self.line() + chr(10)) * 1500); helper.chmod(0o600)
            result = vm.activation_log_diagnostics(root, os.geteuid())['helper.log']
            self.assertTrue(result['truncated']); self.assertLessEqual(len(result['events']), 96)

    def test_instrumentation_preserves_charge_start_and_readiness_order(self):
        finalizer = (HELPER / 'VPNSelectedCandidateFinalizer.swift').read_text()
        for token in ('trace.mark(.charge)', 'trace.mark(.start)', 'trace.mark(.readiness)', 'trace.mark(.finalValidation)'):
            self.assertIn(token, finalizer)
        self.assertLess(finalizer.index('trace.mark(.charge)'), finalizer.index('try budget.beginAttempt'))
        self.assertIn('+ 5_000_000_000', finalizer)
        self.assertIn('min(2000, Int((deadline - now)', finalizer)
        helper = (HELPER / 'VPNHelperDaemon.swift').read_text()
        self.assertIn('role: .journal, stage: .journal', helper)
        self.assertIn('role: .readinessPolicy, stage: .readinessPolicy', helper)
        logger = (HELPER / 'VPNActivationDiagnostics.swift').read_text()
        self.assertNotIn('error.description', logger)
        self.assertNotIn('String(describing:', logger)
        self.assertIn('#if VPN_SYSTEM_ACTIVATION_DIAGNOSTICS', logger)
        self.assertIn('static let maximumProcessRecords = 128', logger)
        self.assertNotIn('SIG_IGN', logger)
        self.assertNotIn('signal(', logger)


@unittest.skipUnless(sys.platform == 'darwin' and shutil.which('swiftc'), 'macOS Swift required')
class ActivationDiagnosticNativeTests(unittest.TestCase):
    def test_native_closed_classifier_elapsed_and_bounded_injected_sink(self):
        with tempfile.TemporaryDirectory(prefix='pp-activation-native-') as folder:
            binary = Path(folder) / 'checks'
            arch = 'arm64' if platform.machine() == 'arm64' else 'x86_64'
            result = subprocess.run(['/usr/bin/swiftc', '-parse-as-library', '-D', 'VPN_ACTIVATION_DIAGNOSTICS_TESTING', '-target', arch + '-apple-macosx11.0',
                                     *map(str, [HELPER / name for name in COMPONENTS] + IMPORTER),
                                     str(ROOT / 'tests/vpn_activation_diagnostics_checks.swift'), '-o', str(binary)],
                                    capture_output=True, text=True, timeout=120)
            self.assertEqual(result.returncode, 0, result.stderr)
            result = subprocess.run([str(binary)], capture_output=True, text=True, timeout=10)
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assertEqual(result.stdout.strip(), 'closed activation diagnostics passed')


if __name__ == '__main__': unittest.main()
