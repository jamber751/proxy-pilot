"""Opt-in disposable VM launchd evidence for frozen139 recovery source.

This rebuilds pinned source with existing test seams and synthetic keys. It is
NOT the production signed139 binary, root destination exchange, broker rotation,
or legacy cleanup acceptance. No host launchd execution is allowed.
"""
import base64
import hashlib
import json
import os
from pathlib import Path
import shutil
import select
import subprocess
import sys
import tempfile
import time
import unittest
from tests import test_vpn_recovery_daemon_entry as existing

ROOT, HELPER, APP_ID, ENV = existing.ROOT, existing.HELPER, existing.APP_ID, existing.ENV
REVISION = 'e80b8be8dcf85d985b960ac5e1b4726469b5bce9'
FROZEN_SHA256 = {'app/VPNConfiguration.swift': '091efe7b41a3653808cdf42a86a68e881845e6321c06eeece3f4b5248919a8a9',
 'app/VPNProfileImporter.swift': '60df30dceebbcbc654d720e0a7a89894f9da85a30b607ee7211028b3fa1d03f8',
 'app/vpn-helper/ServiceMain.swift': '9d4154dbe1aa62874652605e709ed8b3c6d2ce920dd437a4a7e694e45f7b78f5',
 'app/vpn-helper/VPNActivationBudget.swift': '763fcbad0e5ea8a9e374fdf6122e32ad2617143bd83fae4f518666d00b0c5cfc',
 'app/vpn-helper/VPNActivationCoordinator.swift': '16e8e149be94213346c2b50328ab23824f127b743f83f9b9431cc2c780df5232',
 'app/vpn-helper/VPNApplicationSpec.swift': '2887219efd99badf28b08c3e3907bb8714c3016b87de9ee2e51457d80ab41f4d',
 'app/vpn-helper/VPNDirectoryProvisioner.swift': '1e3d8bcf874a53bb143136192cdb6534aa4c59db4f263db2d0ba062e62c07acf',
 'app/vpn-helper/VPNEndpointDirectory.swift': '9fd1de535b4784d489fd5897e370933aeb5029c991e29b4c9e3303ca53edaad1',
 'app/vpn-helper/VPNEngineProcess.swift': 'b297140f37180aa4f6e89124013e0207af50693bc9a11d557e1f9103431cf7c3',
 'app/vpn-helper/VPNEngineSupervisor.swift': '9aa3bd89e96132e1fb4f4c9abd04168532b55f0f332cd97a961e93f83c43a178',
 'app/vpn-helper/VPNHelperArtifact.swift': '1d7849a3cdfa6f3b2a82235552c0b645a494b4271744757d71de599dff4b2d72',
 'app/vpn-helper/VPNHelperDaemon.swift': 'a541ce40702dc4ebf69dc6e717efbee1a1cb9ed2b82c5203ff1defba4628ddff',
 'app/vpn-helper/VPNHelperListener.swift': '4ad104664340bcd71c198f3ec9dcbfd6716fd439e48c8f5ca9168e64540848de',
 'app/vpn-helper/VPNHelperProtocol.swift': 'e63fdb732ca00b8b2a70048f3e8cb426cf89c060420c11d5ebbaeca1b874a940',
 'app/vpn-helper/VPNHelperReadiness.swift': '5d3a8acacaa5f4d6563581f81434a53953615fd75b84bf2a98eeb864f826b45d',
 'app/vpn-helper/VPNHelperRuntime.swift': '1dfebd55a834a9a5b4aa159d758fe51e51fb5a8017ec29d0088c3516cc197878',
 'app/vpn-helper/VPNInstalledApplication.swift': '0d5e11b821f030c435955a16396a43c4f8734dfa58978d8e067ec029a3a1b91e',
 'app/vpn-helper/VPNJointUpdateCleanup.swift': '92aaccafc02d03562490d5981c2d5558dfa0abb31ad07f44c7ebbde82ee97003',
 'app/vpn-helper/VPNLaunchdRuntime.swift': 'eaa6caece555fd8fac493771daa351bed53191a92bdb69e8e993c32cdabffc97',
 'app/vpn-helper/VPNLifecycleOwnership.swift': '5bbe09177e36daa12b20bb30427f05107b736fa269eeeccd646caa6fb6958992',
 'app/vpn-helper/VPNPeerAuthentication.swift': '1dfb7aaefe5f83f7a04df58dcff2d1bcd598f2fe37e44504d3e029404b7e0c2e',
 'app/vpn-helper/VPNProfileVault.swift': '8fcbe34486220ffea81deb5c9be83fe3dfb6892d0960ddbee8c78f65bf216136',
 'app/vpn-helper/VPNPublicReleaseReceipt.swift': 'c54c1dc3da80711d56139dbe64298ce22c26788d406bc6b449e99c30203700b2',
 'app/vpn-helper/VPNRecoveryLaunchdJob.swift': '40f5f30e019712586ac708ebc2857a4b2b7cb94541a50eb1c421d79d518ecb42',
 'app/vpn-helper/VPNReleaseAuthorization.swift': 'f0cd3d270907129a933ce50ebcdd22522c2565e3e4ee6eb23d86457399375b6c',
 'app/vpn-helper/VPNReleaseStore.swift': '09b92ed993168c863d6841bde9d6a554e23486893add5f975bfd22a9b29ec206',
 'app/vpn-helper/VPNReleaseTrust.swift': '6a8e6426a920cb757957461bb43683c0e9b70abcbf98470ede5a06c1da54daca',
 'app/vpn-helper/VPNSelectedCandidateFinalizer.swift': 'f3c888960db75ec83925cd33272fbc1b93cb293959dbf106d3a29bef401b8384',
 'app/vpn-helper/VPNSelectedCandidateRecovery.swift': '8310bc91f4e1712db37b21df063bafef75f7bff9617464b43600d69621438ea7',
 'app/vpn-helper/VPNSelectedCandidateRecoveryDaemonEntry.swift': '590c1835675c963cc51a0d3ce2ff954db44b0bdc1467e716f553d64fa905c099',
 'app/vpn-helper/VPNStagedApplication.swift': '070c1c66892e717bd29e354bf153a98f94b0909b01524fa319f19f03b5197a95',
 'app/vpn-helper/VPNTunnelStateStore.swift': '658811cd01241599854c78a6d7264c7b1ec017e2750889ff74000b35529e55b2'}

@unittest.skipUnless(sys.platform == 'darwin' and os.geteuid() != 0
                     and os.environ.get('PROXYPILOT_VM_LAUNCHD_TESTS') == '1',
                     'explicit disposable macOS user launchd fixture')
class VPNFrozen139RecoveryHandoffTests(unittest.TestCase):
    command = existing.VPNRecoveryDaemonEntryTests.__dict__['command']
    code_pins = existing.VPNRecoveryDaemonEntryTests.__dict__['code_pins']
    make_app = existing.VPNRecoveryDaemonEntryTests.make_app
    rebuild = existing.VPNRecoveryDaemonEntryTests.rebuild
    sign = existing.VPNRecoveryDaemonEntryTests.sign
    pins = existing.VPNRecoveryDaemonEntryTests.pins
    run_helper = existing.VPNRecoveryDaemonEntryTests.run_helper
    boot_out = existing.VPNRecoveryDaemonEntryTests.boot_out
    loaded = existing.VPNRecoveryDaemonEntryTests.loaded
    wait_recovered = existing.VPNRecoveryDaemonEntryTests.wait_recovered
    assert_terminal_state = existing.VPNRecoveryDaemonEntryTests.assert_terminal_state
    wait_recovery_cleanup = existing.VPNRecoveryDaemonEntryTests.wait_recovery_cleanup

    @classmethod
    def freeze(cls, path):
        relative = str(path.relative_to(ROOT))
        result = subprocess.run(['git', '-C', str(ROOT), 'show', REVISION + ':' + relative],
                                capture_output=True, timeout=30, check=True)
        if hashlib.sha256(result.stdout).hexdigest() != FROZEN_SHA256[relative]:
            raise AssertionError('Frozen source changed: ' + relative)
        output = cls.build / 'frozen' / relative
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_bytes(result.stdout)
        return output

    @classmethod
    def setUpClass(cls):
        if os.geteuid() == 0:
            raise unittest.SkipTest('Never run the recovery fixture as root')
        cls.temporary = tempfile.TemporaryDirectory(prefix='pp-recovery-entry-build-', dir='/tmp')
        cls.addClassCleanup(cls.temporary.cleanup)
        cls.build = Path(cls.temporary.name)
        source = cls.build / 'fixture.c'; source.write_text('int main(void) { return 86; }\n')
        cls.slices = {}
        for arch in ('arm64', 'x86_64'):
            cls.slices[arch] = cls.build / f'app-{arch}'
            cls.command(['clang', '-target', arch + '-apple-macosx11.0',
                         str(source), '-o', str(cls.slices[arch])])
        cls.universal = cls.build / 'app-universal'
        cls.command(['lipo', '-create', *map(str, cls.slices.values()),
                     '-output', str(cls.universal)])
        cls.domain = f'gui/{os.geteuid()}'
        if not os.environ.get('PROXYPILOT_FROZEN_COMPILE_ONLY') and subprocess.run(
                ['/bin/launchctl', 'print', cls.domain], capture_output=True, timeout=60).returncode:
            raise AssertionError('Opted-in VM has no reachable per-user GUI launchd domain')
        components = [
            'VPNPeerAuthentication.swift', 'VPNReleaseAuthorization.swift', 'VPNReleaseTrust.swift',
            'VPNHelperArtifact.swift', 'VPNReleaseStore.swift', 'VPNDirectoryProvisioner.swift',
            'VPNEndpointDirectory.swift', 'VPNHelperProtocol.swift', 'VPNHelperReadiness.swift',
            'VPNHelperListener.swift', 'VPNApplicationSpec.swift', 'VPNTunnelStateStore.swift',
            'VPNProfileVault.swift', 'VPNEngineProcess.swift', 'VPNEngineSupervisor.swift',
            'VPNLifecycleOwnership.swift',
            'VPNActivationBudget.swift', 'VPNActivationCoordinator.swift', 'VPNLaunchdRuntime.swift',
            'VPNRecoveryLaunchdJob.swift', 'VPNStagedApplication.swift', 'VPNInstalledApplication.swift',
            'VPNSelectedCandidateFinalizer.swift', 'VPNSelectedCandidateRecovery.swift',
            'VPNJointUpdateCleanup.swift', 'VPNHelperRuntime.swift', 'VPNHelperDaemon.swift',
            'VPNPublicReleaseReceipt.swift',
            'VPNSelectedCandidateRecoveryDaemonEntry.swift', 'ServiceMain.swift',
        ]
        sources = [ROOT / 'app/VPNConfiguration.swift', ROOT / 'app/VPNProfileImporter.swift']
        sources += [HELPER / name for name in components]
        sources += [ROOT / 'tests/vpn_frozen139_recovery_handoff_checks.swift']
        sources = [cls.freeze(path) if path.is_relative_to(HELPER) or path.parent == ROOT / 'app' else path
                   for path in sources]
        flags = ['-D', 'VPN_RECOVERY_DAEMON_ENTRY', '-D', 'VPN_RECOVERY_DAEMON_TESTING',
                 '-D', 'VPN_DAEMON_TESTING', '-D', 'VPN_LAUNCHD_TESTING',
                 '-D', 'VPN_APPLICATION_DESTINATION_TESTING',
                 '-D', 'VPN_HELPER_READINESS_TESTING', '-D', 'VPN_HELPER_LISTENER_TESTING']
        helper_slices = []
        probe_slices = []
        probe_sources = [HELPER / name for name in (
            'VPNPeerAuthentication.swift', 'VPNReleaseAuthorization.swift',
            'VPNHelperProtocol.swift', 'VPNHelperReadiness.swift')]
        probe_sources = [cls.freeze(path) for path in probe_sources]
        probe_sources.append(ROOT / 'tests/vpn_recovery_probe.swift')
        for arch in ('arm64', 'x86_64'):
            helper = cls.build / f'recovery-helper-{arch}'
            cls.command(['swiftc', '-O', '-parse-as-library', *flags,
                         '-target', f'{arch}-apple-macosx11.0', *map(str, sources), '-o', str(helper)])
            helper_slices.append(str(helper))
            probe = cls.build / f'recovery-probe-{arch}'
            cls.command(['swiftc', '-D', 'VPN_HELPER_READINESS_TESTING',
                         '-target', f'{arch}-apple-macosx11.0',
                         *map(str, probe_sources), '-o', str(probe)])
            probe_slices.append(str(probe))
        cls.recovery_helper = cls.build / 'recovery-helper'
        cls.recovery_probe = cls.build / 'recovery-probe'
        cls.command(['lipo', '-create', *helper_slices, '-output', str(cls.recovery_helper)])
        cls.command(['lipo', '-create', *probe_slices, '-output', str(cls.recovery_probe)])
        cls.recovery_helper.chmod(0o700)
        cls.command(['codesign', '--force', '--sign', '-', '--options', 'runtime,hard,kill',
                     '--identifier', 'kz.documentolog.proxypilot.vpn-helper',
                     str(cls.recovery_helper)])
        cls.helper_pins = cls.code_pins(cls.recovery_helper)

    def setUp(self):
        if os.environ.get('PROXYPILOT_FROZEN_COMPILE_ONLY'):
            self.skipTest('compile-only mode forbids launchd execution')
        # Reuse only setup helpers; force its pending-B initial layout.
        original = self._testMethodName
        self._testMethodName = 'test_pending_b_recovers_forward_without_a_live_updater'
        try:
            existing.VPNRecoveryDaemonEntryTests.setUp(self)
        finally:
            self._testMethodName = original

    def assert_receipt(self):
        receipt = json.loads((self.storage / 'cleanup.json').read_text())
        self.assertEqual(receipt['schema'], 2)
        self.assertEqual(receipt['journal']['phase'], 'completed')
        self.assertEqual(receipt['journal']['revision'], 3)
        self.assertEqual(receipt['phase'], 'pending')

    def test_pending_b_recovers_and_preserves_exact_cleanup_receipt(self):
        before = json.loads((self.storage / 'update.json').read_text())
        result = self.run_helper('fixture-arm', str(self.storage))
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.wait_recovered(timeout=40)
        self.assert_terminal_state()
        self.wait_recovery_cleanup()
        self.assert_receipt()
        receipt = json.loads((self.storage / 'cleanup.json').read_text())
        self.assertEqual(receipt['journal']['transactionID'], before['transactionID'])
        for key in ('previousPayload', 'candidatePayload', 'transitionPayload'):
            self.assertEqual(receipt['journal'][key], before[key])

    def test_armed_recovery_retries_only_after_pending_lease_release(self):
        before = (self.storage / 'update.json').read_bytes()
        selected = (self.storage / 'release.json').read_bytes()
        holder = subprocess.Popen([str(self.recovery_helper), 'fixture-arm-held', str(self.storage)],
                                  env=ENV, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                  stderr=subprocess.PIPE, text=True)
        def cleanup():
            if holder.poll() is None:
                holder.kill()
            holder.communicate()
        self.addCleanup(cleanup)
        ready, _, _ = select.select([holder.stdout], [], [], 30)
        self.assertTrue(ready, 'Timed out waiting for bounded arm completion')
        self.assertEqual(holder.stdout.readline().strip(), 'armed:held')
        deadline = time.monotonic() + 15
        state = ''
        while time.monotonic() < deadline:
            state = subprocess.run(['/bin/launchctl', 'print', f'{self.domain}/{self.recovery_label}'],
                                   capture_output=True, text=True, timeout=30).stdout
            if 'last exit code = 75' in state:
                break
            time.sleep(0.05)
        self.assertIn('last exit code = 75', state)
        self.assertEqual((self.storage / 'update.json').read_bytes(), before)
        self.assertEqual((self.storage / 'release.json').read_bytes(), selected)
        self.assertFalse(self.loaded(self.helper_label))
        holder.stdin.write('release\n'); holder.stdin.flush()
        self.assertEqual(holder.wait(timeout=10), 0)
        self.wait_recovered(timeout=40)
        self.assert_terminal_state()
        self.wait_recovery_cleanup()
        self.assert_receipt()

if __name__ == '__main__':
    unittest.main()
