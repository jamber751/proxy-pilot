"""Opt-in root ownership integration for a disposable macOS VM, never the host.

Runs the destination primitive against temporary signed fixture bundles only.
No Installer, launchd, network, Keychain, or real Applications mutation.
This is not full installed update acceptance.
"""
import os
import hashlib
import plistlib
import shutil
import sys
import unittest

import test_vpn_application_destination_exchange as destination


@unittest.skipUnless(sys.platform == 'darwin' and os.geteuid() == 0
                     and os.environ.get('PROXYPILOT_VM_ROOT_TESTS') == '1'
                     and shutil.which('swiftc'),
                     'requires explicit opt-in inside disposable macOS VM as root')
class VPNDestinationRootVMTests(destination.VPNApplicationDestinationExchangeTests):
    root_vm_fixture = True

    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        # Frozen source at the recorded 137 baseline. Only the fixture entry's
        # UID guard is adapted; production exchange behavior remains unchanged.
        revision = '8519961fdf157252f195b469550f1bcebbd1878d'
        # Hosted checkout belongs to the runner user. Scope this read-only
        # exception to this exact checkout and command; do not alter git config.
        result = cls.command(['git', '-c', 'safe.directory=' + str(destination.ROOT),
                              '-C', str(destination.ROOT), 'show',
                              revision + ':app/vpn-helper/VPNApplicationDestinationExchange.swift'])
        original = result.stdout
        if hashlib.sha256(original.encode()).hexdigest() != '5b9b4ed417b0aca742d5c979c384e48d30aa7718741111d24ef28d2debb28d65':
            raise AssertionError('Frozen legacy exchange source mismatch')
        guard = 'guard getuid() != 0, geteuid() == getuid() else { throw VPNPeerAuthenticationError.denied }'
        if original.count(guard) != 1:
            raise AssertionError('Legacy fixture entry guard changed')
        legacy = cls.build / 'LegacyDestinationExchange.swift'
        legacy.write_text(original.replace(guard,
            'guard getuid() == 0, geteuid() == 0 else { throw VPNPeerAuthenticationError.denied }')
            .replace('VPNApplicationDestinationExchange', 'VPNLegacyApplicationDestinationExchange'))
        driver = cls.build / 'legacy-destination-checks.swift'
        driver.write_text((destination.ROOT / 'tests/vpn_application_destination_exchange_checks.swift')
            .read_text().replace('VPNApplicationDestinationExchange', 'VPNLegacyApplicationDestinationExchange'))
        cls.legacy_checker = cls.build / 'legacy-destination-checks'
        cls.command(['swiftc', '-D', 'VPN_APPLICATION_DESTINATION_TESTING',
                     '-D', 'VPN_APPLICATION_DESTINATION_ROOT_TESTING',
                     *[str(destination.HELPER / name) for name in (
                         'VPNPeerAuthentication.swift', 'VPNReleaseAuthorization.swift',
                         'VPNLifecycleOwnership.swift', 'VPNStagedApplication.swift',
                         'VPNReplacementExecutor.swift', 'VPNProtectedApplicationSwap.swift',
                         'VPNApplicationDestinationStage.swift')],
                     str(legacy), str(driver), '-o', str(cls.legacy_checker)])

    def test_frozen_legacy_executor_reproduces_root_source_failure(self):
        self.checker = self.legacy_checker
        self.assert_rejected('exchange', 'invalidLayout')
        self.assertEqual(self.identities(), self.initial)

    def test_frozen_legacy_executor_accepts_uniform_user_owned_source(self):
        self.set_owner(self.destination / 'ProxyPilot.app', 501)
        self.checker = self.legacy_checker
        self.test_exchange_and_idempotent_retry()

    def test_sealed_source_capability_required_for_root_owner(self):
        installed = self.destination / 'ProxyPilot.app'
        self.app = installed
        metadata = installed / 'Contents/Info.plist'
        original = plistlib.loads(metadata.read_bytes())
        for capability in (None, True, '1'):
            with self.subTest(capability=capability):
                info = dict(original)
                if capability is not None:
                    info['ProxyPilotVPNRootOwnedUpdateExecutor'] = capability
                metadata.write_bytes(plistlib.dumps(info))
                self.sign(installed, 'kz.documentolog.proxypilot')
                pins = self.pins()
                args = [str(self.staged_checker), 'fixture-source-capability',
                        str(self.destination), pins['arm64'], pins['x86_64'], '1.6.0']
                if capability != '1':
                    args.append('incompatibleExecutor')
                self.command(args)

    def set_owner(self, bundle, owner):
        # Only the generated fixture subtree can be changed, never a supplied path.
        self.assertTrue(bundle.is_relative_to(self.work))
        self.assertFalse(bundle.is_symlink())
        for item in [bundle, *bundle.rglob('*')]:
            os.chown(item, owner, -1, follow_symlinks=False)

    def test_legacy_user_owned_source_exchange_and_retry(self):
        self.set_owner(self.destination / 'ProxyPilot.app', 501)
        self.test_exchange_and_idempotent_retry()
        self.assertEqual((self.destination / 'ProxyPilot.app').stat().st_uid, 0)
        self.assertEqual((self.stage / 'ProxyPilot.app').stat().st_uid, 501)

    def test_unrelated_owner_cannot_exchange_or_resume(self):
        self.set_owner(self.destination / 'ProxyPilot.app', 501)
        super().test_unrelated_owner_cannot_exchange_or_resume()

    def test_mixed_source_owner_rejected_without_exchange(self):
        resource = self.destination / 'ProxyPilot.app/Contents/Resources/data.txt'
        os.chown(resource, 501, -1)
        self.assert_rejected('exchange', 'invalidLayout')
        self.assertEqual(self.identities(), self.initial)

    def test_mixed_retained_owner_rejected_on_resume(self):
        result = self.invoke()
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        os.chown(self.stage / 'ProxyPilot.app/Contents/Resources/data.txt', 501, -1)
        self.assert_rejected('exchange', 'invalidLayout')
        self.assertEqual(self.identities(), self.initial[::-1])

    def test_lock_root_and_layout_guards(self):
        self.assert_rejected('busy', 'busy')
        # Even when run as root, this test binary cannot call the host entry.
        self.assertEqual(self.invoke('production').returncode, 64)
        shutil.rmtree(self.stage)
        self.assert_rejected('exchange', 'unsafeStorage')


if __name__ == '__main__':
    unittest.main()
