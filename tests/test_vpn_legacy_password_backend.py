"""Injected backend only: NEVER invokes a real Security/Keychain/UI API."""
from pathlib import Path
import os
import platform
import shutil
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
SOURCES = ['VPNConfiguration.swift', 'VPNProfileImporter.swift', 'VPNStore.swift',
           'VPNPasswordWorkerWire.swift', 'VPNPasswordWorkerIdentity.swift', 'VPNPasswordWorker.swift',
           'VPNLegacyPasswordBackend.swift', 'vpn-helper/VPNPeerAuthentication.swift',
           'vpn-helper/VPNApplicationSpec.swift', 'vpn-helper/VPNTunnelStateStore.swift',
           'vpn-helper/OpenVPNManagementEvent.swift', 'vpn-helper/OpenVPNStateEvidence.swift',
           'vpn-helper/OpenVPNTransientCredential.swift']

@unittest.skipUnless(sys.platform == 'darwin' and shutil.which('swiftc'), 'macOS Swift required')
class VPNLegacyPasswordBackendTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.folder = tempfile.TemporaryDirectory(prefix='pp-legacy-injected-')
        cls.addClassCleanup(cls.folder.cleanup)
        cls.binary = Path(cls.folder.name) / 'checks'
        arch = 'arm64' if platform.machine() == 'arm64' else 'x86_64'
        built = subprocess.run(['/usr/bin/swiftc', '-parse-as-library', '-D', 'VPN_LEGACY_PASSWORD_BACKEND_TESTING',
            '-target', arch + '-apple-macosx11.0', *[str(ROOT / 'app' / name) for name in SOURCES],
            str(ROOT / 'tests/vpn_legacy_password_backend_checks.swift'), '-o', str(cls.binary)],
            capture_output=True, text=True, timeout=120)
        if built.returncode: raise AssertionError(built.stderr)

    def test_injected_operations(self):
        for case in ('roundtrip', 'before-api', 'uncertain-errors', 'capture-failure', 'wrong-owner',
                     'original-unavailable', 'not-found', 'delete-no-ack', 'malformed-envelope',
                     'wrong-account', 'envelope'):
            with self.subTest(case=case):
                result = subprocess.run([str(self.binary), case], capture_output=True, text=True, timeout=10)
                self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                self.assertIn('legacy injected checks passed', result.stdout)

    def test_delete_query_binds_generic_password_class_and_exact_verified_reference(self):
        source = (ROOT / 'app/VPNLegacyPasswordBackend.swift').read_text()
        body = source.split('    func delete(_ item: VPNLegacyPasswordItem) -> OSStatus {', 1)[1].split('    private func capture(', 1)[0]
        self.assertIn('observed == item.origin', body)
        self.assertIn('(try? identity(item.origin.path)) == item.origin', body)
        self.assertIn('SecItemDelete([kSecClass as String: kSecClassGenericPassword,', body)
        self.assertIn('kSecMatchItemList as String: [reference]] as CFDictionary)', body)
        self.assertEqual(body.count('SecItemDelete('), 1)
        for forbidden in ('SecKeychainCopyDefault', 'kSecMatchSearchList', 'kSecMatchLimit',
                          'kSecAttrService', 'kSecAttrAccount', 'SecItemCopyMatching'):
            self.assertNotIn(forbidden, body)

    def test_real_factory_stays_unwired(self):
        worker = (ROOT / 'app/VPNPasswordWorker.swift').read_text()
        self.assertIn('VPNPasswordWorkerUnavailableBackend()', worker)
        self.assertNotIn('VPNLegacyPasswordBackend', worker)
        source = (ROOT / 'app/VPNLegacyPasswordBackend.swift').read_text()
        for forbidden in ('SecKeychainSetDefault', 'SecKeychainSetSearchList', 'SecKeychainUnlock',
                          'SecKeychainCreate', 'SecItemUpdate', 'SecAccessCreate', 'kSecAttrAccessGroup'):
            self.assertNotIn(forbidden, source)
        self.assertIn('kSecMatchItemList as String: [persistentReference]', source)
        self.assertIn('kSecMatchSearchList as String: [keychain]', source)
        self.assertIn('SecKeychainItemCopyKeychain', source)
        self.assertIn('SecKeychainSetUserInteractionAllowed(false)', source)

if __name__ == '__main__': unittest.main()
