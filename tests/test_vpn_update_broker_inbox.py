"""Filesystem contract for the root-private broker inbox.

Only disposable current-user directories are used. They stand in for the
production root-owned 0700 parent; no system path, service, app or key is used.
"""
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
FIXTURE = ROOT / 'tests/vpn_update_broker_inbox_checks.swift'
INBOX = ROOT / 'app/vpn-helper/VPNUpdateBrokerInbox.swift'


class VPNUpdateBrokerInboxContractSourceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.source = FIXTURE.read_text()

    def test_contract_accepts_descriptors_not_paths(self):
        start = self.source.index('protocol VPNUpdateBrokerInboxDriving')
        end = self.source.index('\n}', start)
        surface = self.source[start:end]
        self.assertIn('trustedParent: Int32', surface)
        self.assertIn('sourceDirectory: Int32', surface)
        for forbidden in ('URL', 'path:', 'destination:', 'name:', 'argv', 'shell'):
            self.assertNotIn(forbidden, surface)

    def test_contract_has_exact_fixed_layout(self):
        for name in ('ProxyPilot.app', 'vpn-helper', 'vpn-engine',
                     'vpn-release.manifest', 'vpn-release.sig',
                     'vpn-previous-release.manifest', 'vpn-previous-release.sig',
                     'vpn-update-transition', 'vpn-update-transition.sig'):
            self.assertIn(f'"{name}"', self.source)
        for rejection in ('symlink', 'hardlink', 'special', 'unexpectedSibling',
                          'missingEntry'):
            self.assertIn(rejection, self.source)

    def test_contract_requires_bounds_and_source_revalidation(self):
        for requirement in ('maximumEntries', 'maximumBytes', 'maximumDepth',
                            'sourceChanged', 'mutateSource', 'publishedCount',
                            'containerMode', 'allNodesOwnedByEffectiveUser',
                            'anyGroupOrWorldWritableNode'):
            self.assertIn(requirement, self.source)

    def test_contract_requires_durable_crash_boundaries(self):
        for point in ('afterCopy:vpn-helper', 'beforePublish', 'afterPublish'):
            self.assertIn(f'"{point}"', self.source)
        for requirement in ('syncedNames', 'parentSynced', 'alreadyPublished'):
            self.assertIn(requirement, self.source)

    def test_contract_requires_content_identity_and_conflict_refusal(self):
        self.assertIn('same.identity == repeated.identity', self.source)
        self.assertIn('.rejectedConflict', self.source)
        self.assertIn('corruptPublished', self.source)
        self.assertIn('publishedSnapshot', self.source)


@unittest.skipUnless(sys.platform == 'darwin' and shutil.which('swiftc'),
                     'macOS Swift required')
class VPNUpdateBrokerInboxProductionBindingTests(unittest.TestCase):
    def test_production_inbox_satisfies_contract(self):
        self.assertTrue(
            INBOX.is_file(),
            'app/vpn-helper/VPNUpdateBrokerInbox.swift is required',
        )
        with tempfile.TemporaryDirectory(prefix='pp-update-inbox-build-') as temporary:
            binary = Path(temporary) / 'inbox-checks'
            compiled = subprocess.run(
                ['swiftc', '-D', 'VPN_UPDATE_BROKER_INBOX_TESTING',
                 '-target', 'arm64-apple-macosx11.0',
                 '-module-cache-path', str(Path(temporary) / 'ModuleCache'),
                 str(INBOX), str(FIXTURE), '-o', str(binary)],
                capture_output=True, text=True, timeout=120,
            )
            self.assertEqual(compiled.returncode, 0, compiled.stdout + compiled.stderr)
            for group in ('layout', 'bounds', 'mutable', 'durability', 'retry'):
                with self.subTest(group=group):
                    result = subprocess.run([str(binary), group], capture_output=True,
                                            text=True, timeout=60)
                    self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                    self.assertEqual(result.stdout.strip(), f'{group} checks passed')


if __name__ == '__main__':
    unittest.main()
