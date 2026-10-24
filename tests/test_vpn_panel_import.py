"""Real NSItemProvider delivery to production adapter; synthetic profiles/temp store only."""
import os
from pathlib import Path
import platform
import shutil
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]

@unittest.skipUnless(sys.platform == 'darwin' and shutil.which('swiftc'), 'macOS Swift required')
class VPNPanelImportTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp = tempfile.TemporaryDirectory(prefix='pp-panel-import-build-')
        cls.addClassCleanup(cls.temp.cleanup)
        folder = Path(cls.temp.name)
        adapter = folder / 'VPNPanelModel.swift'
        adapter.write_text((ROOT / 'app/VPNPanel.swift').read_text().split('\nstruct VPNPanelView:', 1)[0])
        sources = [ROOT / name for name in ('app/VPNConfiguration.swift', 'app/VPNProfileImporter.swift',
            'app/VPNStore.swift', 'app/VPNModel.swift', 'app/VPNPasswordPersistenceCoordinator.swift', 'app/VPNLiveController.swift',
            'app/vpn-helper/VPNHelperProtocol.swift', 'app/vpn-helper/VPNApplicationSpec.swift',
            'app/vpn-helper/VPNTunnelStateStore.swift')]
        cls.binary = folder / 'checks'
        arch = 'arm64' if platform.machine() == 'arm64' else 'x86_64'
        built = subprocess.run(['swiftc', '-D', 'VPN_PANEL_TESTING', '-D', 'VPN_LIVE_CONTROLLER_TESTING',
            '-target', arch + '-apple-macosx11.0', *map(str, sources), str(adapter),
            str(ROOT / 'tests/vpn_panel_import_checks.swift'), '-o', str(cls.binary)],
            capture_output=True, text=True, timeout=120)
        if built.returncode: raise AssertionError(built.stdout + built.stderr)

    def run_case(self, case):
        with tempfile.TemporaryDirectory(prefix='pp-panel-import-') as folder:
            os.chmod(folder, 0o700)
            result = subprocess.run([str(self.binary), case, folder], capture_output=True, text=True, timeout=12)
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assertIn('profile drop flow passed', result.stdout)

    def test_replacement_preserves_resources_and_commits_new_file(self): self.run_case('replacement')
    def test_wrong_extension_preserves_previous_profile(self): self.run_case('wrong-extension')
    def test_empty_file_preserves_previous_profile(self): self.run_case('empty')
    def test_malformed_file_preserves_previous_profile(self): self.run_case('malformed')
    def test_symlink_preserves_previous_profile(self): self.run_case('symlink')
    def test_multiple_files_are_refused(self): self.run_case('multiple')
    def test_non_file_provider_is_refused(self): self.run_case('not-a-file')
    def test_delayed_delivery_cannot_replace_profile_during_an_operation(self): self.run_case('delayed-delivery')

    def test_both_drop_views_use_same_handler_and_hover_copy_source_contract(self):
        # Actual drag-hover rendering remains a native UI acceptance requirement.
        panel = (ROOT / 'app/VPNPanel.swift').read_text()
        initial = panel.split('private var importScreen:', 1)[1].split('private var settings:', 1)[0]
        replacement = panel.split('private var profileCard:', 1)[1].split('private var authenticationSummary:', 1)[0]
        for view in (initial, replacement):
            self.assertIn('.onDrop(of: ["public.file-url"], isTargeted: $dropTarget, perform: panel.acceptDrop)', view)
            self.assertIn('dropTarget ? "Отпустите файл здесь"', view)
        self.assertIn('panel.configuration.profile?.name', replacement)

if __name__ == '__main__': unittest.main()
