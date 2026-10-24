"""Offscreen native SwiftUI resource scrolling over isolated preview data."""
import ast
from pathlib import Path
import platform
import shutil
import subprocess
import sys
import tempfile
import unittest
ROOT = Path(__file__).resolve().parents[1]

@unittest.skipUnless(sys.platform == 'darwin' and shutil.which('swiftc'), 'macOS Swift required')
class VPNResourceListTests(unittest.TestCase):
    def test_short_long_and_editor_navigation_runtime(self):
        layout = ast.parse((ROOT / 'tests/test_vpn_ui_layout.py').read_text())
        stubs = [ast.literal_eval(node.value) for node in ast.walk(layout)
                 if isinstance(node, ast.Assign) and any(isinstance(t, ast.Name) and t.id == 'harness' for t in node.targets)]
        self.assertEqual(len(stubs), 1)
        panel = (ROOT / 'app/VPNPanel.swift').read_text().split('\n/// Keeps the proxy home untouched.', 1)[0]
        for identifier in ('vpnResourceList', 'vpnReplaceProfile', 'vpnAddResource', 'vpnSettingsDone', 'vpnResourceCount'):
            marker = '.accessibilityIdentifier("' + identifier + '")'
            self.assertEqual(panel.count(marker), 1)
            panel = panel.replace(marker, marker + '''.background(GeometryReader { geometry in
                Color.clear.preference(key: VPNScrollHitBounds.self,
                    value: ["''' + identifier + '''": geometry.frame(in: .named("vpnPopover"))])
            })''')
        address = 'Text(resource.address).font(.system(size: 11, design: .monospaced))'
        self.assertEqual(panel.count(address), 1)
        panel = panel.replace(address, address + '''.background(GeometryReader { geometry in
            Color.clear.preference(key: VPNAddressHeights.self, value: [resource.id: geometry.size.height])
        })''')
        checks = (ROOT / 'tests/vpn_resource_list_checks.swift').read_text()
        with tempfile.TemporaryDirectory(prefix='pp-resource-list-') as folder:
            folder = Path(folder); main = folder / 'main.swift'; binary = folder / 'checks'
            main.write_text(stubs[0] + panel + checks)
            sources = [ROOT / 'app' / name for name in ('Controls.swift', 'VPNConfiguration.swift',
                'VPNProfileImporter.swift', 'VPNStore.swift', 'VPNModel.swift')]
            arch = 'arm64' if platform.machine() == 'arm64' else 'x86_64'
            built = subprocess.run(['swiftc', '-target', arch + '-apple-macosx11.0',
                *map(str, sources), str(main), '-o', str(binary)], capture_output=True, text=True, timeout=120)
            self.assertEqual(built.returncode, 0, built.stdout + built.stderr)
            result = subprocess.run([str(binary)], capture_output=True, text=True, timeout=45)
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assertNotIn('Publishing changes from within view updates', result.stderr)
            self.assertNotIn('Modifying state during view update', result.stderr)
            for marker in ('short1 passed', 'short3 passed', 'rows18 passed', 'rows100 passed', 'wrapped-address passed'):
                self.assertIn(marker, result.stdout)
            print(result.stdout.strip())

if __name__ == '__main__': unittest.main()
