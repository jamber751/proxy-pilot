"""Production popover retry/cancellation logic with inert window boundaries."""
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]


@unittest.skipUnless(sys.platform == 'darwin' and shutil.which('swiftc'), 'macOS Swift required')
class PopoverStartupTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp = tempfile.TemporaryDirectory(prefix='proxypilot-popover-startup-')
        cls.addClassCleanup(cls.temp.cleanup)
        source = (ROOT / 'app/main.swift').read_text()
        methods = '    private func hideWindow() {' + source.split('    private func hideWindow() {', 1)[1].split('    func applicationShouldHandleReopen', 1)[0]
        if methods.count('NSApp.activate(ignoringOtherApps: true)') != 1: raise AssertionError('Popover activation boundary changed')
        methods = methods.replace('NSApp.activate(ignoringOtherApps: true)', 'activations += 1')
        fixture = (ROOT / 'tests/popover_startup_checks.swift').read_text().replace('// PRODUCTION_METHODS', methods)
        work = Path(cls.temp.name); script = work / 'checks.swift'; script.write_text(fixture)
        slices = []
        for arch in ('arm64', 'x86_64'):
            binary = work / arch
            result = subprocess.run(['swiftc', '-parse-as-library', '-target', f'{arch}-apple-macosx11.0', str(script), '-o', str(binary)], capture_output=True, text=True, timeout=60)
            if result.returncode: raise AssertionError(result.stderr)
            slices.append(str(binary))
        cls.binary = work / 'checks'
        subprocess.run(['lipo', '-create', *slices, '-output', str(cls.binary)], check=True, capture_output=True)

    def check(self, mode):
        result = subprocess.run([str(self.binary), mode], capture_output=True, text=True, timeout=5)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_waits_for_nonzero_anchor_then_opens_once(self): self.check('ready')
    def test_close_cancels_late_presentation(self): self.check('cancel')
    def test_new_request_supersedes_pending_request(self): self.check('replace')
    def test_retry_is_bounded(self): self.check('timeout')
