"""Execute the production CLI selector with disposable paths, never run a CLI."""
from pathlib import Path
import os
import shutil
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]


@unittest.skipUnless(sys.platform == 'darwin' and shutil.which('swiftc'), 'macOS Swift required')
class CLISelectionTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp = tempfile.TemporaryDirectory(prefix='pp-cli-selection-')
        cls.addClassCleanup(cls.temp.cleanup)
        cls.root = Path(cls.temp.name)
        source = (ROOT / 'app/main.swift').read_text()
        selector = source.split('enum CLI {', 1)[1].split('    static func run(', 1)[0]
        selector = selector.replace('Bundle.main.resourcePath',
                                    'ProcessInfo.processInfo.environment["TEST_RESOURCES"]')
        selector = selector.replace('NSHomeDirectory()',
                                    'ProcessInfo.processInfo.environment["TEST_HOME"]!')
        for path in ('/opt/homebrew/bin/proxypilot', '/usr/local/bin/proxypilot'):
            selector = selector.replace(path, str(cls.root / 'absent' / path.lstrip('/')))
        main = cls.root / 'main.swift'
        main.write_text('import Foundation\nenum CLI {' + selector +
                        '\n}\nprint(CLI.path ?? "unavailable")\n')
        for variant, flags in [('vpn', ['-D', 'VPN_INSTALLER_ENTRY']), ('standard', [])]:
            subprocess.run(['swiftc', *flags, str(main), '-o', str(cls.root / variant)],
                           check=True, capture_output=True, timeout=90)

    def check(self, variant, bundled):
        with tempfile.TemporaryDirectory(dir=self.root) as directory:
            home = Path(directory)
            legacy = home / '.local/bin/proxypilot'
            legacy.parent.mkdir(parents=True)
            legacy.write_text('#!/bin/sh\nexit 99\n'); legacy.chmod(0o755)
            resources = home / 'Resources'
            own = resources / 'bin/proxypilot'
            own.parent.mkdir(parents=True)
            if bundled != 'missing':
                own.write_text('#!/bin/sh\nexit 99\n')
                own.chmod(0o755 if bundled == 'executable' else 0o644)
            env = dict(os.environ, TEST_HOME=str(home), TEST_RESOURCES=str(resources))
            result = subprocess.run([str(self.root / variant)], env=env,
                                    capture_output=True, text=True, check=True, timeout=5)
            expected = str(own) if bundled == 'executable' else (
                'unavailable' if variant == 'vpn' else str(legacy))
            self.assertEqual(result.stdout.strip(), expected)

    def test_vpn_uses_its_own_executable(self): self.check('vpn', 'executable')
    def test_vpn_refuses_missing_cli_instead_of_legacy_fallback(self): self.check('vpn', 'missing')
    def test_vpn_refuses_nonexecutable_cli_instead_of_legacy_fallback(self): self.check('vpn', 'nonexecutable')
    def test_standard_build_retains_existing_fallback(self): self.check('standard', 'missing')
    def test_standard_build_prefers_its_bundle(self): self.check('standard', 'executable')
