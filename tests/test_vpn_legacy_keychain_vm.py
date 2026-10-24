"""Opt-in disposable-VM legacy ACL experiment; NEVER runs Keychain APIs on host.

Compile only: python3 tests/test_vpn_legacy_keychain_vm.py --compile-only
Execute only in disposable ordinary-user macOS CI with GITHUB_ACTIONS=true and
PROXYPILOT_VM_KEYCHAIN_TESTS=1. No default/search-list setters or login access.
Window metadata is sampled evidence, not proof that a GUI prompt never appeared.
"""
import json
import os
from pathlib import Path
import platform
import re
import shutil
import subprocess
import sys
import tempfile
import threading
import unittest

SOURCE = Path(__file__).with_name('vpn_legacy_keychain_vm_checks.swift')
ENABLED = (sys.platform == 'darwin' and os.getuid() == os.geteuid() >= 500
           and os.environ.get('GITHUB_ACTIONS') == 'true'
           and os.environ.get('PROXYPILOT_VM_KEYCHAIN_TESTS') == '1')


def compile_tools(folder):
    arch = 'arm64' if platform.machine() == 'arm64' else 'x86_64'
    tools = []
    for version in (1, 2):
        tool = folder / f'v{version}'
        flags = ['-D', 'LEGACY_KEYCHAIN_V2'] if version == 2 else []
        result = subprocess.run(['/usr/bin/swiftc', '-parse-as-library', '-target',
                                 arch + '-apple-macosx11.0', *flags, str(SOURCE), '-o', str(tool)],
                                capture_output=True, text=True, timeout=120)
        if result.returncode:
            raise AssertionError(result.stderr)
        subprocess.run(['/usr/bin/codesign', '--force', '--sign', '-', '--options', 'runtime,hard,kill', '--identifier',
                        'kz.documentolog.proxypilot.synthetic-keychain-vm', str(tool)],
                       check=True, capture_output=True, timeout=20)
        tools.append(tool)
    requirements = []
    for tool in tools:
        displayed = subprocess.run(['/usr/bin/codesign', '-d', '-r-', str(tool)],
                                   capture_output=True, text=True, check=True)
        requirements.append(displayed.stdout + displayed.stderr)
    hashes = [re.findall(r'cdhash H"([0-9a-f]+)"', value) for value in requirements]
    if not all(hashes) or hashes[0] == hashes[1]:
        raise AssertionError('Experiment needs different actual ad-hoc code identities')
    return tools


@unittest.skipUnless(ENABLED, 'Explicit disposable macOS CI ordinary-user gate required')
class VPNLegacyKeychainVMTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        # resolve /tmp alias, require the Swift-side exact /private/tmp parent.
        cls.temp = tempfile.TemporaryDirectory(prefix='pp-legacy-keychain-vm-', dir='/private/tmp')
        cls.addClassCleanup(cls.temp.cleanup)
        cls.base = Path(cls.temp.name).resolve()
        cls.base.chmod(0o700)
        cls.v1, cls.v2 = compile_tools(cls.base)

    def run_tool(self, tool, action):
        # V1/V2 both execute at the SAME path and identifier. Observer never
        # calls Security APIs and uses the immutable source binary separately.
        if action != 'observe':
            active = self.base / 'client'
            temporary = self.base / 'client-new'
            shutil.copy2(tool, temporary)
            temporary.replace(active)
            tool = active
        result = subprocess.run([str(tool), action, str(self.base)], capture_output=True,
                                text=True, timeout=12)
        if result.returncode != 0:
            # Preserve only the fixed guard schema, never raw stderr/argv or
            # arbitrary child output that could grow secret-bearing later.
            diagnostic = 'No fixed guard diagnostic'
            try:
                refused = json.loads(result.stdout)
                allowed = {'ciMatch', 'vmFlagMatch', 'uidMatch', 'ordinaryUID', 'argumentCountMatch',
                           'canonicalMatch', 'prefixMatch', 'parentMatch', 'present', 'directoryMatch',
                           'ownerMatch', 'modeMatch', 'status'}
                if (isinstance(refused, dict)
                        and set(refused) == {'guardStage', 'checks'}
                        and refused.get('guardStage') in {'execution', 'privateDirectory', 'initialInteractionFlag'}
                        and isinstance(refused.get('checks'), dict)
                        and set(refused['checks']) <= allowed
                        and all(type(value) in (bool, int) for value in refused['checks'].values())):
                    diagnostic = json.dumps(refused, sort_keys=True)
            except (ValueError, TypeError):
                pass
            self.fail(f'VM experiment child exit={result.returncode}; {diagnostic}')
        value = json.loads(result.stdout)
        if action != 'observe':
            self.assertTrue(value.get('interactionRestored'), value)
            self.assertNotIn('setupFailed', value)
            if action != 'metadata':
                self.assertEqual(value['openStatus'], 0, value)
        return value

    def test_exact_adhoc_acl_and_locked_fallback(self):
        samples = []
        stop = threading.Event()

        def observe():
            while not stop.is_set():
                try:
                    samples.append(self.run_tool(self.v1, 'observe'))
                except Exception:
                    samples.append({'windowMetadata': False})
                stop.wait(0.1)

        before = self.run_tool(self.v1, 'metadata')['preferences']
        observer = threading.Thread(target=observe, daemon=True)
        observer.start()
        try:
            created = self.run_tool(self.v1, 'create')
            self.assertEqual(created['addStatus'], 0, created)
            self.assertEqual(created['status'], 0, created)
            self.assertTrue(created['secretMatches'])
            self.assertEqual(before, self.run_tool(self.v1, 'metadata')['preferences'],
                             'Private create altered default/search-list; stopping without preference setters')
            denied = self.run_tool(self.v2, 'read')
            self.assertNotEqual(denied['status'], 0, denied)
            self.assertFalse(denied['secretMatches'])
            original = self.run_tool(self.v1, 'read')
            self.assertEqual(original['status'], 0, original)
            self.assertTrue(original['secretMatches'])
            locked = self.run_tool(self.v1, 'locked-read')
            self.assertEqual(locked['lockStatus'], 0, locked)
            self.assertNotEqual(locked['status'], 0, locked)
            self.assertFalse(locked['secretMatches'])
        finally:
            stop.set(); observer.join(timeout=15)
            # Exact private keychain only. No broad item or keychain cleanup.
            if any((self.base / name).exists() for name in ('experiment.keychain', 'experiment.keychain-db')):
                deleted = self.run_tool(self.v1, 'delete')
                self.assertEqual(deleted['status'], 0, deleted)
            after = self.run_tool(self.v1, 'metadata')['preferences']
            self.assertEqual(before, after, 'Default/search-list metadata changed; no compensating mutation attempted')
        visible = [sample for sample in samples if sample.get('windowMetadata')]
        self.assertTrue(all(sample.get('securityAgentWindows', 0) == 0 for sample in visible),
                        'SecurityAgent window observed; silent legacy read not accepted')
        print(json.dumps({'boundedLegacyExperiment': True,
                          'windowSamples': len(visible),
                          'windowMetadataAvailable': bool(visible),
                          'consoleSessionObserved': any(s.get('consoleSession') for s in visible),
                          'guiAbsenceProven': False}, sort_keys=True))


if __name__ == '__main__':
    if sys.argv[1:] == ['--compile-only']:
        with tempfile.TemporaryDirectory(prefix='pp-keychain-compile-only-') as directory:
            compile_tools(Path(directory))
        print('Two distinct ad-hoc identities compiled; no executable/Keychain API run')
    else:
        unittest.main()
