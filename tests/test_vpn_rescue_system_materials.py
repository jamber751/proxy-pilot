"""Fast signed-material gate for the real-system fixture; no executable artifacts or root."""
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
HELPER = ROOT / 'app/vpn-helper'


@unittest.skipUnless(sys.platform == 'darwin' and shutil.which('swiftc') and os.geteuid() != 0,
                     'ordinary macOS user required')
class VPNRescueSystemMaterialTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp = tempfile.TemporaryDirectory(prefix='pp-system-material-build-')
        cls.addClassCleanup(cls.temp.cleanup)
        base = Path(cls.temp.name)
        cls.seed, cls.checker = base / 'seed', base / 'checker'
        names = ('VPNPeerAuthentication', 'VPNReleaseAuthorization', 'VPNHelperArtifact', 'VPNReleaseStore',
                 'VPNLifecycleOwnership', 'VPNActivationBudget', 'VPNDirectoryProvisioner',
                 'VPNEndpointDirectory', 'VPNHelperProtocol')
        for output, sources in ((cls.seed, [*(HELPER / (name + '.swift') for name in names),
                                           ROOT / 'tests/vpn_rescue_system_seed.swift']),
                                (cls.checker, [HELPER / 'VPNPeerAuthentication.swift',
                                               HELPER / 'VPNReleaseAuthorization.swift',
                                               ROOT / 'tests/vpn_rescue_system_materials_checks.swift'])):
            built = subprocess.run(['swiftc', '-parse-as-library', *map(str, sources), '-o', str(output)],
                                   capture_output=True, text=True, timeout=120)
            if built.returncode: raise AssertionError(built.stdout + built.stderr)

    def check(self, operation, source=137, successor=False, partial_successor=False):
        with tempfile.TemporaryDirectory(prefix='pp-system-material-case-') as folder:
            base = Path(folder)
            (base / 'CandidateStage/Payload').mkdir(parents=True)
            inputs = {'sourceSequence': str(source)}
            for index, name in enumerate(('helperB', 'helperC', 'engineB'), start=1):
                artifact = base / name
                artifact.write_bytes(bytes([index]) * 128)
                inputs[name] = str(artifact)
            # These are bounded parser fixtures, never code-signing or artifact authority.
            for index, name in enumerate(('appA', 'appB', 'appC', 'helperB', 'helperC', 'engineB'), start=1):
                for arch in ('arm64', 'x86_64'): inputs[name + '-' + arch] = f'{index:040x}'
            if successor:
                (base / 'SuccessorStage/Payload').mkdir(parents=True)
                for arch in (('arm64',) if partial_successor else ('arm64', 'x86_64')):
                    inputs['appD-' + arch] = 'd' * 40
            (base / 'input.json').write_text(json.dumps(inputs))
            if partial_successor:
                result = subprocess.run([str(self.seed), 'materials', str(base)], capture_output=True, timeout=15)
                self.assertEqual(result.returncode, 65)
                self.assertFalse((base / 'CandidateStage/Payload/vpn-release.manifest').exists())
                self.assertFalse((base / 'SuccessorStage/Payload/vpn-release.manifest').exists())
                return
            for command in ((self.seed, 'materials', base), (self.checker, operation, base)):
                result = subprocess.run(list(map(str, command)), capture_output=True, text=True, timeout=15)
                self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            if not successor: self.assertFalse((base / 'SuccessorStage').exists())

    def test_both_transitions_preserve_engine_and_verify_in_production(self): self.check('valid')
    def test_foreign_source_fixture_is_separately_valid(self): self.check('valid', source=138)
    def test_even_resigned_engine_removal_is_rejected(self): self.check('remove-engine')
    def test_even_resigned_crypto_downgrade_is_rejected(self): self.check('rollback-crypto')
    def test_resigned_wrong_source_transition_is_rejected(self): self.check('wrong-first-binding')
    def test_partial_successor_pins_fail_before_any_manifest_write(self):
        self.check('successor-valid', successor=True, partial_successor=True)
    def test_successor_preserves_exact_component_bindings(self): self.check('successor-valid', successor=True)
    def test_successor_rejects_previous_helper_bytes(self): self.check('successor-wrong-helper-bytes', successor=True)
    def test_successor_resigned_engine_removal_is_rejected(self): self.check('successor-remove-engine', successor=True)
    def test_successor_resigned_crypto_downgrade_is_rejected(self): self.check('successor-rollback-crypto', successor=True)
    def test_successor_resigned_wrong_c_binding_is_rejected(self): self.check('successor-wrong-binding', successor=True)



if __name__ == '__main__': unittest.main()
