"""Exercise the coordinator with protected temp storage and actual inert signed processes.

The unprivileged runtime is test-only; this does not prove launchd/root cleanup.
"""
import hashlib
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]


@unittest.skipUnless(sys.platform == 'darwin' and shutil.which('swiftc'), 'macOS Swift required')
class VPNActivationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if os.geteuid() == 0:
            raise unittest.SkipTest('Never run inert activation tests as root')
        cls.build = tempfile.TemporaryDirectory(prefix='pp-act-build-', dir='/tmp')
        cls.addClassCleanup(cls.build.cleanup)
        cls.work = Path(cls.build.name)
        common = ['VPNPeerAuthentication.swift', 'VPNReleaseAuthorization.swift', 'VPNHelperReadiness.swift']
        for name, source_names, main, flags in [
            ('server', common, 'vpn_readiness_checks.swift', []),
            ('coordinator', common + ['VPNHelperArtifact.swift', 'VPNReleaseStore.swift', 'VPNActivationCoordinator.swift'],
             'vpn_activation_checks.swift', ['-D', 'VPN_HELPER_READINESS_TESTING', '-D', 'VPN_RELEASE_STORE_TESTING']),
        ]:
            sources = [ROOT / 'app/vpn-helper' / source for source in source_names] + [ROOT / 'tests' / main]
            slices = []
            for arch in ('arm64', 'x86_64'):
                output = cls.work / f'{name}-{arch}'
                cls.command(['swiftc', *flags, '-target', f'{arch}-apple-macosx11.0', *map(str, sources), '-o', str(output)])
                slices.append(str(output))
            cls.command(['lipo', '-create', *slices, '-output', str(cls.work / name)])
        # Ensure the coordinator also compiles without either test-only seam.
        sources = [ROOT / 'app/vpn-helper' / source for source in
                   common + ['VPNHelperArtifact.swift', 'VPNReleaseStore.swift', 'VPNActivationCoordinator.swift']]
        for arch in ('arm64', 'x86_64'):
            cls.command(['swiftc', '-emit-library', '-target', f'{arch}-apple-macosx11.0', *map(str, sources),
                         '-o', str(cls.work / f'production-{arch}.dylib')])
        cls.command(['codesign', '--force', '--sign', '-', '--options', 'runtime,hard,kill', str(cls.work / 'coordinator')])
        cls.helpers, cls.pins = {}, {}
        for version in (1, 2):
            path = cls.work / f'v{version}'
            shutil.copyfile(cls.work / 'server', path)
            path.chmod(0o700)
            cls.command(['codesign', '--force', '--sign', '-', '--identifier', 'kz.documentolog.proxypilot.vpn-helper',
                         '--options', 'runtime,hard,kill' + (',restrict' if version == 2 else ''), str(path)])
            cls.helpers[version] = path
            cls.pins[version] = {}
            for arch in ('arm64', 'x86_64'):
                result = cls.command(['codesign', '-d', '--verbose=4', '--arch', arch, str(path)])
                cls.pins[version][arch] = re.search(r'^CDHash=([a-f0-9]{40})$', result.stderr, re.M).group(1)

    @staticmethod
    def command(args):
        result = subprocess.run(args, capture_output=True, text=True, timeout=90)
        if result.returncode:
            raise AssertionError(result.stdout + result.stderr)
        return result

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='pp-act-', dir='/tmp')
        self.addCleanup(self.temp.cleanup)
        self.base = Path(self.temp.name)
        self.directory = self.base / 'store'
        self.directory.mkdir(mode=0o700)
        self.assertEqual(self.run_coordinator('seed', version=1, sequence=10).returncode, 0)

    def run_coordinator(self, action='update', version=2, sequence=11, expected=10, mode='valid', tamper=False):
        artifact = self.helpers[version].read_bytes()
        fields = {'format': 1, 'product': 'kz.documentolog.proxypilot', 'sequence': sequence, 'version': '1.6.0', 'protocol': 1,
                  'app-arm64': '11' * 20, 'app-x86_64': '22' * 20,
                  'helper-arm64': self.pins[version]['arm64'], 'helper-x86_64': self.pins[version]['x86_64'],
                  'helper-sha256': hashlib.sha256(artifact).hexdigest(), 'helper-bytes': len(artifact)}
        manifest, candidate = self.base / 'manifest', self.base / 'candidate'
        manifest.write_text(''.join(f'{key}={value}\n' for key, value in fields.items()))
        candidate.write_bytes(artifact + b'corrupt' if tamper else artifact)
        return subprocess.run([str(self.work / 'coordinator'), action, str(self.directory), str(manifest), str(candidate),
                               str(expected), mode], capture_output=True, text=True, timeout=15)

    def selected(self):
        result = self.run_coordinator('load')
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        return int(result.stdout.strip().split(':')[1])

    def test_update_orders_stop_commit_start_and_authenticated_ready(self):
        result = self.run_coordinator()
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(result.stdout.splitlines(), ['stop:1', 'start:11', 'ready:11'])
        self.assertEqual(self.selected(), 11)

    def test_bad_signature_never_stops_old_service(self):
        result = self.run_coordinator(mode='bad-signature')
        self.assertEqual(result.returncode, 77)
        self.assertNotIn('stop:', result.stdout)
        self.assertEqual(self.selected(), 10)

    def test_corrupt_candidate_never_stops_old_service(self):
        result = self.run_coordinator(tamper=True)
        self.assertEqual(result.returncode, 77)
        self.assertNotIn('stop:', result.stdout)
        self.assertEqual(self.selected(), 10)

    def test_stale_request_never_stops_old_service(self):
        result = self.run_coordinator(expected=9)
        self.assertIn('staleRevision', result.stdout)
        self.assertNotIn('stop:', result.stdout)
        self.assertEqual(self.selected(), 10)

    def test_failed_stop_prevents_commit_and_start(self):
        result = self.run_coordinator(mode='stop-fails')
        self.assertIn('failure:stop cleanup:false', result.stdout)
        self.assertNotIn('start:', result.stdout)
        self.assertEqual(self.selected(), 10)

    def test_staged_file_rechecked_after_stop(self):
        result = self.run_coordinator(mode='tamper-after-stop')
        self.assertIn('failure:commit cleanup:true', result.stdout)
        self.assertNotIn('start:', result.stdout)
        self.assertEqual(self.selected(), 10)

    def test_stale_preparation_cannot_replace_concurrent_selection(self):
        result = self.run_coordinator(mode='stale-after-stop')
        self.assertIn('failure:commit cleanup:true', result.stdout)
        self.assertNotIn('start:', result.stdout)
        self.assertEqual(self.selected(), 12)

    def test_failed_start_cleans_up_and_does_not_downgrade(self):
        result = self.run_coordinator(mode='start-fails')
        self.assertIn('failure:start cleanup:true', result.stdout)
        self.assertEqual(result.stdout.count('start:'), 1)
        self.assertEqual(self.selected(), 11)
        retry = self.run_coordinator('recover')
        self.assertEqual(retry.stdout.splitlines(), ['stop:1', 'start:11', 'ready:11'])

    def test_wrong_readiness_cleans_up_no_false_success(self):
        result = self.run_coordinator(mode='readiness-fails')
        self.assertIn('failure:readiness cleanup:true', result.stdout)
        self.assertNotIn('ready:', result.stdout)
        self.assertEqual(self.selected(), 11)

    def test_cleanup_failure_is_explicit(self):
        result = self.run_coordinator(mode='cleanup-fails')
        self.assertIn('failure:readiness cleanup:false', result.stdout)
        self.assertNotIn('ready:', result.stdout)
        self.assertEqual(self.selected(), 11)

    def test_changed_selection_during_start_cannot_report_ready(self):
        result = self.run_coordinator(mode='selection-race')
        self.assertIn('failure:selection cleanup:true', result.stdout)
        self.assertNotIn('ready:', result.stdout)
        self.assertEqual(self.selected(), 12)

    def test_reentrant_attempt_is_rejected(self):
        result = self.run_coordinator(mode='reentrant')
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(result.stdout.splitlines(), ['stop:1', 'busy', 'start:11', 'ready:11'])

    def test_crash_before_commit_recovers_only_previous_selection(self):
        result = self.run_coordinator(mode='crash-before-commit')
        self.assertEqual(result.returncode, 86)
        self.assertEqual(self.selected(), 10)
        retry = self.run_coordinator('recover')
        self.assertEqual(retry.stdout.splitlines(), ['stop:1', 'start:10', 'ready:10'])

    def test_crash_after_commit_recovers_only_new_selection(self):
        for mode in ('crash-after-commit', 'crash-selector'):
            with self.subTest(mode=mode):
                expected = self.selected()
                result = self.run_coordinator(mode=mode, expected=expected, sequence=expected + 1)
                self.assertEqual(result.returncode, 86, result.stdout + result.stderr)
                self.assertEqual(self.selected(), expected + 1)
                retry = self.run_coordinator('recover')
                self.assertIn(f'ready:{expected + 1}', retry.stdout)

    def test_recovery_corrupt_selected_state_stops_and_fails_closed(self):
        (self.directory / 'release.json').write_bytes(b'corrupted')
        result = self.run_coordinator('recover')
        self.assertIn('failure:selection cleanup:true', result.stdout)
        self.assertNotIn('start:', result.stdout)

    def test_older_release_remains_rejected_after_failed_start(self):
        self.assertEqual(self.run_coordinator(mode='start-fails').returncode, 77)
        result = self.run_coordinator(version=1, sequence=10, expected=11)
        self.assertIn('rollback', result.stdout)
        self.assertNotIn('stop:', result.stdout)
        self.assertEqual(self.selected(), 11)

    def test_identical_update_makes_one_attempt_without_changing_selection(self):
        result = self.run_coordinator(version=1, sequence=10)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(result.stdout.splitlines(), ['stop:1', 'start:10', 'ready:10'])
        self.assertEqual(self.selected(), 10)

    def test_recovery_does_not_fall_back_when_selected_binary_is_missing(self):
        self.assertEqual(self.run_coordinator().returncode, 0)
        selected = 'helper-' + hashlib.sha256(self.helpers[2].read_bytes()).hexdigest()
        (self.directory / selected).unlink()
        result = self.run_coordinator('recover')
        self.assertIn('failure:selection cleanup:true', result.stdout)
        self.assertNotIn('start:', result.stdout)
