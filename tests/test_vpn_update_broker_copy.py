"""Bounded cross-filesystem inbox copy and actual process-crash recovery."""
import os
from pathlib import Path
import platform
import shutil
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]


@unittest.skipUnless(sys.platform == 'darwin' and shutil.which('swiftc'), 'macOS required')
class VPNUpdateBrokerCopyTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.build = tempfile.TemporaryDirectory(prefix='pp-inbox-copy-build-')
        cls.addClassCleanup(cls.build.cleanup)
        cls.binary = Path(cls.build.name) / 'checks'
        arch = 'arm64' if platform.machine() == 'arm64' else 'x86_64'
        result = subprocess.run(['swiftc', '-D', 'VPN_UPDATE_BROKER_INBOX_COPY_TESTING',
                                 '-target', arch + '-apple-macosx11.0',
                                 str(ROOT / 'app/vpn-helper/VPNUpdateBrokerInbox.swift'),
                                 str(ROOT / 'tests/vpn_update_broker_copy_checks.swift'),
                                 '-o', str(cls.binary)], capture_output=True, text=True, timeout=120)
        if result.returncode: raise AssertionError(result.stderr)

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='pp-inbox-copy-')
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.source = self.root / 'source'
        self.parent = self.root / 'private'
        self.source.mkdir(mode=0o700); self.parent.mkdir(mode=0o700)
        resources = self.source / 'ProxyPilot.app/Contents/Resources'
        resources.mkdir(parents=True)
        (resources / 'large').write_bytes(b'public synthetic bytes' * 10000)
        os.symlink('large', resources / 'current')
        for name in ['vpn-helper', 'vpn-engine', 'vpn-release.manifest', 'vpn-release.sig',
                     'vpn-previous-release.manifest', 'vpn-previous-release.sig',
                     'vpn-update-transition', 'vpn-update-transition.sig']:
            (self.source / name).write_bytes(('synthetic ' + name).encode())
        for path in self.source.rglob('*'):
            if not path.is_symlink(): path.chmod(0o755 if path.is_dir() else 0o644)

    def run_copy(self, point='', error='cross', success=True):
        result = subprocess.run([str(self.binary), str(self.source), str(self.parent), error, point],
                                capture_output=True, text=True, timeout=30)
        if success: self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        return result

    def scratch(self):
        pending, = self.parent.glob('.inbox-*.preparing')
        scratch, = pending.glob('.copy-*')
        return pending, scratch

    def test_cross_filesystem_and_unsupported_copy_exact_bytes_modes_links(self):
        for error in ['cross', 'unsupported']:
            with self.subTest(error=error):
                self.run_copy(error=error)
                published, = self.parent.glob('inbox-*')
                self.assertEqual((published / 'ProxyPilot.app/Contents/Resources/large').read_bytes(),
                                 (self.source / 'ProxyPilot.app/Contents/Resources/large').read_bytes())
                self.assertEqual(os.readlink(published / 'ProxyPilot.app/Contents/Resources/current'), 'large')
                self.assertEqual((published / 'vpn-helper').stat().st_mode & 0o7777, 0o644)
                shutil.rmtree(published)

    def test_process_exit_midfile_middirectory_and_after_publish_resumes(self):
        for point in ['copyScratchCreated:ProxyPilot.app', 'copyDirectory:ProxyPilot.app/Contents',
                      'copyBytes:ProxyPilot.app/Contents/Resources/large', 'copyPublished:ProxyPilot.app']:
            with self.subTest(point=point):
                result = self.run_copy(point, success=False)
                self.assertEqual(result.returncode, 43, result.stderr)
                self.scratch()
                self.run_copy()
                self.assertFalse(list(self.parent.glob('.inbox-*')))
                for path in self.parent.iterdir(): shutil.rmtree(path)

    def test_unknown_scratch_name_refuses_without_removal(self):
        self.assertEqual(self.run_copy('copyScratchCreated:ProxyPilot.app', success=False).returncode, 43)
        pending, scratch = self.scratch()
        foreign = pending / (scratch.name + '-unknown')
        scratch.rename(foreign)
        self.assertNotEqual(self.run_copy(success=False).returncode, 0)
        self.assertTrue(foreign.is_dir())

    def test_unknown_partial_child_refuses_without_removal(self):
        self.assertEqual(self.run_copy('copyDirectory:ProxyPilot.app', success=False).returncode, 43)
        _, scratch = self.scratch()
        unknown = scratch / 'ProxyPilot.app/unknown'
        unknown.write_bytes(b'foreign')
        self.assertNotEqual(self.run_copy(success=False).returncode, 0)
        self.assertEqual(unknown.read_bytes(), b'foreign')

    def test_corrupt_completed_sibling_refuses_before_removing_scratch(self):
        self.assertEqual(self.run_copy('copyBytes:vpn-helper', success=False).returncode, 43)
        pending, scratch = self.scratch()
        (pending / 'ProxyPilot.app/Contents/Resources/large').write_bytes(b'foreign')
        self.assertNotEqual(self.run_copy(success=False).returncode, 0)
        self.assertTrue(scratch.is_dir())

    def test_nested_partial_symlink_cannot_replace_expected_directory(self):
        self.assertEqual(self.run_copy('copyDirectory:ProxyPilot.app/Contents', success=False).returncode, 43)
        _, scratch = self.scratch()
        target = scratch / 'ProxyPilot.app/Contents'
        target.rmdir(); os.symlink(self.source, target)
        self.assertNotEqual(self.run_copy(success=False).returncode, 0)
        self.assertTrue(target.is_symlink())
        self.assertTrue((self.source / 'vpn-helper').exists())

    def test_symlink_scratch_refuses_without_following(self):
        self.assertEqual(self.run_copy('copyScratchCreated:ProxyPilot.app', success=False).returncode, 43)
        _, scratch = self.scratch()
        scratch.rmdir(); os.symlink(self.source, scratch)
        self.assertNotEqual(self.run_copy(success=False).returncode, 0)
        self.assertTrue(scratch.is_symlink())
        self.assertTrue((self.source / 'vpn-helper').exists())

    def test_duplicate_final_and_scratch_entry_refuses_both_untouched(self):
        self.assertEqual(self.run_copy('copyPublished:ProxyPilot.app', success=False).returncode, 43)
        pending, scratch = self.scratch()
        (scratch / 'ProxyPilot.app').mkdir(mode=0o700)
        self.assertNotEqual(self.run_copy(success=False).returncode, 0)
        self.assertTrue((pending / 'ProxyPilot.app').is_dir())
        self.assertTrue((scratch / 'ProxyPilot.app').is_dir())

    def test_changed_source_cannot_reclaim_old_scratch(self):
        self.assertEqual(self.run_copy('copyDirectory:ProxyPilot.app', success=False).returncode, 43)
        _, scratch = self.scratch()
        (self.source / 'vpn-helper').write_bytes(b'changed source')
        self.assertNotEqual(self.run_copy(success=False).returncode, 0)
        self.assertTrue(scratch.is_dir())

    def test_source_mutation_during_copy_does_not_publish(self):
        self.assertNotEqual(self.run_copy(error="mutate", success=False).returncode, 0)
        self.assertFalse(list(self.parent.glob("inbox-*")))

    def test_setuid_and_setgid_source_files_refused_for_clone_and_bytecopy(self):
        for error in ['clone', 'cross']:
            for name in ['vpn-helper', 'ProxyPilot.app/Contents/Resources/large']:
                for mode in [0o4755, 0o2755]:
                    with self.subTest(error=error, name=name, mode=oct(mode)):
                        path = self.source / name
                        path.chmod(mode)
                        self.assertNotEqual(self.run_copy(error=error, success=False).returncode, 0)
                        self.assertFalse(list(self.parent.iterdir()))
                        path.chmod(0o644)

    def test_uninstall_after_process_crash_needs_no_source_material(self):
        for point in ['copyScratchCreated:ProxyPilot.app', 'copyDirectory:ProxyPilot.app/Contents',
                      'copyBytes:ProxyPilot.app/Contents/Resources/large', 'copyPublished:ProxyPilot.app']:
            with self.subTest(point=point):
                self.assertEqual(self.run_copy(point, success=False).returncode, 43)
                hidden = self.root / 'unavailable-source'
                self.source.rename(hidden)
                try:
                    self.run_copy(error='uninstall')
                    self.assertFalse(list(self.parent.iterdir()))
                finally:
                    hidden.rename(self.source)
                    for path in self.parent.iterdir(): shutil.rmtree(path)

    def test_uninstall_broken_relative_scratch_links_only_for_removal(self):
        self.assertEqual(self.run_copy('copyDirectory:ProxyPilot.app/Contents/Resources', success=False).returncode, 43)
        _, scratch = self.scratch()
        resources = scratch / 'ProxyPilot.app/Contents/Resources'
        os.symlink('not-yet-copied', resources / 'broken')
        self.run_copy(error='uninstall')
        self.assertFalse(list(self.parent.iterdir()))

    def test_uninstall_unknown_scratch_duplicate_and_escape_refuse_without_changes(self):
        self.assertEqual(self.run_copy('copyDirectory:ProxyPilot.app/Contents/Resources', success=False).returncode, 43)
        pending, scratch = self.scratch()
        resources = scratch / 'ProxyPilot.app/Contents/Resources'
        link = resources / 'escape'
        os.symlink('../../../../outside', link)
        self.assertNotEqual(self.run_copy(error='uninstall', success=False).returncode, 0)
        self.assertTrue(link.is_symlink())
        link.unlink()
        duplicate = pending / 'ProxyPilot.app'
        duplicate.mkdir(mode=0o700)
        self.assertNotEqual(self.run_copy(error='uninstall', success=False).returncode, 0)
        self.assertTrue(duplicate.is_dir()); self.assertTrue(scratch.is_dir())
        duplicate.rmdir()
        unknown = scratch.with_name(scratch.name + '-unknown')
        scratch.rename(unknown)
        self.assertNotEqual(self.run_copy(error='uninstall', success=False).returncode, 0)
        self.assertTrue(unknown.is_dir())

    def test_uninstall_scratch_depth_overhead_is_constant_and_bounded(self):
        self.assertEqual(self.run_copy('copyDirectory:ProxyPilot.app', success=False).returncode, 43)
        _, scratch = self.scratch()
        node = scratch / 'ProxyPilot.app'
        for _ in range(47):
            node = node / 'd'; node.mkdir(mode=0o700)
        self.run_copy(error='uninstall')
        self.assertFalse(list(self.parent.iterdir()))

    def test_uninstall_oversized_or_too_deep_partial_refuses_without_removal(self):
        self.assertEqual(self.run_copy('copyDirectory:ProxyPilot.app', success=False).returncode, 43)
        _, scratch = self.scratch()
        node = scratch / 'ProxyPilot.app'
        oversized = node / 'oversized'
        with oversized.open('wb') as stream: stream.truncate(512 * 1024 * 1024 + 1)
        self.assertNotEqual(self.run_copy(error='uninstall', success=False).returncode, 0)
        self.assertTrue(oversized.is_file())
        oversized.unlink()
        for _ in range(48):
            node = node / 'd'; node.mkdir(mode=0o700)
        self.assertNotEqual(self.run_copy(error='uninstall', success=False).returncode, 0)
        self.assertTrue(node.is_dir())

    def test_uninstall_fullwidth_scratch_digest_refuses_without_changes(self):
        self.assertEqual(self.run_copy('copyScratchCreated:ProxyPilot.app', success=False).returncode, 43)
        pending, scratch = self.scratch()
        foreign = pending / ('.copy-' + 'ｆ' * 64)
        scratch.rename(foreign)
        self.assertNotEqual(self.run_copy(error='uninstall', success=False).returncode, 0)
        self.assertTrue(foreign.is_dir())

    def test_unicode_lookalike_root_names_are_not_counted_or_removed(self):
        foreign_names = ['inbox-' + 'ｆ' * 64, '.inbox-' + '１' * 64 + '.preparing']
        for name in foreign_names: (self.parent / name).mkdir(mode=0o700)
        self.run_copy(error='uninstall')
        self.assertEqual(set(path.name for path in self.parent.iterdir()), set(foreign_names))

    def test_uninstall_preflights_every_root_before_deleting_any(self):
        self.run_copy()
        published, = self.parent.glob('inbox-*')
        pending = self.parent / ('.inbox-' + '0' * 64 + '.preparing')
        pending.mkdir(mode=0o700)
        foreign = pending / 'unknown'
        foreign.write_bytes(b'leave untouched')
        self.assertNotEqual(self.run_copy(error='uninstall', success=False).returncode, 0)
        self.assertTrue(published.is_dir())
        self.assertEqual(foreign.read_bytes(), b'leave untouched')

    def test_failed_initialization_closes_owned_descriptor_exactly_once(self):
        self.parent.chmod(0o755)
        self.run_copy(error='init-failure')

    def test_permission_error_does_not_trigger_bytecopy(self):
        self.assertNotEqual(self.run_copy(error='denied', success=False).returncode, 0)
        self.assertFalse(list(self.parent.rglob('.copy-*')))
        self.assertFalse(list(self.parent.glob('inbox-*')))


if __name__ == '__main__': unittest.main()
