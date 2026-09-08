"""Bounded, unprivileged updater transport; no network or production preferences."""
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]


@unittest.skipUnless(sys.platform == 'darwin' and shutil.which('swiftc'), 'macOS Swift required')
class UpdateChannelTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp = tempfile.TemporaryDirectory(prefix='proxypilot-update-channel-')
        cls.addClassCleanup(cls.temp.cleanup)
        cls.work = Path(cls.temp.name)
        slices = []
        for arch in ('arm64', 'x86_64'):
            target = cls.work / arch
            command = ['swiftc', '-parse-as-library', '-target', f'{arch}-apple-macosx11.0',
                       str(ROOT / 'app/update-worker/UpdateWire.swift'),
                       str(ROOT / 'app/update-worker/UpdateChannel.swift'),
                       str(ROOT / 'tests/update_channel_checks.swift'), '-o', str(target)]
            result = subprocess.run(command, capture_output=True, text=True, timeout=90)
            if result.returncode:
                raise AssertionError(result.stderr)
            slices.append(str(target))
        cls.binary = cls.work / 'checks'
        subprocess.run(['lipo', '-create', *slices, '-output', str(cls.binary)], check=True, capture_output=True)

    def check(self, mode):
        result = subprocess.run([str(self.binary), mode], capture_output=True, text=True, timeout=16)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn('PASS ' + mode, result.stdout)

    def test_fragmented_and_batched_frames(self): self.check('wire')
    def test_schema_versions_sizes_and_display_text_are_bounded(self): self.check('malformed')
    def test_incoming_fragmented_command(self): self.check('receive')
    def test_outgoing_state(self): self.check('duplex')
    def test_wrong_direction_is_rejected(self): self.check('direction')
    def test_eof_disconnects(self): self.check('eof')
    def test_broken_pipe_does_not_kill_the_app(self): self.check('broken-pipe')
    def test_oversized_header_rejected_before_body(self): self.check('oversized')
    def test_partial_frame_expires(self): self.check('partial-timeout')
    def test_slow_reader_cannot_grow_output_indefinitely(self): self.check('backpressure')
    def test_close_releases_descriptors_without_deinit(self): self.check('close')
