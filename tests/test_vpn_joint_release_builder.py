"""Fail-closed local assembly contract; never invokes the signing script."""
from pathlib import Path
import os
import subprocess
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "app/build-joint-release.sh"


class VPNJointReleaseBuilderTests(unittest.TestCase):
    def test_prebuilt_zip_app_engine_is_executable_after_root_install(self):
        line = next(line for line in SCRIPT.read_text().splitlines()
                    if line.startswith('/bin/chmod ') and 'Resources/bin/gost' in line)
        with tempfile.TemporaryDirectory(prefix='pp-release-mode-') as directory:
            engine = Path(directory) / 'app/ProxyPilot.app/Contents/Resources/bin/gost'
            engine.parent.mkdir(parents=True)
            engine.write_bytes(b'fixture engine bytes')
            engine.chmod(0o700)
            subprocess.run(['zsh', '-f', '-c', line],
                           env=dict(os.environ, WORK=directory), check=True, timeout=5)
            self.assertEqual(engine.stat().st_mode & 0o7777, 0o755)
            self.assertEqual(engine.read_bytes(), b'fixture engine bytes')

    def test_shell_syntax_and_no_external_mutation(self):
        result = subprocess.run(["zsh", "-n", str(SCRIPT)],
                                capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        source = SCRIPT.read_text()
        for forbidden in ("gh release", "git tag", "git push", "installer ",
                          "sudo ", "launchctl "):
            self.assertNotIn(forbidden, source)
        self.assertIn("No tag, upload, installation or system change", source)

    def test_exact_sequence_key_and_artifact_chain(self):
        source = SCRIPT.read_text()
        required = [
            '"$KEY_TOOL" verify-forward-source',
            '"$KEY_TOOL" public',
            '"$KEY_TOOL" verify "$PREVIOUS_MANIFEST"',
            "PROXYPILOT_VPN_RELEASE_SEQUENCE=\"$SEQUENCE\"",
            'lipo -archs "$UNIVERSAL_GOST"',
            'Resources/bin/gost',
            'codesign --force --sign - --options runtime,hard,kill',
            "vpn-package/package.py\" prepare",
            '"$KEY_TOOL" sign ',
            "build-first-install",
            "prepare-update",
            "sign-transition",
            "build-companion",
            "prepare-companion-metadata",
            "sign-companion",
            "verify-companion-artifact",
            'tar --format ustar -czf',
            "verify-engine-sources",
            'PROXYPILOT_PREBUILT_APP="$WORK/app/ProxyPilot.app"',
            'PROXYPILOT_FIRST_INSTALL_PACKAGE="$FIRST_INSTALL_PACKAGE"',
            'zsh "$ROOT/make-dmg.sh"',
            'zsh "$HERE/sign-update.sh"',
        ]
        positions = [source.index(value) for value in required]
        self.assertEqual(positions, sorted(positions))

    def test_fixed_worker_staging_precedes_keychain_and_both_images_enter_bundle(self):
        source = SCRIPT.read_text()
        self.assertIn('[[ $# == 7 ]]', source)
        self.assertLess(source.index('stage_workers.py'), source.index('"$KEY_TOOL" public'))
        for name in ('gost', 'system-resolver'):
            self.assertIn('"$WORK/workers/' + name + '"', source)
            copy = source.index('Resources/bin/' + name)
            self.assertLess(copy, source.index('/usr/bin/codesign --force --sign -'))
        self.assertIn('UNIVERSAL_RESOLVER="${7:A}"', source)

    def test_source_sidecars_are_frozen_before_public_preflight_or_keychain(self):
        source = SCRIPT.read_text()
        block = source.split('"$PREVIOUS_SIGNATURE" "$WORK" <<\'PY\'\n', 1)[1].split('\nPY\n', 1)[0]
        with tempfile.TemporaryDirectory(prefix='pp-release-source-snapshot-') as folder:
            folder = Path(folder); output = folder / 'work'; output.mkdir()
            manifest = folder / 'input.manifest'; signature = folder / 'input.sig'
            manifest.write_bytes(b'public manifest'); signature.write_bytes(b'synthetic signature')
            subprocess.run(['python3', '-c', block, str(manifest), str(signature), str(output)],
                           check=True, capture_output=True, timeout=5)
            manifest.write_bytes(b'changed'); signature.write_bytes(b'changed')
            self.assertEqual((output / 'previous.manifest').read_bytes(), b'public manifest')
            self.assertEqual((output / 'previous.sig').read_bytes(), b'synthetic signature')
            self.assertEqual((output / 'previous.manifest').stat().st_mode & 0o7777, 0o400)
        self.assertLess(source.index('PREVIOUS_MANIFEST="$WORK/previous.manifest"'),
                        source.index('"$KEY_TOOL" verify-forward-source'))

    def test_script_is_executable_and_output_is_no_overwrite(self):
        self.assertTrue(os.access(SCRIPT, os.X_OK))
        source = SCRIPT.read_text()
        self.assertIn('! -e "$OUTPUT" && ! -L "$OUTPUT"', source)
        self.assertIn('mkdir -m 700 "$OUTPUT"', source)
        self.assertIn('vpn-engine-sources.tar.gz', source)
        self.assertIn('vpn-release-sequence.txt', source)
        self.assertIn('COPYFILE_DISABLE=1', source)
        self.assertIn('"$OUTPUT/appcast.xml"', source)
        self.assertNotIn("--clobber", source)


if __name__ == "__main__":
    unittest.main()
