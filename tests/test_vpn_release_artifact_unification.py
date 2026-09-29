"""The public DMG/ZIP and VPN manifest must contain one exact sealed app."""
from pathlib import Path
import unittest


ROOT = Path(__file__).resolve().parents[1]


class VPNReleaseArtifactUnificationTests(unittest.TestCase):
    def test_committed_sequence_is_canonical_and_used_by_public_build(self):
        sequence = (ROOT / "app/vpn-release-sequence.txt").read_text()
        self.assertRegex(sequence, r"^[1-9][0-9]{0,18}\n$")
        package = (ROOT / "make-dmg.sh").read_text()
        self.assertIn('VPN_SEQUENCE=$(< "$HERE/app/vpn-release-sequence.txt")',
                      package)
        self.assertIn("PROXYPILOT_VPN_INSTALLER=1", package)
        self.assertIn('PROXYPILOT_VPN_RELEASE_SEQUENCE="$VPN_SEQUENCE"', package)
        self.assertIn("Print :ProxyPilotVPNReleaseSequence", package)

    def test_prebuilt_mode_does_not_resign_or_replace_the_pinned_app(self):
        package = (ROOT / "make-dmg.sh").read_text()
        start = package.index('if [[ -z "$PREBUILT_APP" ]]; then',
                              package.index('RES_BIN='))
        end = package.index("codesign --verify --deep --strict", start)
        branch = package[start:end]
        self.assertIn("codesign --force --sign", branch)
        self.assertIn("else\n", branch)
        prebuilt = branch[branch.rindex("else\n"):]
        self.assertNotIn("codesign --force", prebuilt)
        self.assertNotIn("cp \"$HERE/bin/proxypilot\"", prebuilt)
        self.assertNotIn("cp \"$HERE/vendor/gost-universal\"", prebuilt)
        self.assertIn("prebuilt release app is not self-contained", prebuilt)

    def test_joint_builder_emits_public_update_from_the_same_app(self):
        builder = (ROOT / "app/build-joint-release.sh").read_text()
        self.assertIn('build-first-install', builder)
        self.assertIn('PROXYPILOT_FIRST_INSTALL_PACKAGE="$FIRST_INSTALL_PACKAGE"',
                      builder)
        self.assertIn(
            'PROXYPILOT_PREBUILT_APP="$WORK/app/ProxyPilot.app"', builder)
        self.assertIn('PROXYPILOT_DIST_DIR="$WORK/distribution"', builder)
        for name in (
            'ProxyPilot-$VERSION.dmg', 'ProxyPilot-$VERSION.zip',
            'appcast.xml', 'vpn-joint.dmg', 'vpn-engine-sources.tar.gz',
        ):
            self.assertIn(name, builder)

    def test_custom_distribution_paths_are_absolute_and_non_symlinked(self):
        for path in (ROOT / "make-dmg.sh", ROOT / "app/sign-update.sh"):
            source = path.read_text()
            self.assertIn('PROXYPILOT_DIST_DIR', source)
            self.assertIn('== /* && ! -L "$DIST"', source)

    def test_first_install_package_is_external_to_the_sealed_app(self):
        package = (ROOT / "make-dmg.sh").read_text()
        self.assertIn('PROXYPILOT_FIRST_INSTALL_PACKAGE', package)
        self.assertIn('Install ProxyPilot + VPN Support.pkg', package)
        self.assertIn('"$STAGE/Install ProxyPilot + VPN Support.pkg"', package)
        self.assertNotIn('Contents/Resources/Install ProxyPilot + VPN Support.pkg',
                         package)
        self.assertLess(package.index('codesign --verify --deep --strict'),
                        package.index('Install ProxyPilot + VPN Support.pkg'))

    def test_manual_installer_refuses_vpn_footprints_before_replacement(self):
        package = (ROOT / "make-dmg.sh").read_text()
        guard = package.index('VPN support is already installed or pending an update')
        replacement = package.index('rm -rf "$DST"')
        self.assertLess(guard, replacement)
        for footprint in (
            '/Applications/.ProxyPilot.vpn-update',
            '/Library/Application Support/ProxyPilot',
            'kz.documentolog.proxypilot.vpn-helper.plist',
            'kz.documentolog.proxypilot.vpn-update-broker.plist',
        ):
            self.assertIn(footprint, package)


if __name__ == "__main__":
    unittest.main()
