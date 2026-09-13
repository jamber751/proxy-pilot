"""Real Sparkle offer veto/retry, only disposable apps, signed loopback feeds and fake VPN markers."""
import os
import sys
import unittest
from test_isolated_update_install import IsolatedInstallFixture


@unittest.skipUnless(sys.platform == 'darwin' and os.environ.get('PROXYPILOT_TEST_ISOLATED_INSTALLER') == '1',
                     'opt-in isolated disposable app installation')
class VPNUpdateInstallTests(IsolatedInstallFixture, unittest.TestCase):
    def prepare_environment(self, work, mode):
        mode = mode.removeprefix('native-')
        if mode == 'vpn-unknown':
            parent = work / 'admission/daemons'
            parent.rmdir(); parent.write_bytes(b'unchanged malformed fixture')
        else:
            (work / 'admission/support/ProxyPilot').write_bytes(b'unchanged VPN fixture')

    def verify_environment(self, app, work, mode, events):
        mode = mode.removeprefix('native-')
        marker = work / 'admission/support/ProxyPilot'
        if mode == 'vpn-present': self.assertEqual(marker.read_bytes(), b'unchanged VPN fixture')
        if mode == 'vpn-unknown': self.assertEqual((work / 'admission/daemons').read_bytes(), b'unchanged malformed fixture')
        if mode == 'vpn-retry': self.assertFalse(marker.exists())

    def test_present_vpn_vetoes_before_offer_and_download(self): self.scenario('vpn-present')
    def test_unknown_state_is_not_treated_as_no_vpn(self): self.scenario('vpn-unknown')
    def test_retry_rechecks_state_and_installs_when_marker_is_gone(self): self.scenario('vpn-retry')


if __name__ == '__main__':
    import argparse
    parser = argparse.ArgumentParser(description='Disposable native VPN update error; acknowledge within three minutes.')
    parser.add_argument('--native-preview', action='store_true', required=True)
    parser.add_argument('--scenario', choices=['present', 'unknown'], default='present')
    args = parser.parse_args()
    VPNUpdateInstallTests.native_preview = True
    VPNUpdateInstallTests.setUpClass()
    try:
        VPNUpdateInstallTests().scenario('native-vpn-' + args.scenario)
    finally:
        VPNUpdateInstallTests.doClassCleanups()
