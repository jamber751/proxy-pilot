"""Real controller/model at the cache bound; synthetic helper/cache, no UI or APIs."""
from pathlib import Path
import platform
import shutil
import subprocess
import sys
import tempfile
import unittest
ROOT = Path(__file__).resolve().parents[1]
@unittest.skipUnless(sys.platform == 'darwin' and shutil.which('swiftc'), 'macOS Swift required')
class CapacityFlowTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp = tempfile.TemporaryDirectory(prefix='pp-capacity-flow-build-')
        cls.addClassCleanup(cls.temp.cleanup); folder = Path(cls.temp.name)
        helper = folder/'FakeLiveSession.swift'
        live = (ROOT/'tests/vpn_live_controller_checks.swift').read_text()
        helper.write_text('import Foundation\nfinal class FakeLiveSession:'+live.split('final class FakeLiveSession:',1)[1].split('final class FakePasswordSession:',1)[0])
        names = ['VPNConfiguration.swift','VPNProfileImporter.swift','VPNStore.swift','VPNModel.swift',
            'VPNLiveController.swift','VPNPasswordPersistenceCoordinator.swift','vpn-helper/VPNHelperProtocol.swift',
            'vpn-helper/VPNApplicationSpec.swift','vpn-helper/VPNTunnelStateStore.swift']
        arch = 'arm64' if platform.machine() == 'arm64' else 'x86_64'; cls.binary = folder/'checks'
        r = subprocess.run(['swiftc','-D','VPN_LIVE_CONTROLLER_TESTING','-target',arch+'-apple-macosx11.0',
            *[str(ROOT/'app'/n) for n in names],str(helper),str(ROOT/'tests/vpn_password_capacity_flow_checks.swift'),'-o',str(cls.binary)],
            capture_output=True,text=True,timeout=120)
        if r.returncode: raise AssertionError(r.stderr)
    def case(self, name):
        with tempfile.TemporaryDirectory(prefix='pp-capacity-flow-') as folder:
            r = subprocess.run([str(self.binary),name,folder],capture_output=True,text=True,timeout=15)
            self.assertEqual(r.returncode,0,r.stdout+r.stderr)
            self.assertEqual(r.stdout.strip(),'capacity flow passed')
    def test_legacy64_plus_active_manual_connect_and_revoke_import_remove_stay_usable(self): self.case('legacy65')
    def test_retired65_manual_connect_and_settings_stay_usable_without_new_add(self): self.case('retired65')
if __name__ == '__main__': unittest.main()
