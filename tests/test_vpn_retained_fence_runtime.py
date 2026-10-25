"""Private files + fake kernel; never host sysctl/PF_ROUTE/launchd/root/network."""
from pathlib import Path
import os
import subprocess
import tempfile
import unittest
import test_vpn_exact_fence_adapter as adapter
ROOT=adapter.ROOT
SOURCES=adapter.SOURCES+[ROOT/'app/vpn-helper/VPNApplicationSpec.swift',ROOT/'app/vpn-helper/VPNDirectoryProvisioner.swift',ROOT/'app/vpn-helper/VPNRetainedFenceRuntime.swift']
MODES=('inventory-retained','inventory-retired','inventory-corrupt','inventory-expired','inventory-lock-order','inventory-codec','root-guard','before-restore','empty','retained','active-withdraw','foreign','namespace-change','lock','expired','cancel','one-shot')
@unittest.skipUnless(adapter.sys.platform=='darwin' and adapter.shutil.which('swiftc') and os.getuid()==os.geteuid()!=0,'ordinary macOS SDK required')
class RetainedRuntimeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp=tempfile.TemporaryDirectory(prefix='pp-retained-runtime-build-');cls.addClassCleanup(cls.temp.cleanup)
        cls.binary=Path(cls.temp.name)/'checks'
        r=subprocess.run(['/usr/bin/swiftc','-parse-as-library','-D','VPN_DIRECTORY_TESTING',*map(str,SOURCES),
                          str(ROOT/'tests/vpn_retained_fence_runtime_checks.swift'),'-o',str(cls.binary)],capture_output=True,text=True,timeout=90)
        if r.returncode:raise AssertionError(r.stderr)
    def case(self,mode):
        with tempfile.TemporaryDirectory(prefix='pp-retained-runtime-private-') as folder:
            Path(folder).chmod(0o700)
            r=subprocess.run([str(self.binary),mode,folder],capture_output=True,text=True,timeout=10)
        self.assertEqual(r.returncode,0,r.stdout+r.stderr)
        self.assertEqual(r.stdout,'PASS retained-runtime-'+mode+'\n');self.assertEqual(r.stderr,'')

@unittest.skipUnless(adapter.sys.platform=='darwin' and adapter.shutil.which('swiftc') and os.getuid()==os.geteuid()!=0,'ordinary macOS SDK required')
class RetainedDaemonCompileTests(unittest.TestCase):
    def test_complete_daemon_graph_compiles_for_both_architectures_without_running(self):
        sources=[ROOT/'app/VPNConfiguration.swift',ROOT/'app/VPNProfileImporter.swift']
        sources += [p for p in sorted((ROOT/'app/vpn-helper').glob('*.swift')) if p.name not in ('ServiceMain.swift','VPNRescueMain.swift')]
        with tempfile.TemporaryDirectory(prefix='pp-retained-daemon-compile-') as folder:
            captured={p:p.read_bytes() for p in sources}
            inputs=[]
            for path,data in captured.items():
                target=Path(folder)/'Source'/path.relative_to(ROOT)
                target.parent.mkdir(parents=True,exist_ok=True);target.write_bytes(data);inputs.append(str(target))
            for arch in ('arm64','x86_64'):
                r=subprocess.run(['/usr/bin/swiftc','-parse-as-library','-emit-library','-D','VPN_DAEMON_TESTING',
                    '-D','VPN_HELPER_READINESS_TESTING','-target',arch+'-apple-macosx11.0',*inputs,
                    '-o',str(Path(folder)/(arch+'.dylib'))],capture_output=True,text=True,timeout=180)
                self.assertEqual(r.returncode,0,r.stderr)
            self.assertTrue(all(p.read_bytes()==data for p,data in captured.items()),'Source changed during compile')
    def test_daemon_restores_before_endpoint_and_keeps_custody_in_readiness_check(self):
        source=(ROOT/'app/vpn-helper/VPNHelperDaemon.swift').read_text()
        self.assertIn('try VPNRetainedFenceRuntime.system(deadline:deadline,checkCurrent:current)',source)
        self.assertLess(source.index('let protection = try restoreProtection?'),source.index('try runtime.prepareEndpoint'))
        self.assertLess(source.index('let protection = try restoreProtection?'),source.index('trace.mark(.listener)'))
        self.assertIn('try protection?.check()',source[source.index('func stillSelected()'):])
for mode in MODES:setattr(RetainedRuntimeTests,'test_'+mode.replace('-','_'),lambda self,m=mode:self.case(m))
if __name__=='__main__':unittest.main()
