"""Owned stdlib/Cgo worker tests with injected DNS and in-memory HTTP only.
Never starts its listener or calls nativeLookup/getaddrinfo on this host.
"""
from pathlib import Path
import importlib.util
import os
import platform
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch
ROOT=Path(__file__).resolve().parents[1]
WORKER=ROOT/'app/vpn-system-resolver'
spec=importlib.util.spec_from_file_location('pp_resolver_builder',WORKER/'build.py')
builder=importlib.util.module_from_spec(spec);spec.loader.exec_module(builder)

class BuilderGuardTests(unittest.TestCase):
    def test_root_denied_before_files_compiler_or_process(self):
        with patch.object(builder.os,'getuid',return_value=0),patch.object(builder.os,'geteuid',return_value=0),patch.object(builder.shutil,'which') as compiler,patch.object(builder.subprocess,'run') as process:
            with self.assertRaisesRegex(ValueError,'ordinaryMacOSBuilderRequired'):builder.build('/must-not-create')
        compiler.assert_not_called();process.assert_not_called()
    def test_other_platform_denied_before_compiler_or_process(self):
        with patch.object(builder.sys,'platform','linux'),patch.object(builder.shutil,'which') as compiler,patch.object(builder.subprocess,'run') as process:
            with self.assertRaisesRegex(ValueError,'ordinaryMacOSBuilderRequired'):builder.build('/must-not-create')
        compiler.assert_not_called();process.assert_not_called()

@unittest.skipUnless(sys.platform=='darwin' and shutil.which('go') and os.getuid()==os.geteuid()!=0,'ordinary macOS Cgo compiler required')
class HandlerTests(unittest.TestCase):
    def test_authenticated_bounded_handler_uses_fake_lookup_only(self):
        sources={name:(WORKER/name).read_bytes() for name in ('go.mod','main.go','lookup.go','main_test.go')}
        with tempfile.TemporaryDirectory(prefix='pp-system-resolver-pure-') as folder:
            for name,data in sources.items():(Path(folder)/name).write_bytes(data)
            env=dict(os.environ,GOENV='off',GOWORK='off',GOFLAGS='',GOTOOLCHAIN='go1.25.4',CGO_ENABLED='1',
                     GOOS='darwin',GOARCH='arm64' if platform.machine()=='arm64' else 'amd64',CC='/usr/bin/clang',
                     CGO_CFLAGS='-mmacosx-version-min=12.0',CGO_LDFLAGS='-mmacosx-version-min=12.0',
                     MACOSX_DEPLOYMENT_TARGET='12.0',GOPROXY='https://proxy.golang.org',GOSUMDB='sum.golang.org')
            result=subprocess.run(['go','test','-race','-count=1','-v','./...'],cwd=folder,env=env,capture_output=True,text=True,timeout=180)
        self.assertEqual(result.returncode,0,result.stdout+result.stderr)
        expected={'TestStrictRequestBeforeLookup','TestAuthenticationBeforeBodyAndLookup','TestNativeFailureNeverFallsBack',
                  'TestNativeResultAndFamily','TestAdmissionHeldUntilNativeCallActuallyEnds','TestCertificateIsFreshAndLoopbackOnly','TestPasswordAndHostInputs'}
        observed={line.split()[2] for line in result.stdout.splitlines() if line.startswith('--- PASS: ')}
        self.assertEqual(observed,expected);self.assertNotIn('--- SKIP:',result.stdout)
        self.assertTrue(all((WORKER/name).read_bytes()==data for name,data in sources.items()),'Source changed during tests')
if __name__=='__main__':unittest.main()
