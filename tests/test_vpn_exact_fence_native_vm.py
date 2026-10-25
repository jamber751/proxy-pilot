"""Actual production Swift fence boundary in the owned UDP/TCP death VM fixture.
Default compiles both architectures, runs pure checks and ordinary-user denial.
No host root/socket/SC/network/Keychain APIs. Actual mode is fresh-root-GHA only.
Durable fences are retained until disposable VM destruction, including failure.
No production DNS integration proof is claimed here.
"""
from pathlib import Path
import hashlib
import os
import re
import shutil
import signal
import subprocess
import sys
import tempfile
import unittest

import test_vpn_exact_fence_adapter as pure
import test_vpn_exact_route_packet_vm as packets
ROOT = pure.ROOT
FLAG = 'PROXYPILOT_VM_NATIVE_EXACT_FENCE'
BRIDGE = ROOT/'tests/vpn_exact_fence_native_vm.swift'


def compile_probe(folder):
    folder = Path(folder)
    sources = list(pure.SOURCES)+[BRIDGE]+[ROOT/'tests'/name for name in packets.SOURCES]
    captured = {source:source.read_bytes() for source in sources}
    for source,data in captured.items(): (folder/source.name).write_bytes(data)
    outputs = []
    for arch in ('arm64','x86_64'):
        c = folder/('packet-'+arch+'.o'); support = folder/('support-'+arch+'.o')
        for source,output,extra in ((packets.SOURCES[0],c,['-DPP_NATIVE_EXACT_FENCE']), (packets.SOURCES[2],support,[])):
            r = subprocess.run(['/usr/bin/clang','-Wall','-Wextra','-Werror','-target',arch+'-apple-macosx12.0',*extra,
                '-c',str(folder/source),'-o',str(output)],capture_output=True,text=True,timeout=30)
            if r.returncode: raise AssertionError(r.stderr)
        output = folder/arch
        r = subprocess.run(['/usr/bin/swiftc','-parse-as-library','-target',arch+'-apple-macosx12.0',
            *[str(folder/source.name) for source in list(pure.SOURCES)+[BRIDGE]],str(c),str(support),'-o',str(output)],
            capture_output=True,text=True,timeout=90)
        if r.returncode: raise AssertionError(r.stderr)
        outputs.append(str(output))
    binary = folder/'probe'
    subprocess.run(['/usr/bin/lipo','-create',*outputs,'-output',str(binary)],check=True,capture_output=True,timeout=10)
    if any(source.read_bytes()!=data for source,data in captured.items()): raise AssertionError('sourceChanged')
    (folder/'source.sha256').write_text(''.join(hashlib.sha256(data).hexdigest()+' '+str(source.relative_to(ROOT))+'\n' for source,data in captured.items()))
    return binary


@unittest.skipUnless(sys.platform == 'darwin' and shutil.which('swiftc') and os.geteuid()!=0,'ordinary macOS compiler required')
class PureTests(unittest.TestCase):
    def test_both_arch_compile_pure_codec_and_guard_before_live_native_socket(self):
        with tempfile.TemporaryDirectory(prefix='pp-native-fence-compile-') as folder:
            binary = compile_probe(folder)
            for args,expected,extra in ((['--pure-packets'],0,{}),([],77,{}),([],77,{
                'GITHUB_ACTIONS':'true',FLAG:'1',packets.FLAG:'1',packets.SUPPORT_FLAG:'1'})):
                r = subprocess.run([str(binary),*args],env={'PATH':'/usr/bin:/bin',**extra},capture_output=True,timeout=5)
                self.assertEqual((r.returncode,r.stdout,r.stderr),(expected,b'',b''))


def acceptance():
    if not (sys.platform=='darwin' and os.getuid()==os.geteuid()==0 and os.environ.get('GITHUB_ACTIONS')=='true'
            and all(os.environ.get(flag)=='1' for flag in (FLAG,packets.FLAG,packets.SUPPORT_FLAG))): raise SystemExit(77)
    # Never recursively remove a namespace containing kernel-route custody.
    folder = Path(tempfile.mkdtemp(prefix='pp-native-fence-vm-',dir=os.environ['RUNNER_TEMP']))
    binary = compile_probe(folder)
    journal = Path(folder)/'persistent-fences'; journal.mkdir(mode=0o700)
    previous = None
    for order in (0,1):
        run_probe(binary,order,journal)
        identities = retired_ids(journal)
        if previous is not None and not identities.isdisjoint(previous): raise RuntimeError('reusedRetiredInstallation')
        previous = identities
        print('PASS native-exact-fence-order-'+('after-active' if order else 'before-active'),flush=True)
    print('PASS native-exact-fence-durable-two-processes',flush=True)


def retired_ids(journal):
    import json
    import stat
    files = sorted(journal.glob('fence-v1-*.json'))
    if len(files) != 2: raise RuntimeError('durableEntryCount')
    ids = set()
    for path in files:
        fd = os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC|os.O_NONBLOCK)
        try:
            info = os.fstat(fd)
            if not (stat.S_ISREG(info.st_mode) and info.st_uid == 0 and info.st_nlink == 1 and stat.S_IMODE(info.st_mode) == 0o600): raise RuntimeError('durableEntryIdentity')
            data = os.read(fd,256*1024+1)
            if len(data)>256*1024: raise RuntimeError('durableEntryCapacity')
            row = json.loads(data)
            if row['schemaVersion'] != 1 or row['phase'] != 'retired' or len(row['claims']) != 1 or row['claims'][0]['profileSHA256'] != 'a'*64: raise RuntimeError('durableEntryState')
            ids.add(row['installationID'])
        finally: os.close(fd)
    if len(ids) != 2: raise RuntimeError('durableInstallationIdentity')
    return ids



def run_probe(binary,order,journal):
    process = subprocess.Popen([str(binary)],stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True,start_new_session=True,
        env={'PATH':'/usr/bin:/bin:/usr/sbin:/sbin','GITHUB_ACTIONS':'true',FLAG:'1',packets.FLAG:'1',packets.SUPPORT_FLAG:'1','PROXYPILOT_VM_NATIVE_FENCE_AFTER_ACTIVE':str(order),
             'RUNNER_TEMP':os.environ['RUNNER_TEMP'],'PROXYPILOT_VM_NATIVE_FENCE_DIRECTORY':str(journal)})
    try: out,err = process.communicate(timeout=60)
    except subprocess.TimeoutExpired:
        os.killpg(process.pid,signal.SIGKILL); process.communicate(timeout=5)
        raise RuntimeError('ownedProbeTimeout-VM-disposal')
    expected = []
    for f in (4,6):
        expected += ['PASS native-exact-fence-add-'+str(f),'PASS native-exact-fence-delete-'+str(f)]
        expected += [line for line in packets.MARKERS if 'ipv'+str(f)+'-' in line]
    for line in out.splitlines():
        if line not in expected and not re.fullmatch(r'API native-exact-fence type=[0-9]+ index=[0-9]+ addrs=[0-9]+ maskLength=[0-9]+ maskFamily=[0-9]+ gatewayFamily=[0-9]+',line) and not re.fullmatch(r'FAIL native-exact-fence action=(1|2) family=(4|6) category=[A-Za-z]+ errno=[0-9]+ expectedFlags=[0-9]+ observedFlags=[0-9]+',line): raise RuntimeError('outputProtocol')
        print(line,flush=True)
    for line in err.splitlines():
        if not (re.fullmatch(r'FAIL exact-route-pair stage=[A-Za-z]+ errno=[0-9]+ flags=[0-9]+ exact=[01] fullMask=[01]',line)
                or line=='FAIL exact-route-udp-unresolved-VM-disposal'): raise RuntimeError('diagnosticProtocol')
        print(line,file=sys.stderr,flush=True)
    if process.returncode or out.splitlines()!=expected: raise RuntimeError('nativeProofIncomplete')


if __name__=='__main__':
    if sys.argv[1:]==['--acceptance']: acceptance()
    else: unittest.main()
