"""Build-only, both macOS architectures. Never executes the resolver worker."""
from pathlib import Path
import argparse
import hashlib
import json
import os
import shutil
import subprocess
import sys

TOOLCHAIN='go1.25.4'
PRODUCTION=('go.mod','main.go','lookup.go')
IDENTIFIER='kz.documentolog.proxypilot.system-resolver'


def build(destination):
    if sys.platform!='darwin' or os.getuid()!=os.geteuid() or os.geteuid()==0:
        raise ValueError('ordinaryMacOSBuilderRequired')
    root=Path(__file__).resolve().parent
    captured={name:(root/name).read_bytes() for name in (*PRODUCTION,'build.py')}
    destination=Path(destination)
    if not destination.is_absolute() or destination.exists() or destination.is_symlink():raise ValueError('destination')
    destination.mkdir(mode=0o700);destination=destination.resolve(strict=True)
    source=destination/'Source';source.mkdir(mode=0o700)
    for name in PRODUCTION:(source/name).write_bytes(captured[name])
    go=shutil.which('go')
    if not go:raise ValueError('compilerRequired')
    log=destination/'build.log'
    env=dict(os.environ,GOENV='off',GOWORK='off',GOFLAGS='',GOTOOLCHAIN=TOOLCHAIN,
             GOPROXY='https://proxy.golang.org',GOSUMDB='sum.golang.org',CGO_ENABLED='1',GOOS='darwin',MACOSX_DEPLOYMENT_TARGET='12.0')
    def run(arguments,environment=env):
        result=subprocess.run(arguments,cwd=source,env=environment,capture_output=True,timeout=180)
        with log.open('ab') as stream:stream.write(result.stdout);stream.write(result.stderr)
        log.chmod(0o600)
        if result.returncode:raise ValueError('buildOperation')
        return result.stdout
    if not run([go,'version']).decode().startswith('go version '+TOOLCHAIN+' '):raise ValueError('compilerPin')
    outputs={}
    for arch,goarch in (('arm64','arm64'),('x86_64','amd64')):
        output=destination/('system-resolver-'+arch)
        environment=dict(env,GOARCH=goarch,CC='/usr/bin/clang -arch '+arch,
                         CGO_CFLAGS='-mmacosx-version-min=12.0',CGO_LDFLAGS='-mmacosx-version-min=12.0')
        run([go,'build','-mod=readonly','-trimpath','-buildvcs=false','-ldflags=-s -w -linkmode=external','-o',str(output),'.'],environment)
        run(['/usr/bin/codesign','--force','--sign','-','--options','runtime,hard,kill',
             '--identifier',IDENTIFIER,'--runtime-version','12.0.0','--timestamp=none',
             '--digest-algorithm=sha256','--pagesize','4096',str(output)])
        run(['/usr/bin/codesign','--verify','--strict',str(output)])
        architecture=run(['/usr/bin/lipo','-archs',str(output)]).decode().strip()
        load=run(['/usr/bin/otool','-l',str(output)]).decode()
        minimum=[line.split()[1] for line in load.splitlines() if line.strip().startswith('minos ')]
        if architecture!=arch or minimum!=['12.0']:raise ValueError('deploymentTarget')
        outputs[arch]={'bytes':output.stat().st_size,'sha256':hashlib.sha256(output.read_bytes()).hexdigest()}
    universal=destination/'system-resolver'
    run(['/usr/bin/lipo','-create',*[str(destination/('system-resolver-'+arch)) for arch in outputs],'-output',str(universal)])
    universal.chmod(0o700)
    run(['/usr/bin/codesign','--verify','--strict','--all-architectures',str(universal)])
    code_hashes={}
    import re
    for arch in outputs:
        # codesign displays on stderr; it is already retained in the private log.
        result=subprocess.run(['/usr/bin/codesign','--display','--verbose=4','--arch',arch,str(universal)],
                              capture_output=True,timeout=20)
        if result.returncode:raise ValueError('signatureMetadata')
        hashes=re.findall(rb'^CDHash=([a-f0-9]{40})$',result.stderr,re.M)
        identifiers=re.findall(rb'^Identifier=(.+)$',result.stderr,re.M)
        if len(hashes)!=1 or identifiers!=[IDENTIFIER.encode()]:raise ValueError('signatureMetadata')
        code_hashes[arch]=hashes[0].decode()
    if any((root/name).read_bytes()!=data for name,data in captured.items()):raise ValueError('sourceChanged')
    record={'schema':1,'toolchain':TOOLCHAIN,'minimumMacOS':'12.0','outputs':outputs,
            'universal':{'bytes':universal.stat().st_size,'sha256':hashlib.sha256(universal.read_bytes()).hexdigest(),
                         'identifier':IDENTIFIER,'codeDirectoryHashes':code_hashes,'pageSize':4096,'runtimeVersion':'12.0.0'},
            'sources':{name:hashlib.sha256(data).hexdigest() for name,data in captured.items()}}
    manifest=destination/'verification.json';manifest.write_text(json.dumps(record,sort_keys=True,indent=2)+'\n');manifest.chmod(0o600)
    return record

if __name__=='__main__':
    parser=argparse.ArgumentParser();parser.add_argument('destination');args=parser.parse_args()
    previous=os.umask(0o077)
    try:build(args.destination)
    except (ValueError,subprocess.SubprocessError,OSError):raise SystemExit('resolver build refused; see private build log')
    finally:os.umask(previous)
