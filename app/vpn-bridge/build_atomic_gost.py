"""Build a separately pinned candidate. Never installs or executes GOST.
Source downloads use the Go checksum database; local replacement is relative,
trimmed builds contain no temporary path. Whole prepared trees are checked for
changes after both builds. Existing production assets/pins are not modified.
"""
from pathlib import Path
import argparse
import hashlib
import json
import os
import shutil
import stat
import subprocess
import sys

import prepare_atomic_gost as patch

MAIN = 'v0.0.0-20251122144702-340ba32ef0be'
MAIN_SUM = 'h1:khdl4fk9Q7vyDvFxiAsUcUnsZBmle4xdxGKNyrJYfjU='
TOOLCHAIN = 'go1.25.4'
VERSION = '3.2.6-proxypilot.2'


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def source_graph(folder):
    result = {}
    for path in sorted(folder.rglob('*')):
        if path.is_symlink(): raise ValueError('sourceSymlink')
        if path.is_file(): result[str(path.relative_to(folder))] = digest(path)
    return result


def copy_module(source, destination):
    shutil.copytree(source,destination,symlinks=False)
    for path in destination.rglob('*'):
        if path.is_symlink(): raise ValueError('sourceSymlink')
        path.chmod(0o700 if path.is_dir() else 0o600)


def build(destination, *, cache_root=None):
    recipe_inputs={path:path.read_bytes() for pattern in ('*.py','*.go')
                   for path in Path(__file__).parent.glob(pattern)}
    if sys.platform != 'darwin' or os.getuid() != os.geteuid() or os.geteuid() == 0:
        raise ValueError('ordinaryMacOSBuilderRequired')
    destination=Path(destination)
    if not destination.is_absolute() or destination.exists() or destination.is_symlink(): raise ValueError('destination')
    destination.mkdir(mode=0o700)
    destination=destination.resolve(strict=True)
    cache=destination if cache_root is None else Path(cache_root).resolve(strict=True)
    info=cache.stat()
    if not stat.S_ISDIR(info.st_mode) or info.st_uid!=os.getuid() or stat.S_IMODE(info.st_mode)!=0o700:
        raise ValueError('cacheDirectory')
    go=shutil.which('go')
    if not go: raise ValueError('compilerRequired')
    environment=dict(os.environ,GOENV='off',GOWORK='off',GOFLAGS='',GOTOOLCHAIN=TOOLCHAIN,
        GOMODCACHE=str(cache/'mod'),GOPATH=str(cache/'gopath'),GOCACHE=str(cache/'cache'),
        GOPROXY='https://proxy.golang.org',GOSUMDB='sum.golang.org',CGO_ENABLED='0')
    log=destination/'build.log'
    def run(arguments, *, cwd=destination, capture=False):
        with log.open('ab') as output:
            result=subprocess.run(arguments,cwd=cwd,env=environment,stdout=subprocess.PIPE if capture else output,
                stderr=output,timeout=300)
        if result.returncode: raise ValueError('compilerOperation')
        return result.stdout if capture else None
    version=run([go,'version'],capture=True).decode().strip()
    if not version.startswith('go version '+TOOLCHAIN+' '): raise ValueError('compilerPin')
    def download(name, version, expected):
        data=run([go,'mod','download','-json',name+'@'+version],capture=True)
        value=json.loads(data)
        if value.get('Path')!=name or value.get('Version')!=version or value.get('Sum')!=expected:
            raise ValueError('modulePin')
        path=Path(value['Dir']).resolve(strict=True)
        if not path.is_relative_to(cache/'mod'): raise ValueError('moduleDirectory')
        record=destination/(name.rsplit('/',1)[1]+'-download.json');record.write_bytes(data)
        return path,record
    main,_=download('github.com/go-gost/gost',MAIN,MAIN_SUM)
    _,record=download('github.com/go-gost/x',patch.VERSION,patch.MODULE_SUM)
    prepared=destination/'prepared'
    patch.prepare(record,prepared)
    copy_module(main,prepared/'gost')
    run([go,'mod','edit','-replace=github.com/go-gost/x=../x'],cwd=prepared/'gost')
    before=source_graph(prepared)
    artifacts={}
    for arch,golang_arch in (('arm64','arm64'),('x86_64','amd64')):
        environment.update(GOOS='darwin',GOARCH=golang_arch)
        target=destination/('gost-'+arch)
        run([go,'build','-mod=readonly','-trimpath','-buildvcs=false',
             '-ldflags=-s -w -X main.version='+VERSION,'-o',str(target),'./cmd/gost'],cwd=prepared/'gost')
        target.chmod(0o700)
        artifacts[arch]={'bytes':target.stat().st_size,'sha256':digest(target)}
    run([go,'mod','verify'],cwd=prepared/'gost')
    if source_graph(prepared)!=before: raise ValueError('sourceChanged')
    universal=destination/'gost-universal'
    run(['/usr/bin/lipo','-create',str(destination/'gost-arm64'),str(destination/'gost-x86_64'),'-output',str(universal)])
    universal.chmod(0o700)
    artifacts['universal']={'bytes':universal.stat().st_size,'sha256':digest(universal)}
    # Source recipe is evidence too, not just the prepared Go module contents.
    if any(path.read_bytes()!=data for path,data in recipe_inputs.items()): raise ValueError('recipeChanged')
    recipes={path.name:hashlib.sha256(data).hexdigest() for path,data in recipe_inputs.items()}
    proof={'schema':1,'version':VERSION,'toolchain':version,'mainModule':MAIN,'mainSum':MAIN_SUM,
           'dependencySum':patch.MODULE_SUM,'sourceGraph':before,'recipes':recipes,'artifacts':artifacts,
           'scope':'compile only; no GOST process/install/native traffic acceptance'}
    (destination/'verification.json').write_text(json.dumps(proof,indent=2)+'\n')
    return proof


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('destination');parser.add_argument('--cache-root')
    arguments=parser.parse_args();os.umask(0o077)
    try: proof=build(arguments.destination,cache_root=arguments.cache_root)
    except Exception: raise SystemExit('Candidate build refused; inspect private build.log')
    print(json.dumps({'version':proof['version'],'artifacts':proof['artifacts']}))
