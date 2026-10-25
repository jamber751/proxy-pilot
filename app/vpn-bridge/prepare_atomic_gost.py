"""Prepare a separately built candidate; NEVER edits module cache or shipped GOST.
The caller supplies an independently Go-sum-verified x/v0.8.1 tree and a NEW
absolute output path. Only the three exact pinned source preimages are patched.
"""
from pathlib import Path
import hashlib
import json
import os
import shutil
import sys

VERSION = 'v0.8.1'
MODULE_SUM = 'h1:cfV/wgagsitTjW18c95OlrrFQTyQtjvDD5+MO3IEIjI='
PREIMAGES = {
    'api/config_bypass.go': '0f0a6178d209aa9bb404a74e688856154471255ad7af54a689a469c777d8f3bf',
    'registry/bypass.go': '491846673ed919f3d1d7426b8fefd9e800fec43a56a4a64d2793eb5f5cddf7b7',
    'bypass/bypass.go': '97c80dae04ebdcc9c48e415b3d9a5213f317ec61f1f336ab60dff13259cf22b8',
}


def once(text, old, new):
    if text.count(old) != 1:
        raise ValueError('sourcePreimage')
    return text.replace(old, new, 1)


def patches(original):
    if set(original) != set(PREIMAGES):
        raise ValueError('sourceSet')
    for name, digest in PREIMAGES.items():
        if hashlib.sha256(original[name]).hexdigest() != digest:
            raise ValueError('sourcePreimage')
    result = {name: data.decode('utf-8') for name, data in original.items()}
    name = 'registry/bypass.go'
    result[name] = once(result[name], '"context"', '"context"\n\t"errors"\n\t"io"\n\t"reflect"')
    result[name] += '''
// ProxyPilot candidate: replace one live object without an absent-registry gap.
// Existing readers may retain the previous object. Closing it MUST NOT clear
// its matcher state; localBypass.Close only stops background loaders.
func ReplaceBypass(name string, value bypass.Bypass) error {
    r, ok := bypassReg.(*bypassRegistry)
    if !ok || name == "" || value == nil {
        return errors.New("bypass: invalid replacement")
    }
    previous, present := r.m.Load(name)
    if !present || previous == nil || !reflect.TypeOf(previous).Comparable() {
        return errors.New("bypass: missing replacement target")
    }
    if !r.m.CompareAndSwap(name, previous, value) {
        return errors.New("bypass: replacement changed")
    }
    if closer, ok := previous.(io.Closer); ok {
        closer.Close()
    }
    return nil
}
'''
    name = 'api/config_bypass.go'
    result[name] = once(result[name], '''\tregistry.BypassRegistry().Unregister(name)

\tif err := registry.BypassRegistry().Register(name, v); err != nil {''',
        '''\tif err := registry.ReplaceBypass(name, v); err != nil {''')
    name = 'bypass/bypass.go'
    result[name] = once(result[name], '''\tgo p.periodReload(ctx)

\treturn p''', '''\t// The API acknowledgement must follow installation of initial matchers.
\tif err := p.reload(ctx); err != nil {
\t\tp.logger.Warnf("reload: %v", err)
\t}
\tgo p.periodReload(ctx)

\treturn p''')
    result[name] = once(result[name], '''func (p *localBypass) periodReload(ctx context.Context) error {
\tif err := p.reload(ctx); err != nil {
\t\tp.logger.Warnf("reload: %v", err)
\t}

''', '''func (p *localBypass) periodReload(ctx context.Context) error {
''')
    return {name: text.encode('utf-8') for name, text in result.items()}


def prepare(download_record, destination):
    record = json.loads(Path(download_record).read_bytes())
    if record.get('Path') != 'github.com/go-gost/x' or record.get('Version') != VERSION or record.get('Sum') != MODULE_SUM:
        raise ValueError('modulePin')
    source = Path(record['Dir'])
    destination = Path(destination)
    if not source.is_absolute() or not source.is_dir() or not destination.is_absolute() or destination.exists() or destination.is_symlink():
        raise ValueError('destination')
    changed = patches({name: (source/name).read_bytes() for name in PREIMAGES})
    destination.mkdir(mode=0o700)
    # Go has verified the complete immutable module zip against the pinned h1.
    # Never modify this shared/cache source tree in place.
    shutil.copytree(source, destination/'x', symlinks=False)
    for path in (destination/'x').rglob('*'):
        path.chmod(0o700 if path.is_dir() else 0o600)
    for name, data in changed.items():
        (destination/'x'/name).write_bytes(data)
    checks = {'registry': Path(__file__).with_name('atomic_bypass_checks_test.go'),
              'api': Path(__file__).with_name('atomic_bypass_api_checks_test.go')}
    for package, path in checks.items():
        shutil.copyfile(path, destination/'x'/package/'proxypilot_atomic_test.go')
    manifest = {'module': 'github.com/go-gost/x', 'version': VERSION, 'upstreamSum': MODULE_SUM,
                'preimages': PREIMAGES, 'patched': {name:hashlib.sha256(data).hexdigest() for name,data in changed.items()},
                'checksSHA256': {package:hashlib.sha256(path.read_bytes()).hexdigest() for package,path in checks.items()},
                'scope': 'candidate only; shipped binary unchanged; no native GOST/VPN acceptance'}
    (destination/'provenance.json').write_text(json.dumps(manifest,indent=2)+'\n')
    return manifest


if __name__ == '__main__':
    if len(sys.argv) != 3:
        raise SystemExit('Expected verified Go download JSON and new absolute destination')
    os.umask(0o077)
    try:
        prepare(sys.argv[1],sys.argv[2])
    except Exception:
        raise SystemExit('Candidate preparation refused')
    print('Prepared candidate sources; nothing installed or executed')
