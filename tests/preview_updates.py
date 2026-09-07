"""Build a disposable UI preview with fake proxies; never runs the real CLI."""
from pathlib import Path
import argparse
import plistlib
import shutil
import subprocess

ROOT = Path(__file__).resolve().parents[1]
parser = argparse.ArgumentParser()
parser.add_argument('--scenario', choices=['configured', 'empty', 'error'], default='configured')
parser.add_argument('--persistent', action='store_true', help='Keep the test popover open during screenshot inspection')
parser.add_argument('--real-updater', action='store_true', help='Exercise Sparkle in this disposable app only; never click Install')
args = parser.parse_args()
variant = args.scenario + ('.persistent' if args.persistent else '') + ('.updater' if args.real_updater else '')
OUT = ROOT / 'app/build/update-preview' / variant
APP = OUT / 'ProxyPilot Updates Preview.app'
OUT.mkdir(parents=True, exist_ok=True)
if APP.exists():
    shutil.rmtree(APP)
shutil.copytree(ROOT / 'app/build/ProxyPilot.app', APP, symlinks=True)
info_path = APP / 'Contents/Info.plist'
info = plistlib.loads(info_path.read_bytes())
info['CFBundleIdentifier'] = 'kz.documentolog.proxypilot.updates.' + variant + '.preview'
info['CFBundleName'] = 'ProxyPilot Updates Preview'
info['CFBundleDisplayName'] = 'ProxyPilot — ТЕСТОВЫЙ МАКЕТ'
info['PreviewAppearance'] = 'dark'
info['SUEnableAutomaticChecks'] = False
info_path.write_bytes(plistlib.dumps(info))
source = (ROOT / 'app/main.swift').read_text()
if args.real_updater:
    source = source.replace('updates.start(preview: model.preview)', 'updates.start(preview: false)')
if args.persistent:
    source = source.replace('popover.behavior = .transient', 'popover.behavior = .applicationDefined')
source = source.replace('private let model = ProxyModel(preview: Bundle.main.bundleIdentifier?.hasSuffix(".preview") == true)', '''private let model: ProxyModel = {
    let model = ProxyModel(preview: true)
    model.state = ProxyState(configured: true, enabled: true, running: "socks", system_proxy: true,
        selected: "socks", has_socks: true, has_http: true,
        socks_endpoint: "proxy.example:1080", http_endpoint: "proxy.example:3128")
    model.editing = true
    return model
}()''')
if args.scenario == 'empty':
    source = source.replace('    model.editing = true\n    return model', '''    model.state = ProxyState(configured: false, enabled: false, running: "none", system_proxy: false)
    model.editing = true
    return model''')
elif args.scenario == 'error':
    source = source.replace('    model.editing = true\n    return model', '''    model.error = "Не удалось найти прокси в этой сети. Проверьте подключение, доступ к локальной сети в настройках macOS и повторите попытку."
    model.editing = true
    return model''')
main = OUT / 'main.swift'
main.write_text(source)
subprocess.run(['swiftc', '-module-cache-path', str(ROOT / 'app/build/ModuleCache'),
                '-F', str(APP / 'Contents/Frameworks'), '-framework', 'Sparkle',
                '-Xlinker', '-rpath', '-Xlinker', '@executable_path/../Frameworks',
                str(main), str(ROOT / 'app/Updates.swift'), str(ROOT / 'app/Controls.swift'),
                '-o', str(APP / 'Contents/MacOS/ProxyPilot')], check=True)
subprocess.run(['codesign', '--force', '--sign', '-', str(APP)], check=True)
print(APP)
