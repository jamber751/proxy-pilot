"""Prove hardened ad-hoc frontend + separate Sparkle information-only worker.

Uses a disposable uniquely identified bundle and an existing signed local feed.
Never downloads/installs an update, accesses a signing key or changes ProxyPilot.
"""
from functools import partial
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
import plistlib
import shutil
import subprocess
import sys
import tempfile
import threading
import unittest
import uuid

ROOT = Path(__file__).resolve().parents[1]
FRAMEWORK = ROOT / 'vendor/sparkle-2.9.6/Sparkle.xcframework/macos-arm64_x86_64/Sparkle.framework'
FEED = ROOT / 'dist/updates/appcast.xml'


class Handler(SimpleHTTPRequestHandler):
    requests = []

    def do_GET(self):
        self.requests.append(self.path)
        super().do_GET()

    def log_message(self, *args):
        pass


@unittest.skipUnless(sys.platform == 'darwin' and shutil.which('swiftc') and FRAMEWORK.exists()
                     and FEED.exists(), 'macOS, Sparkle and local signed feed required')
class VPNUpdaterIsolationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp = tempfile.TemporaryDirectory(prefix='proxypilot-updater-isolation-')
        cls.addClassCleanup(cls.temp.cleanup)
        cls.work = Path(cls.temp.name)
        cls.server = ThreadingHTTPServer(('127.0.0.1', 0), partial(Handler, directory=str(cls.work)))
        threading.Thread(target=cls.server.serve_forever, daemon=True).start()
        cls.addClassCleanup(cls.server.server_close)
        cls.addClassCleanup(cls.server.shutdown)
        cls.app = cls.work / 'ProxyPilot Isolation TEST.app'
        cls.worker = cls.app / 'Contents/Helpers/Update Probe.app'
        cls.binary = cls.app / 'Contents/MacOS/Frontend'
        cls.worker_binary = cls.worker / 'Contents/MacOS/UpdateProbe'
        cls.binary.parent.mkdir(parents=True)
        cls.worker_binary.parent.mkdir(parents=True)
        (cls.worker / 'Contents/Frameworks').mkdir()
        cls.run_command(['ditto', str(FRAMEWORK), str(cls.worker / 'Contents/Frameworks/Sparkle.framework')])
        for name, output, sparkle in [('Frontend', cls.binary, False), ('UpdateProbe', cls.worker_binary, True)]:
            slices = []
            for arch in ('arm64', 'x86_64'):
                binary = cls.work / f'{name}-{arch}'
                args = ['swiftc', '-parse-as-library', '-target', f'{arch}-apple-macosx11.0']
                if sparkle:
                    args += ['-F', str(FRAMEWORK.parent), '-framework', 'Sparkle',
                             '-Xlinker', '-rpath', '-Xlinker', '@executable_path/../Frameworks']
                cls.run_command([*args, str(ROOT / f'tests/vpn-updater-isolation/{name}.swift'), '-o', str(binary)])
                slices.append(str(binary))
            cls.run_command(['lipo', '-create', *slices, '-output', str(output)])
        cls.identifier = 'kz.documentolog.proxypilot.isolationtest.' + uuid.uuid4().hex
        for domain in (cls.identifier, cls.identifier + '.updater'):
            cls.addClassCleanup(subprocess.run, ['defaults', 'delete', domain], capture_output=True)
        host_info = dict(
            CFBundleIdentifier=cls.identifier, CFBundleExecutable='Frontend',
            CFBundleName='ProxyPilot Isolation TEST', CFBundlePackageType='APPL',
            CFBundleVersion='0.0.1', CFBundleShortVersionString='0.0.1', LSMinimumSystemVersion='11.0',
            SUFeedURL=f'http://127.0.0.1:{cls.server.server_port}/appcast.xml',
            SUPublicEDKey=(ROOT / 'app/updater-public-key.txt').read_text().strip(),
            SUEnableAutomaticChecks=False, SUAutomaticallyUpdate=False, SUAllowsAutomaticUpdates=False,
            SURequireSignedFeed=True, SUVerifyUpdateBeforeExtraction=True, SUSignedFeedFailureExpirationInterval=0)
        worker_info = dict(
            CFBundleIdentifier=cls.identifier + '.updater', CFBundleExecutable='UpdateProbe',
            CFBundleName='Update Probe TEST', CFBundlePackageType='APPL',
            # Higher than the feed: a successful update check must target the host.
            CFBundleVersion='999.0.0', CFBundleShortVersionString='999.0.0', LSMinimumSystemVersion='11.0',
            NSAppTransportSecurity={'NSAllowsArbitraryLoads': True})  # Test loopback only.
        (cls.app / 'Contents/Info.plist').write_bytes(plistlib.dumps(host_info))
        (cls.worker / 'Contents/Info.plist').write_bytes(plistlib.dumps(worker_info))
        cls.run_command(['codesign', '--force', '--sign', '-', str(cls.worker)])
        cls.run_command(['codesign', '--force', '--sign', '-', '--options', 'runtime,hard,kill', str(cls.app)])
        cls.run_command(['codesign', '--verify', '--deep', '--strict', str(cls.app)])

    @staticmethod
    def run_command(args):
        result = subprocess.run(args, capture_output=True, text=True, timeout=90)
        if result.returncode:
            raise AssertionError(result.stderr)
        return result

    def probe(self, feed):
        Handler.requests.clear()
        target = self.work / 'appcast.xml'
        if feed is None:
            target.unlink(missing_ok=True)
        else:
            target.write_bytes(feed)
        result = subprocess.run([str(self.binary)], capture_output=True, text=True, timeout=20)
        self.assertIn('FRONTEND_HARDENED', result.stdout, result.stdout + result.stderr)
        self.assertTrue(Handler.requests)
        self.assertTrue(all(path == '/appcast.xml' for path in Handler.requests), Handler.requests)
        return result

    def test_hardened_frontend_can_check_host_updates_out_of_process(self):
        result = self.probe(FEED.read_bytes())
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn('VALID_UPDATE_FOR_HOST', result.stdout)

    def test_modified_feed_is_rejected_by_worker(self):
        result = self.probe(FEED.read_bytes().replace(b'ProxyPilot', b'ProxyPiloX'))
        self.assertEqual(result.returncode, 2, result.stdout + result.stderr)

    def test_missing_feed_finishes_without_false_update(self):
        result = self.probe(None)
        self.assertEqual(result.returncode, 2, result.stdout + result.stderr)

    def test_frontend_does_not_link_sparkle(self):
        frontend = self.run_command(['otool', '-L', str(self.binary)]).stdout
        worker = self.run_command(['otool', '-L', str(self.worker_binary)]).stdout
        self.assertNotIn('Sparkle.framework', frontend)
        self.assertIn('Sparkle.framework', worker)
