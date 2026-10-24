"""Genuine signed frontend negative entry checks. Never launches its GUI/CLI,
normal app mode, proxies, VPN or a credential/interaction-setting API.
"""
from pathlib import Path
import hashlib
import os
import shutil
import signal
import subprocess
import sys
import tempfile
import unittest

from test_vpn_update_broker_inbox import assert_real_signed_app_survives_inbox

ROOT = Path(__file__).resolve().parents[1]


def snapshot_frontend_sources(snapshot):
    snapshot = Path(snapshot)
    # Capture only public source/build inputs, never app/build artifacts,
    # profiles or a user's application state. Both architectures compile
    # the same bytes even if another task subsequently edits the checkout.
    paths = [ROOT / name for name in ('app/build.sh', 'app/fetch-sparkle.sh',
                                     'app/updater-public-key.txt', 'bin/proxypilot')]
    for directory in ('app', 'app/vpn-helper', 'app/update-worker'):
        paths.extend(sorted((ROOT / directory).glob('*.swift')))
    captured = {path: path.read_bytes() for path in paths}
    for path, data in captured.items():
        target = snapshot / path.relative_to(ROOT)
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(data)
        target.chmod(path.stat().st_mode & 0o777)
    if any(path.read_bytes() != data for path, data in captured.items()):
        raise AssertionError('Frontend sources changed during snapshot')
    archive = ROOT / 'vendor/sparkle-2.9.6/Sparkle.zip'
    if archive.is_file():
        target = snapshot / archive.relative_to(ROOT)
        target.parent.mkdir(parents=True)
        shutil.copyfile(archive, target)
    return {str(path.relative_to(ROOT)): hashlib.sha256(data).hexdigest()
            for path, data in captured.items()}


class VPNPasswordFrontendContractTests(unittest.TestCase):
    def test_installer_only_build_and_early_closed_dispatch(self):
        source = (ROOT / 'app/main.swift').read_text()
        dispatch = source.index('if let status = VPNPasswordWorker.runIfRequested(')
        self.assertLess(source.rfind('#if VPN_INSTALLER_ENTRY', 0, dispatch), dispatch)
        self.assertLess(dispatch, source.index('if let status = VPNInstallationEntry.runIfRequested('))
        self.assertLess(dispatch, source.index('let app = NSApplication.shared'))
        self.assertIn('if CommandLine.arguments.dropFirst().contains(where: { $0.hasPrefix("--vpn-") }) { exit(64) }', source)
        build = (ROOT / 'app/build.sh').read_text()
        installer = build.split('if [[ "$VPN_INSTALLER" == 1 ]]; then\n  SOURCES+=', 1)[1].split('\nfi', 1)[0]
        for name in ('VPNPasswordWorker.swift', 'VPNPasswordWorkerWire.swift',
                     'VPNPasswordWorkerIdentity.swift', 'VPNLegacyPasswordBackend.swift',
                     'VPNPasswordWorkerSession.swift'):
            self.assertIn('"$HERE/' + name + '"', installer)
        panel = (ROOT / 'app/VPNPanel.swift').read_text()
        self.assertIn('controller = VPNLiveController(store: store)', panel)
        self.assertNotIn('VPNPasswordWorkerSession', panel)
        # This increment must not turn coordinator defaults or lifecycle on.
        for name in ('VPNPasswordPersistenceCoordinator.swift', 'VPNPasswordCleanupCoordinator.swift'):
            self.assertIn('available: Bool = false', (ROOT / 'app' / name).read_text())


@unittest.skipUnless(sys.platform == 'darwin' and shutil.which('swiftc') and os.geteuid() >= 500,
                     'Ordinary macOS user and Swift required')
class VPNPasswordGenuineFrontendTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.folder = tempfile.TemporaryDirectory(prefix='pp password frontend ')
        cls.addClassCleanup(cls.folder.cleanup)
        folder = Path(cls.folder.name)
        snapshot = folder / 'Source'
        snapshot_frontend_sources(snapshot)
        environment = dict(os.environ, PROXYPILOT_VPN_INSTALLER='1',
                           PROXYPILOT_VPN_RELEASE_SEQUENCE='140', PROXYPILOT_ISOLATED_UPDATER='1')
        output = folder / 'Build'
        process = subprocess.Popen(['zsh', str(snapshot / 'app/build.sh'), str(output)],
                                   env=environment, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                   text=True, start_new_session=True)
        try:
            stdout, stderr = process.communicate(timeout=720)
        except subprocess.TimeoutExpired:
            # Compilers only, never a credential API: quiesce this own process
            # group before TemporaryDirectory may delete its build inputs.
            try: os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError: pass
            process.communicate(timeout=10)
            raise AssertionError('Own frontend compilation exceeded its bounded budget')
        if process.returncode: raise AssertionError(stdout[-2000:] + stderr[-8000:])
        cls.app = output / 'ProxyPilot.app'
        cls.binary = cls.app / 'Contents/MacOS/ProxyPilot'
        result = subprocess.run(['/usr/bin/codesign', '--verify', '--deep', '--strict', str(cls.app)],
                                capture_output=True, text=True, timeout=20)
        if result.returncode: raise AssertionError(result.stderr)
        result = subprocess.run(['/usr/bin/lipo', '-archs', str(cls.binary)],
                                capture_output=True, text=True, timeout=10)
        if result.returncode or set(result.stdout.split()) != {'arm64', 'x86_64'}:
            raise AssertionError('Genuine frontend must include both architectures')

    def assert_refused_without_gui(self, args, status):
        # Python is deliberately not an authenticated same-image parent, and
        # descriptors 20/21 are absent. The child must reject before factory/GUI.
        result = subprocess.run([str(self.binary), *args], stdin=subprocess.DEVNULL,
                                capture_output=True, close_fds=True,
                                env={'PATH': '/usr/bin:/bin:/usr/sbin:/sbin'}, timeout=8)
        self.assertEqual(result.returncode, status)
        self.assertEqual(result.stdout, b'')
        self.assertEqual(result.stderr, b'')

    def test_already_built_signed_frontend_preserves_sparkle_links_in_real_inbox(self):
        # Share this class's actual signed app; never build another app or use
        # a host-installed/environment-selected application for this acceptance.
        assert_real_signed_app_survives_inbox(self, self.app)

    def test_actual_v2_without_authenticated_parent_or_private_fds_is_denied(self):
        self.assert_refused_without_gui(['--vpn-password-worker-v2'], 77)

    def test_actual_old_future_and_malformed_roles_are_refused_before_gui(self):
        for args in (['--vpn-password-worker-v1'], ['--vpn-password-worker-v3'],
                     ['--vpn-password-worker'], ['--vpn-password-worker-v2', 'extra'],
                     ['extra', '--vpn-password-worker-v2']):
            with self.subTest(args=args): self.assert_refused_without_gui(args, 64)


if __name__ == '__main__': unittest.main()
