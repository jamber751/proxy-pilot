"""Server side of the readiness handshake: real processes on both ends.

The helper fixture runs the production listener; the client is the readiness
probe. Both are separate signed processes over a local socket in a disposable
directory. Unprivileged only: no root helper, no launchd, no VPN operation.
"""
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import socket
import subprocess
import sys
import tempfile
import time
import unittest

ROOT = Path(__file__).resolve().parents[1]
HELPER = ROOT / 'app/vpn-helper'
PROFILE = '''client
dev tun
proto udp
remote vpn.company.example 1194
remote-cert-tls server
auth-user-pass
<ca>
-----BEGIN CERTIFICATE-----
QUJDRA==
-----END CERTIFICATE-----
</ca>
'''
CERTIFICATE_PROFILE = '''client
dev tun
proto udp
remote vpn.company.example 1194
remote-cert-tls server
<ca>
-----BEGIN CERTIFICATE-----
QUJDRA==
-----END CERTIFICATE-----
</ca>
<cert>
-----BEGIN CERTIFICATE-----
QUJDRA==
-----END CERTIFICATE-----
</cert>
<key>
-----BEGIN PRIVATE KEY-----
QUJDRA==
-----END PRIVATE KEY-----
</key>
'''


@unittest.skipUnless(sys.platform == 'darwin' and shutil.which('swiftc'), 'macOS Swift required')
class VPNHelperListenerTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if os.geteuid() == 0:
            raise unittest.SkipTest('Never run the listener fixture as root')
        cls.build = tempfile.TemporaryDirectory(prefix='pp-lis-build-', dir='/tmp')
        cls.addClassCleanup(cls.build.cleanup)
        cls.work = Path(cls.build.name)
        for name, sources, flags in [
            ('service', ['VPNPeerAuthentication.swift', 'VPNReleaseAuthorization.swift', 'VPNHelperArtifact.swift',
                         'VPNReleaseStore.swift', 'VPNHelperProtocol.swift', 'VPNApplicationSpec.swift',
                         'VPNTunnelStateStore.swift', 'VPNProfileVault.swift',
                         'OpenVPNManagementEvent.swift', 'OpenVPNStateEvidence.swift',
                         'OpenVPNTransientCredential.swift',
                         'VPNHelperListener.swift', 'VPNEndpointDirectory.swift'], ['-D', 'VPN_HELPER_LISTENER_TESTING']),
            # The probe's normal build demands a root server, which no test may
            # run: only the client side uses the narrow test-policy seam here.
            ('client', ['VPNPeerAuthentication.swift', 'VPNReleaseAuthorization.swift', 'VPNHelperProtocol.swift',
                        'VPNHelperReadiness.swift', 'VPNHelperSession.swift', 'VPNApplicationSpec.swift',
                        'VPNTunnelStateStore.swift', 'VPNHelperTunnelSession.swift'],
             ['-D', 'VPN_HELPER_READINESS_TESTING']),
            ('previous', ['VPNPeerAuthentication.swift', 'VPNReleaseAuthorization.swift', 'VPNHelperProtocol.swift',
                          'VPNHelperReadiness.swift', 'VPNHelperSession.swift', 'VPNApplicationSpec.swift',
                          'VPNTunnelStateStore.swift', 'VPNHelperTunnelSession.swift'],
             ['-D', 'VPN_HELPER_READINESS_TESTING', '-D', 'VPN_PREVIOUS_CLIENT']),
        ]:
            main = 'vpn_helper_service.swift' if name == 'service' else 'vpn_readiness_checks.swift'
            files = [HELPER / source for source in sources] + [ROOT / 'tests' / main]
            if name in ('service', 'client', 'previous'):
                # The helper re-validates profiles with the application's own importer.
                files += [ROOT / 'app/VPNConfiguration.swift', ROOT / 'app/VPNProfileImporter.swift']
            slices = []
            for arch in ('arm64', 'x86_64'):
                output = cls.work / f'{name}-{arch}'
                cls.command(['swiftc', *flags, '-target', f'{arch}-apple-macosx11.0', *map(str, files), '-o', str(output)])
                slices.append(str(output))
            cls.command(['lipo', '-create', *slices, '-output', str(cls.work / name)])
        shutil.copyfile(cls.work / 'client', cls.work / 'stranger')
        shutil.copyfile(cls.work / 'client', cls.work / 'helper-owner')
        (cls.work / 'service').chmod(0o700)
        (cls.work / 'stranger').chmod(0o700)
        (cls.work / 'helper-owner').chmod(0o700)
        cls.pins = {}
        for name, identifier in [('service', 'kz.documentolog.proxypilot.vpn-helper'),
                                 ('client', 'kz.documentolog.proxypilot'),
                                 ('previous', 'kz.documentolog.proxypilot'),
                                 ('helper-owner', 'kz.documentolog.proxypilot.vpn-helper'),
                                 ('stranger', 'kz.documentolog.proxypilot.other')]:
            cls.command(['codesign', '--force', '--sign', '-', '--identifier', identifier,
                         '--options', 'runtime,hard,kill', str(cls.work / name)])
            cls.pins[name] = {}
            for arch in ('arm64', 'x86_64'):
                result = cls.command(['codesign', '-d', '--verbose=4', '--arch', arch, str(cls.work / name)])
                cls.pins[name][arch] = re.search(r'^CDHash=([a-f0-9]{40})$', result.stderr, re.M).group(1)

    @staticmethod
    def command(args):
        result = subprocess.run(args, capture_output=True, text=True, timeout=180)
        if result.returncode:
            raise AssertionError(' '.join(map(str, args)) + '\n' + result.stdout + result.stderr)
        return result

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='pp-lis-', dir='/tmp')
        self.addCleanup(self.temp.cleanup)
        self.base = Path(self.temp.name)
        self.storage = self.base / 'store'
        self.storage.mkdir(mode=0o700)
        self.endpoint = self.storage / 'helper.sock'

    def seed(self, sequence=10, application='client'):
        artifact = (self.work / 'service').read_bytes()
        fields = {'format': 1, 'product': 'kz.documentolog.proxypilot', 'sequence': sequence,
                  'version': '1.6.0', 'protocol': 1,
                  'app-arm64': self.pins[application]['arm64'], 'app-x86_64': self.pins[application]['x86_64'],
                  'helper-arm64': self.pins['service']['arm64'], 'helper-x86_64': self.pins['service']['x86_64'],
                  'helper-sha256': hashlib.sha256(artifact).hexdigest(), 'helper-bytes': len(artifact)}
        manifest, candidate = self.base / 'manifest', self.base / 'candidate'
        manifest.write_text(''.join(f'{key}={value}\n' for key, value in fields.items()))
        candidate.write_bytes(artifact)
        result = subprocess.run([str(self.work / 'service'), 'seed', str(self.storage), str(manifest), str(candidate)],
                                capture_output=True, text=True, timeout=60)
        self.assertEqual(result.stdout.strip(), f'selected:{sequence}', result.stdout + result.stderr)

    def serve(self, ready=True, extra=None):
        arguments = [str(self.work / 'service'), 'serve', str(self.storage)] + (extra or ([] if ready else ['not-ready']))
        service = subprocess.Popen(arguments, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True)
        self.addCleanup(service.stdout.close)
        self.addCleanup(service.wait, 30)
        self.addCleanup(service.kill)
        # Never read a live process's stderr here: it would block until exit.
        self.assertEqual(service.stdout.readline().strip(), 'listening')
        return service

    def session(self, scenario, client='client', timeout=2000):
        result = subprocess.run([str(self.work / client), 'session', str(self.endpoint),
                                 self.pins['service']['arm64'], str(timeout), scenario],
                                capture_output=True, text=True, timeout=60)
        return result.stdout.strip().splitlines()

    def probe(self, client='client', timeout=2000):
        result = subprocess.run([str(self.work / client), 'probe', str(self.endpoint),
                                 self.pins['service']['arm64'], str(timeout)],
                                capture_output=True, text=True, timeout=60)
        return result.stdout.strip()

    def test_authenticated_client_receives_a_receipt(self):
        self.seed()
        self.serve()
        self.assertEqual(self.probe(), 'ready:10 closed')

    def test_sequential_clients_are_each_served(self):
        self.seed()
        self.serve()
        self.assertEqual(self.probe(), 'ready:10 closed')
        self.assertEqual(self.probe(), 'ready:10 closed')

    def test_client_with_another_identity_is_refused(self):
        self.seed()
        self.serve()
        self.assertIn('rejected:', self.probe(client='stranger'))
        # The refused peer costs one connection; the listener keeps serving.
        self.assertEqual(self.probe(), 'ready:10 closed')

    def test_client_outside_the_release_pins_is_refused(self):
        self.seed(application='stranger')
        self.serve()
        self.assertIn('rejected:', self.probe())

    def test_helper_that_is_not_ready_answers_nothing(self):
        self.seed()
        self.serve(ready=False)
        self.assertIn('rejected:', self.probe())

    def test_challenge_for_another_release_is_refused(self):
        self.seed(sequence=11)
        self.serve()
        self.assertIn('rejected:', self.probe())

    def test_endpoint_is_private_to_its_owner(self):
        self.seed()
        self.serve()
        self.assertTrue(self.endpoint.is_socket())
        self.assertEqual(self.endpoint.stat().st_mode & 0o7777, 0o600)
        self.assertEqual(self.endpoint.stat().st_uid, os.geteuid())

    def test_an_existing_endpoint_is_never_stolen(self):
        self.seed()
        self.endpoint.write_bytes(b'')
        result = subprocess.run([str(self.work / 'service'), 'serve', str(self.storage)],
                                capture_output=True, text=True, timeout=60)
        self.assertEqual(result.returncode, 71, result.stdout + result.stderr)
        self.assertIn('unavailable', result.stderr)
        self.assertFalse(self.endpoint.is_socket())

    def test_shared_storage_directory_is_refused(self):
        self.seed()
        self.storage.chmod(0o755)
        result = subprocess.run([str(self.work / 'service'), 'serve', str(self.storage)],
                                capture_output=True, text=True, timeout=60)
        self.assertEqual(result.returncode, 71, result.stdout + result.stderr)
        self.assertFalse(self.endpoint.exists())

    def test_a_silent_client_does_not_block_the_next_one(self):
        self.seed()
        self.serve()
        silent = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.addCleanup(silent.close)
        silent.connect(str(self.endpoint))
        # The listener spends only its own deadline on this peer, then moves on.
        self.assertEqual(self.probe(timeout=5000), 'ready:10 closed')

    def test_status_answers_the_running_release(self):
        self.seed()
        self.serve()
        self.assertEqual(self.session('status'), ['answer:ok sequence:10 protocol:1'])

    def test_several_requests_share_one_authenticated_connection(self):
        self.seed()
        self.serve()
        self.assertEqual(self.session('twice'), ['answer:ok sequence:10 protocol:1'] * 2)

    def test_a_connection_is_spent_after_its_request_budget(self):
        self.seed()
        self.serve()
        answers = self.session('limit')
        self.assertEqual(answers.count('answer:ok sequence:10 protocol:1'), 8)
        self.assertEqual(answers[-1], 'request9:exhausted')
        # The listener is free again for the next connection.
        self.assertEqual(self.session('status'), ['answer:ok sequence:10 protocol:1'])

    def test_an_unknown_operation_is_refused(self):
        self.seed()
        self.serve()
        self.assertEqual(self.session('unknown'), ['answer:1'])

    def test_a_request_for_another_revision_is_refused(self):
        self.seed()
        self.serve()
        self.assertEqual(self.session('revision'), ['answer:2'])

    def test_an_unexpected_payload_is_refused(self):
        self.seed()
        self.serve()
        self.assertEqual(self.session('payload'), ['answer:2'])

    def test_an_oversized_frame_ends_the_connection_without_reading_it(self):
        self.seed()
        self.serve()
        started = time.monotonic()
        self.assertEqual(self.session('oversize'), ['answer:closed'])
        # Refused on the header, not by waiting out a deadline for a megabyte.
        self.assertLess(time.monotonic() - started, 2)
        self.assertEqual(self.session('status'), ['answer:ok sequence:10 protocol:1'])

    def test_the_helper_stops_answering_after_its_own_request_budget(self):
        self.seed()
        self.serve()
        self.assertEqual(self.session('flood'), ['answered:8'])
        self.assertEqual(self.session('status'), ['answer:ok sequence:10 protocol:1'])

    def test_a_malformed_frame_ends_the_connection(self):
        self.seed()
        self.serve()
        self.assertEqual(self.session('garbage'), ['answer:closed'])

    def store_profile(self, text, client='client'):
        candidate = self.base / 'candidate.ovpn'
        candidate.write_text(text)
        return self.session(f'profile={candidate}', client=client)

    def test_a_valid_profile_is_revalidated_and_kept(self):
        self.seed()
        self.serve()
        self.assertEqual(self.store_profile(PROFILE), ['answer:0 body:0'])
        stored = self.storage / 'profile.ovpn'
        # What is kept is the importer's normalized form, not the client's bytes.
        kept = stored.read_text()
        self.assertIn('remote "vpn.company.example" "1194"', kept)
        self.assertIn('BEGIN CERTIFICATE', kept)
        # The importer's hardening travels with the stored bytes.
        self.assertIn('script-security 1', kept)
        self.assertEqual(stored.stat().st_mode & 0o7777, 0o600)

    def test_the_helper_refuses_what_its_own_importer_rejects(self):
        self.seed()
        self.serve()
        # A client could have "imported" this happily; the helper decides again.
        self.assertEqual(self.store_profile(PROFILE + 'up /tmp/script\n'), ['answer:2 body:0'])
        self.assertFalse((self.storage / 'profile.ovpn').exists())

    def test_a_rejected_profile_leaves_the_stored_one_untouched(self):
        self.seed()
        self.serve()
        self.assertEqual(self.store_profile(PROFILE), ['answer:0 body:0'])
        kept = (self.storage / 'profile.ovpn').read_text()
        self.assertEqual(self.store_profile('not a profile'), ['answer:2 body:0'])
        self.assertEqual((self.storage / 'profile.ovpn').read_text(), kept)

    def test_an_empty_profile_is_refused(self):
        self.seed()
        self.serve()
        self.assertEqual(self.store_profile(''), ['answer:2 body:0'])
        self.assertFalse((self.storage / 'profile.ovpn').exists())

    def test_a_profile_larger_than_the_frame_limit_is_never_sent(self):
        self.seed()
        self.serve()
        self.assertEqual(self.store_profile(PROFILE + '#' + 'x' * 1_048_576), ['request:payloadTooLarge'])
        self.assertFalse((self.storage / 'profile.ovpn').exists())

    def test_profile_above_old_frame_limit_is_accepted(self):
        self.seed()
        self.serve()
        self.assertEqual(self.store_profile(PROFILE + ('# padding\n' * 8000)), ['answer:0 body:0'])

    def test_profile_at_importer_limit_is_accepted(self):
        self.seed()
        self.serve()
        padding = 1_048_576 - len(PROFILE.encode())
        text = PROFILE + ('#\n' * (padding // 2)) + ('\n' if padding % 2 else '')
        self.assertEqual(len(text.encode()), 1_048_576)
        self.assertEqual(self.store_profile(text), ['answer:0 body:0'])

    def test_inert_application_transaction_and_one_shot_credential(self):
        self.seed()
        self.serve()
        candidate = self.base / 'candidate.ovpn'
        candidate.write_text(PROFILE)
        self.assertEqual(self.session(f'application={candidate}'), [
            'store:0', 'apply:0', 'connect:4 kind:1 generation:1',
            'before:needsCredential', 'submit:5', 'replay:2',
            'after:failed challenge:false', 'disconnect:0'])
        state = (self.storage / 'tunnel-state.json').read_text()
        self.assertNotIn('NEVER-PERSIST-THIS-CREDENTIAL', state)
        self.assertNotIn('secret', state.lower())
        decoded = json.loads(state)
        self.assertFalse(decoded['desiredEnabled'])
        self.assertEqual(decoded['phase'], 'off')

    def test_certificate_connect_starts_held_runtime_but_never_claims_connected(self):
        self.seed()
        trace = self.base / 'tunnel-trace'
        self.serve(extra=['tunnel-test', str(trace)])
        candidate = self.base / 'certificate.ovpn'
        candidate.write_text(CERTIFICATE_PROFILE)
        self.assertEqual(self.session(f'certificate={candidate}'), [
            'store:0', 'apply:0', 'connect:5 challenge:false',
            'held:connecting enabled:true', 'disconnect:0',
            'stopped:off enabled:false'])
        self.assertEqual(trace.read_text().splitlines(), ['start-held', 'stop-before-off'])
        state = json.loads((self.storage / 'tunnel-state.json').read_text())
        self.assertEqual(state['phase'], 'off')
        self.assertFalse(state['desiredEnabled'])
        self.assertNotIn('connected', (self.storage / 'tunnel-state.json').read_text().lower())

    def test_verified_route_runtime_publishes_connected_and_disconnects(self):
        self.seed()
        trace = self.base / 'connected-trace'
        self.serve(extra=['managed-connected-test', str(trace)])
        candidate = self.base / 'certificate.ovpn'
        candidate.write_text(CERTIFICATE_PROFILE)
        self.assertEqual(self.session(f'certificate={candidate}'), [
            'store:0', 'apply:0', 'connect:0 challenge:false',
            'held:connected enabled:true', 'disconnect:0',
            'stopped:off enabled:false'])
        self.assertEqual(trace.read_text().splitlines(), [
            'routes-verified', 'stop-before-off'])

    def test_credential_submission_never_starts_the_engine(self):
        self.seed()
        trace = self.base / 'credential-trace'
        self.serve(extra=['tunnel-test', str(trace)])
        candidate = self.base / 'candidate.ovpn'
        candidate.write_text(PROFILE)
        self.assertEqual(self.session(f'application={candidate}'), [
            'store:0', 'apply:0', 'connect:4 kind:1 generation:1',
            'before:needsCredential', 'submit:5', 'replay:2',
            'after:failed challenge:false', 'disconnect:0'])
        self.assertEqual(trace.read_text().splitlines(), ['stop-before-off'])

    def test_management_prompt_is_issued_after_start_and_submit_is_claimed_once(self):
        self.seed()
        trace = self.base / 'managed-trace'
        self.serve(extra=['managed-tunnel-test', str(trace)])
        candidate = self.base / 'candidate.ovpn'
        candidate.write_text(PROFILE)
        self.assertEqual(self.session(f'application={candidate}'), [
            'store:0', 'apply:0', 'connect:4 kind:1 generation:1',
            'before:needsCredential', 'submit:5', 'replay:3',
            'after:failed challenge:false', 'disconnect:0'])
        self.assertEqual(trace.read_text().splitlines(), [
            'management-prompt', 'credential-claimed', 'stop-before-off'])
        state = (self.storage / 'tunnel-state.json').read_text()
        self.assertNotIn('NEVER-PERSIST-THIS-CREDENTIAL', state)
        self.assertNotIn('secret', state.lower())

    def test_cancelled_management_prompt_stops_owned_runtime_before_off(self):
        self.seed()
        trace = self.base / 'managed-cancel-trace'
        self.serve(extra=['managed-tunnel-test', str(trace)])
        candidate = self.base / 'candidate.ovpn'
        candidate.write_text(PROFILE)
        self.assertEqual(self.session(f'managed-cancel={candidate}'), [
            'store:0', 'apply:0', 'connect:4 kind:1 generation:1',
            'before:needsCredential', 'cancel:0', 'after:off enabled:false'])
        self.assertEqual(trace.read_text().splitlines(), [
            'management-prompt', 'stop-before-off'])

    def test_listener_teardown_stops_a_held_runtime(self):
        self.seed()
        trace = self.base / 'teardown-trace'
        service = self.serve(extra=['tunnel-once', str(trace)])
        candidate = self.base / 'certificate.ovpn'
        candidate.write_text(CERTIFICATE_PROFILE)
        self.assertEqual(self.session(f'certificate-once={candidate}'), [
            'store:0', 'apply:0', 'connect:5 challenge:false',
            'held:connecting enabled:true'])
        self.assertEqual(service.wait(timeout=10), 0)
        self.assertEqual(trace.read_text().splitlines(), ['start-held', 'stop-before-off'])

    def test_public_endpoint_keeps_profile_in_private_storage(self):
        self.seed()
        ipc = self.base / 'ipc'
        ipc.mkdir(mode=0o755)
        self.endpoint = ipc / 'helper.sock'
        self.serve(extra=['shared', str(ipc)])
        self.assertEqual(self.endpoint.stat().st_mode & 0o7777, 0o666)
        self.assertEqual(self.storage.stat().st_mode & 0o7777, 0o700)
        self.assertEqual(self.store_profile(PROFILE), ['answer:0 body:0'])
        self.assertEqual(list(ipc.iterdir()), [self.endpoint])
        self.assertEqual((self.storage / 'profile.ovpn').stat().st_mode & 0o7777, 0o600)
        self.assertIn('rejected:', self.probe(client='stranger'))

    def test_installation_role_only_gets_readiness(self):
        self.seed()
        self.serve(extra=['installer-test'])
        self.assertEqual(self.probe(), 'ready:10 closed')
        self.assertNotIn('answer:0 body:0', self.store_profile(PROFILE))
        self.assertFalse((self.storage / 'profile.ovpn').exists())
        self.assertNotEqual(self.session('status'), ['answer:ok sequence:10 protocol:1'])
        self.assertEqual(self.probe(), 'ready:10 closed')

    def transition_service(self, state='enabled', client='previous', role='installer-transition-test'):
        policy_state = self.base / 'transition-policy'
        policy_state.write_text(state)
        self.serve(extra=[role, self.pins[client]['arm64'],
                          self.pins[client]['x86_64'], str(policy_state)])
        return policy_state

    def test_previous_app_is_readiness_only_while_transition_policy_exists(self):
        self.seed()
        self.transition_service()
        self.assertEqual(self.probe(client='previous'), 'ready:10 closed')
        self.assertNotEqual(self.session('status', client='previous'),
                            ['answer:ok sequence:10 protocol:1'])
        self.assertNotIn('answer:0 body:0', self.store_profile(PROFILE, client='previous'))
        self.assertFalse((self.storage / 'profile.ovpn').exists())

    def test_previous_app_is_rejected_after_transition_policy_disappears(self):
        self.seed()
        policy_state = self.transition_service()
        self.assertEqual(self.probe(client='previous'), 'ready:10 closed')
        policy_state.unlink()
        self.assertIn('rejected:', self.probe(client='previous'))
        # The selected app remains the ordinary authenticated fixture owner.
        self.assertEqual(self.probe(), 'ready:10 closed')

    def test_transition_policy_is_rechecked_immediately_before_readiness_reply(self):
        self.seed()
        self.transition_service(state='retire-after-first-check')
        self.assertIn('rejected:', self.probe(client='previous'))

    def test_transition_policy_never_admits_an_unrelated_client(self):
        self.seed()
        self.transition_service()
        self.assertIn('rejected:', self.probe(client='stranger'))
        self.assertEqual(self.probe(client='previous'), 'ready:10 closed')

    def test_selected_helper_is_readiness_only_until_its_transition_policy_disappears(self):
        self.seed()
        policy_state = self.transition_service(client='helper-owner', role='helper-transition-test')
        self.assertEqual(self.probe(client='helper-owner'), 'ready:10 closed')
        self.assertNotEqual(self.session('status', client='helper-owner'),
                            ['answer:ok sequence:10 protocol:1'])
        policy_state.unlink()
        self.assertIn('rejected:', self.probe(client='helper-owner'))

    def test_owner_is_refused_before_readiness_when_operations_are_blocked(self):
        self.seed()
        self.serve(extra=['owner-blocked'])
        self.assertIn('rejected:', self.probe())
        self.assertNotEqual(self.session('status'), ['answer:ok sequence:10 protocol:1'])
