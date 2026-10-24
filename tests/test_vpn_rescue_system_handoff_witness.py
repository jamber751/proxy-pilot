"""Pure source/record/filesystem checks only; no process/network/root APIs."""
from copy import deepcopy
import hashlib
import json
import os
from pathlib import Path
import stat
import platform
import shutil
import subprocess
import sys
import tempfile
from types import SimpleNamespace
import unittest
import uuid

import test_vpn_rescue_system_vm as vm


class HandoffWitnessTests(unittest.TestCase):
    def fixture(self):
        gate = {'schema': 1, 'nonce': '12345678-1234-1234-1234-123456789abc', 'pid': 123,
                'seconds': 456, 'microseconds': 789, 'from': 141, 'to': 142, 'identity': 'ab' * 32}
        transaction = bytearray(128)
        transaction[:8] = b'PPBT\0\0\0\1'; transaction[8:10] = (1).to_bytes(2, 'big')
        for start, value in ((10, 7), (12, 4), (14, 3), (104, 4)):
            transaction[start:start+2] = value.to_bytes(2, 'big')
        transaction[16:20] = (1).to_bytes(4, 'big'); transaction[24:56] = bytes.fromhex(gate['identity'])
        for start, value in ((56, 141), (64, 142), (72, 12), (96, 3)):
            transaction[start:start+8] = value.to_bytes(8, 'big')
        identifier = uuid.UUID('99999999-1234-1234-1234-123456789abc')
        transaction[80:96] = identifier.bytes
        checksum = 0xcbf29ce484222325
        for byte in transaction[:-8]: checksum = ((checksum ^ byte) * 0x100000001b3) & (2**64 - 1)
        transaction[-8:] = checksum.to_bytes(8, 'big')
        node = SimpleNamespace(st_dev=1, st_ino=2, st_uid=0, st_mode=stat.S_IFDIR | 0o700)
        witness = {'gate': deepcopy(gate), 'transaction': str(identifier), 'inboxDevice': 1, 'inboxInode': 2}
        return gate, witness, bytes(transaction), node

    def test_committed_same_actor_matches_after_rotation_without_live_pid(self):
        gate, witness, transaction, node = self.fixture()
        self.assertTrue(vm.handoff_projection_matches(witness, gate, transaction, node))
        # Complete phase7 is intentional: observation need not catch phase4.
        self.assertEqual(vm.broker_record_projection(transaction, 'transaction')['phase'], 'complete')

    def test_wrong_actor_stale_nonce_edge_transaction_and_inbox_are_refused(self):
        gate, witness, transaction, node = self.fixture()
        for key, value in [('pid',124), ('seconds',457), ('microseconds',790), ('nonce',str(uuid.uuid4())),
                           ('from',139), ('to',141), ('identity','cd'*32), ('schema',True)]:
            changed = deepcopy(witness); changed['gate'][key] = value
            self.assertFalse(vm.handoff_projection_matches(changed, gate, transaction, node), key)
        for key, value in [('transaction',str(uuid.uuid4())), ('inboxDevice',2), ('inboxInode',3), ('inboxInode',True)]:
            changed = deepcopy(witness); changed[key] = value
            self.assertFalse(vm.handoff_projection_matches(changed, gate, transaction, node), key)
        self.assertFalse(vm.handoff_projection_matches(witness, gate, transaction[:-1], node))
        changed = bytearray(transaction); changed[24] ^= 1
        self.assertFalse(vm.handoff_projection_matches(witness, gate, bytes(changed), node))
        for value in (None, [], {}, {'gate':gate}):
            self.assertFalse(vm.handoff_projection_matches(value, gate, transaction, node))

    def test_fixed_private_file_rejects_symlink_mode_and_parent_replacement(self):
        with tempfile.TemporaryDirectory(prefix='pp-handoff-pure-') as folder:
            root = Path(folder); root.chmod(0o700); node = root.stat(); identity = (node.st_dev,node.st_ino)
            self.assertIsNone(vm.private_handoff_json('broker-handoff.json',root,identity,os.geteuid()))
            path = root/'broker-handoff.json'; path.write_text('{"closed":true}'); path.chmod(0o600)
            self.assertEqual(vm.private_handoff_json(path.name,root,identity,os.geteuid()), {'closed':True})
            path.chmod(0o644)
            with self.assertRaises(AssertionError): vm.private_handoff_json(path.name,root,identity,os.geteuid())
            path.unlink(); path.symlink_to('target')
            with self.assertRaises(OSError): vm.private_handoff_json(path.name,root,identity,os.geteuid())
            with self.assertRaises(AssertionError): vm.private_handoff_json(path.name,root,(0,0),os.geteuid())

    def test_fixture_digest_covers_bytes_modes_links_and_tree(self):
        with tempfile.TemporaryDirectory(prefix='pp-handoff-digest-') as folder:
            root=Path(folder); (root/'ProxyPilot.app').mkdir(mode=0o700)
            item=root/'ProxyPilot.app/a'; item.write_bytes(b'public fixture'); item.chmod(0o600)
            first=vm.fixture_inbox_identity(root)
            item.write_bytes(b'changed fixture'); self.assertNotEqual(first,vm.fixture_inbox_identity(root))
            second=vm.fixture_inbox_identity(root); item.chmod(0o700)
            self.assertNotEqual(second,vm.fixture_inbox_identity(root))
            third=vm.fixture_inbox_identity(root); (item.parent/'link').symlink_to('a')
            self.assertNotEqual(third,vm.fixture_inbox_identity(root))

    def test_explicit_snapshot_delta_after_durable_commit_never_changes_production(self):
        source=vm.HELPER/'VPNUpdateBrokerHandler.swift'; before=source.read_bytes()
        with tempfile.TemporaryDirectory(prefix='pp-handoff-snapshot-') as folder:
            app=vm.snapshot_current(Path(folder)); handler=(app/'vpn-helper'/source.name).read_text()
            call=handler.index('VPNSystemHandoffWitness.publish')
            self.assertLess(handler.index('transaction, phase: .handoffStarted'),call)
            self.assertLess(call,handler.index('VPNReplacementExecutorHandoff.launchPreparedFromBroker',call))
            self.assertIn('VPN_SYSTEM_HANDOFF_WITNESS',(app/'vpn-helper/build.sh').read_text())
            self.assertTrue((app/'vpn-helper/vpn_rescue_system_handoff_witness.swift').is_file())
        self.assertEqual(source.read_bytes(),before)
        self.assertNotIn(b'VPNSystemHandoffWitness',before)
        writer=(vm.ROOT/'tests/vpn_rescue_system_handoff_witness.swift').read_text()
        for required in ('gate.pid == getpid()', 'process.pbi_start_tvsec == gate.seconds',
                         'transaction.phase == .handoffStarted', 'O_EXCL', 'fsync(output)',
                         'let fd = openat(directory, "broker-handoff-gate.json"', 'UInt32(RENAME_EXCL)'):
            self.assertIn(required,writer)
        self.assertNotIn('sleep(',writer)
        self.assertNotIn('linkat(',writer.replace('unlinkat(',''))
        # Published inbox survives rotation/cleanup and read-only status. Only a
        # future submit retires a completed one, which this last case never does.
        handler=before.decode()
        self.assertEqual(handler.count('try inbox.retirePublished('),2)
        self.assertIn('try retireCompletedTransactionIfPresent()',handler.split('private func performSubmit(',1)[1])
        rotation=(vm.HELPER/'VPNUpdateBrokerRotation.swift').read_text()
        self.assertNotIn('retirePublished',rotation)


@unittest.skipUnless(sys.platform == 'darwin' and shutil.which('swiftc'), 'macOS Swift required')
class NativeDigestTests(unittest.TestCase):
    def test_expected_digest_matches_actual_production_inbox_on_private_fixture(self):
        with tempfile.TemporaryDirectory(prefix='pp-handoff-native-digest-') as folder:
            root=Path(folder); source=root/'source'; parent=root/'parent'
            source.mkdir(mode=0o700); parent.mkdir(mode=0o700)
            app=source/'ProxyPilot.app'; app.mkdir(mode=0o700)
            (app/'public').write_bytes(b'public synthetic app bytes'); (app/'public').chmod(0o600)
            (app/'link').symlink_to('public')
            names=['vpn-helper','vpn-engine','vpn-release.manifest','vpn-release.sig',
                   'vpn-previous-release.manifest','vpn-previous-release.sig',
                   'vpn-update-transition','vpn-update-transition.sig']
            for name in names:
                (source/name).write_bytes(('public synthetic '+name).encode()); (source/name).chmod(0o600)
            main=root/'main.swift'
            main.write_text('import Darwin\nimport Foundation\n'
                'let source = open(CommandLine.arguments[1], O_RDONLY | O_DIRECTORY | O_NOFOLLOW)\n'
                'let parent = open(CommandLine.arguments[2], O_RDONLY | O_DIRECTORY | O_NOFOLLOW)\n'
                'defer { close(source); close(parent) }\n'
                'let result = try VPNUpdateBrokerInbox(trustedParent: parent).ingest(sourceDirectory: source, checkpoint: { _ in })\n'
                'print(result.identity.map { String(format: "%02x", $0) }.joined())\n')
            binary=root/'digest'
            subprocess.run(['/usr/bin/swiftc','-target',platform.machine()+'-apple-macosx11.0',
                str(vm.HELPER/'VPNUpdateBrokerInbox.swift'),str(main),'-o',str(binary)],check=True,capture_output=True,timeout=60)
            result=subprocess.run([str(binary),str(source),str(parent)],check=True,capture_output=True,text=True,timeout=15)
            self.assertEqual(result.stdout.strip(),vm.fixture_inbox_identity(source))


if __name__ == '__main__': unittest.main()
