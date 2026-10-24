"""Exact fixture anchor code against synthetic files only: NO Security APIs."""
from pathlib import Path
import platform
import shutil
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]


def created_class(source):
    # Extract this exact class, not every declaration before create(). The
    # fixture's following Canary/SDK routines must never enter this harness.
    start = source.index('    final class Created {')
    opening = source.index('{', start)
    depth = 0
    for position in range(opening, len(source)):
        if source[position] == '{': depth += 1
        elif source[position] == '}':
            depth -= 1
            if depth == 0: return source[start:position + 1] + '\n'
    raise AssertionError('Unbalanced fixture Created class')


@unittest.skipUnless(platform.system() == 'Darwin' and shutil.which('swiftc'), 'Darwin file identities required')
class DefaultKeychainPostAddAnchorTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp = tempfile.TemporaryDirectory(prefix='pp-default-anchor-pure-')
        cls.addClassCleanup(cls.temp.cleanup)
        fixture = (ROOT / 'tests/vpn_default_keychain_frontend_vm.swift').read_text()
        legacy = (ROOT / 'tests/vpn_legacy_password_backend_vm_checks.swift').read_text()
        proof = legacy.split('// BEGIN NO-KEYCHAIN FILE IDENTITY', 1)[1].split('// END NO-KEYCHAIN FILE IDENTITY', 1)[0]
        anchor = fixture.split('    final class DefaultAnchor {', 1)[1].split('    static func copyDefault()', 1)[0]
        created = created_class(fixture)
        prove = fixture.split('    static func prove(', 1)[1].split('    static func setDefault(', 1)[0]
        code = r'''
import Darwin
import Foundation
typealias SecKeychain = String
struct Origin {
    var path: String
    var device: UInt64
    var inode: UInt64
    var ownerUID: UInt32
    var birthSeconds: Int64
    var birthNanoseconds: UInt32
}
struct VPNPasswordItemLocator {
    var origin: Origin
    func validate() throws {}
}
@main enum Harness {
    enum Failure: Error { case refused, check, guardFailed }
    enum AnchorRole { case standalone, target, expected, actual }
    enum AnchorFailure { case heldStat, heldIdentity, heldLink, namedStat, namedIdentity, namedRegular }
    static func path(_ keychain: String) throws -> String { keychain }
    static func check(_ value: @autoclosure () throws -> Bool) throws { if try !value() { throw Failure.check } }
    static func anchorCheck(_ value: Bool, role: AnchorRole, failure: AnchorFailure) throws {
        if !value { throw Failure.refused }
    }
    static func same(_ a: stat, _ b: stat) -> Bool {
        a.st_dev == b.st_dev && a.st_ino == b.st_ino && a.st_uid == b.st_uid &&
        a.st_birthtimespec.tv_sec == b.st_birthtimespec.tv_sec && a.st_birthtimespec.tv_nsec == b.st_birthtimespec.tv_nsec
    }
    // Inert storage only: the post-Add path exercised below never uses a
    // canary. Its real SDK implementation is deliberately not extracted.
    final class Canary {}
''' + '    final class DefaultAnchor {' + anchor + created + '    static func prove(' + prove + r'''
    static func locator(_ path: String) throws -> VPNPasswordItemLocator {
        var st = stat(); try check(lstat(path, &st) == 0)
        return .init(origin: .init(path: path, device: UInt64(UInt32(bitPattern: st.st_dev)), inode: UInt64(st.st_ino),
            ownerUID: st.st_uid, birthSeconds: Int64(st.st_birthtimespec.tv_sec), birthNanoseconds: UInt32(st.st_birthtimespec.tv_nsec)))
    }
    static func run() throws {
        let mode = CommandLine.arguments[1], folder = URL(fileURLWithPath: CommandLine.arguments[2])
        let path = folder.appendingPathComponent("first.keychain").path
        try Data("synthetic-before".utf8).write(to: URL(fileURLWithPath: path)); try check(chmod(path, 0o600) == 0)
        let directory = open(folder.path, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
        try check(directory >= 0); defer { close(directory) }
        let old = try DefaultAnchor(path)
        let created = Created(anchor: old, folder: folder, directory: directory, target: .first, leaf: .firstBase, canary: Canary())
        let oldReceipt = try locator(path)
        let staged = folder.appendingPathComponent("replacement").path
        try Data("synthetic-after".utf8).write(to: URL(fileURLWithPath: staged)); try check(chmod(staged, 0o600) == 0)
        try check(rename(staged, path) == 0)
        var held = stat(); try check(fstat(old.descriptor, &held) == 0 && held.st_nlink == 0)
        var receipt = try locator(path)
        if mode == "old-receipt" || mode == "pathname-only" { receipt = oldReceipt }
        if mode == "wrong-device" { receipt.origin.device += 1 }
        if mode == "wrong-inode" { receipt.origin.inode += 1 }
        if mode == "wrong-owner" { receipt.origin.ownerUID += 1 }
        if mode == "wrong-birth" { receipt.origin.birthNanoseconds = receipt.origin.birthNanoseconds == 0 ? 1 : 0 }
        if mode == "foreign" {
            let foreign = folder.appendingPathComponent("foreign").path
            try Data("foreign".utf8).write(to: URL(fileURLWithPath: foreign)); try check(chmod(foreign, 0o600) == 0)
            receipt = try locator(foreign)
        }
        if mode == "missing" { try check(unlink(path) == 0) }
        if mode == "symlink" { try check(unlink(path) == 0 && symlink("replacement", path) == 0) }
        if mode == "unknown-add" {
            // An indeterminate response has no authenticated locator and cannot
            // call the confirmed-Add refresh path. Keep the old held anchor.
            do { try created.anchor.validate(); throw Failure.check } catch Failure.refused {}
            try check(created.anchor === old); print("unknown retained"); return
        }
        do {
            if mode == "baseline" { try created.anchor.validate() }
            else { try created.refreshAfterConfirmedAdd(receipt) }
            try check(mode == "positive")
            try created.anchor.validate(); try check(created.anchor !== old)
            try check(fstat(old.descriptor, &held) == 0 && held.st_nlink == 0)
        } catch {
            if mode == "positive" || mode == "baseline" { throw error }
            try check(created.anchor === old && fstat(old.descriptor, &held) == 0)
        }
        print("synthetic anchor proof passed")
    }
    static func main() { do { try run() } catch { exit(77) } }
}
''' + proof
        # Extracted production-like fixture class is the actual implementation;
        # only SecKeychainGetPath is replaced by a literal synthetic path.
        for forbidden in ('import Security', 'SecItem', 'SecKeychainCopy', 'SecKeychainSet', 'SecKeychainGet'):
            if forbidden in code: raise AssertionError('Pure fixture acquired a Security API')
        source = Path(cls.temp.name) / 'Proof.swift'; source.write_text(code)
        cls.binary = Path(cls.temp.name) / 'proof'
        result = subprocess.run(['swiftc', '-parse-as-library', str(source), '-o', str(cls.binary)], capture_output=True, text=True, timeout=60)
        if result.returncode: raise AssertionError(result.stderr)

    def run_case(self, mode, expected=0):
        with tempfile.TemporaryDirectory(prefix='pp-default-anchor-files-') as folder:
            Path(folder).chmod(0o700)
            result = subprocess.run([str(self.binary), mode, str(Path(folder).resolve())], capture_output=True, text=True, timeout=10)
            if expected == 0: self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            else: self.assertNotEqual(result.returncode, 0)

    def test_pre_add_anchor_baseline_rejects_legitimate_replacement(self): self.run_case('baseline', expected=1)
    def test_confirmed_exact_post_add_locator_refreshes_replaced_inode(self): self.run_case('positive')
    def test_unknown_add_cannot_refresh_anchor(self): self.run_case('unknown-add')
    def test_changed_or_unproven_locator_never_replaces_held_anchor(self):
        for mode in ('old-receipt', 'pathname-only', 'wrong-device', 'wrong-inode', 'wrong-owner', 'wrong-birth', 'foreign', 'missing', 'symlink'):
            with self.subTest(mode=mode): self.run_case(mode)


if __name__ == '__main__': unittest.main()
