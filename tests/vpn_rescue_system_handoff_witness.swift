// Private SystemVM snapshot only. This source/flag is never in release builds.
#if VPN_SYSTEM_HANDOFF_WITNESS
import Darwin
import Foundation

enum VPNSystemHandoffWitness {
    private static let folder = "/private/tmp/kz.documentolog.proxypilot-vpn-activation-diagnostics"
    private struct Gate: Codable {
        let schema: UInt32
        let nonce: String
        let pid: Int32
        let seconds: UInt64
        let microseconds: UInt64
        let from: UInt64
        let to: UInt64
        let identity: String
    }
    private struct Witness: Encodable {
        let gate: Gate
        let transaction: String
        let inboxDevice: UInt64
        let inboxInode: UInt64
    }
    // Best effort observation only: no failure can control broker completion.
    static func publish(transaction: VPNUpdateBrokerTransactionSnapshot, inbox: Int32) {
        guard getuid() == 0, geteuid() == 0,
              transaction.phase == .handoffStarted,
              transaction.fromSequence == 141, transaction.toSequence == 142,
              let journal = transaction.journal, transaction.identity.count == 32 else { return }
        let directory = open(folder, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
        guard directory >= 0 else { return }; defer { close(directory) }
        var parent = stat(), namedParent = stat(), node = stat(), file = stat(), again = stat()
        guard fstat(directory, &parent) == 0, parent.st_uid == 0, parent.st_mode & S_IFMT == S_IFDIR,
              parent.st_mode & 0o7777 == 0o700, parent.st_nlink > 0,
              lstat(folder, &namedParent) == 0, namedParent.st_dev == parent.st_dev,
              namedParent.st_ino == parent.st_ino else { return }
        let fd = openat(directory, "broker-handoff-gate.json", O_RDONLY | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC)
        guard fd >= 0 else { return }; defer { close(fd) }
        guard fstat(fd, &file) == 0, file.st_mode & S_IFMT == S_IFREG, file.st_uid == 0,
              file.st_mode & 0o7777 == 0o600, file.st_nlink == 1, file.st_size > 0, file.st_size <= 2048 else { return }
        var bytes = [UInt8](repeating: 0, count: Int(file.st_size))
        guard Darwin.read(fd, &bytes, bytes.count) == bytes.count,
              fstatat(directory, "broker-handoff-gate.json", &again, AT_SYMLINK_NOFOLLOW) == 0,
              again.st_dev == file.st_dev, again.st_ino == file.st_ino, again.st_size == file.st_size,
              let gate = try? JSONDecoder().decode(Gate.self, from: Data(bytes)), gate.schema == 1,
              UUID(uuidString: gate.nonce)?.uuidString.lowercased() == gate.nonce,
              gate.from == 141, gate.to == 142, gate.pid == getpid(),
              gate.identity == transaction.identity.map({ String(format: "%02x", $0) }).joined() else { return }
        var process = proc_bsdinfo()
        let size = Int32(MemoryLayout<proc_bsdinfo>.size)
        guard proc_pidinfo(getpid(), PROC_PIDTBSDINFO, 0, &process, size) == size,
              process.pbi_pid == UInt32(getpid()), process.pbi_uid == 0, process.pbi_ruid == 0,
              process.pbi_start_tvsec == gate.seconds, process.pbi_start_tvusec == gate.microseconds,
              fstat(inbox, &node) == 0, node.st_mode & S_IFMT == S_IFDIR,
              node.st_uid == 0, node.st_mode & 0o7777 == 0o700, node.st_nlink > 0 else { return }
        let encoder = JSONEncoder(); encoder.outputFormatting = [.sortedKeys]
        guard let data = try? encoder.encode(Witness(gate: gate, transaction: journal.transactionID.uuidString.lowercased(),
            inboxDevice: UInt64(UInt32(bitPattern: node.st_dev)), inboxInode: UInt64(node.st_ino))), data.count <= 2048 else { return }
        let temporary = ".broker-handoff.preparing"
        let output = openat(directory, temporary, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0o600)
        guard output >= 0 else { return }
        defer { close(output); unlinkat(directory, temporary, 0) }
        let written = data.withUnsafeBytes { Darwin.write(output, $0.baseAddress, $0.count) }
        guard written == data.count, fsync(output) == 0,
              fstatat(directory, "broker-handoff-gate.json", &again, AT_SYMLINK_NOFOLLOW) == 0,
              again.st_dev == file.st_dev, again.st_ino == file.st_ino, again.st_size == file.st_size,
              lstat(folder, &namedParent) == 0, namedParent.st_dev == parent.st_dev,
              namedParent.st_ino == parent.st_ino,
              renameatx_np(directory, temporary, directory, "broker-handoff.json", UInt32(RENAME_EXCL)) == 0 else { return }
        // Process-death observation only, not a power-loss durability claim.
        _ = fsync(directory)
    }
}
#endif
