// Disposable root VM fixture only; all keys and services below are synthetic.
import CryptoKit
import Darwin
import Dispatch
import Foundation

@main enum VPNRescuePendingCoordinatorChecks {
    enum Injected: Error { case denied, interrupted }
    static func hex(_ data: Data) -> String { data.map { String(format: "%02x", $0) }.joined() }
    static func decode(_ value: String) -> Data {
        var output = Data(); var cursor = value.startIndex
        while cursor < value.endIndex {
            let next = value.index(cursor, offsetBy: 2)
            output.append(UInt8(value[cursor..<next], radix: 16)!); cursor = next
        }
        return output
    }
    static func readHandshake(_ descriptor: Int32, count: Int) throws -> [UInt8] {
        let deadline = DispatchTime.now().uptimeNanoseconds + 5_000_000_000
        var bytes = [UInt8](repeating: 0, count: count), offset = 0
        while offset < count {
            let now = DispatchTime.now().uptimeNanoseconds
            guard now < deadline else { throw Injected.interrupted }
            var event = pollfd(fd: descriptor, events: Int16(POLLIN), revents: 0)
            let status = poll(&event, 1, Int32(max(1, (deadline - now) / 1_000_000)))
            if status < 0, errno == EINTR { continue }
            guard status > 0, event.revents & Int16(POLLIN) != 0 else { throw Injected.interrupted }
            let received = bytes.withUnsafeMutableBytes {
                Darwin.read(descriptor, $0.baseAddress!.advanced(by: offset), count - offset)
            }
            if received < 0, errno == EINTR { continue }
            guard received > 0 else { throw Injected.interrupted }
            offset += received
        }
        return bytes
    }
    static func main() throws {
        let args = CommandLine.arguments
        guard args.count == 16 else { exit(64) }
        let operation = args[1], basePath = args[2], destinationPath = args[3]
        let key = try Curve25519.Signing.PrivateKey(rawRepresentation: Data(repeating: 0x42, count: 32))
        let authority = try VPNReleaseAuthority(trustedPublicKey: key.publicKey.rawRepresentation,
                                                minimumSequence: 1, supportedProtocol: 1)
        let helper = try Data(contentsOf: URL(fileURLWithPath: args[13]))
        func manifest(_ sequence: Int, _ version: String, _ arm: String, _ intel: String) -> Data {
            Data("""
            format=1
            product=kz.documentolog.proxypilot
            sequence=\(sequence)
            version=\(version)
            protocol=1
            app-arm64=\(arm)
            app-x86_64=\(intel)
            helper-arm64=\(args[14])
            helper-x86_64=\(args[15])
            helper-sha256=\(hex(Data(SHA256.hash(data: helper))))
            helper-bytes=\(helper.count)

            """.utf8)
        }
        let a = manifest(137, "1.6.0", args[8], args[9])
        let b = manifest(139, "1.7.0", args[10], args[11])
        func releaseSignature(_ bytes: Data) throws -> Data { try key.signature(for: VPNReleaseAuthority.signatureDomain + bytes) }
        let aSig = try releaseSignature(a), bSig = try releaseSignature(b)
        let previous = try authority.verify(payload: a, signature: aSig, previous: nil)
        func edge(_ bytes: Data, sequence: Int) -> Data {
            Data("format=1\nproduct=kz.documentolog.proxypilot\nfrom-sequence=137\nfrom-sha256=\(hex(Data(SHA256.hash(data: a))))\nto-sequence=\(sequence)\nto-sha256=\(hex(Data(SHA256.hash(data: bytes))))\n".utf8)
        }
        let transitionBytes = edge(b, sequence: 139)
        let transitionSignature = try key.signature(for: VPNReleaseAuthority.updateTransitionDomain + transitionBytes)
        let rescueCandidate = b
        let rescueEdge = transitionBytes
        let artifact = try Data(contentsOf: URL(fileURLWithPath: args[5]))
        let tokenBytes = try VPNRescueAuthorization.encode(previousManifest: a,
            candidateManifest: rescueCandidate, transitionPayload: rescueEdge, rescueArtifact: artifact,
            arm64CDHash: decode(args[6]), intelCDHash: decode(args[7]))
        let token = try VPNRescueAuthorization.verify(payload: tokenBytes,
            signature: key.signature(for: VPNReleaseAuthority.rescueAuthorizationDomain + tokenBytes),
            authority: authority, previous: previous, previousPayload: a, previousSignature: aSig,
            candidatePayload: rescueCandidate, candidateSignature: releaseSignature(rescueCandidate),
            transitionPayload: rescueEdge,
            transitionSignature: key.signature(for: VPNReleaseAuthority.updateTransitionDomain + rescueEdge))
        let base = open(basePath, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
        let destination = open(destinationPath, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
        let rescue = open(args[4], O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
        guard base >= 0, destination >= 0, rescue >= 0 else { exit(65) }
        defer { close(base); close(destination); close(rescue) }
        let service = open(args[12], O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
        guard service >= 0 else { exit(65) }
        defer { close(service) }
        let store = try VPNReleaseStore(trustedDirectoryDescriptor: service, authority: authority)
        let lease = try VPNLifecycleOwnership.acquire(inTrustedDirectory: service)
        defer { lease.release() }
        if operation == "setup" {
            _ = try store.bootstrapDeployment(payload: a, signature: aSig, helper: helper, trustedOwnerUserID: 501)
            let prepared = try store.prepareUpdateJournal(payload: b, signature: bSig, helper: helper,
                transitionPayload: transitionBytes, transitionSignature: transitionSignature, expectedSequence: 137)
            _ = try store.markUpdateReplacementPending(transactionID: prepared.transactionID, expectedRevision: prepared.revision)
            print("setup"); return
        }
        if operation == "progress-worker" {
            // The lease above is actually held before READY is published.
            print("READY"); fflush(stdout)
            guard try readHandshake(STDIN_FILENO, count: 3) == Array("GO\n".utf8) else { exit(78) }
            print("worker:locked"); return
        }
        var trace: [String] = []
        func stale() throws {
            let url = URL(fileURLWithPath: args[12]).appendingPathComponent("update.json")
            var record = try JSONSerialization.jsonObject(with: Data(contentsOf: url)) as! [String: Any]
            record["revision"] = 2
            try JSONSerialization.data(withJSONObject: record, options: .sortedKeys).write(to: url)
            precondition(chmod(url.path, 0o600) == 0)
        }
        do {
            if operation.hasPrefix("progress-") {
                let checkpoint = try VPNRescuePendingCoordinator.captureRecoveryProgress(service: service, lease: lease)
                lease.release()
                guard let checkpoint else { print("progress:absent"); return }
                let journalURL = URL(fileURLWithPath: args[12]).appendingPathComponent("update.json")
                if operation == "progress-unchanged-worker" {
                    let child = Process(), output = Pipe(), input = Pipe()
                    child.executableURL = URL(fileURLWithPath: args[0])
                    var childArgs = Array(args.dropFirst()); childArgs[0] = "progress-worker"
                    child.arguments = childArgs; child.standardInput = input
                    child.standardOutput = output; child.standardError = FileHandle.nullDevice
                    try child.run()
                    var reaped = false
                    defer {
                        try? input.fileHandleForWriting.close()
                        if !reaped {
                            if child.isRunning { kill(child.processIdentifier, SIGKILL) }
                            child.waitUntilExit()
                        }
                    }
                    guard try Self.readHandshake(output.fileHandleForReading.fileDescriptor, count: 6)
                            == Array("READY\n".utf8) else { throw Injected.denied }
                    // Child cannot release its actual Service lease until GO.
                    // All three reads therefore run while another process holds it.
                    for _ in 0..<3 {
                        guard try !VPNRescuePendingCoordinator.hasRecoveryProgress(service: service, checkpoint: checkpoint) else {
                            throw Injected.denied
                        }
                    }
                    try input.fileHandleForWriting.write(contentsOf: Data("GO\n".utf8))
                    try input.fileHandleForWriting.close()
                    child.waitUntilExit(); reaped = true
                    guard child.terminationReason == .exit, child.terminationStatus == 0,
                          String(decoding: output.fileHandleForReading.readDataToEndOfFile(), as: UTF8.self) == "worker:locked\n" else {
                        throw Injected.denied
                    }
                }
                if operation == "progress-rename" {
                    let temporary = journalURL.deletingLastPathComponent().appendingPathComponent("progress-publication")
                    try Data(contentsOf: journalURL).write(to: temporary)
                    guard chmod(temporary.path, 0o600) == 0, rename(temporary.path, journalURL.path) == 0 else { exit(65) }
                }
                if operation == "progress-unlink" { guard unlink(journalURL.path) == 0 else { exit(65) } }
                if operation == "progress-malformed" {
                    try Data("not a journal".utf8).write(to: journalURL)
                    guard chmod(journalURL.path, 0o600) == 0 else { exit(65) }
                }
                if operation == "progress-symlink" {
                    let target = journalURL.deletingLastPathComponent().appendingPathComponent("progress-target")
                    guard rename(journalURL.path, target.path) == 0, symlink(target.path, journalURL.path) == 0 else { exit(65) }
                }
                if operation == "progress-unsafe-mode" { guard chmod(journalURL.path, 0o644) == 0 else { exit(65) } }
                let observedService = operation == "progress-other-service" ? base : service
                let changed = try VPNRescuePendingCoordinator.hasRecoveryProgress(service: observedService, checkpoint: checkpoint)
                print("progress:\(changed ? "changed" : "unchanged")"); return
            }
            let proof = try VPNRescueExecutor.testInspect(inTrustedDirectory: rescue, authorization: token)
            let context = try VPNRescueJournalContext.capture(authorization: token, store: store, lease: lease)
            if operation == "stale-before" { try stale() }
            if operation == "observe-source" {
                try VPNRescuePendingCoordinator.testObserve(service: service, lease: lease,
                    context: context, executor: proof, destination: destination)
                exit(78)
            }
            let result = try VPNRescuePendingCoordinator.testRun(context: context, executor: proof,
                inTrustedDirectory: base, destination: destination,
                armCandidateRecovery: {
                    trace.append("arm")
                    if operation == "arm-failure" { throw Injected.denied }
                    if operation == "stale-after-arm" { try stale() }
                }, drainPreviousService: {
                    trace.append("drain")
                    if operation == "drain-failure" { throw Injected.denied }
                    if operation == "stale-after-drain" { try stale() }
                }, checkpoint: { point in
                    if point == "afterExchange" {
                        trace.append("exchange")
                        if operation == "after-exchange-failure" { throw Injected.interrupted }
                        if operation == "stale-after-exchange" { try stale() }
                    }
                })
            if operation.hasPrefix("observe-") {
                if operation == "observe-foreign" {
                    try Data("foreign".utf8).write(to: URL(fileURLWithPath: destinationPath)
                        .appendingPathComponent("ProxyPilot.app/Contents/Resources/data.txt"))
                }
                for _ in 0..<3 {
                    try VPNRescuePendingCoordinator.testObserve(service: service, lease: lease,
                        context: context, executor: proof, destination: destination, checkpoint: { _ in
                            if operation == "observe-stale" { try stale() }
                            if operation == "observe-lease" { lease.release() }
                            if operation == "observe-executor" {
                                guard chmod(URL(fileURLWithPath: args[4]).appendingPathComponent("vpn-rescue").path, 0o600) == 0 else { exit(65) }
                            }
                            if operation == "observe-changed-installed" {
                                try Data("changed after observation".utf8).write(to: URL(fileURLWithPath: destinationPath)
                                    .appendingPathComponent("ProxyPilot.app/Contents/Resources/data.txt"))
                            }
                        })
                }
                print("observed:3:trace=\(trace.joined(separator: ","))"); return
            }
            print("\(result == .exchanged ? "exchanged" : "alreadyExchanged"):trace=\(trace.joined(separator: ","))")
        } catch {
            print("rejected:\(error):trace=\(trace.joined(separator: ","))")
            exit(77)
        }
    }
}
