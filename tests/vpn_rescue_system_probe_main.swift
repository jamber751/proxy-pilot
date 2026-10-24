import Darwin
import Dispatch
import Foundation

/// Test bundle entry only. The result role and all its checks are production
/// code. This avoids GUI/OTP initialization while observing actual system C.
@main enum VPNRescueSystemProbeMain {
    static func main() {
        let args = CommandLine.arguments
        #if VPN_INSTALLED_UPDATE_RESULT_DIAGNOSTICS
        VPNInstalledUpdateResultEntry.diagnostic = { stage, category in
            FileHandle.standardError.write(Data(("ProxyPilot VPN installed result phase: "
                + stage.rawValue + "; category: " + category.rawValue + "\n").utf8))
        }
        #endif
        if let status = VPNInstalledUpdateResultEntry.runIfRequested(arguments: args) { exit(status) }
        // Setup-only fixture role; never compiled into the normal frontend.
        let seedBroker = args.count == 2 && args[1] == "--vm-seed-broker"
        let seedCompleted = args.count == 3 && args[1] == "--vm-seed-completed-broker"
        // Exercise the real signed frontend's executor/recovery roles. Exact
        // VM root setup modes remain outside its ordinary-root launch guard.
        if !seedBroker && !seedCompleted,
           let status = VPNInstallationEntry.runIfRequested(arguments: args) { exit(status) }
        if args.count >= 2 && args[1] == "--vm-submit-without-reply" {
            guard ordinaryVMOwner(), args.count == 3, args[2].hasPrefix("/"),
                  VPNJointUpdateStartupStatus.sealedRelease()?.sequence == 141 else { exit(77) }
            do { try submitWithoutReply(candidatePath: args[2]); return }
            catch { print("submit:disconnected-probe-rejected"); exit(77) }
        }
        if args.count >= 2 && args[1] == "--vm-submit-update" {
            guard ordinaryVMOwner(), args.count == 3, args[2].hasPrefix("/"),
                  VPNJointUpdateStartupStatus.sealedRelease()?.sequence == 141 else { exit(77) }
            do {
                let candidate = open(args[2], O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
                guard candidate >= 0 else { exit(77) }
                defer { close(candidate) }
                var facts = stat()
                guard fstat(candidate, &facts) == 0, facts.st_uid == geteuid(),
                      facts.st_mode & 0o7777 == 0o700 else { exit(77) }
                let outcome = try VPNUpdateBrokerClient.submit(candidateDirectory: candidate,
                    expectedFromSequence: 141, deadline: deadline())
                switch outcome {
                case .indeterminate: print("submit:indeterminate"); exit(75)
                case .response(let response):
                    guard response.fromSequence == 141, response.toSequence == 142 else { exit(77) }
                    // A successful transport or `.ready` is never an installed
                    // receipt. Parent checks the actual startup-status role.
                    switch response.state {
                    case .accepted: print("submit:accepted")
                    case .checking: print("submit:checking")
                    case .ready: print("submit:ready")
                    case .installing: print("submit:installing")
                    case .complete: print("submit:complete")
                    case .failed: print("submit:failed")
                    case .busy: print("submit:busy")
                    case .stale: print("submit:stale")
                    }
                }
                return
            } catch { print("submit:rejected"); exit(77) }
        }
        if args.count >= 2 && args[1] == "--vm-update-status" {
            guard ordinaryVMOwner(), args.count == 2,
                  let sealed = VPNJointUpdateStartupStatus.sealedRelease(),
                  sealed.sequence == 141 || sealed.sequence == 142 else { exit(77) }
            do {
                switch try VPNJointUpdateStartupStatus.check(sealedRelease: sealed, deadline: deadline()) {
                case .idle: print("status:idle")
                case .verifying: print("status:verifying")
                case .installed: print("status:installed")
                case .failed: print("status:failed")
                }
                return
            } catch { print("status:unavailable"); exit(75) }
        }
        guard seedBroker || seedCompleted, getuid() == 0, geteuid() == 0,
              ProcessInfo.processInfo.environment["GITHUB_ACTIONS"] == "true",
              ProcessInfo.processInfo.environment["PROXYPILOT_VM_SYSTEM_RESCUE_TESTS"] == "1" else { exit(64) }
        do {
            let service = try VPNDirectoryProvisioner.openSystemDirectory(create: false)
            defer { close(service) }
            let store = try VPNReleaseStore(trustedDirectoryDescriptor: service,
                                            authority: VPNReleaseTrust.authority())
            if seedCompleted {
                let privateState = try VPNDirectoryProvisioner.openSystemBrokerDirectory(create: false)
                defer { close(privateState) }
                let brokerLease = try VPNLifecycleOwnership.acquire(inTrustedDirectory: privateState)
                defer { brokerLease.release() }
                let serviceLease = try VPNLifecycleOwnership.acquire(inTrustedDirectory: service)
                defer { serviceLease.release() }
                guard let pending = try store.loadUpdateJournal(), pending.phase == .replacementPending,
                      pending.revision == 1, pending.previous.release.sequence == 137,
                      pending.candidate.release.sequence == 139 else { exit(77) }
                _ = try VPNInstalledApplication.inspect(release: pending.candidate.release)
                let source = open(args[2], O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
                guard source >= 0 else { exit(77) }
                defer { close(source) }
                let payload = try VPNJointUpdatePayload.loadForBroker(inTrustedDirectory: source,
                                                                      authority: VPNReleaseTrust.authority())
                guard payload.previous.isSameRelease(as: pending.previous.release),
                      payload.candidate.release.isSameRelease(as: pending.candidate.release),
                      pending.transition.matchesSource(payload.previous),
                      pending.transition.matchesDestination(payload.candidate.release) else { exit(77) }
                let inbox = try VPNUpdateBrokerInbox(trustedParent: privateState)
                let copied = try inbox.ingest(sourceDirectory: source, checkpoint: { _ in })
                let transactions = try VPNUpdateBrokerTransactionStore(trustedDirectoryDescriptor: privateState)
                var transaction = try transactions.begin(identity: copied.identity, fromSequence: 137, toSequence: 139)
                transaction = try transactions.advance(identity: copied.identity, expectedRevision: transaction.revision,
                    phase: .authorized, journal: nil, recovery: .inboxRetained, rotation: .notStarted)
                transaction = try transactions.advance(identity: copied.identity, expectedRevision: transaction.revision,
                    phase: .prepared, journal: VPNUpdateBrokerJournalReference(transactionID: pending.transactionID, revision: 0, phase: .prepared),
                    recovery: .journalRetained, rotation: .notStarted)
                transaction = try transactions.advance(identity: copied.identity, expectedRevision: transaction.revision,
                    phase: .handoffStarted, journal: VPNUpdateBrokerJournalReference(transactionID: pending.transactionID, revision: 1, phase: .replacementPending),
                    recovery: .journalRetained, rotation: .pending)
                let selected = try store.selectUpdateCandidate(transactionID: pending.transactionID, expectedRevision: 1)
                let completed = try store.completeUpdateJournal(transactionID: selected.transactionID, expectedRevision: 2)
                let reference = VPNUpdateBrokerJournalReference(transactionID: completed.transactionID, revision: 3, phase: .completed)
                transaction = try transactions.advance(identity: copied.identity, expectedRevision: transaction.revision,
                    phase: .handoffComplete, journal: reference, recovery: .executorCommitted, rotation: .pending)
                transaction = try transactions.advance(identity: copied.identity, expectedRevision: transaction.revision,
                    phase: .rotatingBroker, journal: reference, recovery: .executorCommitted, rotation: .complete)
                guard transaction.phase == .rotatingBroker, transaction.journal == reference else { exit(77) }
                print("Seeded exact completed service journal and broker phase6"); return
            }
            let selected = try store.loadDeployment()
            guard selected.release.sequence == 137 else { exit(77) }
            let endpoint = try VPNEndpointDirectory.openSystem(create: true)
            close(endpoint)
            let job = try VPNUpdateBrokerLaunchdJob.system(storageDirectory: service)
            try job.installAndStart(selected, deadline: DispatchTime.now().uptimeNanoseconds + 20_000_000_000)
            print("Seeded authenticated old system broker")
        } catch { exit(77) }
    }

    private static func ordinaryVMOwner() -> Bool {
        getuid() == geteuid() && getuid() >= 500 && getuid() != uid_t.max
            && ProcessInfo.processInfo.environment["GITHUB_ACTIONS"] == "true"
            && ProcessInfo.processInfo.environment["PROXYPILOT_VM_SYSTEM_RESCUE_TESTS"] == "1"
    }

    /// Private fixture sender, not the default production Client API. Keep the
    /// process alive for live-code authentication. SHUT_RD alone does not cause
    /// peer writes to fail on Darwin: synchronize after authenticated recvmsg,
    /// finish its partial frame, then close the socket completely instead.
    private static func submitWithoutReply(candidatePath: String) throws {
        enum Rejected: Error { case fixture }
        let wireDeadline = deadline() // existing 20s client wire budget
        let candidate = open(candidatePath, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
        guard candidate >= 0 else { throw Rejected.fixture }
        defer { close(candidate) }
        var facts = stat()
        guard fstat(candidate, &facts) == 0, facts.st_uid == geteuid(),
              facts.st_mode & 0o7777 == 0o700 else { throw Rejected.fixture }
        let endpoint = VPNUpdateBrokerDaemon.endpointPath
        var socketInfo = stat()
        guard lstat(endpoint, &socketInfo) == 0, socketInfo.st_mode & S_IFMT == S_IFSOCK,
              socketInfo.st_uid == 0, socketInfo.st_mode & 0o7777 == 0o666 else { throw Rejected.fixture }
        var channel = socket(AF_UNIX, SOCK_STREAM, 0)
        guard channel >= 0 else { throw Rejected.fixture }
        defer { if channel >= 0 { close(channel) } }
        var noSignal: Int32 = 1
        guard setsockopt(channel, SOL_SOCKET, SO_NOSIGPIPE, &noSignal,
                         socklen_t(MemoryLayout.size(ofValue: noSignal))) == 0 else { throw Rejected.fixture }
        guard fcntl(channel, F_SETFD, FD_CLOEXEC) == 0 else { throw Rejected.fixture }
        let flags = fcntl(channel, F_GETFL)
        guard flags >= 0, fcntl(channel, F_SETFL, flags | O_NONBLOCK) == 0 else { throw Rejected.fixture }
        var address = sockaddr_un()
        address.sun_family = sa_family_t(AF_UNIX)
        address.sun_len = UInt8(MemoryLayout<sockaddr_un>.size)
        let name = Array(endpoint.utf8CString)
        guard name.count <= MemoryLayout.size(ofValue: address.sun_path) else { throw Rejected.fixture }
        withUnsafeMutableBytes(of: &address.sun_path) { raw in
            name.withUnsafeBytes { raw.copyBytes(from: $0) }
        }
        let connected = withUnsafePointer(to: &address) {
            $0.withMemoryRebound(to: sockaddr.self, capacity: 1) {
                connect(channel, $0, socklen_t(MemoryLayout<sockaddr_un>.size))
            }
        }
        if connected != 0 {
            guard errno == EINPROGRESS else { throw Rejected.fixture }
            try VPNHelperProtocol.wait(channel, events: Int16(POLLOUT), deadline: wireDeadline)
            var error: Int32 = 0, size = socklen_t(MemoryLayout<Int32>.size)
            guard getsockopt(channel, SOL_SOCKET, SO_ERROR, &error, &size) == 0, error == 0 else { throw Rejected.fixture }
        }
        var peerUID: uid_t = 0, peerGID: gid_t = 0
        guard getpeereid(channel, &peerUID, &peerGID) == 0, peerUID == 0 else { throw Rejected.fixture }
        let frame = VPNUpdateBrokerProtocol.encode(try .submit(expectedFromSequence: 141))
        let headerBytes = MemoryLayout<cmsghdr>.size
        let alignment = MemoryLayout<UInt32>.size
        let controlBytes = (headerBytes + MemoryLayout<Int32>.size + alignment - 1) & ~(alignment - 1)
        var control = [UInt64](repeating: 0, count: (controlBytes + 7) / 8)
        var sent = -1
        while sent < 0 {
            try VPNHelperProtocol.wait(channel, events: Int16(POLLOUT), deadline: wireDeadline)
            sent = frame.withUnsafeBytes { payload in
                control.withUnsafeMutableBytes { ancillary in
                    let header = ancillary.baseAddress!.assumingMemoryBound(to: cmsghdr.self)
                    header.pointee.cmsg_len = socklen_t(headerBytes + MemoryLayout<Int32>.size)
                    header.pointee.cmsg_level = SOL_SOCKET
                    header.pointee.cmsg_type = SCM_RIGHTS
                    ancillary.baseAddress!.advanced(by: headerBytes).storeBytes(of: candidate, as: Int32.self)
                    var vector = iovec(iov_base: UnsafeMutableRawPointer(mutating: payload.baseAddress), iov_len: 1)
                    return withUnsafeMutablePointer(to: &vector) {
                        var message = msghdr(msg_name: nil, msg_namelen: 0, msg_iov: $0, msg_iovlen: 1,
                            msg_control: ancillary.baseAddress, msg_controllen: socklen_t(controlBytes), msg_flags: 0)
                        return sendmsg(channel, &message, MSG_DONTWAIT | MSG_NOSIGNAL)
                    }
                }
            }
            if sent < 0 && [EINTR, EAGAIN, EWOULDBLOCK].contains(errno) { continue }
            guard sent == 1 else { throw Rejected.fixture }
        }
        FileHandle.standardOutput.write(Data("submit:partial-frame-sent\n".utf8))
        // The parent releases this barrier only after libproc observed our
        // exact candidate FD in the authenticated broker's descriptor table.
        try expectControl(0x47, deadline: wireDeadline)
        try VPNHelperProtocol.write(Array(frame.dropFirst()), socket: channel, deadline: wireDeadline)
        close(channel); channel = -1
        FileHandle.standardOutput.write(Data("submit:reply-socket-closed\n".utf8))
        // No further transport occurs. Lifetime only follows the driver's
        // existing 300s installation-observation budget, not a longer protocol
        // deadline, and preserves the peer process until D is proved installed.
        try expectControl(0x51, deadline: DispatchTime.now().uptimeNanoseconds + 300_000_000_000)
    }

    private static func expectControl(_ expected: UInt8, deadline: UInt64) throws {
        enum Rejected: Error { case control }
        try VPNHelperProtocol.wait(STDIN_FILENO, events: Int16(POLLIN), deadline: deadline)
        var value: UInt8 = 0
        var count = -1
        while count < 0 {
            count = read(STDIN_FILENO, &value, 1)
            if count < 0 && errno == EINTR { continue }
            guard count == 1 && value == expected else { throw Rejected.control }
        }
    }

    private static func deadline() -> UInt64 {
        DispatchTime.now().uptimeNanoseconds + 20_000_000_000
    }

}
