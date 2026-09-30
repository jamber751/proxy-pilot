import Darwin
import Foundation

final class FakeRouteTransport: VPNRouteSocketTransport {
    var sent: [Data] = []
    var replies: [Result<Data, VPNRouteSocketTransportError>] = []

    func send(_ message: Data, deadline: DispatchTime) throws { sent.append(message) }
    func receive(maximumBytes: Int, deadline: DispatchTime) throws -> Data {
        guard !replies.isEmpty else { throw VPNRouteSocketTransportError.timeout }
        return try replies.removeFirst().get()
    }
}

@main enum VPNDarwinRouteSocketChecks {
    static func require(_ condition: @autoclosure () -> Bool, _ message: String) throws {
        guard condition() else { throw NSError(domain: message, code: 1) }
    }

    static func ipv4(_ text: String) -> in_addr {
        var value = in_addr(); guard text.withCString({ inet_pton(AF_INET, $0, &value) }) == 1 else { exit(64) }
        return value
    }

    static func ipv6(_ text: String) -> in6_addr {
        var value = in6_addr(); guard text.withCString({ inet_pton(AF_INET6, $0, &value) }) == 1 else { exit(64) }
        return value
    }

    static func interfaceIndex() -> UInt32 {
        for name in ["lo0", "en0", "en1"] { let index = if_nametoindex(name); if index > 0 { return index } }
        exit(77)
    }

    static func tunnelIdentity() -> (UInt32, String) {
        guard let first = if_nameindex() else { exit(77) }
        defer { if_freenameindex(first) }
        var cursor = first
        while cursor.pointee.if_index != 0, let raw = cursor.pointee.if_name {
            let item = cursor.pointee
            let name = String(cString: raw), suffix = name.dropFirst(4)
            if name.hasPrefix("utun"), !suffix.isEmpty,
               suffix.utf8.allSatisfy({ (48...57).contains($0) }) {
                return (item.if_index, name)
            }
            cursor = cursor.advanced(by: 1)
        }
        exit(77)
    }

    static func tunnelEvidence() throws -> VPNTunnelInterfaceEvidence {
        let identity = tunnelIdentity()
        let address = try OpenVPNIPAddress(parsing: "10.255.254.1", family: .ipv4)
        let baseline = try VPNKernelInterfaceSnapshot(interfaces: [])
        let after = try VPNKernelInterfaceSnapshot(interfaces: [
            try VPNKernelInterfaceRecord(index: identity.0, name: identity.1, isUp: true,
                isRunning: true, isPointToPoint: true, addresses: [address])
        ])
        let management = OpenVPNConnectedEvidence(tunnelLocalIPv4: address,
            tunnelLocalIPv6: nil,
            remoteAddress: try OpenVPNIPAddress(parsing: "198.51.100.44", family: .ipv4),
            remotePort: 443)
        return try VPNTunnelInterfaceResolver.resolve(baseline: baseline, after: after,
                                                       management: management)
    }

    static func interfaceName(_ index: UInt32) -> String {
        var name = [CChar](repeating: 0, count: Int(IFNAMSIZ))
        guard if_indextoname(index, &name) != nil else { exit(77) }
        return String(cString: name)
    }

    static func observedIdentity(for route: VPNPlannedRoute, interfaceIndex: UInt32,
                                 flags: UInt32) throws -> VPNOwnedRouteIdentity {
        let matching: VPNRouteKernelEvidence
        if route.destination.family == .ipv4 {
            matching = try VPNRouteKernelEvidence(gateway: Optional<in_addr>.none,
                interfaceIndex: route.interfaceIndex!, flags: 0x801)
        } else {
            matching = try VPNRouteKernelEvidence(gateway: Optional<in6_addr>.none,
                interfaceIndex: route.interfaceIndex!, flags: 0x801)
        }
        let owned = try VPNOwnedRouteIdentity(planned: route, evidence: matching)
        var object = try JSONSerialization.jsonObject(with: JSONEncoder().encode(owned))
            as! [String: Any]
        object["interfaceIndex"] = interfaceIndex
        object["interfaceName"] = interfaceName(interfaceIndex)
        object["flags"] = flags
        return try JSONDecoder().decode(VPNOwnedRouteIdentity.self,
            from: JSONSerialization.data(withJSONObject: object))
    }

    static func plan() throws -> VPNRoutePlan {
        try VPNRoutePlan(generation: 31, revision: 7, resources: [
            VPNResource(address: "10.44.0.0/16"), VPNResource(address: "2001:db8::99"),
            VPNResource(address: "2001:db8:44::/48")
        ], peer: VPNRoutePeerEvidence(peer: ipv4("198.51.100.44"),
             gateway: ipv4("192.0.2.1"), interfaceIndex: interfaceIndex()),
           tunnel: try tunnelEvidence())
    }

    static func identities() throws -> [VPNOwnedRouteIdentity] {
        let value = try plan(), index = interfaceIndex(), tunnelIndex = tunnelIdentity().0
        return try value.routes.map { route in
            if route.role == .peerBypass {
                return try VPNOwnedRouteIdentity(planned: route,
                    evidence: VPNRouteKernelEvidence(gateway: ipv4("192.0.2.1"),
                                                     interfaceIndex: index, flags: 0x807))
            }
            if route.destination.family == .ipv4 {
                return try VPNOwnedRouteIdentity(planned: route,
                    evidence: VPNRouteKernelEvidence(gateway: Optional<in_addr>.none,
                                                     interfaceIndex: tunnelIndex, flags: 0x801))
            }
            return try VPNOwnedRouteIdentity(planned: route,
                evidence: VPNRouteKernelEvidence(gateway: Optional<in6_addr>.none,
                                                 interfaceIndex: tunnelIndex,
                                                 flags: route.destination.prefixLength == 128 ? 0x805 : 0x801))
        }
    }

    static func codec() throws {
        for identity in try identities() {
            for messageType in [UInt8(RTM_GET), UInt8(RTM_ADD), UInt8(RTM_DELETE)] {
                let data = try VPNDarwinRouteCodec.encodeReply(type: messageType, sequence: 9,
                                                               pid: 55, error: 0, identity: identity)
                let decoded = try VPNDarwinRouteCodec.decode(data)
                try require(decoded.sequence == 9 && decoded.pid == 55
                            && decoded.type == messageType, "header")
                try require(decoded.snapshot?.matches(identity) == true, "round trip")
                let evidence = try decoded.snapshot!.kernelEvidence()
                try require(evidence.family == identity.destination.family
                            && evidence.gatewayBytes == identity.gatewayBytes, "typed evidence")
            }
        }
        let identity = try identities()[0]
        let confirmed = try VPNDarwinRouteCodec.encodeReply(type: UInt8(RTM_GET), sequence: 10,
            pid: 56, error: 0, identity: identity, responseFlags: UInt32(RTF_DONE))
        let normalized = try VPNDarwinRouteCodec.decode(confirmed).snapshot
        try require(normalized?.matches(identity) == true, "message flags normalized")
        print("codec passed")
    }

    static func malformed() throws {
        let identity = try identities()[1]
        let valid = try VPNDarwinRouteCodec.encodeReply(type: UInt8(RTM_GET), sequence: 1,
                                                        pid: 2, error: 0, identity: identity)
        for broken in [Data(), valid.prefix(3), valid.prefix(valid.count - 1)] {
            do { _ = try VPNDarwinRouteCodec.decode(Data(broken)); throw NSError(domain: "accepted truncated", code: 1) }
            catch VPNDarwinRouteError.malformedMessage {}
        }
        var invalidLength = valid
        invalidLength[MemoryLayout<rt_msghdr>.size] = 1
        do { _ = try VPNDarwinRouteCodec.decode(invalidLength); throw NSError(domain: "accepted sockaddr", code: 1) }
        catch VPNDarwinRouteError.malformedMessage {}
        var trailing = valid; trailing.append(0)
        do { _ = try VPNDarwinRouteCodec.decode(trailing); throw NSError(domain: "accepted trailing bytes", code: 1) }
        catch VPNDarwinRouteError.malformedMessage {}
        print("malformed passed")
    }

    static func matchingAndErrno() throws {
        let identity = try identities()[1], fake = FakeRouteTransport(), pid: Int32 = 414
        var unrelatedMalformed = try VPNDarwinRouteCodec.encodeReply(type: UInt8(RTM_GET), sequence: 1,
                                                                     pid: pid + 1, error: 0,
                                                                     identity: identity)
        unrelatedMalformed[MemoryLayout<rt_msghdr>.size] = 1
        fake.replies = [
            .success(unrelatedMalformed),
            .success(try VPNDarwinRouteCodec.encodeReply(type: UInt8(RTM_GET), sequence: 99,
                                                         pid: pid, error: 0, identity: identity)),
            .success(try VPNDarwinRouteCodec.encodeReply(type: UInt8(RTM_GET), sequence: 1,
                                                         pid: pid, error: 0, identity: identity))
        ]
        let socket = VPNDarwinRouteSocket(transport: fake, pid: pid, timeout: 0.2)
        let found = try socket.lookupExact(identity.destination)
        try require(found?.matches(identity) == true, "seq pid matching")

        let denied = FakeRouteTransport()
        denied.replies = [.success(try VPNDarwinRouteCodec.encodeReply(type: UInt8(RTM_GET),
                           sequence: 1, pid: pid, error: EPERM, identity: nil))]
        do {
            _ = try VPNDarwinRouteSocket(transport: denied, pid: pid).lookupExact(identity.destination)
            throw NSError(domain: "errno ignored", code: 1)
        } catch VPNDarwinRouteError.kernel(EPERM) {}
        let timeout = FakeRouteTransport()
        do {
            _ = try VPNDarwinRouteSocket(transport: timeout, pid: pid).lookupExact(identity.destination)
            throw NSError(domain: "timeout ignored", code: 1)
        } catch VPNDarwinRouteError.timeout {}
        print("matching passed")
    }

    // Independent Darwin wire fixture: sockaddr alignment is four bytes,
    // including a zero-length default netmask. Do not use the codec encoder.
    static func defaultReply(family: VPNRouteAddressFamily, type: UInt8 = UInt8(RTM_GET),
                             sequence: Int32 = 1, pid: Int32 = 515) -> Data {
        let length = family == .ipv4 ? 16 : 28
        var destination = Data(repeating: 0, count: length)
        destination[0] = UInt8(length)
        destination[1] = UInt8(family == .ipv4 ? AF_INET : AF_INET6)
        // Kernel may echo the queried host in the destination field.
        destination[family == .ipv4 ? 4 : 8] = family == .ipv4 ? 198 : 0x20
        var gateway = destination
        gateway[family == .ipv4 ? 4 : 8] = family == .ipv4 ? 192 : 0x20
        var body = destination; body.append(gateway)
        body.append(Data(repeating: 0, count: 4))
        var header = rt_msghdr()
        header.rtm_msglen = UInt16(MemoryLayout<rt_msghdr>.size + body.count)
        header.rtm_version = UInt8(RTM_VERSION); header.rtm_type = type
        header.rtm_index = UInt16(interfaceIndex())
        header.rtm_flags = RTF_UP | RTF_GATEWAY | RTF_STATIC | RTF_DONE
        header.rtm_addrs = RTA_DST | RTA_GATEWAY | RTA_NETMASK
        header.rtm_seq = sequence; header.rtm_pid = pid
        var reply = withUnsafeBytes(of: &header) { Data($0) }
        reply.append(body); return reply
    }

    static func defaultBestRoute() throws {
        for family in [VPNRouteAddressFamily.ipv4, .ipv6] {
            let reply = defaultReply(family: family)
            let decoded = try VPNDarwinRouteCodec.decode(reply)
            try require(decoded.snapshot == nil, "default must not become owned evidence")
            let fake = FakeRouteTransport(); fake.replies = [.success(reply)]
            let host = try VPNRoutePrefix(resource: VPNResource(address:
                family == .ipv4 ? "198.51.100.44" : "2001:db8::44"))
            let result = try VPNDarwinRouteSocket(transport: fake, pid: 515).lookupExact(host)
            try require(result == nil && fake.sent.count == 1, "default is not exact")
            var oversized = reply
            oversized.append(Data(repeating: 0, count: 4))
            var oversizedHeader = try VPNDarwinRouteCodec.identify(reply)
            oversizedHeader.rtm_msglen = UInt16(oversized.count)
            withUnsafeBytes(of: &oversizedHeader) {
                oversized.replaceSubrange(0..<MemoryLayout<rt_msghdr>.size, with: $0)
            }
            do { _ = try VPNDarwinRouteCodec.decode(oversized)
                 throw NSError(domain: "64-bit mask padding accepted", code: 1) }
            catch VPNDarwinRouteError.malformedMessage {}
            for type in [UInt8(RTM_ADD), UInt8(RTM_DELETE)] {
                do {
                    _ = try VPNDarwinRouteCodec.decode(defaultReply(family: family, type: type))
                    throw NSError(domain: "default mutation accepted", code: 1)
                } catch VPNDarwinRouteError.malformedMessage {}
            }
            var invalid = reply
            invalid[MemoryLayout<rt_msghdr>.size] = 0
            do { _ = try VPNDarwinRouteCodec.decode(invalid)
                 throw NSError(domain: "zero destination sockaddr accepted", code: 1) }
            catch VPNDarwinRouteError.malformedMessage {}
        }
        let identity = try identities()[1], fake = FakeRouteTransport(), pid: Int32 = 515
        fake.replies = [
            .success(defaultReply(family: .ipv4)),
            .success(try VPNDarwinRouteCodec.encodeReply(type: UInt8(RTM_ADD), sequence: 2,
                pid: pid, error: 0, identity: nil)),
            .success(try VPNDarwinRouteCodec.encodeReply(type: UInt8(RTM_GET), sequence: 3,
                pid: pid, error: 0, identity: identity))
        ]
        let added = try VPNDarwinRouteSocket(transport: fake, pid: pid).add(identity)
        try require(added == .installed, "default fallback allows exact install")
        let foreign = FakeRouteTransport(); foreign.replies = [.success(defaultReply(family: .ipv4))]
        do { _ = try VPNDarwinRouteSocket(transport: foreign, pid: pid).delete(identity)
             throw NSError(domain: "default deleted", code: 1) }
        catch VPNDarwinRouteError.missingOrForeign {}
        try require(foreign.sent.count == 1, "default never mutated")
        print("default best route passed")
    }

    static func addCases() throws {
        let identity = try identities()[1], pid: Int32 = 701
        let missing = try VPNDarwinRouteCodec.encodeReply(type: UInt8(RTM_GET), sequence: 1,
                                                          pid: pid, error: ESRCH, identity: nil)
        let ack = try VPNDarwinRouteCodec.encodeReply(type: UInt8(RTM_ADD), sequence: 2,
                                                      pid: pid, error: 0, identity: nil)
        let present = try VPNDarwinRouteCodec.encodeReply(type: UInt8(RTM_GET), sequence: 3,
                                                          pid: pid, error: 0, identity: identity)
        let fake = FakeRouteTransport(); fake.replies = [.success(missing), .success(ack), .success(present)]
        let result = try VPNDarwinRouteSocket(transport: fake, pid: pid).add(identity)
        try require(result == .installed && fake.sent.count == 3, "install and verify")

        let same = FakeRouteTransport()
        same.replies = [.success(try VPNDarwinRouteCodec.encodeReply(type: UInt8(RTM_GET),
                         sequence: 1, pid: pid, error: 0, identity: identity))]
        let idempotent = try VPNDarwinRouteSocket(transport: same, pid: pid).add(identity)
        try require(idempotent == .alreadyPresent, "idempotent")
        try require(same.sent.count == 1, "idempotent no add")

        let planRoute = try plan().routes[1]
        let foreign = try observedIdentity(for: planRoute, interfaceIndex: interfaceIndex(), flags: 0x901)
        let conflict = FakeRouteTransport()
        conflict.replies = [.success(try VPNDarwinRouteCodec.encodeReply(type: UInt8(RTM_GET),
                             sequence: 1, pid: pid, error: 0, identity: foreign))]
        do { _ = try VPNDarwinRouteSocket(transport: conflict, pid: pid).add(identity)
             throw NSError(domain: "foreign overwritten", code: 1) }
        catch VPNDarwinRouteError.preexistingNonIdentical {}
        try require(conflict.sent.count == 1, "foreign no add")
        print("add passed")
    }

    static func deleteCases() throws {
        let identity = try identities()[2], pid: Int32 = 808
        let fake = FakeRouteTransport()
        fake.replies = [
            .success(try VPNDarwinRouteCodec.encodeReply(type: UInt8(RTM_GET), sequence: 1,
                                                         pid: pid, error: 0, identity: identity)),
            .success(try VPNDarwinRouteCodec.encodeReply(type: UInt8(RTM_DELETE), sequence: 2,
                                                         pid: pid, error: 0, identity: nil)),
            .success(try VPNDarwinRouteCodec.encodeReply(type: UInt8(RTM_GET), sequence: 3,
                                                         pid: pid, error: ESRCH, identity: nil))
        ]
        let removed = try VPNDarwinRouteSocket(transport: fake, pid: pid).delete(identity)
        try require(removed == .removed, "exact delete")
        let missing = FakeRouteTransport()
        missing.replies = [.success(try VPNDarwinRouteCodec.encodeReply(type: UInt8(RTM_GET),
                             sequence: 1, pid: pid, error: ESRCH, identity: nil))]
        do { _ = try VPNDarwinRouteSocket(transport: missing, pid: pid).delete(identity)
             throw NSError(domain: "missing treated owned", code: 1) }
        catch VPNDarwinRouteError.missingOrForeign {}

        let planned = try plan().routes.first { $0.destination == identity.destination }!
        let foreign = try observedIdentity(for: planned, interfaceIndex: interfaceIndex(), flags: 0x905)
        let conflict = FakeRouteTransport()
        conflict.replies = [.success(try VPNDarwinRouteCodec.encodeReply(type: UInt8(RTM_GET),
                             sequence: 1, pid: pid, error: 0, identity: foreign))]
        do { _ = try VPNDarwinRouteSocket(transport: conflict, pid: pid).delete(identity)
             throw NSError(domain: "foreign deleted", code: 1) }
        catch VPNDarwinRouteError.missingOrForeign {}
        try require(conflict.sent.count == 1, "foreign no delete")
        print("delete passed")
    }

    static func recovery(_ path: String) throws {
        let descriptor = open(path, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
        guard descriptor >= 0 else { exit(70) }; defer { close(descriptor) }
        let routePlan = try plan(), identity = try identities()[0]
        let journal = try VPNRouteJournal(trustedDirectoryDescriptor: descriptor)
        _ = try journal.create(routePlan)
        _ = try journal.beginInstall(identity, generation: 31, revision: 7)
        let recovered = try VPNRouteJournal(trustedDirectoryDescriptor: descriptor).load()
        try require(recovered.operation?.entry == identity, "checkpoint lost")
        let pid: Int32 = 909, fake = FakeRouteTransport()
        fake.replies = [.success(try VPNDarwinRouteCodec.encodeReply(type: UInt8(RTM_GET),
                         sequence: 1, pid: pid, error: 0, identity: identity))]
        let compared = try VPNDarwinRouteSocket(transport: fake, pid: pid).add(identity)
        try require(compared == .alreadyPresent, "recovery compare")
        let resolved = try journal.resolveInstall(identity, present: true, generation: 31, revision: 7)
        try require(resolved.applied == [identity] && resolved.operation == nil, "recovery resolve")
        print("recovery passed")
    }

    static func main() throws {
        try codec(); try malformed(); try matchingAndErrno(); try defaultBestRoute()
        try addCases(); try deleteCases()
        guard CommandLine.arguments.count == 2 else { exit(64) }
        try recovery(CommandLine.arguments[1]); print("route socket checks passed")
    }
}
