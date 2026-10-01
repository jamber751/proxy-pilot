import Darwin
import Foundation

final class FakePeerRouteTransport: VPNRouteSocketTransport {
    var sent: [Data] = []
    var replies: [Result<Data, VPNRouteSocketTransportError>] = []
    var deadlines: [UInt64] = []

    func send(_ message: Data, deadline: DispatchTime) throws {
        sent.append(message); deadlines.append(deadline.uptimeNanoseconds)
    }

    func receive(maximumBytes: Int, deadline: DispatchTime) throws -> Data {
        deadlines.append(deadline.uptimeNanoseconds)
        guard !replies.isEmpty else { throw VPNRouteSocketTransportError.timeout }
        let data = try replies.removeFirst().get()
        guard data.count <= maximumBytes else { throw VPNRouteSocketTransportError.closed }
        return data
    }
}

@main enum VPNPeerRouteEvidenceChecks {
    static let headerSize = MemoryLayout<rt_msghdr>.size
    static let wordSize = MemoryLayout<UInt32>.size

    static func require(_ condition: @autoclosure () -> Bool, _ message: String) throws {
        guard condition() else { throw NSError(domain: message, code: 1) }
    }

    static func physicalInterface() -> (UInt32, String) {
        for name in ["en0", "en1", "bridge0", "awdl0"] {
            let index = if_nametoindex(name)
            if index > 0 { return (index, name) }
        }
        exit(77)
    }

    static func existingUTUN() -> (UInt32, String)? {
        for number in 0...63 {
            let name = "utun\(number)", index = if_nametoindex(name)
            if index > 0 { return (index, name) }
        }
        return nil
    }

    static func ip(_ text: String, _ family: OpenVPNIPAddressFamily) throws -> OpenVPNIPAddress {
        try OpenVPNIPAddress(parsing: Substring(text), family: family)
    }

    static func sockaddr(_ text: String, family: OpenVPNIPAddressFamily) -> Data {
        if family == .ipv4 {
            var address = in_addr()
            guard text.withCString({ inet_pton(AF_INET, $0, &address) }) == 1 else { exit(64) }
            var value = sockaddr_in(); value.sin_len = UInt8(MemoryLayout<sockaddr_in>.size)
            value.sin_family = sa_family_t(AF_INET); value.sin_addr = address
            return withUnsafeBytes(of: &value) { Data($0) }
        }
        var address = in6_addr()
        guard text.withCString({ inet_pton(AF_INET6, $0, &address) }) == 1 else { exit(64) }
        var value = sockaddr_in6(); value.sin6_len = UInt8(MemoryLayout<sockaddr_in6>.size)
        value.sin6_family = sa_family_t(AF_INET6); value.sin6_addr = address
        return withUnsafeBytes(of: &value) { Data($0) }
    }

    static func netmask(prefix: Int, family: OpenVPNIPAddressFamily,
                        zeroLengthDefault: Bool = false) -> Data {
        if prefix == 0 && zeroLengthDefault { return Data(repeating: 0, count: wordSize) }
        let count = family == .ipv4 ? MemoryLayout<sockaddr_in>.size : MemoryLayout<sockaddr_in6>.size
        let offset = family == .ipv4 ? 4 : 8
        var result = [UInt8](repeating: 0, count: count)
        result[0] = UInt8(count); result[1] = UInt8(family == .ipv4 ? AF_INET : AF_INET6)
        for bit in 0..<prefix { result[offset + bit / 8] |= UInt8(0x80 >> (bit % 8)) }
        return Data(result)
    }

    static func linkGateway(index: UInt32, name: String) -> Data {
        let nameBytes = Array(name.utf8)
        var result = [UInt8](repeating: 0, count: 8 + nameBytes.count)
        result[0] = UInt8(result.count); result[1] = UInt8(AF_LINK)
        result[2] = UInt8(index & 0xff); result[3] = UInt8((index >> 8) & 0xff)
        result[5] = UInt8(nameBytes.count)
        result.replaceSubrange(8..<result.count, with: nameBytes)
        return Data(result)
    }

    static func reply(sequence: Int32, pid: Int32, family: OpenVPNIPAddressFamily,
                      destination: String, prefix: Int, gateway: String?,
                      index: UInt32, name: String, flags: UInt32,
                      error: Int32 = 0, zeroLengthDefault: Bool = false) -> Data {
        var entries: [(Int32, Data)] = [(RTA_DST, sockaddr(destination, family: family))]
        if let gateway { entries.append((RTA_GATEWAY, sockaddr(gateway, family: family))) }
        else { entries.append((RTA_GATEWAY, linkGateway(index: index, name: name))) }
        if prefix != (family == .ipv4 ? 32 : 128) {
            entries.append((RTA_NETMASK, netmask(prefix: prefix, family: family,
                                                 zeroLengthDefault: zeroLengthDefault)))
        }
        var body = Data(), mask: Int32 = 0
        for (bit, address) in entries.sorted(by: { $0.0 < $1.0 }) {
            mask |= bit; body.append(address)
            let padding = aligned(address.count) - address.count
            if padding > 0 { body.append(Data(repeating: 0, count: padding)) }
        }
        var header = rt_msghdr()
        header.rtm_msglen = UInt16(headerSize + body.count)
        header.rtm_version = UInt8(RTM_VERSION); header.rtm_type = UInt8(RTM_GET)
        header.rtm_index = UInt16(index); header.rtm_flags = Int32(bitPattern: flags)
        header.rtm_addrs = mask; header.rtm_pid = pid; header.rtm_seq = sequence
        header.rtm_errno = error
        var result = Data(bytes: &header, count: headerSize); result.append(body)
        return result
    }

    static func ipv4Default() throws {
        let (index, name) = physicalInterface(), pid: Int32 = 501
        let fake = FakePeerRouteTransport()
        fake.replies = [.success(reply(sequence: 1, pid: pid, family: .ipv4,
            destination: "0.0.0.0", prefix: 0, gateway: "192.0.2.1", index: index,
            name: name, flags: UInt32(RTF_UP | RTF_GATEWAY | RTF_STATIC),
            zeroLengthDefault: true))]
        let evidence = try VPNPeerRouteEvidenceResolver(transport: fake, pid: pid,
            timeout: 0.2).resolve(peer: ip("198.51.100.44", .ipv4))
        try require(evidence.peer.canonical == "198.51.100.44", "peer changed")
        try require(evidence.gatewayBytes == [192, 0, 2, 1], "gateway")
        try require(evidence.interfaceIndex == index && evidence.interfaceName == name, "interface")
        try require(fake.sent.count == 1, "request count")
        let header = try VPNDarwinRouteCodec.identify(fake.sent[0])
        try require(header.rtm_type == UInt8(RTM_GET) && header.rtm_seq == 1, "not get")
        try require(Set(fake.deadlines).count == 1, "deadline was reset")
        print("ipv4 default passed")
    }

    static func ipv6AndDirect() throws {
        let (index, name) = physicalInterface(), pid: Int32 = 601
        let viaGateway = FakePeerRouteTransport()
        viaGateway.replies = [.success(reply(sequence: 1, pid: pid, family: .ipv6,
            destination: "2001:db8:44::", prefix: 48, gateway: "2001:db8::1", index: index,
            name: name, flags: UInt32(RTF_UP | RTF_GATEWAY | RTF_STATIC)))]
        let v6 = try VPNPeerRouteEvidenceResolver(transport: viaGateway, pid: pid)
            .resolve(peer: ip("2001:db8:44::99", .ipv6))
        try require(v6.peer.family == .ipv6 && v6.gatewayBytes != nil, "ipv6")

        let direct = FakePeerRouteTransport()
        direct.replies = [.success(reply(sequence: 1, pid: pid, family: .ipv4,
            destination: "198.51.100.0", prefix: 24, gateway: nil, index: index,
            name: name, flags: UInt32(RTF_UP | RTF_STATIC)))]
        let local = try VPNPeerRouteEvidenceResolver(transport: direct, pid: pid)
            .resolve(peer: ip("198.51.100.9", .ipv4))
        try require(local.gatewayBytes == nil, "direct gateway")
        print("ipv6 and direct passed")
    }

    static func matchingAndBounds() throws {
        let (index, name) = physicalInterface(), pid: Int32 = 701
        let fake = FakePeerRouteTransport()
        fake.replies = [
            .success(reply(sequence: 99, pid: pid, family: .ipv4, destination: "0.0.0.0",
                prefix: 0, gateway: "192.0.2.1", index: index, name: name,
                flags: UInt32(RTF_UP | RTF_GATEWAY), zeroLengthDefault: true)),
            .success(reply(sequence: 1, pid: pid, family: .ipv4, destination: "0.0.0.0",
                prefix: 0, gateway: "192.0.2.1", index: index, name: name,
                flags: UInt32(RTF_UP | RTF_GATEWAY), zeroLengthDefault: true))
        ]
        _ = try VPNPeerRouteEvidenceResolver(transport: fake, pid: pid)
            .resolve(peer: ip("203.0.113.8", .ipv4))

        let timeout = FakePeerRouteTransport()
        do {
            _ = try VPNPeerRouteEvidenceResolver(transport: timeout, pid: pid, timeout: 0.01)
                .resolve(peer: ip("203.0.113.8", .ipv4))
            throw NSError(domain: "timeout accepted", code: 1)
        } catch VPNPeerRouteEvidenceError.timeout {}

        let overflow = FakePeerRouteTransport()
        do {
            _ = try VPNPeerRouteEvidenceResolver(transport: overflow, pid: pid,
                initialSequence: Int32.max).resolve(peer: ip("203.0.113.8", .ipv4))
            throw NSError(domain: "sequence overflow", code: 1)
        } catch VPNPeerRouteEvidenceError.responseLimit {}
        print("matching and bounds passed")
    }

    static func notifications() throws {
        let (index, name) = physicalInterface(), pid: Int32 = 711
        var noticeHeader = ifa_msghdr()
        noticeHeader.ifam_msglen = UInt16(MemoryLayout<ifa_msghdr>.size)
        noticeHeader.ifam_version = UInt8(RTM_VERSION)
        noticeHeader.ifam_type = UInt8(RTM_NEWADDR)
        noticeHeader.ifam_index = UInt16(index)
        // Shape captured during the real attempt: NEWADDR 80 bytes,
        // netmask(7->8), link(20), address(16), point-to-point peer(16).
        // Addresses here are documentation fixtures, never captured payload.
        var body = Data([7, UInt8(AF_INET), 0, 0, 255, 255, 255, 0])
        var link = Data(repeating: 0, count: 20)
        link[0] = 20; link[1] = UInt8(AF_LINK)
        body.append(link)
        body.append(sockaddr("192.0.2.9", family: .ipv4))
        body.append(sockaddr("192.0.2.1", family: .ipv4))
        noticeHeader.ifam_addrs = RTA_NETMASK | RTA_IFP | RTA_IFA | RTA_BRD
        noticeHeader.ifam_msglen = UInt16(MemoryLayout<ifa_msghdr>.size + body.count)
        var notice = withUnsafeBytes(of: &noticeHeader) { Data($0) }
        notice.append(body)
        try require(notice.count == 80 && notice.count < headerSize, "captured notification shape")
        let valid = reply(sequence: 1, pid: pid, family: .ipv4, destination: "0.0.0.0",
            prefix: 0, gateway: "192.0.2.1", index: index, name: name,
            flags: UInt32(RTF_UP | RTF_GATEWAY), zeroLengthDefault: true)
        let fake = FakePeerRouteTransport()
        fake.replies = [.success(notice), .success(valid)]
        let evidence = try VPNPeerRouteEvidenceResolver(transport: fake, pid: pid)
            .resolve(peer: ip("203.0.113.8", .ipv4))
        try require(evidence.interfaceIndex == index && fake.replies.isEmpty,
                    "notification blocked matched peer reply")
        try require(Set(fake.deadlines).count == 1, "notification extended deadline")
        var malformed = notice; malformed[0] = 0
        let bad = FakePeerRouteTransport(); bad.replies = [.success(malformed), .success(valid)]
        do { _ = try VPNPeerRouteEvidenceResolver(transport: bad, pid: pid)
            .resolve(peer: ip("203.0.113.8", .ipv4))
            throw NSError(domain: "malformed framing ignored", code: 1)
        } catch VPNPeerRouteEvidenceError.malformedMessage {}
        let flood = FakePeerRouteTransport()
        flood.replies = Array(repeating: .success(notice), count: 128) + [.success(valid)]
        do { _ = try VPNPeerRouteEvidenceResolver(transport: flood, pid: pid)
            .resolve(peer: ip("203.0.113.8", .ipv4))
            throw NSError(domain: "unbounded notification drain", code: 1)
        } catch VPNPeerRouteEvidenceError.responseLimit {}
        try require(flood.replies.count == 1, "bounded notification drain")
        print("notification handling passed")
    }

    static func existingVPNChaining() throws {
        guard let (index, name) = existingUTUN() else {
            print("existing utun unavailable; chaining fixture skipped")
            return
        }
        let pid: Int32 = 751, fake = FakePeerRouteTransport()
        fake.replies = [.success(reply(sequence: 1, pid: pid, family: .ipv4,
            destination: "198.51.100.0", prefix: 24, gateway: nil, index: index,
            name: name, flags: UInt32(RTF_UP | RTF_STATIC)))]
        let evidence = try VPNPeerRouteEvidenceResolver(transport: fake, pid: pid)
            .resolve(peer: ip("198.51.100.9", .ipv4))
        try require(evidence.interfaceIndex == index && evidence.interfaceName == name,
                    "existing vpn route rejected")
        print("existing vpn chaining passed")
    }

    static func rejectsUntrustedEvidence() throws {
        let (index, name) = physicalInterface(), pid: Int32 = 801
        let peer = try ip("198.51.100.9", .ipv4)
        let cases: [(String, Data)] = [
            ("wrong network", reply(sequence: 1, pid: pid, family: .ipv4,
                destination: "203.0.113.0", prefix: 24, gateway: "192.0.2.1", index: index,
                name: name, flags: UInt32(RTF_UP | RTF_GATEWAY))),
            ("noncanonical network", reply(sequence: 1, pid: pid, family: .ipv4,
                destination: "198.51.100.7", prefix: 24, gateway: "192.0.2.1", index: index,
                name: name, flags: UInt32(RTF_UP | RTF_GATEWAY))),
            ("down", reply(sequence: 1, pid: pid, family: .ipv4,
                destination: "0.0.0.0", prefix: 0, gateway: "192.0.2.1", index: index,
                name: name, flags: UInt32(RTF_GATEWAY), zeroLengthDefault: true)),
            ("rejected", reply(sequence: 1, pid: pid, family: .ipv4,
                destination: "0.0.0.0", prefix: 0, gateway: "192.0.2.1", index: index,
                name: name, flags: UInt32(RTF_UP | RTF_GATEWAY | RTF_REJECT),
                zeroLengthDefault: true)),
            ("gateway flag mismatch", reply(sequence: 1, pid: pid, family: .ipv4,
                destination: "0.0.0.0", prefix: 0, gateway: nil, index: index,
                name: name, flags: UInt32(RTF_UP | RTF_GATEWAY), zeroLengthDefault: true))
        ]
        for (label, data) in cases {
            let fake = FakePeerRouteTransport(); fake.replies = [.success(data)]
            do {
                _ = try VPNPeerRouteEvidenceResolver(transport: fake, pid: pid).resolve(peer: peer)
                throw NSError(domain: "accepted \(label)", code: 1)
            } catch VPNPeerRouteEvidenceError.unusableRoute {}
        }

        let malformed = FakePeerRouteTransport()
        var truncated = cases[0].1; truncated.removeLast()
        malformed.replies = [.success(truncated)]
        do {
            _ = try VPNPeerRouteEvidenceResolver(transport: malformed, pid: pid).resolve(peer: peer)
            throw NSError(domain: "malformed accepted", code: 1)
        } catch VPNPeerRouteEvidenceError.malformedMessage {}

        let denied = FakePeerRouteTransport()
        denied.replies = [.success(reply(sequence: 1, pid: pid, family: .ipv4,
            destination: "0.0.0.0", prefix: 0, gateway: "192.0.2.1", index: index,
            name: name, flags: UInt32(RTF_UP | RTF_GATEWAY), error: EPERM,
            zeroLengthDefault: true))]
        do {
            _ = try VPNPeerRouteEvidenceResolver(transport: denied, pid: pid).resolve(peer: peer)
            throw NSError(domain: "kernel error accepted", code: 1)
        } catch VPNPeerRouteEvidenceError.kernel(EPERM) {}

        let invalidPeers: [(String, OpenVPNIPAddressFamily)] = [
            ("0.0.0.0", .ipv4), ("127.0.0.1", .ipv4), ("224.0.0.1", .ipv4),
            ("::", .ipv6), ("::1", .ipv6), ("fe80::1", .ipv6), ("ff00::1", .ipv6)
        ]
        for (address, family) in invalidPeers {
            let invalidPeer = FakePeerRouteTransport()
            do {
                _ = try VPNPeerRouteEvidenceResolver(transport: invalidPeer, pid: pid)
                    .resolve(peer: ip(address, family))
                throw NSError(domain: "invalid peer accepted: \(address)", code: 1)
            } catch VPNPeerRouteEvidenceError.invalidPeer {}
            try require(invalidPeer.sent.isEmpty, "invalid peer reached kernel: \(address)")
        }
        print("untrusted evidence rejected")
    }

    static func main() throws {
        try ipv4Default(); try ipv6AndDirect(); try matchingAndBounds(); try notifications(); try existingVPNChaining()
        try rejectsUntrustedEvidence(); print("peer route evidence checks passed")
    }

    static func aligned(_ count: Int) -> Int {
        (count + wordSize - 1) & ~(wordSize - 1)
    }
}
