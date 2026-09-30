import Foundation

enum EvidenceCheckFailure: Error { case failed(String) }

func requireEvidence(_ condition: @autoclosure () -> Bool, _ message: String) throws {
    if !condition() { throw EvidenceCheckFailure.failed(message) }
}

func ip(_ text: String, _ family: OpenVPNIPAddressFamily) throws -> OpenVPNIPAddress {
    try OpenVPNIPAddress(parsing: Substring(text), family: family)
}

func record(_ index: UInt32, _ name: String, _ addresses: [OpenVPNIPAddress],
            up: Bool = true, running: Bool = true, pointToPoint: Bool = true) throws
    -> VPNKernelInterfaceRecord {
    try VPNKernelInterfaceRecord(index: index, name: name, isUp: up, isRunning: running,
                                 isPointToPoint: pointToPoint, addresses: addresses)
}

func connected(_ local4: OpenVPNIPAddress? = nil,
               _ local6: OpenVPNIPAddress? = nil) throws -> OpenVPNConnectedEvidence {
    OpenVPNConnectedEvidence(tunnelLocalIPv4: local4, tunnelLocalIPv6: local6,
        remoteAddress: try ip("203.0.113.9", .ipv4), remotePort: 443)
}

func ipv4AndIPv6Checks() throws {
    let v4 = try ip("10.8.0.2", .ipv4), v6 = try ip("fd00::2", .ipv6)
    let baseline = try VPNKernelInterfaceSnapshot(interfaces: [])
    let after4 = try VPNKernelInterfaceSnapshot(interfaces: [try record(10, "utun9", [v4])])
    let found4 = try VPNTunnelInterfaceResolver.resolve(baseline: baseline, after: after4,
                                                         management: try connected(v4))
    try requireEvidence(found4.index == 10 && found4.name == "utun9", "v4")
    let after6 = try VPNKernelInterfaceSnapshot(interfaces: [try record(11, "utun10", [v6])])
    let found6 = try VPNTunnelInterfaceResolver.resolve(baseline: baseline, after: after6,
                                                         management: try connected(nil, v6))
    try requireEvidence(found6.addresses.contains(v6), "v6")
    let dual = try VPNKernelInterfaceSnapshot(interfaces: [try record(12, "utun11", [v4, v6])])
    _ = try VPNTunnelInterfaceResolver.resolve(baseline: baseline, after: dual,
                                                management: try connected(v4, v6))
    print("families passed")
}

func rejectionChecks() throws {
    let local = try ip("10.8.0.2", .ipv4), other = try ip("10.8.0.3", .ipv4)
    let empty = try VPNKernelInterfaceSnapshot(interfaces: [])
    for after in [
        try VPNKernelInterfaceSnapshot(interfaces: [try record(1, "utun0", [other])]),
        try VPNKernelInterfaceSnapshot(interfaces: [try record(1, "utun0", [local], up: false)]),
        try VPNKernelInterfaceSnapshot(interfaces: [try record(1, "tun0", [local])])
    ] {
        do {
            _ = try VPNTunnelInterfaceResolver.resolve(baseline: empty, after: after,
                                                        management: try connected(local))
            throw EvidenceCheckFailure.failed("mismatch accepted")
        } catch VPNTunnelInterfaceResolutionError.noCandidate {}
    }
    let ambiguous = try VPNKernelInterfaceSnapshot(interfaces: [
        try record(1, "utun0", [local]), try record(2, "utun1", [local])])
    do {
        _ = try VPNTunnelInterfaceResolver.resolve(baseline: empty, after: ambiguous,
                                                    management: try connected(local))
        throw EvidenceCheckFailure.failed("ambiguity accepted")
    } catch VPNTunnelInterfaceResolutionError.ambiguous {}

    let before = try VPNKernelInterfaceSnapshot(interfaces: [try record(8, "utun7", [other])])
    let reused = try VPNKernelInterfaceSnapshot(interfaces: [try record(9, "utun7", [local])])
    do {
        _ = try VPNTunnelInterfaceResolver.resolve(baseline: before, after: reused,
                                                    management: try connected(local))
        throw EvidenceCheckFailure.failed("reused name accepted")
    } catch VPNTunnelInterfaceResolutionError.reusedIdentity {}
    print("rejections passed")
}

func captureCheck() throws {
    let snapshot = try VPNKernelInterfaceSnapshot.capture()
    try requireEvidence(!snapshot.interfaces.isEmpty, "capture")
    print("capture passed")
}

@main
struct TunnelInterfaceEvidenceChecks {
    static func main() {
        do {
            guard CommandLine.arguments.count == 2 else {
                throw EvidenceCheckFailure.failed("case")
            }
            switch CommandLine.arguments[1] {
            case "families": try ipv4AndIPv6Checks()
            case "rejections": try rejectionChecks()
            case "capture": try captureCheck()
            default: throw EvidenceCheckFailure.failed("unknown")
            }
        } catch {
            fputs("\(error)\n", stderr)
            exit(1)
        }
    }
}
