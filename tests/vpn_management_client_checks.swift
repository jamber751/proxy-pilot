import Darwin
import Dispatch
import Foundation

enum CheckFailure: Error { case failed(String) }

func require(_ condition: @autoclosure () -> Bool, _ message: String) throws {
    if !condition() { throw CheckFailure.failed(message) }
}

func pair() throws -> (Int32, Int32) {
    var descriptors = [Int32](repeating: -1, count: 2)
    guard socketpair(AF_UNIX, SOCK_STREAM, 0, &descriptors) == 0 else {
        throw CheckFailure.failed("socketpair")
    }
    return (descriptors[0], descriptors[1])
}

func sendAll(_ descriptor: Int32, _ text: String) throws {
    let bytes = Array(text.utf8)
    let sent = bytes.withUnsafeBytes { Darwin.send(descriptor, $0.baseAddress, bytes.count, MSG_NOSIGNAL) }
    try require(sent == bytes.count, "send")
}

func parserChecks() throws {
    let info = try OpenVPNManagementParser.parse(line: Array(">INFO:version".utf8))
    let state = try OpenVPNManagementParser.parse(line: Array(">STATE:1,CONNECTED,SUCCESS,10.0.0.2,1.2.3.4,443".utf8))
    let auth = try OpenVPNManagementParser.parse(line: Array(">PASSWORD:Need 'Auth' username/password".utf8))
    let otp = try OpenVPNManagementParser.parse(line: Array(">PASSWORD:Need 'Auth' username/password SC:OTP".utf8))
    let rejected = try OpenVPNManagementParser.parse(line: Array(">PASSWORD:Verification Failed: 'Auth'".utf8))
    let key = try OpenVPNManagementParser.parse(line: Array(">PASSWORD:Need 'Private Key' password".utf8))
    let ignored = try OpenVPNManagementParser.parse(line: Array(">LOG:1,N,message".utf8))
    try require(info == .ready, "info")
    guard case .state(let connectedState) = state,
          let connected = connectedState.connected else {
        throw CheckFailure.failed("connected evidence")
    }
    try require(connectedState.timestamp == 1 && connectedState.state == .connected, "state")
    try require(connected.tunnelLocalIPv4?.bytes == [10, 0, 0, 2], "local v4")
    try require(connected.remoteAddress.bytes == [1, 2, 3, 4]
                && connected.remotePort == 443, "redacted remote")
    let ipv4Event = try OpenVPNManagementParser.parse(line: Array(
        ">STATE:2,CONNECTED,SUCCESS,10.0.0.2,1.2.3.4,443,192.0.2.10,54321".utf8))
    guard case .state(let ipv4State) = ipv4Event,
          ipv4State.connected?.tunnelLocalIPv4 != nil,
          ipv4State.connected?.tunnelLocalIPv6 == nil else { throw CheckFailure.failed("OpenVPN 2.7 IPv4 state") }
    let dualEvent = try OpenVPNManagementParser.parse(line: Array(
        ">STATE:2,CONNECTED,SUCCESS,10.0.0.2,1.2.3.4,443,192.0.2.10,54321,fd00::2".utf8))
    for line in [">STATE:2,CONNECTED,SUCCESS,10.0.0.2,1.2.3.4,443,,",
                 ">STATE:2,CONNECTED,SUCCESS,10.0.0.2,1.2.3.4,443,,,fd00::2"] {
        guard case .state(let result) = try OpenVPNManagementParser.parse(line: Array(line.utf8)),
              result.connected?.tunnelLocalIPv4 != nil else { throw CheckFailure.failed("UDP unspecified local bind") }
    }
    guard case .state(let dualState) = dualEvent, let dual = dualState.connected else {
        throw CheckFailure.failed("dual-stack evidence")
    }
    try require(dual.tunnelLocalIPv4?.bytes == [10, 0, 0, 2]
                && dual.tunnelLocalIPv6?.bytes.count == 16
                && dual.remoteAddress.family == .ipv4 && dual.remotePort == 443, "dual-stack")
    let ipv6Event = try OpenVPNManagementParser.parse(line: Array(
        ">STATE:3,CONNECTED,SUCCESS,,2001:db8::1,1194,2001:db8:ffff::2,54321,fd00::2".utf8))
    guard case .state(let ipv6State) = ipv6Event, let ipv6 = ipv6State.connected else {
        throw CheckFailure.failed("ipv6 evidence")
    }
    try require(ipv6.tunnelLocalIPv6?.bytes.count == 16
                && ipv6.remoteAddress.family == .ipv6 && ipv6.remotePort == 1194, "ipv6")
    try require(auth == .credentialRequired(.usernameAndPassword), "auth")
    try require(otp == .credentialRequired(.staticChallenge), "otp")
    try require(rejected == .credentialRejected(.usernameAndPassword), "rejected")
    try require(key == .credentialRequired(.privateKeyPassphrase), "key")
    try require(ignored == nil, "ignored")
    let tokenNotice = try OpenVPNManagementParser.parse(line: Array(
        ">PASSWORD:Auth-Token:NEVER-PERSIST-THIS-TOKEN".utf8))
    let rejectionNotice = try OpenVPNManagementParser.parse(line: Array(
        ">PASSWORD:Verification Failed: 'Auth' ['NEVER-LOG-SERVER-EXPLANATION']".utf8))
    try require(tokenNotice == nil, "discard token notification")
    try require(rejectionNotice == .credentialRejected(.usernameAndPassword), "discard rejection explanation")

    for unsafe in [[UInt8](repeating: 65, count: OpenVPNManagementParser.maximumLineBytes + 1),
                   Array(">STATE:nope,CONNECTED".utf8),
                   Array(">STATE:1,CONNECTED,secret,10.0.0.2,server.example,443".utf8),
                   Array(">STATE:1,CONNECTED,secret,10.0.0.2,1.2.3.4,0".utf8),
                   Array(">STATE:1,CONNECTED,secret,10.0.0.2,1.2.3.4,443,192.0.2.10,0".utf8),
                   Array(">STATE:1,CONNECTED,secret,10.0.0.2,1.2.3.4,443,192.0.2.10,".utf8),
                   Array(">STATE:1,CONNECTED,secret,10.0.0.2,1.2.3.4,443,,54321".utf8),
                   Array(">STATE:1,CONNECTED,secret,10.0.0.2,1.2.3.4,443,2001:db8::2,54321".utf8),
                   Array(">STATE:1,CONNECTED,secret,10.0.0.2,1.2.3.4,443,2001:db8::2,54321,fd00::2".utf8),
                   Array(">STATE:1,CONNECTED,secret,10.0.0.2,1.2.3.4,443,192.0.2.10,54321,not-an-ip".utf8),
                   Array(">STATE:4102444801,AUTH,,,,".utf8),
                   Array(">PASSWORD:Need 'Auth' username/password Private Key".utf8),
                   Array(">PASSWORD:Need 'Other' username/password 'Auth'".utf8),
                   Array(">PASSWORD:Need 'Auth' username/password SC:".utf8),
                   Array(">PASSWORD:Verification Failed: 'Other' 'Auth'".utf8),
                   Array(">PASSWORD:Verification Failed: 'Other' ['Auth']".utf8),
                   Array(">PASSWORD:Verification Failed: 'Auth' ['unterminated".utf8),
                   [0xff], Array("arbitrary response".utf8)] {
        do {
            _ = try OpenVPNManagementParser.parse(line: unsafe)
            throw CheckFailure.failed("unsafe line accepted")
        } catch is OpenVPNManagementParseError {}
    }
    print("parser passed")
}

func streamChecks() throws {
    let (clientFD, serverFD) = try pair()
    defer { Darwin.close(serverFD) }
    let client = try OpenVPNManagementClient(takingConnectedSocket: clientFD)
    try sendAll(serverFD, ">LOG:ignored\r\n>STATE:2,AUTH,,,,\r\n")
    let event = try client.readEvent()
    guard case .state(let streamState) = event else { throw CheckFailure.failed("stream event") }
    try require(streamState.state == .authenticating && streamState.timestamp == 2, "stream event")
    try client.send(.releaseHold)
    let responseSize = "hold release\n".utf8.count
    var response = [UInt8](repeating: 0, count: responseSize)
    let count = response.withUnsafeMutableBytes { recv(serverFD, $0.baseAddress, responseSize, 0) }
    try require(count == response.count && String(bytes: response, encoding: .utf8) == "hold release\n", "fixed command")
    print("stream passed")
}

func limitsChecks() throws {
    do {
        let (clientFD, serverFD) = try pair(); defer { Darwin.close(serverFD) }
        let client = try OpenVPNManagementClient(takingConnectedSocket: clientFD)
        try sendAll(serverFD, String(repeating: "x", count: OpenVPNManagementParser.maximumLineBytes + 1) + "\n")
        _ = try client.readEvent()
        throw CheckFailure.failed("long line accepted")
    } catch OpenVPNManagementClientError.lineTooLong {}

    do {
        let (clientFD, serverFD) = try pair(); defer { Darwin.close(serverFD) }
        let client = try OpenVPNManagementClient(takingConnectedSocket: clientFD)
        try sendAll(serverFD, String(repeating: ">LOG:x\n", count: OpenVPNManagementClient.maximumIgnoredMessages + 1))
        _ = try client.readEvent()
        throw CheckFailure.failed("message flood accepted")
    } catch OpenVPNManagementClientError.tooManyIgnoredMessages {}

    do {
        let (clientFD, serverFD) = try pair(); defer { Darwin.close(serverFD) }
        let client = try OpenVPNManagementClient(takingConnectedSocket: clientFD)
        _ = try client.readEvent(timeoutMilliseconds: 20)
        throw CheckFailure.failed("deadline ignored")
    } catch OpenVPNManagementClientError.timeout {}
    print("limits passed")
}

func loopbackChecks() throws {
    let listener = socket(AF_INET, SOCK_STREAM, 0)
    guard listener >= 0 else { throw CheckFailure.failed("listener") }
    defer { Darwin.close(listener) }
    var address = sockaddr_in(sin_len: UInt8(MemoryLayout<sockaddr_in>.size),
                              sin_family: sa_family_t(AF_INET), sin_port: 0,
                              sin_addr: in_addr(s_addr: inet_addr("127.0.0.1")),
                              sin_zero: (0, 0, 0, 0, 0, 0, 0, 0))
    let bound = withUnsafePointer(to: &address) {
        $0.withMemoryRebound(to: sockaddr.self, capacity: 1) {
            bind(listener, $0, socklen_t(MemoryLayout<sockaddr_in>.size))
        }
    }
    try require(bound == 0 && listen(listener, 1) == 0, "bind")
    var length = socklen_t(MemoryLayout<sockaddr_in>.size)
    withUnsafeMutablePointer(to: &address) {
        $0.withMemoryRebound(to: sockaddr.self, capacity: 1) { _ = getsockname(listener, $0, &length) }
    }
    let group = DispatchGroup(); group.enter()
    DispatchQueue.global().async {
        let accepted = accept(listener, nil, nil)
        if accepted >= 0 {
            try? sendAll(accepted, ">INFO:local fake\n")
            Darwin.close(accepted)
        }
        group.leave()
    }
    let client = try OpenVPNManagementClient.connect(to: .loopbackTCP(UInt16(bigEndian: address.sin_port)))
    let event = try client.readEvent()
    try require(event == .ready, "loopback")
    try require(group.wait(timeout: .now() + 2) == .success, "fake server")
    print("loopback passed")
}

func unixChecks() throws {
    let path = "/tmp/pp-management-\(getpid())-\(UUID().uuidString).sock"
    defer { unlink(path) }
    let listener = socket(AF_UNIX, SOCK_STREAM, 0)
    guard listener >= 0 else { throw CheckFailure.failed("unix listener") }
    defer { Darwin.close(listener) }
    var address = sockaddr_un()
    let pathBytes = Array(path.utf8) + [0]
    address.sun_len = UInt8(MemoryLayout<sockaddr_un>.size)
    address.sun_family = sa_family_t(AF_UNIX)
    withUnsafeMutableBytes(of: &address.sun_path) { $0.copyBytes(from: pathBytes) }
    let bound = withUnsafePointer(to: &address) {
        $0.withMemoryRebound(to: sockaddr.self, capacity: 1) {
            bind(listener, $0, socklen_t(MemoryLayout<sockaddr_un>.size))
        }
    }
    try require(bound == 0 && listen(listener, 1) == 0, "unix bind")
    let group = DispatchGroup(); group.enter()
    DispatchQueue.global().async {
        let accepted = accept(listener, nil, nil)
        if accepted >= 0 {
            try? sendAll(accepted, ">STATE:3,WAIT,,,,\n")
            Darwin.close(accepted)
        }
        group.leave()
    }
    let client = try OpenVPNManagementClient.connect(to: .unixSocket(path))
    let event = try client.readEvent()
    guard case .state(let unixState) = event else { throw CheckFailure.failed("unix") }
    try require(unixState.state == .waiting && unixState.timestamp == 3, "unix")
    try require(group.wait(timeout: .now() + 2) == .success, "unix fake server")
    print("unix passed")
}

@main
struct ManagementChecks {
    static func main() {
        do {
            guard CommandLine.arguments.count == 2 else { throw CheckFailure.failed("case") }
            switch CommandLine.arguments[1] {
            case "parser": try parserChecks()
            case "stream": try streamChecks()
            case "limits": try limitsChecks()
            case "loopback": try loopbackChecks()
            case "unix": try unixChecks()
            default: throw CheckFailure.failed("unknown")
            }
        } catch {
            fputs("\(error)\n", stderr)
            exit(1)
        }
    }
}
