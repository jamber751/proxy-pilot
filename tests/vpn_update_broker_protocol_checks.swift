import Foundation

@main enum VPNUpdateBrokerProtocolChecks {
    static func require(_ value: @autoclosure () -> Bool) throws {
        guard value() else { throw NSError(domain: "broker-wire", code: 1) }
    }

    static func rejects(_ bytes: [UInt8]) throws {
        do {
            _ = try VPNUpdateBrokerProtocol.decodeRequest(bytes)
            throw NSError(domain: "broker-wire", code: 2)
        } catch VPNUpdateBrokerProtocolError.invalidFrame { }
    }

    static func main() throws {
        let submit = try VPNUpdateBrokerRequest.submit(expectedFromSequence: 41)
        let frame = VPNUpdateBrokerProtocol.encode(submit)
        try require(frame.count == 18)
        let decodedSubmit = try VPNUpdateBrokerProtocol.decodeRequest(frame)
        try require(decodedSubmit == submit)

        // The directory descriptor is necessarily ancillary Unix-socket data.
        // Appending even one byte leaves no wire slot for a path, URL, argv,
        // shell, owner UID, token, destination or arbitrary payload.
        try rejects(frame + [0])
        try rejects(Array(frame.dropLast()))
        var unknown = frame
        unknown[8] = 0x7f; unknown[9] = 0xff
        try rejects(unknown)
        var zeroSequence = frame
        for index in 10..<18 { zeroSequence[index] = 0 }
        try rejects(zeroSequence)

        let status = VPNUpdateBrokerProtocol.encode(.status)
        try require(status.count == 18)
        let decodedStatus = try VPNUpdateBrokerProtocol.decodeRequest(status)
        try require(decodedStatus == .status)
        var statusWithArgument = status
        statusWithArgument[17] = 1
        try rejects(statusWithArgument)

        let response = VPNUpdateBrokerResponse(
            state: .installing, fromSequence: 41, toSequence: 42, revision: 3)
        let responseFrame = VPNUpdateBrokerProtocol.encode(response)
        try require(responseFrame.count == 34)
        let decodedResponse = try VPNUpdateBrokerProtocol.decodeResponse(responseFrame)
        try require(decodedResponse == response)
        // Status is a fixed numeric receipt. It cannot carry paths, signatures,
        // payload bytes, usernames, secrets or an unbounded error description.
        try require(!responseFrame.contains(0x2f))

        print("broker wire checks passed")
    }
}
