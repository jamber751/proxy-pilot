import Foundation

enum VPNUpdateBrokerProtocolError: Error {
    case invalidFrame
}

/// Fixed, non-extensible wire vocabulary for the future root update broker.
/// The candidate directory descriptor is transferred out-of-band by the local
/// Unix transport for `.submit`; it is deliberately impossible to encode a path,
/// URL, command, owner, destination, token, or arbitrary payload in this frame.
enum VPNUpdateBrokerOperation: UInt16 {
    case submit = 1
    case status = 2
}

struct VPNUpdateBrokerRequest: Equatable {
    let operation: VPNUpdateBrokerOperation
    let expectedFromSequence: UInt64

    static func submit(expectedFromSequence: UInt64) throws -> Self {
        guard expectedFromSequence > 0 else {
            throw VPNUpdateBrokerProtocolError.invalidFrame
        }
        return Self(operation: .submit, expectedFromSequence: expectedFromSequence)
    }

    static let status = Self(operation: .status, expectedFromSequence: 0)
}

enum VPNUpdateBrokerState: UInt16 {
    case accepted = 0
    case checking = 1
    case ready = 2
    case installing = 3
    case complete = 4
    case failed = 5
    case busy = 6
    case stale = 7
}

struct VPNUpdateBrokerResponse: Equatable {
    let state: VPNUpdateBrokerState
    let fromSequence: UInt64
    let toSequence: UInt64
    let revision: UInt64
}

enum VPNUpdateBrokerProtocol {
    static let requestMagic = Array("PPVPNB01".utf8)
    static let responseMagic = Array("PPVPNR01".utf8)
    static let requestBytes = 8 + 2 + 8
    static let responseBytes = 8 + 2 + 8 + 8 + 8

    static func encode(_ request: VPNUpdateBrokerRequest) -> [UInt8] {
        requestMagic + number(request.operation.rawValue)
            + number(request.expectedFromSequence)
    }

    static func decodeRequest(_ bytes: [UInt8]) throws -> VPNUpdateBrokerRequest {
        guard bytes.count == requestBytes,
              Array(bytes[0..<8]) == requestMagic,
              let operation = VPNUpdateBrokerOperation(
                rawValue: UInt16(exactly: value(bytes[8..<10])) ?? 0) else {
            throw VPNUpdateBrokerProtocolError.invalidFrame
        }
        let sequence = value(bytes[10..<18])
        switch operation {
        case .submit:
            return try .submit(expectedFromSequence: sequence)
        case .status:
            guard sequence == 0 else {
                throw VPNUpdateBrokerProtocolError.invalidFrame
            }
            return .status
        }
    }

    static func encode(_ response: VPNUpdateBrokerResponse) -> [UInt8] {
        responseMagic + number(response.state.rawValue)
            + number(response.fromSequence) + number(response.toSequence)
            + number(response.revision)
    }

    static func decodeResponse(_ bytes: [UInt8]) throws -> VPNUpdateBrokerResponse {
        guard bytes.count == responseBytes,
              Array(bytes[0..<8]) == responseMagic,
              let state = VPNUpdateBrokerState(
                rawValue: UInt16(exactly: value(bytes[8..<10])) ?? UInt16.max) else {
            throw VPNUpdateBrokerProtocolError.invalidFrame
        }
        return VPNUpdateBrokerResponse(
            state: state,
            fromSequence: value(bytes[10..<18]),
            toSequence: value(bytes[18..<26]),
            revision: value(bytes[26..<34]))
    }

    private static func number(_ value: UInt16) -> [UInt8] {
        [UInt8(truncatingIfNeeded: value >> 8), UInt8(truncatingIfNeeded: value)]
    }

    private static func number(_ value: UInt64) -> [UInt8] {
        (0..<8).reversed().map { UInt8(truncatingIfNeeded: value >> ($0 * 8)) }
    }

    private static func value(_ bytes: ArraySlice<UInt8>) -> UInt64 {
        bytes.reduce(0) { ($0 << 8) | UInt64($1) }
    }
}

