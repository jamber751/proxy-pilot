import Dispatch
import Foundation

/// Read-only evidence used by the newly launched, sealed application B. This
/// never authorizes an install and never accepts a sequence from UI/updater IPC.
enum VPNJointUpdateStartupStatus {
    struct SealedRelease {
        let sequence: UInt64
    }

    enum Result: Equatable {
        case idle
        case verifying
        case installed
        case failed
    }

    static func sealedRelease(in bundle: Bundle = .main) -> SealedRelease? {
        guard bundle.object(forInfoDictionaryKey: "ProxyPilotVPNInstaller") as? Bool == true,
              let number = bundle.object(forInfoDictionaryKey: "ProxyPilotVPNReleaseSequence") as? NSNumber,
              CFGetTypeID(number) != CFBooleanGetTypeID() else { return nil }
        let sequence = number.uint64Value
        guard sequence > 0, NSNumber(value: sequence) == number else { return nil }
        return SealedRelease(sequence: sequence)
    }

    static func check(sealedRelease: SealedRelease,
                      deadline: UInt64) throws -> Result {
        let response = try VPNUpdateBrokerClient.status(deadline: deadline)

        // Broker's synthetic idle response is `.complete` with revision zero.
        // It is deliberately not evidence that this application was installed.
        if response.state == .complete,
           response.toSequence == sealedRelease.sequence,
           response.fromSequence > 0,
           response.fromSequence < response.toSequence,
           response.revision > 0 {
            return .installed
        }

        guard response.toSequence == sealedRelease.sequence,
              response.fromSequence > 0,
              response.fromSequence < response.toSequence,
              response.revision > 0 else { return .idle }
        switch response.state {
        case .accepted, .checking, .ready, .installing: return .verifying
        case .failed: return .failed
        case .complete, .busy, .stale: return .idle
        }
    }
}
