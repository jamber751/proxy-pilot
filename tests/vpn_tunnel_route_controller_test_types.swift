import Foundation

// The production definition lives with the engine coordinator. Focused route
// tests compile no process-management code and mirror only its immutable proof.
struct VPNTunnelBootstrapProof: Equatable {
    let generation: UInt64
    let management: OpenVPNConnectedEvidence
    let tunnel: VPNTunnelInterfaceEvidence
}
