import Foundation

extension VPNBridgeRuntime: VPNBridgeBootstrapOwnedRuntime {}

/// The product entry: root custody -> durable boot union -> native/GOST
/// activation -> store verification -> final root ACK. No legacy fallback.
enum VPNBridgeRuntimeBootstrap {
    static func start(session: VPNBridgeBootstrapSession,store: VPNBridgeProtectionStore,
        configuration: VPNConfiguration,route: VPNBridgeGOSTConfiguration.Route,bypass: [String],port: Int = 3129,
        gostImage: VPNBridgeWorkerSelection,nativeImage: VPNBridgeWorkerSelection,
        trustedDirectoryDescriptor: Int32,path: String,
        clock: VPNDNSContinuousClock = VPNDarwinDNSContinuousClock(),
        checkConfiguration: @escaping (VPNConfiguration) throws -> Void) throws -> VPNBridgeRuntime {
        // Ordinary system lookup is not the corporate domain answer authority.
        // Keep that capability closed until its root publication path is wired.
        guard !configuration.resources.contains(where:{ $0.kind == .domain }) else { throw VPNBridgeRuntimeError.domainAuthorityUnavailable }
        return try VPNBridgeBootstrap.start(session:session,store:store,configuration:configuration,
            checkConfiguration:checkConfiguration,activate:{ snapshot,deadline in
                try VPNBridgeRuntime.activatePrepared(snapshot:snapshot,route:route,bypass:bypass,port:port,
                    gostImage:gostImage,nativeImage:nativeImage,trustedDirectoryDescriptor:trustedDirectoryDescriptor,
                    path:path,deadline:deadline,clock:clock,checkIntent:{ try checkConfiguration(configuration) })
            })
    }
}
