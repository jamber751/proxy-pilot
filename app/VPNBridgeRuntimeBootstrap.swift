import Foundation

extension VPNBridgeRuntime: VPNBridgeBootstrapOwnedRuntime {}

/// The product entry: root custody -> durable boot union -> native/GOST
/// activation -> store verification -> final root ACK. No legacy fallback.
enum VPNBridgeRuntimeBootstrap {
    /// Use only the two fixed images inside this application's sealed resources.
    /// Selection happens under root custody and consumes the ORIGINAL deadline.
    /// A missing/stale bundle never falls back to PATH, Homebrew or a download.
    static func startBundled(session: VPNBridgeBootstrapSession,store: VPNBridgeProtectionStore,
        configuration: VPNConfiguration,route: VPNBridgeGOSTConfiguration.Route,bypass: [String],port: Int = 3129,
        trustedDirectoryDescriptor: Int32,path: String,
        clock: VPNDNSContinuousClock = VPNDarwinDNSContinuousClock(),
        checkConfiguration: @escaping (VPNConfiguration) throws -> Void) throws -> VPNBridgeRuntime {
        try startSelecting(session:session,store:store,configuration:configuration,route:route,bypass:bypass,port:port,
            images:{ deadline in
                guard let resources=Bundle.main.resourceURL else { throw VPNBridgeRuntimeError.invalid }
                let directory=resources.appendingPathComponent("bin",isDirectory:true)
                let gost=try VPNBridgeWorkerSelection(path:directory.appendingPathComponent("gost").path,deadline:deadline)
                let native=try VPNBridgeWorkerSelection.systemResolver(
                    path:directory.appendingPathComponent("system-resolver").path,deadline:deadline)
                return (gost,native)
            },trustedDirectoryDescriptor:trustedDirectoryDescriptor,path:path,clock:clock,
            checkConfiguration:checkConfiguration)
    }

    static func start(session: VPNBridgeBootstrapSession,store: VPNBridgeProtectionStore,
        configuration: VPNConfiguration,route: VPNBridgeGOSTConfiguration.Route,bypass: [String],port: Int = 3129,
        gostImage: VPNBridgeWorkerSelection,nativeImage: VPNBridgeWorkerSelection,
        trustedDirectoryDescriptor: Int32,path: String,
        clock: VPNDNSContinuousClock = VPNDarwinDNSContinuousClock(),
        checkConfiguration: @escaping (VPNConfiguration) throws -> Void) throws -> VPNBridgeRuntime {
        try startSelecting(session:session,store:store,configuration:configuration,route:route,bypass:bypass,port:port,
            images:{ _ in (gostImage,nativeImage) },trustedDirectoryDescriptor:trustedDirectoryDescriptor,
            path:path,clock:clock,checkConfiguration:checkConfiguration)
    }

    private static func startSelecting(session: VPNBridgeBootstrapSession,store: VPNBridgeProtectionStore,
        configuration: VPNConfiguration,route: VPNBridgeGOSTConfiguration.Route,bypass: [String],port: Int,
        images: (DispatchTime) throws -> (VPNBridgeWorkerSelection,VPNBridgeWorkerSelection),
        trustedDirectoryDescriptor: Int32,path: String,clock: VPNDNSContinuousClock,
        checkConfiguration: @escaping (VPNConfiguration) throws -> Void) throws -> VPNBridgeRuntime {
        // Ordinary system lookup is not the corporate domain answer authority.
        // Keep that capability closed until its root publication path is wired.
        guard !configuration.resources.contains(where:{ $0.kind == .domain }) else { throw VPNBridgeRuntimeError.domainAuthorityUnavailable }
        return try VPNBridgeBootstrap.start(session:session,store:store,configuration:configuration,
            checkConfiguration:checkConfiguration,activate:{ snapshot,deadline in
                let budget=try VPNBridgeRuntimeBudget(deadline:deadline,clock:clock)
                try budget.check { try checkConfiguration(configuration) }
                let (gost,native)=try images(deadline)
                try budget.check { try checkConfiguration(configuration) }
                return try VPNBridgeRuntime.activatePrepared(snapshot:snapshot,route:route,bypass:bypass,port:port,
                    gostImage:gost,nativeImage:native,trustedDirectoryDescriptor:trustedDirectoryDescriptor,
                    path:path,deadline:deadline,clock:clock,activationBudget:budget,
                    checkIntent:{ try checkConfiguration(configuration) })
            })
    }
}
