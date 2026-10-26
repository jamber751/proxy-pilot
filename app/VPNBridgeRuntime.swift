import Darwin
import Foundation
import Security

enum VPNBridgeRuntimeError: Error { case invalid, retired, cleanupUnknown, domainAuthorityUnavailable }

/// One activation budget. Continuous time also expires across system sleep;
/// it is never reinterpreted as DispatchTime or refreshed between workers.
final class VPNBridgeRuntimeBudget {
    let deadline: DispatchTime, continuousDeadline: VPNDNSContinuousInstant
    private let clock: VPNDNSContinuousClock
    private var previous: VPNDNSContinuousInstant
    init(deadline: DispatchTime,clock: VPNDNSContinuousClock) throws {
        let now=try clock.now(),uptime=DispatchTime.now()
        guard deadline>uptime else { throw VPNBridgeWorkerError.expired }
        self.deadline=deadline;self.clock=clock;previous=now
        continuousDeadline=try now.addingChecked(deadline.uptimeNanoseconds-uptime.uptimeNanoseconds)
        try check({})
    }
    func check(_ body: () throws -> Void) throws {
        func current() throws {
            let now=try clock.now()
            guard now>=previous else { throw VPNDNSContinuousClockError.backwards }
            previous=now
            guard now<continuousDeadline,DispatchTime.now()<deadline else { throw VPNBridgeWorkerError.expired }
        }
        try current();try body();try current()
    }
}

/// Ordinary-user owned runtime. The product must enter through the root/cache
/// bootstrap adapter; activatePrepared alone grants no root/DNS answer permit.
final class VPNBridgeRuntime: CustomStringConvertible, CustomDebugStringConvertible {
    let epoch: UUID, port: Int, initialProtection: VPNBridgeProtectedSnapshot
    private let native: VPNSystemResolverWorker, gost: VPNBridgeWorkerProcess
    private let connections: VPNBridgeUnixAPIConnections, api: VPNBridgeProtectionAPI
    private let clock: VPNDNSContinuousClock, checkIntent: () throws -> Void
    private let lock=NSRecursiveLock()
    private var retired=false, cleanupConfirmed=false
    var ownedWorkers: (gost: VPNBridgeWorkerStamp,native: VPNBridgeWorkerStamp) { (gost.child,native.child) }
    var resolverPort: Int { native.port }
    var description: String { "VPNBridgeRuntime(redacted)" }
    var debugDescription: String { description }
    private init(epoch: UUID,port: Int,snapshot: VPNBridgeProtectedSnapshot,native: VPNSystemResolverWorker,
                 gost: VPNBridgeWorkerProcess,connections: VPNBridgeUnixAPIConnections,api: VPNBridgeProtectionAPI,
                 clock: VPNDNSContinuousClock,checkIntent: @escaping () throws -> Void) {
        self.epoch=epoch;self.port=port;initialProtection=snapshot;self.native=native;self.gost=gost
        self.connections=connections;self.api=api;self.clock=clock;self.checkIntent=checkIntent
    }
    private static func secret() throws -> Data {
        var bytes=[UInt8](repeating:0,count:32)
        guard SecRandomCopyBytes(kSecRandomDefault,bytes.count,&bytes)==errSecSuccess else { throw VPNBridgeRuntimeError.invalid }
        defer { bytes.withUnsafeMutableBufferPointer { $0.initialize(repeating:0) } }
        return Data(bytes.map({ String(format:"%02x",$0) }).joined().utf8)
    }
    static func activatePrepared(snapshot: VPNBridgeProtectedSnapshot,route: VPNBridgeGOSTConfiguration.Route,
        bypass: [String],port: Int = 3129,gostImage: VPNBridgeWorkerSelection,nativeImage: VPNBridgeWorkerSelection,
        trustedDirectoryDescriptor directory: Int32,path: String,deadline: DispatchTime,
        clock: VPNDNSContinuousClock = VPNDarwinDNSContinuousClock(),
        activationBudget: VPNBridgeRuntimeBudget? = nil,
        checkIntent: @escaping () throws -> Void) throws -> VPNBridgeRuntime {
        guard gostImage.role == .gost,nativeImage.role == .systemResolver else { throw VPNBridgeRuntimeError.invalid }
        try snapshot.validate()
        let budget=try activationBudget ?? VPNBridgeRuntimeBudget(deadline:deadline,clock:clock)
        guard budget.deadline==deadline else { throw VPNBridgeRuntimeError.invalid }
        func current() throws { try budget.check(checkIntent) }
        try current()
        var apiSecret=try secret(),nativeSecret=try secret()
        defer { apiSecret.resetBytes(in:0..<apiSecret.count);nativeSecret.resetBytes(in:0..<nativeSecret.count) }
        guard apiSecret != nativeSecret else { throw VPNBridgeRuntimeError.invalid }
        let epoch=UUID()
        let native=try VPNSystemResolverWorker.start(selection:nativeImage,password:nativeSecret,
            trustedDirectoryDescriptor:directory,path:path,deadline:deadline,checkCurrent:current)
        var gost:VPNBridgeWorkerProcess?
        do {
            try current()
            let recipe=try VPNBridgeGOSTConfiguration(route:route,port:port,bypass:bypass,protected:snapshot,
                epochDirectory:path,resolverPort:native.port,apiPassword:apiSecret,resolverPassword:nativeSecret)
            let config=try recipe.materialize(trustedDirectoryDescriptor:directory,deadline:deadline,checkCurrent:current)
            let worker=try VPNBridgeWorkerProcess.launch(selection:gostImage,configuration:config.descriptor,deadline:deadline)
            gost=worker
            let connections=try VPNBridgeUnixAPIConnections(trustedDirectoryDescriptor:directory,clock:clock,
                authenticatePeer:{ try worker.authenticate($0) })
            let api=try VPNBridgeProtectionAPI(epoch:epoch,password:apiSecret,connections:connections,clock:clock)
            // PID-ready is not API-ready. Wait only under the original budget;
            // only endpoint absence/not-yet-listening is retryable, not a write.
            while true {
                try current();try worker.checkLive()
                do {
                    let connection=try connections.open(deadline:budget.continuousDeadline,checkCurrent:current)
                    defer { connection.close() };try connection.authenticate();break
                } catch VPNBridgeProtectionAPIError.unsafeEndpoint { usleep(5_000) }
                  catch VPNBridgeProtectionAPIError.transport { usleep(5_000) }
            }
            try api.replace(snapshot,epoch:epoch,deadline:budget.continuousDeadline,checkCurrent:current)
            try VPNBridgeWorkerListener.require(process:worker,port:port,deadline:deadline)
            try current();try native.validate(deadline:deadline,checkCurrent:current)
            let result=VPNBridgeRuntime(epoch:epoch,port:port,snapshot:snapshot,native:native,gost:worker,
                connections:connections,api:api,clock:clock,checkIntent:checkIntent)
            try result.validate(deadline:deadline);try current();return result
        } catch {
            var clean=true
            if let gost { do { try gost.stop(deadline:.now()+2) } catch { clean=false } }
            do { try native.stop(deadline:.now()+2) } catch { clean=false }
            if !clean { throw VPNBridgeRuntimeError.cleanupUnknown };throw error
        }
    }
    func validate(deadline: DispatchTime) throws {
        lock.lock();defer { lock.unlock() }
        guard !retired else { throw VPNBridgeRuntimeError.retired }
        do {
            let budget=try VPNBridgeRuntimeBudget(deadline:deadline,clock:clock)
            func current() throws { try budget.check(checkIntent) }
            try current();try native.validate(deadline:deadline,checkCurrent:current)
            let connection=try connections.open(deadline:budget.continuousDeadline,checkCurrent:current)
            defer { connection.close() };try connection.authenticate()
            guard try VPNBridgeWorkerListener.probe(process:gost,port:port,deadline:deadline) else { throw VPNBridgeWorkerError.unavailable }
            try current()
        } catch {
            do { try stop(deadline:.now()+4) } catch { throw VPNBridgeRuntimeError.cleanupUnknown }
            throw error
        }
    }
    func stop(deadline: DispatchTime) throws {
        lock.lock();defer { lock.unlock() };retired=true
        if cleanupConfirmed { return }
        var clean=true
        do { try gost.stop(deadline:min(deadline,.now()+2)) } catch { clean=false }
        do { try native.stop(deadline:min(deadline,.now()+2)) } catch { clean=false }
        cleanupConfirmed=clean
        if !clean { throw VPNBridgeRuntimeError.cleanupUnknown }
    }
    func retire() { try? stop(deadline:.now()+4) }
}
