import Foundation

/// Process-local cooperative signal only; no descriptor, service lease or API
/// mutation. A future lifecycle adapter must connect actual revocation to cancel.
final class VPNDNSUpstreamCancellation {
    private let lock = NSLock()
    private var cancelled = false
    func cancel() { lock.lock(); cancelled = true; lock.unlock() }
    fileprivate func check() throws {
        lock.lock(); let value = cancelled; lock.unlock()
        if value { throw VPNDNSUpstreamExchangeError.cancelled }
    }
}
enum VPNDNSUpstreamExchangeError: Error, Equatable { case invalidBinding, alreadyUsed, cancelled }

/// Inert one-shot coordinator: actual bound UDP, then at most one bound TCP ONLY
/// on a sealed codec needsTCP receipt. Never emits an answer or issues a release
/// permit; VPNDNSAnswerRelease still requires its separate current leased proof.
/// No resolver/default/unbound/alternate-server/EDNS-downgrade retry exists.
///
/// One original absolute deadline (capped once by the existing 20s IO ceiling)
/// covers both legs. Arbitrary authority-checker execution is NOT hard-bounded;
/// clock checks after it prevent expired traffic, not slow verifier execution.
final class VPNDNSUpstreamExchange {
    private let request: VPNDNSAnswerRequest
    private let binding: VPNDNSUpstreamBinding
    private let authority: VPNDNSUpstreamAuthority
    private let cancellation: VPNDNSUpstreamCancellation
    private let calls: VPNDNSUpstreamSyscalls
    private let question: Data
    private let lock = NSLock()
    private var attempted = false

    /// Pure binding checks only; no interface lookup, clock, socket or factory
    /// activation. Binding's typed constructor validated its complete proof;
    /// REQUIRED authority must freshly verify it before each actual IO below.
    init(request: VPNDNSAnswerRequest, binding: VPNDNSUpstreamBinding,
         authority: VPNDNSUpstreamAuthority, cancellation: VPNDNSUpstreamCancellation,
         syscalls: VPNDNSUpstreamSyscalls = VPNDarwinDNSUpstreamSyscalls()) throws {
        guard request.generation == binding.generation, request.revision == binding.revision,
              binding.networkPlan.domainResources.contains(request.resource) else {
            throw VPNDNSUpstreamExchangeError.invalidBinding
        }
        question = try request.upstreamQuery() // Unsupported client version fails before any FD.
        self.request = request; self.binding = binding; self.authority = authority
        self.cancellation = cancellation; calls = syscalls
    }

    private func leg(_ transport: VPNDNSUpstreamTransport, _ io: InterruptibleCalls,
                     _ deadline: DispatchTime) throws -> (Data, UInt64) {
        io.lastReceiveAt = nil
        let socket = try VPNBoundDNSUpstreamSocket.prepare(binding: binding, transport: transport,
            authority: authority, deadline: deadline, syscalls: io)
        do {
            let bytes = try socket.exchange(question: question, deadline: deadline)
            try io.check()
            guard let receivedAt = io.lastReceiveAt else { throw VPNDNSUpstreamExchangeError.invalidBinding }
            try socket.close() // SAME owner; UDP is closed before a TCP FD can reuse its number.
            return (bytes, receivedAt)
        } catch {
            try? socket.close() // exchange/prepare failure already closes; never retry native close.
            throw error
        }
    }

    func exchange() throws -> VPNDNSValidatedAnswer {
        lock.lock()
        guard !attempted else { lock.unlock(); throw VPNDNSUpstreamExchangeError.alreadyUsed }
        attempted = true; lock.unlock() // Permanently consumed, including cancellation/failure.
        try cancellation.check()
        let start = calls.now(), ceiling = VPNBoundDNSUpstreamSocket.maximumIOBudget
        let end = min(request.deadline, start > UInt64.max - ceiling ? UInt64.max : start + ceiling)
        let io = InterruptibleCalls(calls, cancellation: cancellation, start: start, deadline: end)
        try io.check()
        let deadline = DispatchTime(uptimeNanoseconds: end)
        let udp = try leg(.udp, io, deadline)
        try io.check()
        let answer: VPNDNSValidatedAnswer
        switch try VPNDNSAnswerCodec.inspectUpstream(udp.0, request: request, receivedAt: udp.1, transport: .udp) {
        case .answer(let value): answer = value
        case .needsTCP(let receipt):
            guard receipt.request == request else { throw VPNDNSUpstreamExchangeError.invalidBinding }
            try io.check()
            let tcp = try leg(.tcp, io, deadline) // Same immutable binding/question/authority/end.
            try io.check()
            switch try VPNDNSAnswerCodec.inspectUpstream(tcp.0, request: request, receivedAt: tcp.1, transport: .tcp) {
            case .answer(let value): answer = value
            case .needsTCP: throw VPNDNSUpstreamExchangeError.invalidBinding // No recursive fallback.
            }
        }
        try io.check()
        guard answer.request == request else { throw VPNDNSUpstreamExchangeError.invalidBinding }
        try answer.checkTime(calls.now()) // Do not restart TTL after a slow post-read proof check.
        try io.check()
        return answer
    }

    /// No lease is held over poll. <=100ms underlying slices observe cancellation
    /// while waiting; owner unwinds and closes its own FD. Not an immediate wake
    /// or hard100ms latency guarantee (scheduling/checker/syscall cost excluded).
    private final class InterruptibleCalls: VPNDNSUpstreamSyscalls {
        private let real: VPNDNSUpstreamSyscalls
        private let cancellation: VPNDNSUpstreamCancellation
        private let start: UInt64
        private let deadline: UInt64
        var lastReceiveAt: UInt64?
        init(_ real: VPNDNSUpstreamSyscalls, cancellation: VPNDNSUpstreamCancellation,
             start: UInt64, deadline: UInt64) {
            self.real = real; self.cancellation = cancellation; self.start = start; self.deadline = deadline
        }
        func now() -> UInt64 { real.now() }
        func check() throws {
            try cancellation.check()
            let time = real.now()
            guard time >= start, time < deadline else { throw VPNBoundDNSUpstreamError.timeout }
        }
        func interfaces() throws -> VPNKernelInterfaceSnapshot { try check(); return try real.interfaces() }
        func socket(family: Int32, transport: VPNDNSUpstreamTransport) throws -> Int32 {
            try check()
            // NEVER throw after allocation before BoundSocket records ownership.
            return try real.socket(family: family, transport: transport)
        }
        func configure(_ descriptor: Int32) throws { try check(); try real.configure(descriptor) }
        func bindInterface(_ descriptor: Int32, family: Int32, index: UInt32) throws {
            try check(); try real.bindInterface(descriptor, family: family, index: index)
        }
        func boundInterface(_ descriptor: Int32, family: Int32) throws -> (UInt32, Int) {
            try check(); return try real.boundInterface(descriptor, family: family)
        }
        func connect(_ descriptor: Int32, binding: VPNDNSUpstreamBinding) throws {
            try check(); try real.connect(descriptor, binding: binding)
        }
        func connectionError(_ descriptor: Int32) throws -> Int32 { try check(); return try real.connectionError(descriptor) }
        func send(_ descriptor: Int32, bytes: Data, offset: Int) throws -> Int {
            try check(); return try real.send(descriptor, bytes: bytes, offset: offset)
        }
        func receive(_ descriptor: Int32, maximum: Int, datagram: Bool) throws -> (Data, Bool) {
            try check()
            let value = try real.receive(descriptor, maximum: maximum, datagram: datagram)
            lastReceiveAt = real.now() // BEFORE potentially costly post-read authority checks.
            return value
        }
        func poll(_ descriptor: Int32, events: Int16, milliseconds: Int32) throws -> Int16 {
            try check()
            guard milliseconds > 0 else { throw VPNBoundDNSUpstreamError.timeout }
            let time = real.now(), interval = UInt64(milliseconds) * 1_000_000
            let (proposed, overflow) = time.addingReportingOverflow(interval)
            let end = min(deadline, overflow ? UInt64.max : proposed)
            while true {
                try check()
                let time = real.now()
                if time >= end { return 0 }
                let slice = Int32(min(100, (end - time + 999_999) / 1_000_000))
                let result = try real.poll(descriptor, events: events, milliseconds: slice)
                try check()
                if result != 0 { return result }
            }
        }
        func close(_ descriptor: Int32) { real.close(descriptor) } // Always close despite cancellation.
    }
}
