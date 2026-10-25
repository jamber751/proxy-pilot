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
/// One original continuous-time deadline (capped once by the existing 20s ceiling)
/// covers both legs. Arbitrary authority-checker execution is NOT hard-bounded;
/// clock checks after it prevent expired traffic, not slow verifier execution.
final class VPNDNSUpstreamExchange {
    private let request: VPNDNSAnswerRequest
    private let binding: VPNDNSUpstreamBinding
    private let authority: VPNDNSUpstreamAuthority
    private let cancellation: VPNDNSUpstreamCancellation
    private let clock: VPNDNSContinuousClock
    private let calls: VPNDNSUpstreamSyscalls
    private let question: Data
    private let lock = NSLock()
    private var attempted = false

    /// Pure binding checks only; no interface lookup, clock, socket or factory
    /// activation. Binding's typed constructor validated its complete proof;
    /// REQUIRED authority must freshly verify it before each actual IO below.
    init(request: VPNDNSAnswerRequest, binding: VPNDNSUpstreamBinding,
         authority: VPNDNSUpstreamAuthority, cancellation: VPNDNSUpstreamCancellation,
         syscalls: VPNDNSUpstreamSyscalls = VPNDarwinDNSUpstreamSyscalls(),
         clock: VPNDNSContinuousClock = VPNDarwinDNSContinuousClock()) throws {
        guard request.generation == binding.generation, request.revision == binding.revision,
              binding.networkPlan.resource(forCanonicalDNSName: request.questionName) == request.resource else {
            throw VPNDNSUpstreamExchangeError.invalidBinding
        }
        question = try request.upstreamQuery() // Unsupported client version fails before any FD.
        self.request = request; self.binding = binding; self.authority = authority
        self.cancellation = cancellation; calls = syscalls; self.clock = clock
    }

    private func leg(_ transport: VPNDNSUpstreamTransport, _ io: InterruptibleCalls,
                     _ deadline: DispatchTime) throws -> (Data, VPNDNSContinuousInstant) {
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
        let continuousStart = try clock.now()
        let uptimeStart = calls.now()
        let continuousSample = try clock.now()
        guard continuousSample >= continuousStart else { throw VPNDNSContinuousClockError.backwards }
        let continuousEnd = min(request.deadline, continuousStart.addingClamped(VPNBoundDNSUpstreamSocket.maximumIOBudget))
        guard continuousSample < continuousEnd else { throw VPNBoundDNSUpstreamError.timeout }
        // Translate a REMAINING DURATION, never a continuous timestamp. Uptime
        // was sampled BEFORE the fresh continuous sample: this is conservative.
        // Both sealed ends survive UDP→TCP unchanged, including across sleep.
        let remaining = try continuousEnd.elapsed(since: continuousSample)
        let (proposed, overflow) = uptimeStart.addingReportingOverflow(remaining)
        let uptimeEnd = overflow ? UInt64.max : proposed
        let io = InterruptibleCalls(calls, clock: clock, cancellation: cancellation,
            uptimeStart: uptimeStart, uptimeEnd: uptimeEnd,
            continuousSample: continuousSample, continuousEnd: continuousEnd)
        try io.check()
        let deadline = DispatchTime(uptimeNanoseconds: uptimeEnd)
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
        try answer.checkTime(io.continuousNow()) // Do not restart TTL after a slow post-read proof check.
        try io.check()
        return answer
    }

    /// No lease is held over poll. <=100ms underlying slices observe cancellation
    /// while waiting; owner unwinds and closes its own FD. Not an immediate wake
    /// or hard100ms latency guarantee (scheduling/checker/syscall cost excluded).
    private final class InterruptibleCalls: VPNDNSUpstreamSyscalls {
        private let real: VPNDNSUpstreamSyscalls
        private let cancellation: VPNDNSUpstreamCancellation
        private let clock: VPNDNSContinuousClock
        private let deadline: UInt64
        private let continuousEnd: VPNDNSContinuousInstant
        private var lastUptime: UInt64
        private var lastContinuous: VPNDNSContinuousInstant
        var lastReceiveAt: VPNDNSContinuousInstant?
        init(_ real: VPNDNSUpstreamSyscalls, clock: VPNDNSContinuousClock,
             cancellation: VPNDNSUpstreamCancellation, uptimeStart: UInt64, uptimeEnd: UInt64,
             continuousSample: VPNDNSContinuousInstant, continuousEnd: VPNDNSContinuousInstant) {
            self.real = real; self.clock = clock; self.cancellation = cancellation
            deadline = uptimeEnd; self.continuousEnd = continuousEnd
            lastUptime = uptimeStart; lastContinuous = continuousSample
        }
        func now() -> UInt64 { real.now() } // BoundSocket IO domain only.
        func continuousNow() throws -> VPNDNSContinuousInstant {
            let value = try clock.now()
            guard value >= lastContinuous else { throw VPNDNSContinuousClockError.backwards }
            lastContinuous = value; return value
        }
        func check() throws {
            try cancellation.check()
            let time = real.now(), continuous = try continuousNow()
            guard time >= lastUptime else { throw VPNDNSContinuousClockError.backwards }
            lastUptime = time
            guard time < deadline, continuous < continuousEnd else { throw VPNBoundDNSUpstreamError.timeout }
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
            lastReceiveAt = try continuousNow() // BEFORE potentially costly post-read authority checks.
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
                let continuous = try continuousNow()
                guard continuous < continuousEnd else { throw VPNBoundDNSUpstreamError.timeout }
                let remaining = min(end - time, try continuousEnd.elapsed(since: continuous))
                let slice = Int32(min(100, (remaining + 999_999) / 1_000_000))
                let result = try real.poll(descriptor, events: events, milliseconds: slice)
                try check()
                if result != 0 { return result }
            }
        }
        func close(_ descriptor: Int32) { real.close(descriptor) } // Always close despite cancellation.
    }
}
