import Darwin

/// Process-local continuous-clock nanoseconds, including system sleep. Never
/// reinterpret this value as DispatchTime.uptimeNanoseconds or wall time.
struct VPNDNSContinuousInstant: Equatable, Comparable {
    let nanoseconds: UInt64
    init(nanoseconds: UInt64) { self.nanoseconds = nanoseconds }
    static func < (left: Self, right: Self) -> Bool { left.nanoseconds < right.nanoseconds }
    func addingClamped(_ duration: UInt64) -> Self {
        let (value, overflow) = nanoseconds.addingReportingOverflow(duration)
        return Self(nanoseconds: overflow ? UInt64.max : value)
    }
    func addingChecked(_ duration: UInt64) throws -> Self {
        let (value, overflow) = nanoseconds.addingReportingOverflow(duration)
        guard !overflow else { throw VPNDNSContinuousClockError.overflow }
        return Self(nanoseconds: value)
    }
    func elapsed(since previous: Self) throws -> UInt64 {
        guard self >= previous else { throw VPNDNSContinuousClockError.backwards }
        return nanoseconds - previous.nanoseconds
    }
}
enum VPNDNSContinuousClockError: Error { case unavailable, invalidTime, overflow, backwards }
protocol VPNDNSContinuousClock {
    func now() throws -> VPNDNSContinuousInstant
}

/// Construction performs no clock read. Public Darwin CLOCK_MONOTONIC_RAW maps
/// to mach_continuous_time (macOS10.12+) and advances during sleep, unlike uptime.
/// https://github.com/apple-oss-distributions/Libc/blob/main/gen/clock_gettime.c
struct VPNDarwinDNSContinuousClock: VPNDNSContinuousClock {
    func now() throws -> VPNDNSContinuousInstant {
        var value = timespec()
        guard clock_gettime(CLOCK_MONOTONIC_RAW, &value) == 0 else { throw VPNDNSContinuousClockError.unavailable }
        return try Self.instant(seconds: value.tv_sec, nanoseconds: value.tv_nsec)
    }
    static func instant(seconds: Int, nanoseconds: Int) throws -> VPNDNSContinuousInstant {
        guard seconds >= 0, nanoseconds >= 0, nanoseconds < 1_000_000_000 else {
            throw VPNDNSContinuousClockError.invalidTime
        }
        let (secondsNS, multiplyOverflow) = UInt64(seconds).multipliedReportingOverflow(by: 1_000_000_000)
        let (total, additionOverflow) = secondsNS.addingReportingOverflow(UInt64(nanoseconds))
        guard !multiplyOverflow, !additionOverflow else { throw VPNDNSContinuousClockError.overflow }
        return VPNDNSContinuousInstant(nanoseconds: total)
    }
}
