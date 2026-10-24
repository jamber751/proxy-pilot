import Darwin

private var reads = 0
private var mode = 0
@_cdecl("clock_gettime")
func fixtureDNSClock(_ clock: UInt32, _ output: UnsafeMutablePointer<timespec>?) -> Int32 {
    reads += 1
    guard clock == UInt32(CLOCK_MONOTONIC_RAW.rawValue), let output else { return -1 }
    if mode == 1 { return -1 }
    output.pointee.tv_sec = mode == 2 ? -1 : (mode == 4 ? Int.max : 42)
    output.pointee.tv_nsec = mode == 3 ? 1_000_000_000 : 7
    return 0
}
private enum Failure: Error { case check }
private func check(_ value: Bool) throws { if !value { throw Failure.check } }
private func rejects(_ action: () throws -> Void) throws {
    do { try action() } catch is Failure { throw Failure.check } catch { return }; throw Failure.check
}
@main enum Checks {
    static func main() {
        do {
            let clock = VPNDarwinDNSContinuousClock()
            try check(reads == 0)
            try check(try clock.now() == VPNDNSContinuousInstant(nanoseconds: 42_000_000_007))
            try check(reads == 1)
            for value in 1...4 { mode = value; try rejects { _ = try clock.now() } }
            let end = VPNDNSContinuousInstant(nanoseconds: UInt64.max)
            try check(end.addingClamped(1) == end)
            try rejects { _ = try end.addingChecked(1) }
            try rejects { _ = try VPNDNSContinuousInstant(nanoseconds: 1).elapsed(since: VPNDNSContinuousInstant(nanoseconds: 2)) }
            print("pure continuous DNS clock checks passed")
        } catch { print("pure continuous DNS clock failure"); exit(1) }
    }
}
