import Darwin
import Foundation

private final class Clock: VPNDNSContinuousClock {
    var value=VPNDNSContinuousInstant(nanoseconds:1_000_000)
    func now() throws -> VPNDNSContinuousInstant { value }
}
@main enum Checks {
    static func require(_ value: Bool) throws { if !value { throw VPNBridgeRuntimeError.invalid } }
    static func reject(_ body: () throws -> Void) throws {
        do { try body() } catch { return };throw VPNBridgeRuntimeError.invalid
    }
    static func main() throws {
        let mode=CommandLine.arguments[1],clock=Clock()
        switch mode {
        case "original-budget":
            let budget=try VPNBridgeRuntimeBudget(deadline:.now()+5,clock:clock)
            let original=budget.continuousDeadline
            for _ in 0..<3 { clock.value=try clock.value.addingChecked(1_000_000_000);try budget.check({}) }
            try require(budget.continuousDeadline==original)
            clock.value=original;try reject { try budget.check({}) }
        case "sleep":
            let budget=try VPNBridgeRuntimeBudget(deadline:.now()+5,clock:clock)
            clock.value=try clock.value.addingChecked(6_000_000_000)
            try reject { try budget.check({}) }
        case "backwards":
            let budget=try VPNBridgeRuntimeBudget(deadline:.now()+5,clock:clock)
            clock.value=VPNDNSContinuousInstant(nanoseconds:1)
            try reject { try budget.check({}) }
        case "callback":
            let budget=try VPNBridgeRuntimeBudget(deadline:.now()+5,clock:clock)
            try reject { try budget.check { clock.value=budget.continuousDeadline } }
        case "overflow":
            clock.value=VPNDNSContinuousInstant(nanoseconds:UInt64.max-2)
            try reject { _=try VPNBridgeRuntimeBudget(deadline:.now()+5,clock:clock) }
        case "expired":
            try reject { _=try VPNBridgeRuntimeBudget(deadline:.now(),clock:clock) }
        default:throw VPNBridgeRuntimeError.invalid
        }
        print("PASS bridge-runtime-"+mode)
    }
}
