// Second actual process after the VM parent SIGKILLed the first. Never host.
import Darwin
import Foundation
@main private struct Recovery {
    static func main() {
        let env = ProcessInfo.processInfo.environment
        guard getuid() == 0, geteuid() == 0, env["GITHUB_ACTIONS"] == "true",
              env["PROXYPILOT_VM_NATIVE_EXACT_FENCE"] == "1",
              env["PROXYPILOT_VM_EXACT_ROUTE_PACKETS"] == "1",
              env["PROXYPILOT_VM_DNS_UTUN_TESTS"] == "1" else { exit(77) }
        do {
            let store = try NativeStore.get(), previous = try store.entries()
            guard previous.count == 1, previous[0].phase == .applied,
                  previous[0].identity.address.canonical == "198.19.253.201",
                  previous[0].claims.count == 1,
                  previous[0].claims[0].profileSHA256 == String(repeating:"a",count:64) else {
                throw VPNExactFenceStoreError.invalidState
            }
            let socket = try VPNDarwinRouteSocket.production()
            let transaction = VPNExactFenceTransaction(store:store,kernel:socket)
            let deadline = DispatchTime.now()+5
            let restored = try transaction.restoreRetained(deadline:deadline,checkOwner:{})
            guard restored == previous else { throw VPNExactFenceStoreError.invalidState }
            print("PASS native-exact-fence-crash-reopen-applied"); fflush(stdout)
            // The first process group and every owned client/utun FD are gone.
            // Only its proved global fence remains; explicitly release the VM fixture.
            _ = try transaction.retire(restored[0],deadline:deadline,checkCurrent:{})
            guard try store.entries().allSatisfy({ $0.phase == .retired }),
                  try socket.lookupExactFence(restored[0].identity,deadline:deadline) == nil else {
                throw VPNExactFenceStoreError.invalidState
            }
            print("PASS native-exact-fence-crash-cleanup"); fflush(stdout)
        } catch {
            let code = (error as? VPNFlowDiagnosticError)?.vpnFlowFailureCode.rawValue ?? "unknown"
            print("FAIL native-exact-fence-recovery category="+code); exit(1)
        }
    }
}
