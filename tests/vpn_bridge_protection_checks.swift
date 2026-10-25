import Darwin
import Foundation
private func check(_ value: @autoclosure () throws -> Bool) throws { if try !value() { throw VPNBridgeProtectionError.invalidState } }
private final class Clock: VPNDNSContinuousClock {
    var value: UInt64 = 1
    func now() throws -> VPNDNSContinuousInstant { VPNDNSContinuousInstant(nanoseconds:value) }
}
private final class Transport: VPNBridgeProtectionTransport {
    var sent = [VPNBridgeProtectedSnapshot](), onReplace: (() throws -> Void)?, fails = false
    func replace(_ snapshot: VPNBridgeProtectedSnapshot, epoch: UUID, deadline: VPNDNSContinuousInstant,
                 checkCurrent: () throws -> Void) throws {
        try checkCurrent();sent.append(snapshot);try onReplace?()
        if fails { throw VPNBridgeProtectionError.stale }
        try checkCurrent()
    }
}
@main private enum Checks {
    static func run() throws {
        let mode = CommandLine.arguments[1],path = CommandLine.arguments[2]
        let fd = open(path,O_RDONLY|O_DIRECTORY|O_NOFOLLOW|O_CLOEXEC)
        try check(fd >= 0);defer { close(fd) }
        let clock = Clock(),transport = Transport(),epoch = UUID(),end = VPNDNSContinuousInstant(nanoseconds:100)
        func create(_ store: VPNBridgeProtectionStore, epoch expected: UUID? = nil,
                    checkEpoch: ((UUID) throws -> Void)? = nil) -> VPNBridgeProtectionPublisher {
            VPNBridgeProtectionPublisher(store:store,transport:transport,epoch:expected ?? epoch,clock:clock,
                checkEpoch:checkEpoch ?? { try check($0 == epoch) })
        }
        func refused(_ code: VPNBridgeProtectionError, _ body: () throws -> Void) throws {
            do { try body();throw NSError(domain:"missing",code:1) }
            catch let error as VPNBridgeProtectionError { try check(error == code) }
        }
        if mode == "reopen" {
            func first() throws {
                let store = try VPNBridgeProtectionStore(trustedDirectoryDescriptor:fd)
                _ = try create(store).withPublished(["198.19.253.201"],deadline:end,checkCurrent:{}) { $0 }
            }
            try first()
            let store = try VPNBridgeProtectionStore(trustedDirectoryDescriptor:fd)
            let value = try create(store).withPublished(["2001:db8:fff:fd::c9"],deadline:end,checkCurrent:{}) { $0 }
            try check(value.revision == 2 && value.matchers == ["198.19.253.201/32","2001:db8:fff:fd::c9/128"])
        } else if mode == "symlink" || mode == "hardlink" || mode == "bad-mode" {
            let target = path+"/target",name = path+"/"+VPNBridgeProtectionStore.filename
            try Data("{}".utf8).write(to:URL(fileURLWithPath:target));chmod(target,0o600)
            if mode == "symlink" { try check(symlink(target,name) == 0) }
            else { try check(link(target,name) == 0) }
            if mode == "bad-mode" { chmod(path,0o755) }
            try refused(.unsafeStorage) { _ = try VPNBridgeProtectionStore(trustedDirectoryDescriptor:fd) }
        } else {
            let store = try VPNBridgeProtectionStore(trustedDirectoryDescriptor:fd),publisher = create(store)
            var outputs = 0
            func publish(_ values: [String] = ["198.19.253.201"], current: () throws -> Void = {}) throws -> VPNBridgeProtectedSnapshot {
                try publisher.withPublished(values,deadline:end,checkCurrent:current) { value in outputs += 1;return value }
            }
            switch mode {
            case "order":
                transport.onReplace = { try check(try store.snapshot() == transport.sent.last && outputs == 0) }
                let value = try publish()
                try check(value.revision == 1 && transport.sent == [value] && outputs == 1)
            case "union":
                let first = try publish(),same = try publish(["198.19.253.201/32"])
                try check(first == same)
                let next = try publish(["2001:db8:fff:fd::c9","10.44.0.0/16"])
                try check(next.revision == 2 && next.matchers == ["10.44.0.0/16","198.19.253.201/32","2001:db8:fff:fd::c9/128"])
                try check(try publish([]) == next)
            case "unknown-api":
                transport.fails = true
                try refused(.stale) { _ = try publish() }
                try check(outputs == 0 && transport.sent.count == 1 && store.snapshot()?.matchers == ["198.19.253.201/32"])
                transport.fails = false
                _ = try publish(["2001:db8:fff:fd::c9"])
                try check(transport.sent.last?.matchers.count == 2 && outputs == 1)
            case "expired":
                clock.value = 100
                try refused(.expired) { _ = try publish() }
                try check(outputs == 0 && transport.sent.isEmpty && store.snapshot() == nil)
            case "late-api":
                transport.onReplace = { clock.value = 100 }
                try refused(.expired) { _ = try publish() }
                try check(outputs == 0 && transport.sent.count == 1 && store.snapshot() != nil)
            case "backwards":
                transport.onReplace = { clock.value = 0 }
                do { _ = try publish();throw NSError(domain:"missing",code:1) } catch VPNDNSContinuousClockError.backwards {}
                try check(outputs == 0 && store.snapshot() != nil)
            case "cancelled":
                try refused(.stale) { _ = try publish(current:{ throw VPNBridgeProtectionError.stale }) }
                try check(outputs == 0 && transport.sent.isEmpty && store.snapshot() == nil)
            case "epoch-changed":
                var valid = true
                let current = create(store,checkEpoch:{ try check($0 == epoch);if !valid { throw VPNBridgeProtectionError.stale } })
                transport.onReplace = { valid = false }
                try refused(.stale) { _ = try current.withPublished(["198.19.253.201"],deadline:end,checkCurrent:{}) { _ in outputs += 1 } }
                try check(outputs == 0 && store.snapshot() != nil)
            case "missing-after-use", "corrupt-after-use":
                _ = try publish();let count = transport.sent.count
                let name = path+"/"+VPNBridgeProtectionStore.filename
                if mode == "missing-after-use" { try check(unlink(name) == 0) }
                else {
                    let data = try Data(contentsOf:URL(fileURLWithPath:name))
                    try (data+Data([10])).write(to:URL(fileURLWithPath:name));chmod(name,0o600)
                }
                do { _ = try publish();throw NSError(domain:"missing",code:1) }
                catch is VPNBridgeProtectionError {}
                try check(transport.sent.count == count && outputs == 1)
            case "lock":
                try refused(.busy) { _ = try VPNBridgeProtectionStore(trustedDirectoryDescriptor:fd) }
            case "lock-replaced":
                transport.onReplace = {
                    let name = path+"/protected-bridge.lock"
                    try check(unlink(name) == 0)
                    let replacement = open(name,O_CREAT|O_EXCL|O_WRONLY,0o600);try check(replacement >= 0);close(replacement)
                }
                try refused(.unsafeStorage) { _ = try publish() }
                try check(outputs == 0)
            case "invalid":
                for raw in ["company.test","127.0.0.1","127.0.0.1/32","::1/128","0.0.0.0/0","::ffff:198.19.253.201/128"] {
                    do { _ = try publish([raw]);throw NSError(domain:"accepted",code:1) }
                    catch is VPNValidationError {} catch is VPNBridgeProtectionError {}
                }
                try check(outputs == 0 && transport.sent.isEmpty && store.snapshot() == nil)
            case "capacity":
                try refused(.capacity) { _ = try publish([String](repeating:"198.19.253.201",count:5097)) }
                try check(transport.sent.isEmpty && store.snapshot() == nil)
            case "reentrant":
                let other = create(store)
                _ = try publisher.withPublished(["198.19.253.201"],deadline:end,checkCurrent:{}) { value in
                    try refused(.busy) { _ = try other.withPublished(["2001:db8:fff:fd::c9"],deadline:end,checkCurrent:{}) { $0 } }
                    return value
                }
                try check(transport.sent.count == 1 && store.snapshot()?.matchers == ["198.19.253.201/32"])
            case "concurrent":
                let group = DispatchGroup(),queue = DispatchQueue(label:"cache",attributes:.concurrent),mutex = NSLock()
                var errors = 0
                for n in 1...8 {
                    group.enter();queue.async {
                        defer { group.leave() }
                        do { _ = try publisher.withPublished(["198.19.0.\(n)"],deadline:end,checkCurrent:{}) { $0 } }
                        catch { mutex.lock();errors += 1;mutex.unlock() }
                    }
                }
                try check(group.wait(timeout:.now()+5) == .success && errors == 0)
                try check(transport.sent.map { $0.matchers.count } == Array(1...8) && store.snapshot()?.revision == 8)
            default:throw NSError(domain:"mode",code:1)
            }
        }
        print("PASS bridge-protection-"+mode)
    }
    static func main() { do { try run() } catch { fputs("FAIL bridge-protection-check\n",stderr);exit(1) } }
}
