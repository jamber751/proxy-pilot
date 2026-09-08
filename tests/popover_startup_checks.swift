import AppKit

final class Anchor { var frame = NSRect(x: 0, y: 0, width: 38, height: 0) }
final class Button {
    var window: Anchor? = Anchor()
    var bounds = NSRect(x: 0, y: 0, width: 24, height: 30)
}
final class Item { var button: Button? = Button() }
final class Model { let preview = true }
final class Popover {
    var contentViewController: NSViewController?
    var isShown = false
    var shows = 0
    func show(relativeTo: NSRect, of: Button, preferredEdge: NSRectEdge) { shows += 1; isShown = true }
    func performClose(_ sender: Any?) { isShown = false }
}

final class Harness {
    let item = Item(), popover = Popover(), model = Model()
    var activations = 0
    private var pendingPopoverRequest: UUID?
    // PRODUCTION_METHODS

    func test(_ mode: String) {
        showWindow()
        precondition(popover.shows == 0 && activations == 0)
        if mode == "cancel" { hideWindow() }
        if mode == "replace" { showWindow() }
        if mode == "timeout" {
            let request = UUID(); pendingPopoverRequest = request
            showWindowWhenReady(request, attemptsLeft: 1)
            RunLoop.main.run(until: Date().addingTimeInterval(0.15))
            precondition(pendingPopoverRequest == nil)
        }
        item.button?.window?.frame.size.height = 33
        RunLoop.main.run(until: Date().addingTimeInterval(0.15))
        let expected = (mode == "cancel" || mode == "timeout") ? 0 : 1
        precondition(popover.shows == expected && activations == expected)
        precondition(pendingPopoverRequest == nil)
        print("PASS \(mode)")
    }
}

@main enum Checks {
    static func main() { Harness().test(CommandLine.arguments[1]) }
}
