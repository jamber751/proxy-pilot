import AppKit

// Linked with the production ProxyModel and an inert CLI fixture only.
@main enum QuiescenceChecks {
    static func until(_ condition: () -> Bool) {
        let deadline = Date().addingTimeInterval(3)
        while !condition() && Date() < deadline { RunLoop.main.run(until: Date().addingTimeInterval(0.01)) }
        precondition(condition(), "Timed out")
    }

    static func main() {
        let mode = CommandLine.arguments[1]
        let model = ProxyModel(preview: false)
        model.state = CLI.state(); model.loading = false
        model.selectRoute("socks") // Blocks only the fixture's command queue briefly.
        var first = 0, second = 0
        model.prepareForUpdate { first += 1 }
        precondition(model.busy && first == 0)
        if mode == "wait" {
            until { first == 1 }
            precondition(model.busy && model.state?.selected == "socks")
            precondition(model.state?.socks_endpoint == "192.0.2.47:1080" && model.state?.http_endpoint == "192.0.2.48:3128")
            model.cancelUpdatePreparation()
            until { !model.busy }
        } else if mode == "cancel" {
            model.cancelUpdatePreparation()
            until { CLI.finishedRoutes == 1 }
            RunLoop.main.run(until: Date().addingTimeInterval(0.1))
            precondition(first == 0, "Cancelled preparation called its completion")
            precondition(!model.busy, "Late completion froze the app again")
            model.selectRoute("http")
            until { !model.busy && model.state?.selected == "http" }
        } else {
            if mode == "replace-after-cancel" { model.cancelUpdatePreparation() }
            model.prepareForUpdate { second += 1 }
            until { second == 1 }
            precondition(first == 0 && model.busy, "Superseded preparation still completed")
            model.cancelUpdatePreparation()
            until { !model.busy }
        }
        precondition(model.state?.enabled == true && model.state?.system_proxy == true)
        print("PASS \(mode)")
    }
}
