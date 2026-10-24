// Compiled with the real VPN views and preview model. No helper or store exists.
struct VPNScrollHitBounds: PreferenceKey {
    static var defaultValue: [String: CGRect] = [:]
    static func reduce(value: inout [String: CGRect], nextValue: () -> [String: CGRect]) {
        value.merge(nextValue(), uniquingKeysWith: { _, new in new })
    }
}
struct VPNAddressHeights: PreferenceKey {
    static var defaultValue: [UUID: CGFloat] = [:]
    static func reduce(value: inout [UUID: CGFloat], nextValue: () -> [UUID: CGFloat]) {
        value.merge(nextValue(), uniquingKeysWith: { _, new in new })
    }
}
final class ScrollMetrics {
    var hits: [String: CGRect] = [:]
    var rows: [UUID: CGRect] = [:]
    var addressHeights: [UUID: CGFloat] = [:]
}
// This extension exists only in the generated render fixture. It exercises
// view updates across synthetic published statuses, without a helper/session.
extension VPNPanelModel {
    func setSyntheticLiveState(_ state: VPNLiveState) { liveState = state }
}
func demand(_ value: @autoclosure () -> Bool, _ message: @autoclosure () -> String) {
    precondition(value(), message())
}
func settle(_ host: NSView, cycles: Int = 15) {
    for _ in 0..<cycles {
        host.layoutSubtreeIfNeeded()
        RunLoop.main.run(until: Date().addingTimeInterval(0.02))
    }
}
func findScroll(_ view: NSView) -> NSScrollView? {
    if let scroll = view as? NSScrollView { return scroll }
    for child in view.subviews { if let result = findScroll(child) { return result } }
    return nil
}
func configure(_ count: Int) throws -> VPNPanelModel {
    let panel = VPNPanelModel(preview: true)
    let profile = """
    client
    dev tun
    proto udp
    remote vpn.company.example 1194
    remote-cert-tls server
    auth-user-pass
    <ca>
    -----BEGIN CERTIFICATE-----
    QUJDRA==
    -----END CERTIFICATE-----
    </ca>
    """
    try panel.configuration.importProfile(data: Data(profile.utf8), name: "synthetic.ovpn")
    try panel.configuration.setAuthentication(mode: .password, login: "employee")
    for index in 0..<count {
        panel.configuration.beginAddingResource()
        panel.configuration.resourceDraft?.name = "Resource \(index + 1)"
        panel.configuration.resourceDraft?.address = "10.44.\(index).1"
        try panel.configuration.saveResourceDraft()
    }
    panel.settings = true
    return panel
}
func render(_ panel: VPNPanelModel) -> (NSView, NSWindow, ScrollMetrics) {
    let metrics = ScrollMetrics()
    let root = VPNPanelView(panel: panel, close: {})
        .coordinateSpace(name: "vpnPopover")
        .onPreferenceChange(VPNScrollHitBounds.self) { metrics.hits = $0 }
        .onPreferenceChange(VPNResourceRowsKey.self) { metrics.rows = $0 }
        .onPreferenceChange(VPNAddressHeights.self) { metrics.addressHeights = $0 }
    let host = NSHostingView(rootView: root)
    host.frame = NSRect(x: 0, y: 0, width: 344, height: 432)
    let window = NSWindow(contentRect: host.frame, styleMask: [.borderless], backing: .buffered, defer: false)
    window.contentView = host
    window.setFrameOrigin(NSPoint(x: -10000, y: -10000)); window.orderBack(nil)
    settle(host)
    return (host, window, metrics)
}
func checkChrome(_ host: NSView, _ metrics: ScrollMetrics) {
    guard let list = metrics.hits["vpnResourceList"], let file = metrics.hits["vpnReplaceProfile"],
          let add = metrics.hits["vpnAddResource"], let done = metrics.hits["vpnSettingsDone"],
          let count = metrics.hits["vpnResourceCount"], let scroll = findScroll(host) else {
        fatalError("missing fixed chrome/scroll: \(metrics.hits)")
    }
    demand(list.height > 0 && list.height <= 144.5, "unbounded list \(list)")
    demand(file.maxY <= list.minY + 0.5 && add.maxY <= list.minY + 0.5 && count.maxY <= list.minY + 0.5,
           "fixed header moved inside list: \(metrics.hits)")
    demand(done.minY >= list.maxY - 0.5 && done.maxY <= 432.5, "footer escaped: \(metrics.hits)")
    demand(!scroll.hasHorizontalScroller, "horizontal scroller enabled")
    demand((scroll.documentView?.frame.width ?? 0) <= scroll.contentView.bounds.width + 1, "horizontal content overflow")
}
func visible(_ id: UUID, _ metrics: ScrollMetrics) -> Bool {
    guard let row = metrics.rows[id], let list = metrics.hits["vpnResourceList"] else { return false }
    return row.minY >= -0.5 && row.maxY <= list.height + 0.5
}
let app = NSApplication.shared
app.setActivationPolicy(.prohibited)
for count in [1, 3, 18, 100] {
    let panel = try configure(count)
    let (host, window, metrics) = render(panel)
    checkChrome(host, metrics)
    guard let scroll = findScroll(host), let document = scroll.documentView else { fatalError("missing native scroll") }
    if count <= 3 {
        let viewport = metrics.hits["vpnResourceList"]!.height
        demand(abs(document.frame.height - viewport) <= 1, "short list empty space or overflow count=\(count): document=\(document.frame), viewport=\(viewport)")
        if count == 3 {
            panel.beginResource(panel.configuration.configuration.resources.last!)
            panel.requestResourceRemoval(); settle(host)
            checkChrome(host, metrics)
            guard let smaller = findScroll(host), let smallerDocument = smaller.documentView else { fatalError("short list missing after delete") }
            let smallerHeight = metrics.hits["vpnResourceList"]!.height
            demand(smallerHeight < viewport && abs(smallerDocument.frame.height - smallerHeight) <= 1,
                   "short list retained empty height after removal: document=\(smallerDocument.frame), viewport=\(smallerHeight)")
        }
        print("short\(count) passed")
    } else {
        let offset = min(max(0, document.frame.height - scroll.contentView.bounds.height), document.frame.height * 0.6)
        scroll.contentView.scroll(to: NSPoint(x: 0, y: offset)); scroll.reflectScrolledClipView(scroll.contentView)
        settle(host)
        guard let anchor = panel.topVisibleResourceID,
              let resource = panel.configuration.configuration.resources.first(where: { $0.id == anchor }) else {
            fatalError("no recorded visible row after scroll count=\(count), rows=\(metrics.rows)")
        }
        demand(anchor != panel.configuration.configuration.resources.first?.id, "scroll did not move")
        panel.beginResource(resource); settle(host, cycles: 5)
        panel.cancelResource(); settle(host)
        demand(panel.topVisibleResourceID == anchor && visible(anchor, metrics),
               "editor cancel lost anchor count=\(count), expected=\(anchor), actual=\(String(describing: panel.topVisibleResourceID)), rows=\(metrics.rows)")
        panel.setSyntheticLiveState(.connecting)
        panel.message = "Synthetic background status update"
        settle(host)
        demand(panel.topVisibleResourceID == anchor && visible(anchor, metrics), "background status/layout update lost anchor")
        panel.setSyntheticLiveState(.failed("Synthetic status")); panel.message = ""
        settle(host)
        demand(panel.topVisibleResourceID == anchor && visible(anchor, metrics), "status refresh lost anchor")
        panel.beginResource(resource); panel.resourceName = "Edited resource"; panel.saveResource(); settle(host)
        demand(visible(resource.id, metrics), "edited row not visible")
        panel.beginResource(); panel.resourceName = "Added resource"; panel.resourceAddress = "10.255.0.1"
        panel.saveResource(); settle(host)
        let added = panel.configuration.configuration.resources.last!
        demand(added.name == "Added resource" && visible(added.id, metrics), "added row not visible count=\(count), rows=\(metrics.rows)")
        let neighbor = panel.configuration.configuration.resources.dropLast().last!.id
        panel.beginResource(added); panel.requestResourceRemoval(); settle(host)
        demand(visible(neighbor, metrics) && !panel.configuration.configuration.resources.contains(where: { $0.id == added.id }),
               "neighbor after deletion not visible")
        checkChrome(host, metrics)
        print("rows\(count) passed")
    }
    window.orderOut(nil); window.contentView = nil
}
let panel = try configure(1)
let first = panel.configuration.configuration.resources[0]
try panel.configuration.beginEditingResource(id: first.id)
panel.configuration.resourceDraft?.name = "Long synthetic resource name for address wrapping"
panel.configuration.resourceDraft?.address = "fd00:1111:2222:3333:4444:5555:6666:7777"
try panel.configuration.saveResourceDraft()
let (host, window, metrics) = render(panel)
checkChrome(host, metrics)
demand((metrics.addressHeights[first.id] ?? 0) > 18, "long address did not wrap: \(metrics.addressHeights)")
demand(visible(first.id, metrics), "wrapped row missing")
print("wrapped-address passed")
window.orderOut(nil); window.contentView = nil
