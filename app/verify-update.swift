// Release-time check against the PUBLIC key embedded in the shipped app.
// Sparkle itself verifies the signed feed and archive on clients.
import Foundation
import CryptoKit

final class Feed: NSObject, XMLParserDelegate {
    var enclosures: [[String: String]] = []
    var versions: [String] = []
    private var version: String?
    func parser(_ parser: XMLParser, didStartElement name: String, namespaceURI: String?, qualifiedName: String?, attributes: [String: String]) {
        if name == "enclosure" { enclosures.append(attributes) }
        if name == "sparkle:version" { version = "" }
    }
    func parser(_ parser: XMLParser, foundCharacters string: String) { if version != nil { version! += string } }
    func parser(_ parser: XMLParser, didEndElement name: String, namespaceURI: String?, qualifiedName: String?) {
        if name == "sparkle:version", let value = version { versions.append(value); version = nil }
    }
}

do {
    guard CommandLine.arguments.count == 5 else { throw NSError(domain: "Usage: verify-update PUBLIC_KEY_FILE ARCHIVE APPCAST VERSION", code: 1) }
    let args = CommandLine.arguments
    let keyText = try String(contentsOfFile: args[1], encoding: .utf8).trimmingCharacters(in: .whitespacesAndNewlines)
    guard let keyData = Data(base64Encoded: keyText) else { throw NSError(domain: "Invalid public key", code: 1) }
    let key = try Curve25519.Signing.PublicKey(rawRepresentation: keyData)
    let archive = try Data(contentsOf: URL(fileURLWithPath: args[2]), options: .mappedIfSafe)
    let feedData = try Data(contentsOf: URL(fileURLWithPath: args[3]))
    let feed = Feed(), parser = XMLParser(data: feedData)
    parser.delegate = feed
    let expectedURL = "https://github.com/jamber751/proxy-pilot/releases/download/v\(args[4])/ProxyPilot-\(args[4]).zip"
    guard parser.parse(), feed.versions == [args[4]], feed.enclosures.count == 1,
          let enclosure = feed.enclosures.first, enclosure["url"] == expectedURL,
          enclosure["length"] == String(archive.count),
          let encoded = enclosure["sparkle:edSignature"], let signature = Data(base64Encoded: encoded),
          key.isValidSignature(signature, for: archive) else {
        throw NSError(domain: "Update archive signature or metadata mismatch", code: 1)
    }
    print("Verified update archive with embedded public key")
} catch {
    fputs("\(error)\n", stderr)
    exit(1)
}
