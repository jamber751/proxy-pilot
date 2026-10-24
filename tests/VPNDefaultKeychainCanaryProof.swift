// Private disposable-VM fixture support ONLY. No Security or live I/O APIs.
import Foundation

/// A filesystem observation, NOT an immutable keychain/database identifier.
struct VPNDefaultCanaryFingerprint: Codable, Equatable {
    let device: UInt64, inode: UInt64
    let uid: UInt32
    let birthSeconds: Int64
    let birthNanoseconds: UInt32
    func validate() throws {
        guard device <= UInt32.max, inode > 0, uid != UInt32.max,
              birthNanoseconds < 1_000_000_000 else { throw VPNDefaultCanaryProof.Failure.invalid }
    }
}

struct VPNDefaultCanaryRequest: Codable, CustomStringConvertible, CustomDebugStringConvertible {
    let schema: Int
    let target: String, leaf: String
    let service: String, account: String
    let persistentReference: Data, value: Data
    let candidate: VPNDefaultCanaryFingerprint
    let root: VPNDefaultCanaryFingerprint, parent: VPNDefaultCanaryFingerprint, image: VPNDefaultCanaryFingerprint
    let nonce: String
    var description: String { "<private canary request>" }
    var debugDescription: String { description }
    func validate() throws {
        guard schema == 1, ["first", "second"].contains(target),
              leaf == target + ".keychain" || leaf == target + ".keychain-db",
              Self.randomName(service, prefix:"kz.documentolog.proxypilot.vm-canary."),
              Self.randomName(account, prefix:"canary."),
              UUID(uuidString:nonce)?.uuidString.lowercased() == nonce,
              !persistentReference.isEmpty, persistentReference.count <= 4096, value.count == 32 else {
            throw VPNDefaultCanaryProof.Failure.invalid
        }
        for fingerprint in [candidate,root,parent,image] { try fingerprint.validate() }
        guard candidate.uid == parent.uid, parent.uid == root.uid else { throw VPNDefaultCanaryProof.Failure.invalid }
    }
    private static func randomName(_ text:String,prefix:String)->Bool {
        guard text.hasPrefix(prefix) else { return false }
        let suffix = String(text.dropFirst(prefix.count))
        return UUID(uuidString:suffix)?.uuidString.lowercased() == suffix
    }
}

enum VPNDefaultCanaryProof {
    enum Failure: Error { case invalid, mismatch }
    static let maximumPayload = 8192
    static let requestKeys:Set<String> = ["schema","target","leaf","service","account","persistentReference","value","candidate","root","parent","image","nonce"]
    static let fingerprintKeys:Set<String> = ["device","inode","uid","birthSeconds","birthNanoseconds"]
    static func encode(_ request:VPNDefaultCanaryRequest) throws -> Data {
        try request.validate()
        let encoder=JSONEncoder();encoder.outputFormatting=[.sortedKeys]
        let body=try encoder.encode(request)
        guard body.count <= maximumPayload else { throw Failure.invalid }
        let size=UInt32(body.count)
        var frame=Data([UInt8(size>>24),UInt8((size>>16)&255),UInt8((size>>8)&255),UInt8(size&255)])
        frame.append(body);return frame
    }
    static func length(_ header:Data)throws->Int {
        guard header.count == 4 else { throw Failure.invalid }
        let size=header.reduce(UInt32(0)) { ($0<<8)|UInt32($1) }
        guard size > 0, size <= maximumPayload else { throw Failure.invalid };return Int(size)
    }
    static func decode(_ frame:Data)throws->VPNDefaultCanaryRequest {
        guard frame.count >= 4,frame.count <= maximumPayload+4,
              try length(Data(frame.prefix(4))) == frame.count-4 else { throw Failure.invalid }
        let body=Data(frame.dropFirst(4))
        guard let object=try JSONSerialization.jsonObject(with:body) as? [String:Any],Set(object.keys)==requestKeys else { throw Failure.invalid }
        for key in ["candidate","root","parent","image"] {
            guard let value=object[key] as? [String:Any],Set(value.keys)==fingerprintKeys else { throw Failure.invalid }
        }
        let request=try JSONDecoder().decode(VPNDefaultCanaryRequest.self,from:body)
        try request.validate()
        // Our own encoder is canonical. Refuse duplicate-key/alternate JSON
        // interpretations rather than letting two parsers choose differently.
        guard try encode(request) == frame else { throw Failure.invalid };return request
    }
    struct Located: CustomStringConvertible, CustomDebugStringConvertible {
        var description:String { "<private canary item>" }
        var debugDescription:String { description }
        let service:String, account:String, persistentReference:Data
        let owner:VPNDefaultCanaryFingerprint
    }
    /// The caller's locator MUST return metadata/owner proof without reading
    /// the value. Both are mandatory; there is no permissive/default adapter.
    static func verify(_ request:VPNDefaultCanaryRequest, target:String,
                       image:VPNDefaultCanaryFingerprint, nonce:String,
                       binding:() throws -> Void,
                       locate:() throws -> Located,
                       readValue:() throws -> Data) throws {
        try request.validate()
        guard request.target == target, request.image == image, request.nonce == nonce else { throw Failure.mismatch }
        try binding()
        let found=try locate()
        guard found.service == request.service, found.account == request.account,
              found.persistentReference == request.persistentReference, found.owner == request.candidate else { throw Failure.mismatch }
        try binding() // check owner/file identity BEFORE any value read
        var value=try readValue();defer { value.resetBytes(in:0..<value.count) }
        guard value.count == 32,value == request.value else { throw Failure.mismatch }
        try binding() // same held/named candidate AFTER value verification
    }
}
