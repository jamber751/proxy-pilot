import Darwin
import Foundation

@main enum CanaryChecks {
    enum Failure:Error {case check, missing}
    static func check(_ value:@autoclosure () throws -> Bool)throws { if try !value() {throw Failure.check} }
    static func rejects(_ operation:() throws -> Void)throws {
        do {try operation()} catch Failure.check {throw Failure.check} catch {return};throw Failure.check
    }
    static let id="11111111-1111-4111-8111-111111111111"
    static func mark(_ inode:UInt64=1)->VPNDefaultCanaryFingerprint {
        VPNDefaultCanaryFingerprint(device:1,inode:inode,uid:getuid(),birthSeconds:1,birthNanoseconds:2)
    }
    static func request()->VPNDefaultCanaryRequest {
        VPNDefaultCanaryRequest(schema:1,target:"first",leaf:"first.keychain",service:"kz.documentolog.proxypilot.vm-canary."+id,
            account:"canary."+id,persistentReference:Data([1,2,3]),value:Data(repeating:7,count:32),
            candidate:mark(),root:mark(2),parent:mark(3),image:mark(4),nonce:id)
    }
    static func mutate(_ value:VPNDefaultCanaryRequest,_ edit:(inout [String:Any])->Void)throws->VPNDefaultCanaryRequest {
        let encoder=JSONEncoder()
        var object=try JSONSerialization.jsonObject(with:encoder.encode(value)) as! [String:Any]
        edit(&object)
        return try JSONDecoder().decode(VPNDefaultCanaryRequest.self,from:JSONSerialization.data(withJSONObject:object))
    }
    static func frame(_ body:Data)->Data {
        let size=UInt32(body.count);var value=Data([UInt8(size>>24),UInt8((size>>16)&255),UInt8((size>>8)&255),UInt8(size&255)])
        value.append(body);return value
    }
    static func fingerprint(_ info:stat)->VPNDefaultCanaryFingerprint {
        VPNDefaultCanaryFingerprint(device:UInt64(UInt32(bitPattern:info.st_dev)),inode:UInt64(info.st_ino),uid:info.st_uid,
            birthSeconds:Int64(info.st_birthtimespec.tv_sec),birthNanoseconds:UInt32(info.st_birthtimespec.tv_nsec))
    }
    static func filesystem(_ mode:String,_ folder:String)throws {
        let a=folder+"/A",b=folder+"/B"
        for path in [a,b] {try FileManager.default.createDirectory(atPath:path,withIntermediateDirectories:false,attributes:[.posixPermissions:0o700])}
        let file=a+"/first.keychain"
        try check(FileManager.default.createFile(atPath:file,contents:Data("SYNTHETIC NOT KEYCHAIN".utf8),attributes:[.posixPermissions:0o600]))
        let directory=open(a,O_RDONLY|O_DIRECTORY|O_NOFOLLOW|O_CLOEXEC)
        let fd=open(file,O_RDONLY|O_NOFOLLOW|O_CLOEXEC)
        guard directory >= 0,fd >= 0 else {throw Failure.check};defer {close(directory);close(fd)}
        var initial=stat();try check(fstat(fd,&initial)==0)
        let expected=fingerprint(initial)
        var bindingCalls=0,reads=0
        func binding()throws {
            bindingCalls+=1
            let path=mode == "foreign-file" ? b+"/first.keychain" : file
            let proof=VPNPrivateKeychainPathProof.inspect(actual:path,directory:directory,target:.first,requiredLeaf:.firstBase)
            var held=stat()
            guard proof.accepted,let actual=proof.attributes,fstat(fd,&held)==0,held.st_nlink==1,
                  fingerprint(held)==expected,fingerprint(actual)==expected else {throw Failure.missing}
        }
        if mode == "foreign-file" {try check(FileManager.default.createFile(atPath:b+"/first.keychain",contents:Data([1]),attributes:[.posixPermissions:0o600]))}
        if mode == "hardlink" {try check(Darwin.link(file,a+"/linked")==0)}
        if mode == "replaced-parent" {
            try check(rename(a,folder+"/old-A")==0)
            try FileManager.default.createDirectory(atPath:a,withIntermediateDirectories:false,attributes:[.posixPermissions:0o700])
            try check(FileManager.default.createFile(atPath:file,contents:Data([3]),attributes:[.posixPermissions:0o600]))
        }
        if mode == "ambiguous-leaf" {try check(FileManager.default.createFile(atPath:a+"/first.keychain-db",contents:Data([1]),attributes:[.posixPermissions:0o600]))}
        let r=try mutate(request()) {value in
            value["candidate"]=try! JSONSerialization.jsonObject(with:JSONEncoder().encode(expected))
        }
        func replace()throws {
            let next=a+"/replacement";try check(FileManager.default.createFile(atPath:next,contents:Data([2]),attributes:[.posixPermissions:0o600]))
            try check(rename(next,file)==0)
        }
        let operation = {
            try VPNDefaultCanaryProof.verify(r,target:"first",image:r.image,nonce:r.nonce,binding:binding,locate:{
                if mode == "replace-before-value" {try replace()}
                if mode == "missing-file" {try check(unlink(file)==0)}
                return VPNDefaultCanaryProof.Located(service:r.service,account:r.account,persistentReference:r.persistentReference,owner:expected)
            },readValue:{
                reads+=1
                if mode == "replace-after-value" {try replace()}
                return r.value
            })
        }
        if mode == "filesystem-positive" {try operation();try check(reads==1 && bindingCalls==3)}
        else {try rejects(operation);try check(reads == (mode == "replace-after-value" ? 1 : 0))}
    }
    static func run(_ mode:String,_ folder:String)throws {
        let r=request()
        switch mode {
        case "roundtrip":
            let bytes=try VPNDefaultCanaryProof.encode(r)
            try check(try VPNDefaultCanaryProof.encode(VPNDefaultCanaryProof.decode(bytes))==bytes)
        case "bounds":
            for count in [0,4097] {
                let bad=try mutate(r) {$0["persistentReference"]=Data(repeating:1,count:count).base64EncodedString()}
                try rejects {_ = try VPNDefaultCanaryProof.encode(bad)}
            }
            let max=try mutate(r) {$0["persistentReference"]=Data(repeating:1,count:4096).base64EncodedString()}
            try check(try VPNDefaultCanaryProof.encode(max).count <= VPNDefaultCanaryProof.maximumPayload+4)
            for bytes in [Data(),Data([0,0,0,0]),Data([0,0,32,1]),Data(repeating:0,count:8197)] {try rejects {_ = try VPNDefaultCanaryProof.decode(bytes)}}
        case "shape":
            for (key,value) in [("schema",2 as Any),("target","third"),("leaf","second.keychain"),("leaf","../first.keychain"),
                                ("service","foreign"),("account","foreign"),("nonce","invalid"),("value",Data([1]).base64EncodedString())] {
                let bad=try mutate(r) {$0[key]=value};try rejects {try bad.validate()}
            }
        case "fingerprint-bounds":
            for key in ["candidate","root","parent","image"] {
                for (field,value) in [("device",UInt64(UInt32.max)+1),("inode",0),("uid",UInt64(UInt32.max)),("birthNanoseconds",1_000_000_000)] {
                    let bad=try mutate(r) {var f=$0[key] as! [String:Any];f[field]=value;$0[key]=f}
                    try rejects {try bad.validate()}
                }
            }
        case "channel-shape":
            let encoded=try VPNDefaultCanaryProof.encode(r),body=Data(encoded.dropFirst(4))
            var obj=try JSONSerialization.jsonObject(with:body) as! [String:Any];obj["unknown"]=true
            try rejects {_ = try VPNDefaultCanaryProof.decode(frame(JSONSerialization.data(withJSONObject:obj)))}
            var extra=encoded;extra.append(0);try rejects {_ = try VPNDefaultCanaryProof.decode(extra)}
            try rejects {_ = try VPNDefaultCanaryProof.decode(encoded+encoded)}
            let duplicate=Data(("{\"schema\":2,"+String(decoding:body.dropFirst(),as:UTF8.self)).utf8)
            try rejects {_ = try VPNDefaultCanaryProof.decode(frame(duplicate))}
            try rejects {_ = try VPNDefaultCanaryProof.decode(frame(Data(" ".utf8)+body))}
        case "redacted":
            let located=VPNDefaultCanaryProof.Located(service:r.service,account:r.account,persistentReference:r.persistentReference,owner:r.candidate)
            let text=String(reflecting:r)+String(describing:r)+String(reflecting:located)
            for privateText in [r.service,r.account,r.nonce,r.value.base64EncodedString(),r.persistentReference.base64EncodedString()] {try check(!text.contains(privateText))}
        case "filesystem-positive","foreign-file","ambiguous-leaf","replace-before-value","replace-after-value","missing-file","hardlink","replaced-parent":
            try filesystem(mode,folder)
        default:
            var events:[String]=[],reads=0
            let operation = {
                try VPNDefaultCanaryProof.verify(r,target:mode == "wrong-target" ? "second" : "first",
                    image:mode == "wrong-image" ? mark(9) : r.image,nonce:mode == "wrong-nonce" ? UUID().uuidString.lowercased() : r.nonce,
                    binding:{
                        events.append("bind")
                        if mode == "race-before-value" && events.filter({$0=="bind"}).count==2 {throw Failure.missing}
                        if mode == "race-after-value" && events.filter({$0=="bind"}).count==3 {throw Failure.missing}
                    },locate:{
                        events.append("locate")
                        if mode == "missing-item" {throw Failure.missing}
                        return VPNDefaultCanaryProof.Located(service:mode == "wrong-service" ? "foreign" : r.service,
                            account:mode == "wrong-account" ? "foreign" : r.account,
                            persistentReference:mode == "wrong-reference" ? Data([9]) : r.persistentReference,
                            owner:mode == "wrong-owner" ? mark(9) : r.candidate)
                    },readValue:{events.append("read");reads+=1;return mode == "wrong-value" ? Data(repeating:9,count:32) : mode == "wrong-length" ? Data(repeating:7,count:31) : r.value})
            }
            if mode == "ordered-positive" {try operation();try check(events==["bind","locate","bind","read","bind"])}
            else {try rejects(operation);try check(reads == (["wrong-value","wrong-length","race-after-value"].contains(mode) ? 1 : 0))}
        }
    }
    static func main() throws {
        guard CommandLine.arguments.count==3 else {exit(64)}
        try run(CommandLine.arguments[1],CommandLine.arguments[2]);print("pure private canary proof passed")
    }
}
