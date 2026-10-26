import Darwin
import Foundation
import Security

/// Only the canonical one-line message produced by the fixed native worker.
/// Its pipe must already be bound to an owned, live, authenticated code image.
struct VPNSystemResolverReady {
    let port: Int
    let certificate: Data
    init(_ data: Data) throws {
        struct Reply: Decodable { let port: Int, certificate: String }
        guard !data.isEmpty,data.count<=4096 else { throw VPNBridgeWorkerError.invalid }
        let value=try JSONDecoder().decode(Reply.self,from:data)
        guard (1024...65535).contains(value.port) else { throw VPNBridgeWorkerError.invalid }
        let quoted=try JSONSerialization.data(withJSONObject:value.certificate,options:[.fragmentsAllowed,.withoutEscapingSlashes])
        let canonical=Data("{\"port\":\(value.port),\"certificate\":".utf8)+quoted+Data("}\n".utf8)
        guard canonical==data else { throw VPNBridgeWorkerError.invalid }
        let prefix="-----BEGIN CERTIFICATE-----\n",suffix="-----END CERTIFICATE-----\n"
        guard value.certificate.hasPrefix(prefix),value.certificate.hasSuffix(suffix) else { throw VPNBridgeWorkerError.invalid }
        let body=String(value.certificate.dropFirst(prefix.count).dropLast(suffix.count))
        guard !body.isEmpty,body.hasSuffix("\n"),body.utf8.allSatisfy({
            (65...90).contains($0) || (97...122).contains($0) || (48...57).contains($0) || [10,43,47,61].contains($0)
        }),let der=Data(base64Encoded:body.replacingOccurrences(of:"\n",with:"")),
              let cert=SecCertificateCreateWithData(nil,der as CFData),SecCertificateCopyData(cert) as Data==der else {
            throw VPNBridgeWorkerError.invalid
        }
        port=value.port;certificate=Data(value.certificate.utf8)
    }
}

/// Owns one epoch-local public CA file. A competing file is never replaced or
/// removed. The joint bridge runtime must retain this lease through GOST stop.
final class VPNSystemResolverCertificate {
    let path: String
    private let directoryPath: String, bytes: Data
    private var directory: Int32 = -1, descriptor: Int32 = -1
    private var attributes=stat()
    init(bytes: Data,trustedDirectoryDescriptor: Int32,path directoryPath: String,deadline: DispatchTime,
         checkCurrent: () throws -> Void) throws {
        self.bytes=bytes;self.directoryPath=directoryPath;path=directoryPath+"/ca.pem"
        guard !bytes.isEmpty,bytes.count<=4096 else { throw VPNBridgeWorkerError.invalid }
        directory=fcntl(trustedDirectoryDescriptor,F_DUPFD_CLOEXEC,64)
        do {
            try VPNBridgeWorkerIO.current(deadline);try checkCurrent()
            _=try VPNBridgeConfigurationFile.checkDirectory(directory,path:directoryPath)
            descriptor=openat(directory,"ca.pem",O_RDWR|O_CREAT|O_EXCL|O_NOFOLLOW|O_NONBLOCK|O_CLOEXEC,0o600)
            guard descriptor>=0 else { throw VPNBridgeWorkerError.invalid }
            var offset=0
            while offset<bytes.count {
                try VPNBridgeWorkerIO.current(deadline);try checkCurrent()
                let n=bytes.withUnsafeBytes { Darwin.write(descriptor,$0.baseAddress!.advanced(by:offset),bytes.count-offset) }
                if n<0 && errno==EINTR { continue }
                guard n>0 else { throw VPNBridgeWorkerError.transport };offset+=n
            }
            guard fstat(descriptor,&attributes)==0 else { throw VPNBridgeWorkerError.invalid }
            try validate(deadline:deadline,checkCurrent:checkCurrent)
        } catch {
            removeOwned();if descriptor>=0 { close(descriptor);descriptor = -1 }
            if directory>=0 { close(directory);directory = -1 };throw error
        }
    }
    deinit {
        removeOwned();if descriptor>=0 { close(descriptor) };if directory>=0 { close(directory) }
    }
    private func removeOwned() {
        guard descriptor>=0,directory>=0 else { return }
        var held=stat(),named=stat()
        if fstat(descriptor,&held)==0,fstatat(directory,"ca.pem",&named,AT_SYMLINK_NOFOLLOW)==0,
           held.st_dev==named.st_dev,held.st_ino==named.st_ino { _=unlinkat(directory,"ca.pem",0) }
    }
    func validate(deadline: DispatchTime,checkCurrent: () throws -> Void) throws {
        try VPNBridgeWorkerIO.current(deadline);try checkCurrent()
        _=try VPNBridgeConfigurationFile.checkDirectory(directory,path:directoryPath)
        var held=stat(),named=stat()
        guard fstat(descriptor,&held)==0,fstatat(directory,"ca.pem",&named,AT_SYMLINK_NOFOLLOW)==0,
              held.st_mode&S_IFMT==S_IFREG,held.st_uid==getuid(),held.st_nlink==1,held.st_mode&0o7777==0o600,
              VPNBridgeWorkerSelection.same(attributes,held),VPNBridgeWorkerSelection.same(held,named) else { throw VPNBridgeWorkerError.invalid }
        var read=[UInt8](repeating:0,count:bytes.count+1)
        let count=pread(descriptor,&read,read.count,0)
        guard count==bytes.count,Data(read.prefix(count))==bytes,
              fstat(descriptor,&held)==0,fstatat(directory,"ca.pem",&named,AT_SYMLINK_NOFOLLOW)==0,
              VPNBridgeWorkerSelection.same(attributes,held),VPNBridgeWorkerSelection.same(held,named) else { throw VPNBridgeWorkerError.invalid }
        try checkCurrent();try VPNBridgeWorkerIO.current(deadline)
    }
}

/// Owned resolver factory; never selected by normal App entry on its own. Boot
/// custody and ongoing DNS/bridge answer authority belong to the joint runtime.
final class VPNSystemResolverWorker: CustomStringConvertible, CustomDebugStringConvertible {
    let port: Int
    let certificate: VPNSystemResolverCertificate
    private let process: VPNBridgeWorkerProcess
    var child: VPNBridgeWorkerStamp { process.child }
    var description: String { "VPNSystemResolverWorker(redacted)" }
    var debugDescription: String { description }
    private init(process: VPNBridgeWorkerProcess,port: Int,certificate: VPNSystemResolverCertificate) {
        self.process=process;self.port=port;self.certificate=certificate
    }
    static func start(selection: VPNBridgeWorkerSelection,password: Data,
                      trustedDirectoryDescriptor directory: Int32,path: String,deadline: DispatchTime,
                      checkCurrent: () throws -> Void) throws -> VPNSystemResolverWorker {
        guard selection.role == .systemResolver,password.count==64,
              password.allSatisfy({ (48...57).contains($0) || (97...102).contains($0) }) else { throw VPNBridgeWorkerError.invalid }
        try VPNBridgeWorkerIO.current(deadline);try checkCurrent()
        let startup=try VPNBridgeConfigurationFile.create(trustedDirectoryDescriptor:directory,path:path,
            deadline:deadline,checkCurrent:checkCurrent,encode:{
                try JSONSerialization.data(withJSONObject:["password":String(decoding:password,as:UTF8.self)])+Data([10])
            })
        let process=try VPNBridgeWorkerProcess.launch(selection:selection,configuration:startup.descriptor,deadline:deadline)
        do {
            try process.authenticateResolverOutput();try checkCurrent();try VPNBridgeWorkerIO.current(deadline)
            guard let data=process.resolverReady else { throw VPNBridgeWorkerError.invalid }
            let ready=try VPNSystemResolverReady(data)
            let ca=try VPNSystemResolverCertificate(bytes:ready.certificate,trustedDirectoryDescriptor:directory,
                path:path,deadline:deadline,checkCurrent:{ try process.authenticateResolverOutput();try checkCurrent() })
            let result=VPNSystemResolverWorker(process:process,port:ready.port,certificate:ca)
            try result.validate(deadline:deadline,checkCurrent:checkCurrent);return result
        } catch {
            do { try process.stop(deadline:.now()+2) } catch { throw VPNBridgeWorkerError.cleanupUnknown }
            throw error
        }
    }
    func validate(deadline: DispatchTime,checkCurrent: () throws -> Void) throws {
        try VPNBridgeWorkerIO.current(deadline);try checkCurrent();try process.authenticateResolverOutput()
        guard try VPNBridgeWorkerListener.probe(process:process,port:port,deadline:deadline) else { throw VPNBridgeWorkerError.unavailable }
        try certificate.validate(deadline:deadline,checkCurrent:checkCurrent)
        try process.authenticateResolverOutput();try VPNBridgeWorkerIO.current(deadline)
    }
    func stop(deadline: DispatchTime) throws { try process.stop(deadline:deadline) }
}
