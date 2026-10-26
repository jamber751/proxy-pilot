import Darwin
import Foundation

@main enum Checks {
    static func require(_ value: @autoclosure () throws -> Bool) throws {
        if try !value() { throw VPNBridgeWorkerError.invalid }
    }
    static func reject(_ body: () throws -> Void) throws {
        do { try body() } catch { return };throw VPNBridgeWorkerError.invalid
    }
    static func main() {
        if let status=VPNBridgeWorkerSupervisorEntry.runIfRequested(arguments:CommandLine.arguments) { exit(status) }
        guard getuid()==geteuid(),getuid()>=500,CommandLine.arguments.count==5 else { exit(77) }
        do { try run() } catch { fputs("FAIL resolver-owner\n",stderr);exit(1) }
    }
    static func run() throws {
        let mode=CommandLine.arguments[1],folder=CommandLine.arguments[2],image=CommandLine.arguments[3],pem=CommandLine.arguments[4]
        let directory=open(folder,O_RDONLY|O_DIRECTORY|O_CLOEXEC);defer { close(directory) }
        try require(directory>=0)
        let certificate=try String(contentsOfFile:pem,encoding:.utf8)
        func ready(_ port: Int = 12345) throws -> Data {
            Data("{\"port\":\(port),\"certificate\":".utf8)+(try JSONSerialization.data(withJSONObject:certificate,options:[.fragmentsAllowed,.withoutEscapingSlashes]))+Data("}\n".utf8)
        }
        if mode=="ready" {
            let raw=try ready(),parsed=try VPNSystemResolverReady(raw)
            try require(parsed.port==12345 && parsed.certificate==Data(certificate.utf8))
            for changed in [Data(raw.dropLast()),Data(" ".utf8)+raw,Data(raw.dropLast(2))+Data(",\"extra\":1}\n".utf8),try ready(0),try ready(80),try ready(65536),Data("{\"port\":12345,\"certificate\":\"fixture\"}\n".utf8)] {
                try reject { _=try VPNSystemResolverReady(changed) }
            }
        } else if mode=="certificate" || mode=="certificate-changed" || mode=="certificate-replaced" || mode=="foreign-certificate" {
            let bytes=Data(certificate.utf8)
            if mode=="foreign-certificate" {
                try Data("foreign".utf8).write(to:URL(fileURLWithPath:folder+"/ca.pem"))
                try reject { _=try VPNSystemResolverCertificate(bytes:bytes,trustedDirectoryDescriptor:directory,path:folder,deadline:.now()+3,checkCurrent:{}) }
                try require(try String(contentsOfFile:folder+"/ca.pem",encoding:.utf8)=="foreign")
            } else {
                var lease:VPNSystemResolverCertificate?=try .init(bytes:bytes,trustedDirectoryDescriptor:directory,path:folder,deadline:.now()+3,checkCurrent:{})
                try lease!.validate(deadline:.now()+3,checkCurrent:{})
                if mode=="certificate-changed" {
                    try require(chmod(folder+"/ca.pem",0o644)==0)
                    try reject { try lease!.validate(deadline:.now()+3,checkCurrent:{}) }
                } else if mode=="certificate-replaced" {
                    try require(rename(folder+"/ca.pem",folder+"/saved.pem")==0)
                    try Data("foreign".utf8).write(to:URL(fileURLWithPath:folder+"/ca.pem"))
                    try reject { try lease!.validate(deadline:.now()+3,checkCurrent:{}) }
                }
                lease=nil
                if mode=="certificate-replaced" { try require(try String(contentsOfFile:folder+"/ca.pem",encoding:.utf8)=="foreign") }
                else { try require(access(folder+"/ca.pem",F_OK) != 0) }
            }
        } else if mode=="pin" {
            try reject { _=try VPNBridgeWorkerSelection.systemResolver(path:image) }
        } else if mode=="factory-auth" || mode=="factory-role" {
            let choice=try VPNBridgeWorkerSelection.test(path:image,role:mode=="factory-role" ? .gost:.systemResolver)
            try reject { _=try VPNSystemResolverWorker.start(selection:choice,password:Data(repeating:97,count:64),trustedDirectoryDescriptor:directory,path:folder,deadline:.now()+3,checkCurrent:{}) }
            try require(access(folder+"/ca.pem",F_OK) != 0)
        } else {
            let marker=folder+"/child"
            let config=try VPNBridgeConfigurationFile.create(trustedDirectoryDescriptor:directory,path:folder,deadline:.now()+3,checkCurrent:{},encode:{ Data((marker+"|"+(mode=="force" ? "ignore":mode=="crash-startup" ? "hang":mode)+"\n").utf8) })
            let choice=try VPNBridgeWorkerSelection.test(path:image,role:.systemResolver)
            if mode=="long" || mode=="hang" {
                try reject { _=try VPNBridgeWorkerProcess.launch(selection:choice,configuration:config.descriptor,deadline:.now()+1) }
                let pid=try String(contentsOfFile:marker,encoding:.utf8).split(separator:" ").first!.trimmingCharacters(in:.whitespacesAndNewlines)
                try require((try? VPNBridgeWorkerStamp.live(Int32(pid)!))==nil)
            } else {
                let process=try VPNBridgeWorkerProcess.launch(selection:choice,configuration:config.descriptor,deadline:.now()+3)
                try require(process.role == .systemResolver && process.resolverReady==Data("{\"port\":12345,\"certificate\":\"fixture\"}\n".utf8))
                try process.checkLive();try reject { try process.authenticateResolverOutput() }
                if mode=="crash" {
                    print("READY \(process.child.pid) \(process.child.parent)");fflush(stdout)
                    while true { sleep(1) }
                }
                if mode=="stopped" { try require(kill(process.child.pid,SIGSTOP)==0) }
                try process.stop(deadline:.now()+2);try process.stop(deadline:.now()+2)
                try reject { try process.checkLive() }
            }
        }
        print("PASS resolver-owner-"+mode)
    }
}
