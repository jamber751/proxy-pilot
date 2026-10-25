import Darwin
import Foundation
@main private enum Checks {
    enum Failure: Error { case check }
    static func require(_ value: @autoclosure () -> Bool) throws { if !value() { throw Failure.check } }
    static func emit(_ mode: String) -> Never {
        var data=Data("pid = 1974\n".utf8)
        switch mode {
        case "large":data=Data(repeating:120,count:200*1024)+Data("\npid = 1974\n".utf8)
        case "cap":data=Data(repeating:120,count:300*1024)
        case "duplicate":data+=Data("pid = 1975\n".utf8)
        case "absent":data=Data("state = running\n".utf8)
        case "utf8":data=Data([255,10])+data
        case "late":usleep(1_000_000)
        default:break
        }
        data.withUnsafeBytes { bytes in
            var at=0
            while at<bytes.count {
                let size=mode=="fragmented" ? 1:min(4096,bytes.count-at)
                let n=Darwin.write(STDOUT_FILENO,bytes.baseAddress!.advanced(by:at),size)
                if n<0 && errno==EINTR { continue };if n<=0 { exit(2) };at+=n
            }
        }
        if mode=="eof-alive" { close(STDOUT_FILENO);usleep(1_000_000) }
        exit(mode=="nonzero" ? 7:0)
    }
    static func main() {
        guard getuid()==geteuid(), geteuid() != 0,CommandLine.arguments.count==3 else { exit(77) }
        let operation=CommandLine.arguments[1],mode=CommandLine.arguments[2]
        if operation=="emit" { emit(mode) }
        do {
            let executable=URL(fileURLWithPath:CommandLine.arguments[0])
            if mode=="legacy" {
                let child=Process(),pipe=Pipe()
                child.executableURL=executable;child.arguments=["emit","large"]
                child.standardInput=FileHandle.nullDevice;child.standardOutput=pipe;child.standardError=FileHandle.nullDevice;child.environment=[:]
                try child.run()
                defer { if child.isRunning { kill(child.processIdentifier,SIGKILL) };child.waitUntilExit() }
                // Consume only one byte to prove the writer has started; then
                // reproduce the original wait-before-drain on the rest.
                var item=pollfd(fd:pipe.fileHandleForReading.fileDescriptor,events:Int16(POLLIN),revents:0)
                try require(poll(&item,1,2000)>0)
                var first: UInt8=0
                try require(read(pipe.fileHandleForReading.fileDescriptor,&first,1)==1 && first==120)
                let end=DispatchTime.now().uptimeNanoseconds+200_000_000
                while child.isRunning && DispatchTime.now().uptimeNanoseconds<end { usleep(1000) }
                try require(child.isRunning) // Observed pipe pressure, not cold startup.
            } else {
                let now=DispatchTime.now().uptimeNanoseconds
                let end=mode=="expired" ? now-1:now+((mode=="late" || mode=="eof-alive") ? 100_000_000:3_000_000_000)
                let target=mode=="expired" ? URL(fileURLWithPath:"/does-not-exist"):executable
                do {
                    let pid=try VPNUpdateBrokerLaunchdJob.testCapturedProcessID(executable:target,arguments:["emit",mode],deadline:end)
                    try require(["small","large","fragmented"].contains(mode) && pid==1974)
                } catch let error as VPNUpdateBrokerLaunchdJobError {
                    switch error {
                    case .timeout:try require(["late","eof-alive","expired"].contains(mode))
                    case .launchFailed:try require(["cap","duplicate","absent","utf8","nonzero"].contains(mode))
                    default:throw error
                    }
                }
            }
            print("PASS broker-output-"+mode)
        } catch { fputs("FAIL broker-output-check\n",stderr);exit(1) }
    }
}
