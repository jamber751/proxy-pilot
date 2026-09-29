import Darwin
import Dispatch
import Foundation

enum VPNJointArtifactMountError: Error {
    case invalidArtifact, unsafeMount, invalidMountMetadata, invalidMountedFilesystem
    case toolFailed, timeout
}

/// Read-only transport container for the already signed nine-entry joint
/// payload. The public boundary accepts an open file, never a path or URL.
/// Authority still comes exclusively from the inner release/transition
/// signatures rechecked by the root broker.
final class VPNJointArtifactMount {
    static let maximumArtifactBytes: off_t = 768 * 1024 * 1024
    private(set) var directory: Int32
    private let mountPoint: String

    static func open(artifactFile: Int32, deadline: UInt64) throws
        -> VPNJointArtifactMount {
        guard getuid() == geteuid(), geteuid() != 0, artifactFile >= 0,
              DispatchTime.now().uptimeNanoseconds < deadline else {
            throw VPNJointArtifactMountError.invalidArtifact
        }
        var opened = stat(), filesystem = statfs()
        guard fstat(artifactFile, &opened) == 0,
              opened.st_mode & S_IFMT == S_IFREG, opened.st_nlink == 1,
              opened.st_uid == geteuid(), opened.st_mode & 0o0022 == 0,
              opened.st_size > 0, opened.st_size <= maximumArtifactBytes,
              fstatfs(artifactFile, &filesystem) == 0,
              filesystem.f_flags & UInt32(MNT_LOCAL) != 0 else {
            throw VPNJointArtifactMountError.invalidArtifact
        }
        var path = [CChar](repeating: 0, count: Int(MAXPATHLEN))
        guard fcntl(artifactFile, F_GETPATH, &path) == 0 else {
            throw VPNJointArtifactMountError.invalidArtifact
        }
        let artifactPath = String(cString: path)
        var named = stat()
        guard lstat(artifactPath, &named) == 0,
              named.st_dev == opened.st_dev, named.st_ino == opened.st_ino,
              named.st_mode & S_IFMT == S_IFREG else {
            throw VPNJointArtifactMountError.invalidArtifact
        }

        var template = Array((NSTemporaryDirectory()
            + "ProxyPilot-VPN-Joint.XXXXXX").utf8CString)
        guard mkdtemp(&template) != nil else {
            throw VPNJointArtifactMountError.unsafeMount
        }
        let createdMountPoint = String(cString: template)
        let mountPoint = URL(fileURLWithPath: createdMountPoint,
            isDirectory: true).resolvingSymlinksInPath().path
        var mounted = false
        do {
            let data = try runHdiutil([
                "attach", "-readonly", "-nobrowse", "-noautoopen",
                "-owners", "off", "-mountpoint", mountPoint,
                "-plist", artifactPath,
            ], deadline: deadline, capture: true)
            guard try confirmsMount(data, at: mountPoint) else {
                throw VPNJointArtifactMountError.invalidMountMetadata
            }
            mounted = true
            let directory = Darwin.open(mountPoint,
                O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
            guard directory >= 0 else {
                throw VPNJointArtifactMountError.unsafeMount
            }
            do {
                var root = stat(), mountedFS = statfs()
                guard fstat(directory, &root) == 0,
                      root.st_mode & S_IFMT == S_IFDIR, root.st_nlink > 0,
                      root.st_mode & 0o0022 == 0,
                      fstatfs(directory, &mountedFS) == 0,
                      mountedFS.f_flags & UInt32(MNT_LOCAL | MNT_RDONLY)
                        == UInt32(MNT_LOCAL | MNT_RDONLY) else {
                    throw VPNJointArtifactMountError.invalidMountedFilesystem
                }
                return VPNJointArtifactMount(
                    directory: directory, mountPoint: mountPoint)
            } catch {
                close(directory)
                throw error
            }
        } catch {
            if mounted {
                _ = try? runHdiutil(["detach", mountPoint],
                    deadline: DispatchTime.now().uptimeNanoseconds
                        + 10_000_000_000, capture: false)
            }
            _ = rmdir(mountPoint)
            throw error
        }
    }

    private init(directory: Int32, mountPoint: String) {
        self.directory = directory
        self.mountPoint = mountPoint
    }

    deinit {
        if directory >= 0 { close(directory); directory = -1 }
        _ = try? Self.runHdiutil(["detach", mountPoint],
            deadline: DispatchTime.now().uptimeNanoseconds + 10_000_000_000,
            capture: false)
        _ = rmdir(mountPoint)
    }

    private static func confirmsMount(_ data: Data, at mountPoint: String) throws
        -> Bool {
        let value = try PropertyListSerialization.propertyList(
            from: data, options: [], format: nil)
        guard let root = value as? [String: Any],
              let entities = root["system-entities"] as? [[String: Any]] else {
            return false
        }
        let mounted = entities.compactMap { $0["mount-point"] as? String }.map {
            URL(fileURLWithPath: $0, isDirectory: true)
                .resolvingSymlinksInPath().path
        }
        return mounted == [mountPoint]
    }

    private static func runHdiutil(_ arguments: [String], deadline: UInt64,
                                   capture: Bool) throws -> Data {
        guard DispatchTime.now().uptimeNanoseconds < deadline else {
            throw VPNJointArtifactMountError.timeout
        }
        let process = Process()
        process.executableURL = URL(fileURLWithPath: "/usr/bin/hdiutil")
        process.arguments = arguments
        process.environment = ["PATH": "/usr/bin:/bin:/usr/sbin:/sbin"]
        let output = Pipe()
        process.standardOutput = capture ? output : FileHandle.nullDevice
        process.standardError = FileHandle.nullDevice
        try process.run()
        while process.isRunning {
            if DispatchTime.now().uptimeNanoseconds >= deadline {
                process.terminate(); process.waitUntilExit()
                throw VPNJointArtifactMountError.timeout
            }
            usleep(20_000)
        }
        guard process.terminationStatus == 0 else {
            throw VPNJointArtifactMountError.toolFailed
        }
        return capture ? output.fileHandleForReading.readDataToEndOfFile() : Data()
    }
}
