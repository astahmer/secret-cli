import Foundation
#if canImport(Darwin)
import Darwin
#elseif canImport(Glibc)
import Glibc
#endif

// MARK: - Spawn helpers

func spawnDetached(_ executable: String, _ args: [String]) -> pid_t? {
    let process = Process()
    process.executableURL = URL(fileURLWithPath: executable)
    process.arguments = args
    process.standardInput = FileHandle.nullDevice
    process.standardOutput = FileHandle.nullDevice
    process.standardError = FileHandle.nullDevice
    do {
        try process.run()
    } catch {
        return nil
    }
    return process.processIdentifier
}

func ownExecutablePath() -> String? {
    let arg0 = CommandLine.arguments[0]
    if arg0.contains("/") {
        return URL(fileURLWithPath: arg0).resolvingSymlinksInPath().path
    }
    return pathTo(arg0)
}

func runCommandPassthrough(_ executable: String, _ args: [String], env: [String: String]? = nil) -> Int32 {
    let resolved = executable.contains("/") ? executable : (pathTo(executable) ?? executable)
    guard let pid = posixSpawnChild(resolved, args, env: env) else { return 127 }
    var status: Int32 = 0
    waitpid(pid, &status, 0)
    return exitStatus(status)
}

func envWithoutStaleSession() -> [String: String] {
    var clean = ProcessInfo.processInfo.environment
    clean.removeValue(forKey: "BW_SESSION")
    return clean
}

func envWithSession(_ token: String) -> [String: String] {
    var env = envWithoutStaleSession()
    env["BW_SESSION"] = token
    return env
}

// MARK: - Keychain session

let keychainService = "secret-cli"
let keychainAccount = "bitwarden-session"

func readSession() -> String? {
    #if os(macOS)
    if let security = pathTo("security") {
        let r = runCommand(security, ["find-generic-password", "-a", keychainAccount, "-s", keychainService, "-w"])
        if r.status == 0, !r.stdout.isEmpty {
            return r.stdout.trimmingCharacters(in: .whitespacesAndNewlines)
        }
    }
    #endif
    guard exists(sessionPath), let raw = readFile(sessionPath) else { return nil }
    let trimmed = raw.trimmingCharacters(in: .whitespacesAndNewlines)
    return trimmed.isEmpty ? nil : trimmed
}

func storeSession(_ token: String) {
    if token.isEmpty { fail("refusing to store an empty session token") }
    #if os(macOS)
    if let security = pathTo("security") {
        let r = runCommand(security, ["add-generic-password", "-U", "-a", keychainAccount, "-s", keychainService, "-w", token])
        if r.status == 0 { return }
    }
    warn("macOS keychain unavailable — falling back to a plaintext session file")
    #endif
    writeAtomic(sessionPath, token)
}

func clearSession() {
    #if os(macOS)
    if let security = pathTo("security") {
        _ = runCommand(security, ["delete-generic-password", "-a", keychainAccount, "-s", keychainService])
    }
    #endif
    if exists(sessionPath) {
        try? FileManager.default.removeItem(atPath: sessionPath)
    }
}

// MARK: - History

struct HistoryEntry {
    var at: String
    var cmd: String
    var target: String
    var env: String
}

func readHistory() -> [HistoryEntry] {
    guard exists(historyPath), let raw = readFile(historyPath), let parsed = parseJSONOrdered(raw) else { return [] }
    var entries: [HistoryEntry] = []
    for item in parsed.items() ?? [] {
        guard let pairs = item.pairs() else { continue }
        var at = "", cmd = "", target = "", env = ""
        for (key, value) in pairs {
            switch key {
            case "at": at = value.string() ?? ""
            case "cmd": cmd = value.string() ?? ""
            case "target": target = value.string() ?? ""
            case "env": env = value.string() ?? ""
            default: break
            }
        }
        entries.append(HistoryEntry(at: at, cmd: cmd, target: target, env: env))
    }
    return entries
}

func recordHistory(entry: HistoryEntry) {
    var entries = readHistory()
    entries.append(entry)
    let kept = Array(entries.suffix(historyLimit))
    let items = kept.map { entry -> J in
        .obj([
            ("at", .str(entry.at)),
            ("cmd", .str(entry.cmd)),
            ("target", .str(entry.target)),
            ("env", .str(entry.env)),
        ])
    }
    writeAtomic(historyPath, jStringify(.arr(items)) + "\n")
}

func isoNow() -> String {
    ISO8601DateFormatter().string(from: Date())
}

func printRecent(json: Bool) {
    var byAlias: [String: (last: String, count: Int)] = [:]
    for entry in readHistory() where entry.cmd == "get" || entry.cmd == "set" {
        if var current = byAlias[entry.target] {
            current.count += 1
            if entry.at > current.last { current.last = entry.at }
            byAlias[entry.target] = current
        } else {
            byAlias[entry.target] = (entry.at, 1)
        }
    }
    let rows = byAlias.sorted { $0.value.last > $1.value.last }.prefix(10)
    if rows.isEmpty {
        writeErr("secret recent: no aliases used yet — try secret get <alias> or secret set <alias>\n")
        return
    }
    if json {
        let items = rows.map { alias, info -> J in
            .obj([("alias", .str(alias)), ("last", .str(info.last)), ("count", .num(Double(info.count)))])
        }
        print(jStringify(.arr(Array(items)), pretty: false))
    } else {
        for (alias, info) in rows { print("\(alias)\t\(info.last)\t\(info.count)") }
    }
    writeErr("secret recent: \(rows.count) aliases, most recent first\n")
}

func printHistory(json: Bool) {
    let all = readHistory()
    let entries = Array(all.suffix(20))
    if entries.isEmpty {
        writeErr("secret history: empty — run a secret command first\n")
        return
    }
    if json {
        let items = entries.map { entry -> J in
            .obj([
                ("at", .str(entry.at)),
                ("cmd", .str(entry.cmd)),
                ("target", .str(entry.target)),
                ("env", .str(entry.env)),
            ])
        }
        print(jStringify(.arr(items), pretty: false))
    } else {
        for entry in entries {
            print("\(entry.at)\t\(entry.cmd)\t\(entry.target)\t\(entry.env)")
        }
    }
    writeErr("secret history: last \(entries.count) commands (\(all.count) total)\n")
}

// MARK: - bw serve daemon over a unix socket

struct DaemonState {
    var pid: Int
    var socket: String
}

func readDaemonState() -> DaemonState? {
    guard exists(daemonStatePath), let raw = readFile(daemonStatePath), let parsed = parseJSONOrdered(raw) else {
        return nil
    }
    guard let pid = parsed.get("pid")?.asDouble,
          let socket = parsed.get("socket")?.string()
    else { return nil }
    return DaemonState(pid: Int(pid), socket: socket)
}

func writeDaemonState(pid: Int, socket: String) {
    try? FileManager.default.createDirectory(atPath: daemonDir, withIntermediateDirectories: true, attributes: [.posixPermissions: 0o700])
    writeAtomic(daemonStatePath, jStringify(.obj([("pid", .num(Double(pid))), ("socket", .str(socket))]), pretty: false))
}

func daemonRequest(_ socketPath: String, method: String, path: String, body: String? = nil) -> (status: Int, body: String)? {
    let fd = socket(AF_UNIX, SOCK_STREAM, 0)
    guard fd >= 0 else { return nil }
    defer { close(fd) }

    var addr = sockaddr_un()
    addr.sun_family = sa_family_t(AF_UNIX)
    let pathBytes = Array(socketPath.utf8)
    let pathCapacity = MemoryLayout<sockaddr_un>.size - MemoryLayout<sockaddr_un>.offset(of: \.sun_path)!
    guard pathBytes.count < pathCapacity else { return nil }
    withUnsafeMutablePointer(to: &addr) { pointer in
        let raw = UnsafeMutableRawPointer(pointer).advanced(by: MemoryLayout<sockaddr_un>.offset(of: \.sun_path)!)
        pathBytes.withUnsafeBytes { buffer in
            raw.copyMemory(from: buffer.baseAddress!, byteCount: pathBytes.count)
        }
    }
    let rc = withUnsafePointer(to: &addr) { pointer in
        pointer.withMemoryRebound(to: sockaddr.self, capacity: 1) { sockaddrPointer in
            connect(fd, sockaddrPointer, socklen_t(MemoryLayout<sockaddr_un>.size))
        }
    }
    guard rc == 0 else { return nil }

    var timeout = timeval(tv_sec: 5, tv_usec: 0)
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, socklen_t(MemoryLayout<timeval>.size))
    setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &timeout, socklen_t(MemoryLayout<timeval>.size))

    var request = "\(method) \(path) HTTP/1.1\r\nHost: \(daemonHost):\(daemonPort)\r\n"
    if let body {
        request += "Content-Type: application/json\r\nContent-Length: \(body.utf8.count)\r\n"
    }
    request += "Connection: close\r\n\r\n"
    if let body { request += body }

    let requestBytes = Array(request.utf8)
    var sent = 0
    while sent < requestBytes.count {
        let n = requestBytes.withUnsafeBytes { buffer -> Int in
            send(fd, buffer.baseAddress!.advanced(by: sent), requestBytes.count - sent, 0)
        }
        if n <= 0 { return nil }
        sent += n
    }

    var response = Data()
    var buffer = [UInt8](repeating: 0, count: 65536)
    while true {
        let n = recv(fd, &buffer, buffer.count, 0)
        if n <= 0 { break }
        response.append(contentsOf: buffer[0..<n])
    }
    guard let text = String(data: response, encoding: .utf8) else { return nil }
    let parts = text.split(separator: "\r\n\r\n", maxSplits: 1, omittingEmptySubsequences: false)
    let head = parts.first.map(String.init) ?? ""
    let bodyText = parts.count > 1 ? String(parts[1]) : ""
    let statusLine = head.split(separator: "\r\n").first.map(String.init) ?? ""
    let statusParts = statusLine.split(separator: " ")
    guard statusParts.count >= 2, let status = Int(statusParts[1]) else { return nil }
    return (status, bodyText)
}

enum DaemonResult {
    case ok(data: Any)
    case denied
}

func parseDaemon(_ response: (status: Int, body: String)?) -> DaemonResult? {
    guard let response else { return nil }
    guard let parsed = jsonObject(response.body) else { return nil }
    if let success = parsed["success"] as? Bool, success, response.status == 200 {
        return .ok(data: parsed["data"] as Any)
    }
    if let success = parsed["success"] as? Bool, !success { return .denied }
    return nil
}

func daemonStatus() async -> String? {
    guard let state = readDaemonState() else { return nil }
    guard let parsed = parseDaemon(daemonRequest(state.socket, method: "GET", path: "/status")),
          case .ok(let data) = parsed,
          let data = data as? JSON
    else { return nil }
    let status = (data["template"] as? JSON)?["status"] as? String ?? data["status"] as? String
    return status
}

func daemonListItems() -> (kind: String, items: [JSON])? {
    guard let state = readDaemonState() else { return nil }
    guard let parsed = parseDaemon(daemonRequest(state.socket, method: "GET", path: "/list/object/items")) else {
        return nil
    }
    switch parsed {
    case .denied: return (kind: "denied", items: [])
    case .ok(let data):
        let items: [Any]
        if let array = data as? [Any] {
            items = array
        } else if let dict = data as? JSON, let nested = dict["data"] as? [Any] {
            items = nested
        } else {
            return nil
        }
        return (kind: "ok", items: items.compactMap { $0 as? JSON })
    }
}

func daemonMutate(method: String, path: String, payload: JSON? = nil) async -> Bool {
    if !daemonEnabled() { return false }
    guard let state = readDaemonState() else { return false }
    guard let response = daemonRequest(
        state.socket,
        method: method,
        path: path,
        body: payload.map { jsonString($0) }
    ) else { return false }
    guard let parsed = parseDaemon(response) else {
        daemonStop()
        return false
    }
    switch parsed {
    case .ok: return true
    case .denied: fail("Bitwarden is locked; run bw unlock --raw and export BW_SESSION")
    }
}

func generatePassword() async -> String {
    if daemonEnabled(), let state = readDaemonState() {
        let response = daemonRequest(
            state.socket,
            method: "GET",
            path: "/generate?length=32&uppercase=true&lowercase=true&number=true&special=true"
        )
        if let response {
            let parsed = parseDaemon(response)
            switch parsed {
            case .ok(let data):
                if let data = data as? JSON, let value = data["data"] as? String, !value.isEmpty {
                    return value
                }
            case .denied: fail("Bitwarden is locked; run bw unlock --raw and export BW_SESSION")
            case nil: break
            }
            daemonStop()
        }
    }
    return runBw(["generate", "-ulns", "--length", "32"])
}

func daemonStop() {
    guard let state = readDaemonState() else { return }
    kill(pid_t(state.pid), SIGTERM)
    try? FileManager.default.removeItem(atPath: state.socket)
    try? FileManager.default.removeItem(atPath: daemonStatePath)
}

func keepaliveLoop(socket: String) -> Never {
    var seen = false
    var failures = 0
    while true {
        if seen && !exists(socket) { exit(0) }
        if exists(socket) { seen = true }
        if daemonRequest(socket, method: "GET", path: "/status") != nil {
            failures = 0
        } else {
            failures += 1
            if failures >= 3 { exit(0) }
        }
        Thread.sleep(forTimeInterval: 10)
    }
}

func daemonStart() async -> Bool {
    try? FileManager.default.createDirectory(atPath: daemonDir, withIntermediateDirectories: true, attributes: [.posixPermissions: 0o700])
    try? FileManager.default.removeItem(atPath: daemonSocketPath)
    guard let bw = pathTo("bw") else { return false }
    guard let pid = spawnDetached(bw, ["serve", "--hostname", "unix://\(daemonSocketPath)", "--port", String(daemonPort)]) else {
        return false
    }
    if let selfPath = ownExecutablePath() {
        _ = spawnDetached(selfPath, ["__secret-keepalive", daemonSocketPath])
    }
    let deadline = Date().addingTimeInterval(8)
    while Date() < deadline {
        if kill(pid, 0) != 0 { return false }
        if let response = daemonRequest(daemonSocketPath, method: "GET", path: "/status"), response.status == 200 {
            let parsed = parseDaemon(response)
            var statusText: String?
            if case .ok(let data)? = parsed, let data = data as? JSON {
                statusText = (data["template"] as? JSON)?["status"] as? String ?? data["status"] as? String
            }
            if parsed == nil || statusText != "unlocked" {
                kill(pid, SIGKILL)
                return false
            }
            writeDaemonState(pid: Int(pid), socket: daemonSocketPath)
            _ = daemonRequest(daemonSocketPath, method: "POST", path: "/sync")
            return true
        }
        try? await Task.sleep(nanoseconds: 100_000_000)
    }
    kill(pid, SIGKILL)
    return false
}

func ensureDaemon() async -> Bool {
    if let state = readDaemonState() {
        if let response = daemonRequest(state.socket, method: "GET", path: "/status"), response.status == 200 {
            return true
        }
        daemonStop()
    }
    return await daemonStart()
}

func spawnStatus() -> (authenticated: Bool, unlocked: Bool) {
    guard let bw = pathTo("bw") else { fail("could not run Bitwarden CLI (is 'bw' installed?)") }
    let r = runCommand(bw, ["status"])
    if r.status != 0 { fail("Bitwarden status request failed") }
    guard let data = jsonObject(r.stdout) else { fail("Bitwarden returned invalid status data") }
    let status = data["status"] as? String ?? ""
    return (authenticated: status != "unauthenticated", unlocked: status == "unlocked")
}

func currentAuthState() async -> (authenticated: Bool, unlocked: Bool) {
    if daemonEnabled() {
        if await ensureDaemon() {
            if await daemonStatus() == "unlocked" {
                return (authenticated: true, unlocked: true)
            }
            daemonStop()
        }
    }
    return spawnStatus()
}

func spawnVaultItems() -> [JSON]? {
    guard let bw = pathTo("bw") else { fail("could not run Bitwarden CLI (is 'bw' installed?)") }
    let r = runCommand(bw, ["list", "items"])
    guard r.status == 0 else { return nil }
    guard let parsed = jsonParse(r.stdout) as? [Any] else { return nil }
    return parsed.compactMap { $0 as? JSON }
}

func vaultItems() async -> [JSON]? {
    if !daemonEnabled() { return spawnVaultItems() }
    if let viaDaemon = daemonListItems() {
        if viaDaemon.kind == "ok" {
            if !viaDaemon.items.isEmpty { return viaDaemon.items }
            let spawned = spawnVaultItems()
            if let spawned, !spawned.isEmpty { return spawned }
            return viaDaemon.items
        }
        if viaDaemon.kind == "denied" {
            if env("BW_SESSION").map({ !$0.isEmpty }) == true {
                daemonStop()
                if await daemonStart() {
                    if let retry = daemonListItems(), retry.kind == "ok" {
                        return retry.items
                    }
                }
            }
            return nil
        }
    }
    if await ensureDaemon() {
        if let retry = daemonListItems() {
            if retry.kind == "ok" { return retry.items }
            if retry.kind == "denied" { return nil }
        }
    }
    return spawnVaultItems()
}

func bitwardenRequireUnlocked() async {
    var current = await currentAuthState()
    if !current.unlocked {
        if current.authenticated, isatty(0) == 1, env("SECRET_NO_PROMPT") == nil {
            if env("SECRET_DEBUG") != nil { writeErr("debug: interactive unlock attempt\n") }
            let token = runBwUnlock()
            if !token.isEmpty {
                let check = runCommand(pathTo("bw") ?? "bw", ["status"], env: envWithSession(token))
                if check.status == 0, let data = jsonObject(check.stdout), (data["status"] as? String) == "unlocked" {
                    setenv("BW_SESSION", token, 1)
                    storeSession(token)
                    daemonStop()
                    success("unlocked; session stored")
                    return
                }
            }
        }
        current = await currentAuthState()
    }
    if !current.authenticated { fail("Bitwarden is not authenticated; run bw login first") }
    if !current.unlocked { fail("Bitwarden is locked; run bw unlock --raw and export BW_SESSION") }
}
