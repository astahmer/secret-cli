import Foundation
#if canImport(Darwin)
import Darwin
#elseif canImport(Glibc)
import Glibc
#endif

// MARK: - Paths

let home = ProcessInfo.processInfo.environment["HOME"] ?? FileManager.default.homeDirectoryForCurrentUser.path
let configDir = "\(home)/.config/secret"
let userConfigPath = "\(configDir)/config.json"
let historyPath = "\(configDir)/history.json"
let sessionPath = ProcessInfo.processInfo.environment["SECRET_SESSION_FILE"] ?? "\(configDir)/session"
let daemonDir = "\(configDir)/daemon"
let daemonStatePath = "\(daemonDir)/daemon.json"
let daemonSocketPath = "\(daemonDir)/bw.sock"
let daemonHost = "localhost"
let daemonPort = 8087
let projectConfigName = ".secret.json"
let localConfigName = ".secret.local.json"
let placeholderValues: Set<String> = ["replace-me", "REPLACE-ME"]
let historyLimit = 100

func env(_ key: String) -> String? { ProcessInfo.processInfo.environment[key] }

func daemonEnabled() -> Bool { env("SECRET_DAEMON") != "0" }

// MARK: - ANSI colors (TTY only)

func outIsTTY() -> Bool { isatty(1) == 1 }
func errIsTTY() -> Bool { isatty(2) == 1 }

func paint(_ enabled: Bool, _ code: String, _ text: String) -> String {
    enabled ? "\u{1B}[\(code)m\(text)\u{1B}[0m" : text
}

func outColor(_ code: String, _ text: String) -> String { paint(outIsTTY(), code, text) }
func errColor(_ code: String, _ text: String) -> String { paint(errIsTTY(), code, text) }

// MARK: - Output helpers

func writeErr(_ text: String) {
    try? FileHandle.standardError.write(contentsOf: Data(text.utf8))
}

func fail(_ message: String) -> Never {
    writeErr(errColor("31", "secret: \(message)\n"))
    exit(1)
}

func info(_ text: String) { writeErr(errColor("2", "secret: \(text)\n")) }
func success(_ text: String) { writeErr(errColor("32", "secret: \(text)\n")) }
func warn(_ text: String) { writeErr(errColor("33", "secret: \(text)\n")) }

// MARK: - JSON

typealias JSON = [String: Any]

func jsonParse(_ data: String) -> Any? {
    try? JSONSerialization.jsonObject(with: Data(data.utf8))
}

func jsonObject(_ data: String) -> JSON? { jsonParse(data) as? JSON }
func jsonArray(_ data: String) -> [Any]? { jsonParse(data) as? [Any] }

func jsonString(_ value: Any) -> String {
    guard let data = try? JSONSerialization.data(withJSONObject: value, options: [.sortedKeys]) else { return "" }
    return String(data: data, encoding: .utf8) ?? ""
}

// MARK: - File IO

func readFile(_ path: String) -> String? { try? String(contentsOfFile: path, encoding: .utf8) }

func writeAtomic(_ path: String, _ contents: String, mode: Int32 = 0o600) {
    let dir = (path as NSString).deletingLastPathComponent
    try? FileManager.default.createDirectory(atPath: dir, withIntermediateDirectories: true)
    let tmp = "\(path).tmp.\(ProcessInfo.processInfo.processIdentifier)"
    FileManager.default.createFile(atPath: tmp, contents: Data(contents.utf8), attributes: [.posixPermissions: mode])
    _ = try? FileManager.default.removeItem(atPath: path)
    try? FileManager.default.moveItem(atPath: tmp, toPath: path)
}

func readJSONFile(_ path: String) -> JSON {
    guard let raw = readFile(path), let obj = jsonObject(raw) else { return [:] }
    return obj
}

func exists(_ path: String) -> Bool { FileManager.default.fileExists(atPath: path) }

// MARK: - Prompts

func readStdinAll() -> String {
    var data = Data()
    var buffer = [UInt8](repeating: 0, count: 4096)
    while true {
        let n = read(0, &buffer, buffer.count)
        if n <= 0 { break }
        data.append(contentsOf: buffer[0..<n])
    }
    return String(data: data, encoding: .utf8) ?? ""
}

func promptHidden(_ label: String) -> String {
    if isatty(0) == 0 {
        return readStdinAll().trimmingCharacters(in: .whitespacesAndNewlines)
    }
    var term = termios()
    tcgetattr(0, &term)
    var noEcho = term
    noEcho.c_lflag &= ~tcflag_t(ECHO)
    tcsetattr(0, TCSANOW, &noEcho)
    try? FileHandle.standardError.write(contentsOf: Data("\(label): ".utf8))
    let value = readLine() ?? ""
    try? FileHandle.standardError.write(contentsOf: Data("\n".utf8))
    tcsetattr(0, TCSANOW, &term)
    return value
}

func promptLine(_ label: String) -> String {
    try? FileHandle.standardError.write(contentsOf: Data("\(label): ".utf8))
    let value = readLine() ?? ""
    try? FileHandle.standardError.write(contentsOf: Data("\n".utf8))
    return value.trimmingCharacters(in: .whitespacesAndNewlines)
}

func confirmPrompt(_ label: String) -> Bool {
    try? FileHandle.standardError.write(contentsOf: Data("\(label) [y/N] ".utf8))
    let value = readLine()?.lowercased() ?? ""
    return value == "y" || value == "yes"
}

// MARK: - Clipboard

func copyToClipboard(_ value: String) -> Bool {
    #if os(macOS)
    let candidates: [[String]] = [["pbcopy"]]
    #else
    let candidates: [[String]] = [["wl-copy"], ["xclip", "-selection", "clipboard"], ["pbcopy"]]
    #endif
    for cmd in candidates {
        let r = runCommand(cmd[0], Array(cmd.dropFirst()), input: value)
        if r.status == 0 { return true }
    }
    return false
}

// MARK: - Commands

struct CommandResult {
    let status: Int32
    let stdout: String
    let stderr: String
}

// posix_spawn (Foundation Process put children in their own process group,
// which stops them from reading the tty — SIGTTIN — when the parent is the
// foreground group, e.g. under expect; Node's spawnSync keeps the group).
func posixSpawnChild(
    _ executable: String,
    _ args: [String],
    env: [String: String]? = nil,
    stdinFD: Int32? = nil,
    stdoutFD: Int32? = nil,
    stderrFD: Int32? = nil
) -> pid_t? {
    var fileActions: posix_spawn_file_actions_t?
    posix_spawn_file_actions_init(&fileActions)
    // CLOEXEC_DEFAULT closes every fd (including 0/1/2) unless dup2'd, so
    // always keep the standard streams; pipes override them when given.
    posix_spawn_file_actions_adddup2(&fileActions, stdinFD ?? 0, 0)
    posix_spawn_file_actions_adddup2(&fileActions, stdoutFD ?? 1, 1)
    posix_spawn_file_actions_adddup2(&fileActions, stderrFD ?? 2, 2)

    var attr: posix_spawnattr_t?
    posix_spawnattr_init(&attr)
    posix_spawnattr_setflags(&attr, Int16(POSIX_SPAWN_CLOEXEC_DEFAULT))

    var cargs: [UnsafeMutablePointer<CChar>?] = ([executable] + args).map { strdup($0) }
    cargs.append(nil)

    var pid: pid_t = 0
    let rc: Int32
    if let env {
        // Explicit environment (e.g. session verification): build it fresh.
        var cenv: [UnsafeMutablePointer<CChar>?] = env.map { strdup("\($0.key)=\($0.value)") }
        cenv.append(nil)
        rc = posix_spawn(&pid, executable, &fileActions, &attr, &cargs, &cenv)
        for pointer in cenv { free(pointer) }
    } else {
        // macOS posix_spawn does NOT inherit when envp is NULL (empty env),
        // and setenv() calls (BW_SESSION) must be visible, so pass environ.
        let envp = environ
        rc = posix_spawn(&pid, executable, &fileActions, &attr, &cargs, envp)
    }

    for pointer in cargs { free(pointer) }
    posix_spawn_file_actions_destroy(&fileActions)
    posix_spawnattr_destroy(&attr)
    return rc == 0 ? pid : nil
}

func readFD(_ fd: Int32) -> Data {
    var data = Data()
    var buffer = [UInt8](repeating: 0, count: 65536)
    while true {
        let n = read(fd, &buffer, buffer.count)
        if n <= 0 { break }
        data.append(contentsOf: buffer[0..<n])
    }
    return data
}

func exitStatus(_ status: Int32) -> Int32 {
    let signaled = status & 0x7f
    if signaled == 0 { return (status >> 8) & 0xff }
    return 128 + signaled
}

func runCommand(
    _ executable: String,
    _ args: [String],
    input: String? = nil,
    env: [String: String]? = nil,
    stdin: Pipe? = nil,
    stdoutPipe: Pipe? = nil,
    stderrPipe: Pipe? = nil
) -> CommandResult {
    let resolved = executable.contains("/") ? executable : (pathTo(executable) ?? executable)
    var stdinFD: Int32? = nil
    var stdinWriteFD: Int32? = nil
    if let input {
        var fds: [Int32] = [0, 0]
        guard pipe(&fds) == 0 else { return CommandResult(status: 127, stdout: "", stderr: "") }
        stdinFD = fds[0]
        stdinWriteFD = fds[1]
    }
    var outFDs: [Int32] = [0, 0]
    guard pipe(&outFDs) == 0 else { return CommandResult(status: 127, stdout: "", stderr: "") }
    var errFDs: [Int32] = [0, 0]
    guard pipe(&errFDs) == 0 else { return CommandResult(status: 127, stdout: "", stderr: "") }

    guard let pid = posixSpawnChild(
        resolved,
        args,
        env: env,
        stdinFD: stdinFD,
        stdoutFD: outFDs[1],
        stderrFD: errFDs[1]
    ) else {
        return CommandResult(status: 127, stdout: "", stderr: "")
    }
    close(outFDs[1])
    close(errFDs[1])
    if let stdinWriteFD {
        if !input!.isEmpty {
            _ = Array(input!.utf8).withUnsafeBytes { buffer in
                write(stdinWriteFD, buffer.baseAddress!, input!.utf8.count)
            }
        }
        close(stdinWriteFD)
    }
    if let stdinFD { close(stdinFD) }
    var status: Int32 = 0
    waitpid(pid, &status, 0)
    let outData = readFD(outFDs[0])
    close(outFDs[0])
    let errData = readFD(errFDs[0])
    close(errFDs[0])
    return CommandResult(
        status: exitStatus(status),
        stdout: String(data: outData, encoding: .utf8) ?? "",
        stderr: String(data: errData, encoding: .utf8) ?? ""
    )
}

func runCommandInherit(
    _ executable: String,
    _ args: [String],
    env: [String: String]? = nil
) -> CommandResult {
    let resolved = executable.contains("/") ? executable : (pathTo(executable) ?? executable)
    var outFDs: [Int32] = [0, 0]
    guard pipe(&outFDs) == 0 else { return CommandResult(status: 127, stdout: "", stderr: "") }
    guard let pid = posixSpawnChild(
        resolved,
        args,
        env: env,
        stdinFD: nil,
        stdoutFD: outFDs[1],
        stderrFD: nil
    ) else {
        return CommandResult(status: 127, stdout: "", stderr: "")
    }
    close(outFDs[1])
    var status: Int32 = 0
    waitpid(pid, &status, 0)
    let outData = readFD(outFDs[0])
    close(outFDs[0])
    return CommandResult(
        status: exitStatus(status),
        stdout: String(data: outData, encoding: .utf8) ?? "",
        stderr: ""
    )
}

func pathTo(_ name: String) -> String? {
    guard let path = env("PATH") else { return nil }
    for dir in path.split(separator: ":") {
        let candidate = "\(dir)/\(name)"
        if FileManager.default.isExecutableFile(atPath: candidate) { return candidate }
    }
    return nil
}

func runBw(_ args: [String], input: String? = nil, env: [String: String]? = nil) -> String {
    guard let bw = pathTo("bw") else { fail("could not run Bitwarden CLI (is 'bw' installed?)") }
    let r = runCommand(bw, args, input: input, env: env)
    if r.status != 0 {
        let detail = r.stderr.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty
            ? r.stdout.trimmingCharacters(in: .whitespacesAndNewlines)
            : r.stderr.trimmingCharacters(in: .whitespacesAndNewlines)
        fail("Bitwarden CLI request failed: \(detail.isEmpty ? "no output" : String(detail.prefix(300)))")
    }
    return r.stdout.trimmingCharacters(in: .whitespacesAndNewlines)
}

func tryGetItemRaw(_ item: String) -> String? {
    guard let bw = pathTo("bw") else { return nil }
    let r = runCommand(bw, ["get", "item", item, "--raw"])
    return r.status == 0 ? r.stdout.trimmingCharacters(in: .whitespacesAndNewlines) : nil
}

func runBwUnlock() -> String {
    guard let bw = pathTo("bw") else { fail("could not run Bitwarden CLI (is 'bw' installed?)") }
    var cleanEnv = ProcessInfo.processInfo.environment
    cleanEnv.removeValue(forKey: "BW_SESSION")
    let r = runCommandInherit(bw, ["unlock", "--raw"], env: cleanEnv)
    if r.status != 0 {
        let detail = r.stdout.trimmingCharacters(in: .whitespacesAndNewlines)
        fail("Bitwarden unlock failed: \(detail.isEmpty ? "no output" : String(detail.prefix(300)))")
    }
    return r.stdout.trimmingCharacters(in: .whitespacesAndNewlines)
}

// MARK: - Config model

struct SecretDefinition {
    var item: String
    var field: String?
    var envKey: String?
    var itemType: String? = nil
    var expiresAt: String? = nil
    var tags: [String]? = nil
}

struct LoadedConfig {
    var definitions: [String: SecretDefinition]
    var ordered: [(alias: String, definition: SecretDefinition)]
    var selectedAliases: [String]?
}

func definitionInConfig(_ config: J, _ alias: String, environment: String) -> SecretDefinition? {
    let value = (environment == "prod" ? nil : config.get("environments")?.get(environment)?.get("secrets")?.get(alias))
        ?? config.get("secrets")?.get(alias)
    guard let value else { return nil }
    var item = ""
    var field: String?
    var envKey: String?
    var itemType: String?
    var expiresAt: String?
    var tags: [String]?
    for (key, child) in value.pairs() ?? [] {
        switch key {
        case "item": item = child.string() ?? ""
        case "field": field = child.string()
        case "env": envKey = child.string()
        case "type": itemType = child.string()
        case "expiresAt": expiresAt = child.string()
        case "tags": tags = child.items()?.compactMap { $0.string() }
        default: break
        }
    }
    if item.isEmpty { fail("invalid definition for \(alias)") }
    return SecretDefinition(item: item, field: field, envKey: envKey, itemType: itemType, expiresAt: expiresAt, tags: tags)
}

func dotenvKey(_ alias: String, _ definition: SecretDefinition) -> String {
    let key = definition.envKey ?? alias
    if key.range(of: "^[A-Za-z_][A-Za-z0-9_]*$", options: .regularExpression) == nil {
        fail("invalid dotenv key for \(alias)")
    }
    return key
}

func dotenvAssignment(_ line: String) -> (key: String, value: String)? {
    let trimmed = line.trimmingCharacters(in: .whitespaces)
    if trimmed.isEmpty || trimmed.hasPrefix("#") { return nil }
    let body = trimmed.hasPrefix("export ") ? String(trimmed.dropFirst("export ".count)) : trimmed
    guard let eq = body.firstIndex(of: "=") else { return nil }
    let key = String(body[..<eq])
    if key.range(of: "^[A-Za-z_][A-Za-z0-9_]*$", options: .regularExpression) == nil { return nil }
    return (key, String(body[body.index(after: eq)...]))
}

struct IncomingDotenvVar {
    var key: String
    var assignment: String
    var source: String?
}

func incomingDotenvVars(_ lines: [String]) -> [IncomingDotenvVar] {
    var incoming: [IncomingDotenvVar] = []
    var pendingSource: String?
    for line in lines {
        if line.hasPrefix("# source:") {
            pendingSource = line
            continue
        }
        guard let parsed = dotenvAssignment(line) else {
            pendingSource = nil
            continue
        }
        incoming.append(IncomingDotenvVar(key: parsed.key, assignment: line, source: pendingSource))
        pendingSource = nil
    }
    return incoming
}

func mergeDotenv(existing: String, incoming: [IncomingDotenvVar]) -> String {
    let byKey = Dictionary(uniqueKeysWithValues: incoming.map { ($0.key, $0) })
    var seen = Set<String>()
    var out: [String] = []
    let rawLines = existing.split(separator: "\n", omittingEmptySubsequences: false).map(String.init)
    var index = 0
    while index < rawLines.count {
        let line = rawLines[index]
        let next = index + 1 < rawLines.count ? rawLines[index + 1] : nil
        if line.hasPrefix("# source:"), let next, let parsed = dotenvAssignment(next), byKey[parsed.key] != nil {
            index += 1
            continue
        }
        if let parsed = dotenvAssignment(line), let neu = byKey[parsed.key] {
            if let source = neu.source { out.append(source) }
            out.append(neu.assignment)
            seen.insert(parsed.key)
            index += 1
            continue
        }
        out.append(line)
        index += 1
    }
    while out.last == "" { out.removeLast() }
    for neu in incoming where !seen.contains(neu.key) {
        if let source = neu.source { out.append(source) }
        out.append(neu.assignment)
    }
    return out.joined(separator: "\n") + "\n"
}

func dotenvKeySet(_ text: String) -> Set<String> {
    Set(text.split(separator: "\n").compactMap { dotenvAssignment(String($0))?.key })
}

// TS semantics: user config, project config, then local config; environment
// overrides merge after the bases. Duplicate aliases keep their first-seen
// position (JS object assignment does not reorder keys).
func loadDefinitions(configPath: String? = nil, environment: String = "prod", allowUnknownEnvironment: Bool = false) -> LoadedConfig {
    var definitions: [String: SecretDefinition] = [:]
    var ordered: [(alias: String, definition: SecretDefinition)] = []

    func add(_ alias: String, _ definition: SecretDefinition) {
        if let idx = ordered.firstIndex(where: { $0.alias == alias }) {
            ordered[idx].definition = definition
        } else {
            ordered.append((alias, definition))
        }
        definitions[alias] = definition
    }

    func definition(from value: J) -> SecretDefinition {
        var item = ""
        var field: String?
        var envKey: String?
        var itemType: String?
        var expiresAt: String?
        var tags: [String]?
        for (key, val) in value.pairs() ?? [] {
            switch key {
            case "item": item = val.string() ?? ""
            case "field": field = val.string()
            case "env": envKey = val.string()
            case "type": itemType = val.string()
            case "expiresAt": expiresAt = val.string()
            case "tags": tags = val.items()?.compactMap { $0.string() }
            default: break
            }
        }
        return SecretDefinition(item: item, field: field, envKey: envKey, itemType: itemType, expiresAt: expiresAt, tags: tags)
    }

    func baseSecrets(_ config: J?) -> [(String, J)] { config?.get("secrets")?.pairs() ?? [] }
    func envSecrets(_ config: J?, _ envName: String) -> [(String, J)] {
        config?.get("environments")?.get(envName)?.get("secrets")?.pairs() ?? []
    }

    let user = exists(userConfigPath) ? readConfig(userConfigPath) : nil
    let projectPath = configPath ?? findProjectConfig()
    let project = projectPath.map { readConfig($0) }
    let localPath = findProjectLocalConfig()
    let local = localPath.map { readConfig($0) }

    if environment != "prod" {
        let sources = [user, project, local]
        if !allowUnknownEnvironment && !sources.contains(where: { $0?.get("environments")?.get(environment) != nil }) {
            var available = ["prod"]
            for source in sources {
                for (name, _) in source?.get("environments")?.pairs() ?? [] where !available.contains(name) {
                    available.append(name)
                }
            }
            fail("unknown environment: \(environment) (available: \(available.joined(separator: ", ")))")
        }
    }

    for source in [user, project, local] {
        for (alias, value) in baseSecrets(source) { add(alias, definition(from: value)) }
    }
    if environment != "prod" {
        for source in [user, project, local] {
            for (alias, value) in envSecrets(source, environment) { add(alias, definition(from: value)) }
        }
    }

    for (alias, definition) in ordered where definition.item.isEmpty {
        fail("invalid definition for \(alias)")
    }

    var projectAliases: [String] = projectPath == nil ? [] : baseSecrets(project).map(\.0)
    if projectPath != nil, environment != "prod" {
        projectAliases += envSecrets(project, environment).map(\.0)
    }
    var localAliases: [String] = localPath == nil ? [] : baseSecrets(local).map(\.0)
    if localPath != nil, environment != "prod" {
        localAliases += envSecrets(local, environment).map(\.0)
    }

    var selected: [String]? = nil
    if projectPath != nil || localPath != nil {
        var seen: Set<String> = []
        selected = (projectAliases + localAliases).filter { seen.insert($0).inserted }
    }
    return LoadedConfig(definitions: definitions, ordered: ordered, selectedAliases: selected)
}

func readConfig(_ path: String) -> J {
    guard let raw = readFile(path) else { fail("cannot read config \(path): no such file") }
    // A global config may carry only settings (e.g. {"backend": "..."}), so
    // accept a secrets map, a backend selector, or an empty object.
    guard let parsed = parseJSONOrdered(raw), parsed.isObject,
          parsed.get("secrets")?.isObject == true
              || parsed.get("backend")?.string() != nil
              || (parsed.pairs() ?? []).isEmpty else {
        fail("invalid config: \(path)")
    }
    return parsed
}

func configContainsAlias(_ config: J, _ alias: String) -> Bool {
    if config.get("secrets")?.get(alias) != nil { return true }
    for (_, environment) in config.get("environments")?.pairs() ?? [] {
        if environment.get("secrets")?.get(alias) != nil { return true }
    }
    return false
}

func configWithAlias(
    _ alias: String,
    projectPath: String?,
    localPath: String?
) -> (filePath: String, config: J)? {
    for filePath in [localPath, projectPath].compactMap({ $0 }) {
        let config = readConfig(filePath)
        if configContainsAlias(config, alias) { return (filePath, config) }
    }
    if exists(userConfigPath) {
        let config = readConfig(userConfigPath)
        if configContainsAlias(config, alias) { return (userConfigPath, config) }
    }
    return nil
}

func updateAliasTags(_ alias: String, _ tags: [String], configPath: String, environment: String) {
    var config = readConfig(configPath)
    var updated = false

    func withTags(_ definition: J) -> J {
        let pairs = (definition.pairs() ?? []).filter { $0.0 != "tags" }
        guard !tags.isEmpty else { return .obj(pairs) }
        return .obj(pairs + [("tags", .arr(tags.map { .str($0) }))])
    }

    func updateSecrets(_ value: J) -> J {
        guard let secrets = value.pairs() else { return value }
        return .obj(secrets.map { key, definition in
            guard key == alias else { return (key, definition) }
            updated = true
            return (key, withTags(definition))
        })
    }

    var rootPairs = config.pairs() ?? []
    if environment == "prod" {
        rootPairs = rootPairs.map { key, value in
            key == "secrets" ? (key, updateSecrets(value)) : (key, value)
        }
    } else {
        rootPairs = rootPairs.map { key, value in
            guard key == "environments", let environments = value.pairs() else { return (key, value) }
            let updatedEnvironments = environments.map { name, environmentValue in
                guard name == environment,
                      let environmentPairs = environmentValue.pairs()
                else { return (name, environmentValue) }
                let updatedEnvironment = J.obj(environmentPairs.map { childKey, childValue in
                    childKey == "secrets" ? (childKey, updateSecrets(childValue)) : (childKey, childValue)
                })
                return (name, updatedEnvironment)
            }
            return (key, J.obj(updatedEnvironments))
        }
        if !updated {
            rootPairs = rootPairs.map { key, value in
                key == "secrets" ? (key, updateSecrets(value)) : (key, value)
            }
        }
    }

    guard updated else { fail("alias \(alias) not found in \(configPath)") }
    config = .obj(rootPairs)
    writeAtomic(configPath, jStringify(config) + "\n")
}

func unsetAlias(_ alias: String, _ selectedConfig: String?, quiet: Bool = false) {
    guard let holder = configWithAlias(
        alias,
        projectPath: selectedConfig ?? findProjectConfig(),
        localPath: findProjectLocalConfig()
    ) else {
        fail("alias \(alias) is not in a project, local, or user config (see 'secret print --all')")
    }
    guard let secrets = holder.config.get("secrets")?.pairs() else { return }
    var newSecrets = secrets.filter { $0.0 != alias }
    var environments = holder.config.get("environments")?.pairs() ?? []
    for (index, pair) in environments.enumerated() {
        if let envSecrets = pair.1.get("secrets")?.pairs() {
            let filtered = envSecrets.filter { $0.0 != alias }
            let updated = pair.1
            if let objPairs = updated.pairs() {
                let newEnv = J.obj(objPairs.map { key, value in
                    key == "secrets" ? ("secrets", J.obj(filtered)) : (key, value)
                })
                environments[index] = (pair.0, newEnv)
            }
        }
    }
    var rootPairs = holder.config.pairs() ?? []
    rootPairs = rootPairs.map { key, value in
        switch key {
        case "secrets": return (key, J.obj(newSecrets))
        case "environments": return (key, J.obj(environments))
        default: return (key, value)
        }
    }
    writeAtomic(holder.filePath, jStringify(.obj(rootPairs)) + "\n")
    if !quiet { success("removed \(alias) from \(holder.filePath)") }
}

func moveAlias(_ from: String, _ to: String, _ selectedConfig: String?) {
    if !validAlias(to) {
        fail("invalid alias name: \(to) (letters, digits, underscore, hyphen; must not start with a digit)")
    }
    if from == to { fail("alias is already named \(to)") }
    guard let holder = configWithAlias(
        from,
        projectPath: selectedConfig ?? findProjectConfig(),
        localPath: findProjectLocalConfig()
    ) else {
        fail("alias \(from) is not in a project, local, or user config (see 'secret print --all')")
    }
    if configContainsAlias(holder.config, to) { fail("alias \(to) already exists in \(holder.filePath)") }

    func renamePairs(_ pairs: [(String, J)]?) -> [(String, J)] {
        guard var renamed = pairs else { return [] }
        if let idx = renamed.firstIndex(where: { $0.0 == from }) {
            let value = renamed[idx].1
            renamed.remove(at: idx)
            renamed.append((to, value))
        }
        return renamed
    }

    var rootPairs = holder.config.pairs() ?? []
    rootPairs = rootPairs.map { key, value in
        switch key {
        case "secrets": return (key, J.obj(renamePairs(value.pairs())))
        case "environments":
            let envPairs = value.pairs()?.map { envName, envValue -> (String, J) in
                if let envSecrets = envValue.pairs() {
                    return (envName, J.obj(envSecrets.map { k, v in
                        k == "secrets" ? ("secrets", J.obj(renamePairs(v.pairs()))) : (k, v)
                    }))
                }
                return (envName, envValue)
            }
            return (key, J.obj(envPairs ?? []))
        default: return (key, value)
        }
    }
    writeAtomic(holder.filePath, jStringify(.obj(rootPairs)) + "\n")
    success("renamed \(from) to \(to) in \(holder.filePath)")
}

func findProjectConfig() -> String? {
    var dir = FileManager.default.currentDirectoryPath
    while true {
        let candidate = "\(dir)/\(projectConfigName)"
        if exists(candidate) { return candidate }
        if dir == home || dir == "/" { return nil }
        dir = (dir as NSString).deletingLastPathComponent
    }
}

func findProjectLocalConfig() -> String? {
    var dir = FileManager.default.currentDirectoryPath
    while true {
        let candidate = "\(dir)/\(localConfigName)"
        if exists(candidate) { return candidate }
        if dir == home || dir == "/" { return nil }
        dir = (dir as NSString).deletingLastPathComponent
    }
}

func optionalConfig(_ path: String) -> JSON {
    exists(path) ? readJSONFile(path) : [:]
}

let aliasNamePattern = "^[A-Za-z_][A-Za-z0-9_-]*$"

func validAlias(_ alias: String) -> Bool {
    alias.range(of: aliasNamePattern, options: .regularExpression) != nil
}

func invalidAliasMessage(_ alias: String) -> String {
    "invalid alias name: \(alias) (letters, digits, underscore, hyphen; must not start with a digit)"
}

func kebab(_ alias: String) -> String { alias.lowercased().replacingOccurrences(of: "_", with: "-") }
func scream(_ alias: String) -> String { alias.uppercased().replacingOccurrences(of: "-", with: "_") }

// MARK: - Item helpers

func itemField(_ item: JSON, _ field: String) -> Any? {
    if field == "password" { return (item["login"] as? JSON)?["password"] }
    if field == "username" { return (item["login"] as? JSON)?["username"] }
    if field == "notes" { return item["notes"] }
    let customName = field.hasPrefix("custom:") ? String(field.dropFirst(7)) : field
    if let fields = item["fields"] as? [Any] {
        for case let entry as JSON in fields where entry["name"] as? String == customName {
            return entry["value"]
        }
    }
    return nil
}

func fieldName(_ field: String) -> String {
    field.hasPrefix("custom:") ? String(field.dropFirst(7)) : field
}

func setItemField(_ item: inout JSON, _ field: String, _ value: String) {
    if field == "password" || field == "username" {
        var login = (item["login"] as? JSON) ?? [:]
        login[field] = value
        item["login"] = login
    } else if field == "notes" {
        item["notes"] = value
    } else {
        let name = fieldName(field)
        var fields = (item["fields"] as? [Any]) ?? []
        var found = false
        for (index, entry) in fields.enumerated() {
            if var entry = entry as? JSON, entry["name"] as? String == name {
                entry["value"] = value
                fields[index] = entry
                found = true
                break
            }
        }
        if !found {
            fields.append(["name": name, "value": value, "type": 0])
        }
        item["fields"] = fields
    }
}

func itemTypeCode(_ itemType: String?) -> Int {
    switch itemType?.lowercased() {
    case nil, "", "login": return 1
    case "secure-note", "secure_note", "note": return 2
    default: fail("invalid item type: \(itemType ?? "") (use login or secure-note)")
    }
}

func newItem(name: String, field: String, value: String, itemType: String? = nil) -> JSON {
    var item: JSON = ["type": itemTypeCode(itemType), "name": name]
    if field == "password" || field == "username" {
        item["login"] = [field: value]
    } else if field == "notes" {
        item["notes"] = value
    } else {
        item["fields"] = [["name": fieldName(field), "value": value, "type": 0]]
    }
    return item
}

func addDefinitionToConfig(_ config: J?, alias: String, definition: J, environment: String) -> J {
    var rootPairs = config?.pairs() ?? []
    func replacing(_ pairs: [(String, J)], _ key: String, _ value: J) -> [(String, J)] {
        var found = false
        let updated = pairs.map { pair in
            if pair.0 == key {
                found = true
                return (key, value)
            }
            return pair
        }
        return found ? updated : updated + [(key, value)]
    }

    if environment == "prod" {
        let secrets = config?.get("secrets")?.pairs() ?? []
        rootPairs = replacing(rootPairs, "secrets", .obj(secrets + [(alias, definition)]))
        return .obj(rootPairs)
    }

    let environments = config?.get("environments")?.pairs() ?? []
    let currentEnvironment = config?.get("environments")?.get(environment)
    let secrets = currentEnvironment?.get("secrets")?.pairs() ?? []
    let updatedEnvironment = J.obj(replacing(currentEnvironment?.pairs() ?? [], "secrets", .obj(secrets + [(alias, definition)])))
    let updatedEnvironments = replacing(environments, environment, updatedEnvironment)
    rootPairs = replacing(rootPairs, "environments", .obj(updatedEnvironments))
    return .obj(rootPairs)
}

func itemFor(_ items: [JSON]?, _ item: String) -> JSON? {
    items?.first { $0["id"] as? String == item || $0["name"] as? String == item }
}

func formatCreatedAt(_ iso: String) -> String {
    guard !iso.isEmpty else { return "-" }
    let fractional = ISO8601DateFormatter()
    fractional.formatOptions = [.withInternetDateTime, .withFractionalSeconds]
    let plain = ISO8601DateFormatter()
    guard let d = fractional.date(from: iso) ?? plain.date(from: iso) else { return "-" }
    let f = DateFormatter()
    f.dateFormat = "yyyy-MM-dd HH:mm"
    return f.string(from: d)
}

func itemCreationDate(_ items: [JSON]?, _ item: String) -> String {
    formatCreatedAt(itemFor(items, item)?["creationDate"] as? String ?? "")
}

func valueFor(_ item: JSON?, _ definition: SecretDefinition) -> String? {
    guard let item else { return nil }
    let value = itemField(item, definition.field ?? "password")
    if let value = value as? String, !value.isEmpty, !placeholderValues.contains(value) { return value }
    return nil
}


// MARK: - Output leak scrubbing for `secret run`

/// Streams a child process's stdout/stderr through a filter that replaces
/// every occurrence of known secret values with "[scrubbed]" before anything
/// reaches the terminal. Handles matches split across chunk boundaries by
/// holding back a tail until more data arrives.
final class StreamScrubber {
    private let needles: [Data]
    private var pending = Data()
    private let marker = Data("[scrubbed]".utf8)

    init(secrets: [String]) {
        needles = Set(secrets.filter { !$0.isEmpty })
            .map { Data($0.utf8) }
            .sorted { $0.count > $1.count }
    }

    func scrub(_ chunk: Data) -> Data {
        guard !needles.isEmpty else { return chunk }
        pending.append(chunk)
        var out = Data()
        while true {
            // find earliest match across needles (longest-first ordering
            // breaks ties at the same position)
            var hitStart = -1
            var hitEnd = -1
            for needle in needles {
                if let range = pending.range(of: needle) {
                    if hitStart == -1 || range.lowerBound < hitStart
                        || (range.lowerBound == hitStart && needle.count > hitEnd - hitStart) {
                        hitStart = range.lowerBound
                        hitEnd = range.upperBound
                    }
                }
            }
            guard hitStart != -1 else { break }
            out.append(pending.prefix(hitStart))
            out.append(marker)
            pending.removeFirst(hitEnd)
        }
        let holdback = (needles.map { $0.count }.max() ?? 1) - 1
        if pending.count > holdback {
            out.append(pending.prefix(pending.count - holdback))
            pending.removeFirst(pending.count - holdback)
        }
        return out
    }

    func flush() -> Data {
        var out = pending
        pending.removeAll()
        var final = Data()
        while true {
            var hitStart = -1
            var hitEnd = -1
            for needle in needles {
                if let range = out.range(of: needle) {
                    if hitStart == -1 || range.lowerBound < hitStart {
                        hitStart = range.lowerBound
                        hitEnd = range.upperBound
                    }
                }
            }
            guard hitStart != -1 else { break }
            final.append(out.prefix(hitStart))
            final.append(marker)
            out.removeFirst(hitEnd)
        }
        final.append(out)
        return final
    }
}

/// Like runCommandPassthrough, but child stdout/stderr are filtered so secret
/// values never appear in terminal output or logs.
func runCommandScrubbed(
    _ executable: String,
    _ args: [String],
    env: [String: String],
    secrets: [(key: String, value: String)]
) -> Int32 {
    let process = Process()
    process.executableURL = URL(fileURLWithPath: executable)
    process.arguments = args
    process.environment = env

    let outPipe = Pipe()
    let errPipe = Pipe()
    process.standardOutput = outPipe
    process.standardError = errPipe
    process.standardInput = FileHandle.nullDevice

    do {
        try process.run()
    } catch {
        writeErr("secret run: could not launch \(executable): \(error.localizedDescription)\n")
        return 127
    }

    let stdoutScrubber = StreamScrubber(secrets: secrets.map { $0.value })
    let stderrScrubber = StreamScrubber(secrets: secrets.map { $0.value })

    let drainGroup = DispatchGroup()

    func pump(_ handle: FileHandle, _ scrubber: StreamScrubber, to target: FileHandle) {
        drainGroup.enter()
        handle.readabilityHandler = { h in
            let data = h.availableData
            if data.isEmpty {
                h.readabilityHandler = nil
                target.write(scrubber.flush())
                drainGroup.leave()
                return
            }
            target.write(scrubber.scrub(data))
        }
    }
    pump(outPipe.fileHandleForReading, stdoutScrubber, to: FileHandle.standardOutput)
    pump(errPipe.fileHandleForReading, stderrScrubber, to: FileHandle.standardError)

    process.waitUntilExit()
    // Wait for both streams to hit EOF and flush, otherwise short-lived
    // commands can exit before their filtered output reaches the terminal.
    _ = drainGroup.wait(timeout: .now() + 10)
    return process.terminationStatus
}

