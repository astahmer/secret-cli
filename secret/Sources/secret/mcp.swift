import Foundation
#if canImport(Darwin)
import Darwin
#elseif canImport(Glibc)
import Glibc
#endif

// MARK: - MCP server (stdio, JSON-RPC 2.0, newline-delimited)

/// `secret mcp` exposes secret *metadata* and env-injected execution to agents
/// over the Model Context Protocol. It never returns a secret value: reads are
/// metadata-only, and command output is scrubbed before it leaves the process.
let mcpDefaultProtocolVersion = "2024-11-05"
let mcpMaxOutputBytes = 512 * 1024
let mcpDefaultTimeout = 60.0
let mcpMaximumTimeout = 300.0

func mcpSend(_ payload: J) {
    let line = jStringify(payload, pretty: false) + "\n"
    // Tool calls answer concurrently, so a whole line is written under one lock
    // to keep frames from interleaving.
    mcpWriteLock.lock()
    defer { mcpWriteLock.unlock() }
    FileHandle.standardOutput.write(Data(line.utf8))
}

private let mcpWriteLock = NSLock()

/// How many tool calls may run at once. `secret_run` spawns a child, so this is
/// a process budget, not a thread count.
let mcpMaxConcurrentCalls = 8

/// Vault items change rarely and every check/run needs the same metadata. A
/// one-second cache turns a fan-out of tool calls into one vault read; a changed
/// value is still picked up on the next call after the window.
let mcpItemsTTL: TimeInterval = 1.0
private let mcpItemsLock = NSLock()
private var mcpItemsCached: (items: [JSON]?, at: Date)?

func mcpVaultItems() async -> [JSON]? {
    mcpItemsLock.lock()
    let cached = mcpItemsCached
    mcpItemsLock.unlock()
    if let cached, Date().timeIntervalSince(cached.at) < mcpItemsTTL { return cached.items }
    let items = await vaultBackend.items()
    mcpItemsLock.lock()
    mcpItemsCached = (items, Date())
    mcpItemsLock.unlock()
    return items
}

func mcpResponse(id: J?, result: J) {
    mcpSend(.obj([("jsonrpc", .str("2.0")), ("id", id ?? .null), ("result", result)]))
}

func mcpFailure(id: J?, code: Double, message: String) {
    mcpSend(.obj([
        ("jsonrpc", .str("2.0")),
        ("id", id ?? .null),
        ("error", .obj([("code", .num(code)), ("message", .str(message))])),
    ]))
}

func mcpText(_ text: String, isError: Bool = false) -> J {
    var pairs: [(String, J)] = [
        ("content", .arr([.obj([("type", .str("text")), ("text", .str(text))])])),
    ]
    if isError { pairs.append(("isError", .bool(true))) }
    return .obj(pairs)
}

func mcpArgString(_ args: J?, _ key: String) -> String? {
    guard let value = args?.get(key)?.string(), !value.isEmpty else { return nil }
    return value
}

func mcpArgStrings(_ args: J?, _ key: String) -> [String]? {
    args?.get(key)?.items()?.compactMap { $0.string() }
}

// MARK: - Captured, scrubbed child run

final class MCPOutputBuffer {
    private let lock = NSLock()
    private var data = Data()
    private let limit: Int
    private var didTruncate = false

    init(limit: Int) { self.limit = limit }

    func append(_ chunk: Data) {
        lock.lock()
        defer { lock.unlock() }
        guard data.count < limit else {
            didTruncate = true
            return
        }
        let room = limit - data.count
        if chunk.count > room { didTruncate = true }
        data.append(chunk.prefix(room))
    }

    func text() -> String {
        lock.lock()
        defer { lock.unlock() }
        return String(data: data, encoding: .utf8) ?? ""
    }

    func truncated() -> Bool {
        lock.lock()
        defer { lock.unlock() }
        return didTruncate
    }
}

struct MCPRunOutcome {
    var status: Int32
    var stdout: String
    var stderr: String
    var timedOut: Bool
}

func mcpRunCaptured(
    _ executable: String,
    _ args: [String],
    environment: [String: String],
    secrets: [String],
    timeout: Double
) -> MCPRunOutcome {
    var outFDs: [Int32] = [0, 0]
    var errFDs: [Int32] = [0, 0]
    guard pipe(&outFDs) == 0, pipe(&errFDs) == 0 else {
        return MCPRunOutcome(status: 127, stdout: "", stderr: "could not create pipes", timedOut: false)
    }
    // The Bitwarden CLI path uses posix_spawn; Foundation.Process pays extra
    // setup and showed up as per-call latency under concurrent tool calls.
    // stdin must never be the server's protocol stream.
    let nullFD = open("/dev/null", O_RDONLY)
    guard let pid = posixSpawnChild(
        executable,
        args,
        env: environment,
        stdinFD: nullFD,
        stdoutFD: outFDs[1],
        stderrFD: errFDs[1]
    ) else {
        close(nullFD)
        close(outFDs[0])
        close(outFDs[1])
        close(errFDs[0])
        close(errFDs[1])
        return MCPRunOutcome(status: 127, stdout: "", stderr: "could not launch \(executable)", timedOut: false)
    }
    close(outFDs[1])
    close(errFDs[1])
    close(nullFD)

    let outBuffer = MCPOutputBuffer(limit: mcpMaxOutputBytes)
    let errBuffer = MCPOutputBuffer(limit: mcpMaxOutputBytes)
    let outScrubber = StreamScrubber(secrets: secrets)
    let errScrubber = StreamScrubber(secrets: secrets)
    let drainGroup = DispatchGroup()
    // A raw FileHandle wrapped around a descriptor is not retained by the
    // handler; keep it alive until the stream drains, or its deinit closes the
    // fd before anything is read.
    var handles: [FileHandle] = []

    func pump(_ descriptor: Int32, _ scrubber: StreamScrubber, _ buffer: MCPOutputBuffer) {
        let handle = FileHandle(fileDescriptor: descriptor, closeOnDealloc: true)
        handles.append(handle)
        drainGroup.enter()
        handle.readabilityHandler = { reader in
            let chunk = reader.availableData
            if chunk.isEmpty {
                reader.readabilityHandler = nil
                buffer.append(scrubber.flush())
                drainGroup.leave()
            } else {
                buffer.append(scrubber.scrub(chunk))
            }
        }
    }
    pump(outFDs[0], outScrubber, outBuffer)
    pump(errFDs[0], errScrubber, errBuffer)

    var status: Int32 = 0
    let waitGroup = DispatchGroup()
    waitGroup.enter()
    DispatchQueue.global(qos: .userInitiated).async {
        waitpid(pid, &status, 0)
        waitGroup.leave()
    }
    var timedOut = false
    if waitGroup.wait(timeout: .now() + timeout) == .timedOut {
        timedOut = true
        kill(pid, SIGTERM)
        if waitGroup.wait(timeout: .now() + 5) == .timedOut {
            kill(pid, SIGKILL)
            _ = waitGroup.wait(timeout: .now() + 2)
        }
    }
    _ = drainGroup.wait(timeout: .now() + 5)
    for handle in handles { handle.readabilityHandler = nil }
    handles.removeAll()
    return MCPRunOutcome(
        status: exitStatus(status),
        stdout: outBuffer.text(),
        stderr: errBuffer.text(),
        timedOut: timedOut
    )
}

// MARK: - Config access

/// Load config without letting a malformed file kill the long-lived server.
func mcpLoad(configPath: String?, environment: String) -> LoadedConfig? {
    func readableJSON(_ path: String) -> Bool {
        guard exists(path) else { return true }
        guard let raw = readFile(path) else { return false }
        return parseJSONOrdered(raw) != nil
    }
    if let configPath, !exists(configPath) { return nil }
    if !readableJSON(userConfigPath) { return nil }
    if let configPath, !readableJSON(configPath) { return nil }
    if let project = findProjectConfig(), !readableJSON(project) { return nil }
    if let local = findProjectLocalConfig(), !readableJSON(local) { return nil }
    return loadDefinitions(configPath: configPath, environment: environment, allowUnknownEnvironment: true)
}

func mcpEnvironment(_ args: J?) -> String {
    mcpArgString(args, "env") ?? "prod"
}

// MARK: - Tools

func mcpToolsList() -> J {
    let tools: [J] = [
        .obj([
            ("name", .str("secret_list")),
            ("description", .str("List configured aliases with metadata only (item, field, env key, expiry). Never returns values.")),
            ("inputSchema", .obj([
                ("type", .str("object")),
                ("properties", .obj([
                    ("env", .obj([("type", .str("string")), ("description", .str("Environment name (default prod)."))])),
                    ("configPath", .obj([("type", .str("string")), ("description", .str("Path to a .secret.json instead of auto-detection."))])),
                ])),
                ("additionalProperties", .bool(false)),
            ])),
        ]),
        .obj([
            ("name", .str("secret_check")),
            ("description", .str("Check whether one alias resolves without returning its value. Reports item, field, env key, expiry and availability.")),
            ("inputSchema", .obj([
                ("type", .str("object")),
                ("properties", .obj([
                    ("alias", .obj([("type", .str("string")), ("description", .str("Alias to check."))])),
                    ("env", .obj([("type", .str("string")), ("description", .str("Environment name (default prod)."))])),
                    ("configPath", .obj([("type", .str("string")), ("description", .str("Path to a .secret.json instead of auto-detection."))])),
                ])),
                ("required", .arr([.str("alias")])),
                ("additionalProperties", .bool(false)),
            ])),
        ]),
        .obj([
            ("name", .str("secret_status")),
            ("description", .str("Report the configured backend and whether the vault is authenticated and unlocked. No secrets.")),
            ("inputSchema", .obj([
                ("type", .str("object")),
                ("properties", .obj([])),
                ("additionalProperties", .bool(false)),
            ])),
        ]),
        .obj([
            ("name", .str("secret_run")),
            ("description", .str("Run a command with the project's aliases injected as environment variables. Values are never returned: exact value bytes in stdout/stderr are replaced with [scrubbed]. Use this instead of reading secrets.")),
            ("inputSchema", .obj([
                ("type", .str("object")),
                ("properties", .obj([
                    ("command", .obj([
                        ("oneOf", .arr([
                            .obj([
                                ("type", .str("array")),
                                ("items", .obj([("type", .str("string"))])),
                                ("minItems", .num(1)),
                            ]),
                            .obj([("type", .str("string"))]),
                        ])),
                        ("description", .str("Command as argv, e.g. [\"npm\", \"test\"]. A plain string runs through /bin/sh -lc.")),
                    ])),
                    ("cwd", .obj([("type", .str("string")), ("description", .str("Working directory (default: server cwd)."))])),
                    ("env", .obj([("type", .str("string")), ("description", .str("Environment name (default prod)."))])),
                    ("configPath", .obj([("type", .str("string")), ("description", .str("Path to a .secret.json instead of auto-detection."))])),
                    ("timeoutSeconds", .obj([("type", .str("number")), ("description", .str("Maximum run time in seconds (default 60, max 300)."))])),
                ])),
                ("required", .arr([.str("command")])),
                ("additionalProperties", .bool(false)),
            ])),
        ]),
    ]
    return .obj([("tools", .arr(tools))])
}

func mcpCallList(_ args: J?) async -> J {
    let envName = mcpEnvironment(args)
    guard let loaded = mcpLoad(configPath: mcpArgString(args, "configPath"), environment: envName) else {
        return mcpText("invalid or unreadable secret config", isError: true)
    }
    let aliases = loaded.ordered.map { alias, definition -> J in
        .obj([
            ("alias", .str(alias)),
            ("item", .str(definition.item)),
            ("field", .str(definition.field ?? "password")),
            ("envKey", .str(definition.envKey ?? alias)),
            ("expiresAt", .str(definition.expiresAt ?? "")),
            ("tags", .arr((definition.tags ?? []).map { .str($0) })),
        ])
    }
    let payload: J = .obj([
        ("environment", .str(envName)),
        ("count", .num(Double(aliases.count))),
        ("aliases", .arr(aliases)),
        ("note", .str("Metadata only. Use secret_run to inject values; values are never returned.")),
    ])
    return mcpText(jStringify(payload, pretty: false))
}

func mcpCallCheck(_ args: J?) async -> J {
    guard let alias = mcpArgString(args, "alias") else {
        return mcpText("secret_check requires alias", isError: true)
    }
    let envName = mcpEnvironment(args)
    guard let loaded = mcpLoad(configPath: mcpArgString(args, "configPath"), environment: envName) else {
        return mcpText("invalid or unreadable secret config", isError: true)
    }
    guard let definition = loaded.definitions[alias] else {
        return mcpText("unknown alias: \(alias) (\(loaded.ordered.count) declared aliases; call secret_list)", isError: true)
    }
    let items = await mcpVaultItems()
    let available = resolveOptional(items, definition) != nil
    var expired = false
    if let expiresAt = definition.expiresAt, let date = parseExpiry(expiresAt) {
        expired = date < Date()
    }
    let payload: J = .obj([
        ("alias", .str(alias)),
        ("available", .bool(available)),
        ("item", .str(definition.item)),
        ("field", .str(definition.field ?? "password")),
        ("envKey", .str(definition.envKey ?? alias)),
        ("expiresAt", .str(definition.expiresAt ?? "")),
        ("expired", .bool(expired)),
        ("note", .str("Availability only; the value is not returned.")),
    ])
    return mcpText(jStringify(payload, pretty: false), isError: !available)
}

func mcpCallStatus() async -> J {
    let state = await vaultBackend.authState()
    let daemon = await vaultBackend.daemonSummary()
    let payload: J = .obj([
        ("version", .str(secretVersion)),
        ("backend", .str(vaultBackend.id)),
        ("backendLabel", .str(vaultBackend.displayName)),
        ("authenticated", .bool(state.authenticated)),
        ("unlocked", .bool(state.unlocked)),
        ("daemon", .str(daemon)),
        ("auditLog", .str(auditPath)),
    ])
    return mcpText(jStringify(payload, pretty: false))
}

func mcpCallRun(_ args: J?) async -> J {
    var command = mcpArgStrings(args, "command") ?? []
    if command.isEmpty, let single = mcpArgString(args, "command") {
        command = ["/bin/sh", "-lc", single]
    }
    guard !command.isEmpty else {
        return mcpText("secret_run requires command: [string] (or a string run through /bin/sh -lc)", isError: true)
    }
    let envName = mcpEnvironment(args)
    let configPath = mcpArgString(args, "configPath")
    let timeout = min(mcpMaximumTimeout, max(1, args?.get("timeoutSeconds")?.asDouble ?? mcpDefaultTimeout))

    let previousDirectory = FileManager.default.currentDirectoryPath
    defer { _ = FileManager.default.changeCurrentDirectoryPath(previousDirectory) }
    if let cwd = mcpArgString(args, "cwd") {
        var isDirectory: ObjCBool = false
        guard FileManager.default.fileExists(atPath: cwd, isDirectory: &isDirectory), isDirectory.boolValue else {
            return mcpText("cwd is not a directory: \(cwd)", isError: true)
        }
        guard FileManager.default.changeCurrentDirectoryPath(cwd) else {
            return mcpText("could not enter cwd: \(cwd)", isError: true)
        }
    }

    guard let loaded = mcpLoad(configPath: configPath, environment: envName) else {
        return mcpText("invalid or unreadable secret config", isError: true)
    }
    guard let selected = loaded.selectedAliases, !selected.isEmpty else {
        return mcpText("no project config (.secret.json) found in \(FileManager.default.currentDirectoryPath) — pass configPath", isError: true)
    }

    let items = await mcpVaultItems()
    var environment = ProcessInfo.processInfo.environment
    var secrets: [String] = []
    var injected: [String] = []
    var unresolved: [String] = []
    for alias in selected {
        guard let definition = loaded.definitions[alias] else { continue }
        guard let value = resolveOptional(items, definition) else {
            unresolved.append(alias)
            continue
        }
        let key = definition.envKey ?? alias
        guard key.range(of: "^[A-Za-z_][A-Za-z0-9_]*$", options: .regularExpression) != nil else {
            unresolved.append(alias)
            continue
        }
        environment[key] = value
        secrets.append(value)
        injected.append(alias)
    }
    guard unresolved.isEmpty else {
        return mcpText("unresolved alias(es): \(unresolved.joined(separator: ", ")) — unlock the vault or fix the config; nothing was executed", isError: true)
    }

    let executable = command[0].contains("/") ? command[0] : (pathTo(command[0]) ?? command[0])
    // mcpRunCaptured blocks on a child process; run it off the cooperative pool
    // so concurrent tool calls keep their own threads instead of starving.
    let outcome = await withCheckedContinuation { (continuation: CheckedContinuation<MCPRunOutcome, Never>) in
        DispatchQueue.global(qos: .userInitiated).async {
            continuation.resume(
                returning: mcpRunCaptured(
                    executable,
                    Array(command.dropFirst()),
                    environment: environment,
                    secrets: secrets,
                    timeout: timeout
                )
            )
        }
    }
    auditWrite(
        outcome: outcome.timedOut || outcome.status != 0 ? "error" : "ok",
        error: outcome.timedOut ? "timeout after \(Int(timeout))s" : nil,
        command: "mcp:run",
        target: (command[0] as NSString).lastPathComponent,
        environment: envName
    )
    let truncated = outcome.stdout.count >= mcpMaxOutputBytes || outcome.stderr.count >= mcpMaxOutputBytes
    let payload: J = .obj([
        ("exitCode", .num(Double(outcome.status))),
        ("timedOut", .bool(outcome.timedOut)),
        ("stdout", .str(outcome.stdout)),
        ("stderr", .str(outcome.stderr)),
        ("truncated", .bool(truncated)),
        ("injectedAliases", .arr(injected.map { .str($0) })),
        ("note", .str("Values were injected into the child environment; their exact bytes are replaced with [scrubbed]. No value is returned.")),
    ])
    return mcpText(jStringify(payload, pretty: false), isError: outcome.status != 0 || outcome.timedOut)
}

func mcpToolCall(_ params: J?) async -> J {
    guard let name = params?.get("name")?.string() else {
        return mcpText("tools/call requires a tool name", isError: true)
    }
    let args = params?.get("arguments")
    switch name {
    case "secret_list":
        return await mcpCallList(args)
    case "secret_check":
        return await mcpCallCheck(args)
    case "secret_status":
        return await mcpCallStatus()
    case "secret_run":
        return await mcpCallRun(args)
    default:
        return mcpText("unknown tool: \(name)", isError: true)
    }
}

// MARK: - Server loop

func mcpInitializeResult(_ params: J?) -> J {
    let version = params?.get("protocolVersion")?.string() ?? mcpDefaultProtocolVersion
    let instructions = """
    Secret values are never returned by this server. Use secret_run to run a command with values \
    injected as environment variables; its stdout/stderr are scrubbed. secret_list and secret_check \
    expose metadata only. Reads through the CLI (`secret get`) belong to humans, not agents.
    """
    return .obj([
        ("protocolVersion", .str(version)),
        ("capabilities", .obj([("tools", .obj([("listChanged", .bool(false))]))])),
        ("serverInfo", .obj([("name", .str("secret")), ("version", .str(secretVersion))])),
        ("instructions", .str(instructions)),
    ])
}

func runMCPServer() async -> Never {
    auditContext.command = "mcp"
    auditContext.source = "mcp"
    auditContext.caller = resolvedCaller(nil)
    let inFlight = DispatchGroup()
    let budget = DispatchSemaphore(value: mcpMaxConcurrentCalls)
    while let line = readLine(strippingNewline: true) {
        let trimmed = line.trimmingCharacters(in: .whitespacesAndNewlines)
        if trimmed.isEmpty { continue }
        guard let message = parseJSONOrdered(trimmed), message.isObject else {
            mcpFailure(id: nil, code: -32700, message: "parse error")
            continue
        }
        let id = message.get("id")
        let method = message.get("method")?.string() ?? ""
        let params = message.get("params")
        switch method {
        case "initialize":
            mcpResponse(id: id, result: mcpInitializeResult(params))
        case "notifications/initialized", "notifications/cancelled":
            continue
        case "ping":
            mcpResponse(id: id, result: .obj([]))
        case "tools/list":
            mcpResponse(id: id, result: mcpToolsList())
        case "tools/call":
            // A slow tool (a child process, a vault read) must not block the
            // next call: an agent fanning out runs would otherwise serialize.
            budget.wait()
            inFlight.enter()
            Task {
                let result = await mcpToolCall(params)
                mcpResponse(id: id, result: result)
                inFlight.leave()
                budget.signal()
            }
        case "shutdown":
            inFlight.wait()
            mcpResponse(id: id, result: .obj([]))
            exit(0)
        default:
            mcpFailure(id: id, code: -32601, message: "method not found: \(method)")
        }
    }
    // Let queued calls finish before the process exits, so a client that closes
    // stdin still gets its answers.
    inFlight.wait()
    exit(0)
}
