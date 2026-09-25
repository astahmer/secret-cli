import AppKit
import Foundation
import LocalAuthentication
import Security
import SwiftUI
import UniformTypeIdentifiers

// SecretBar is a deliberately value-minimizing UI around the `secret` CLI.
// Normal copy operations stay in the CLI process and write directly to the
// clipboard. Values enter this process only when the user enables hold-to-
// reveal and actively holds on a row.

// MARK: - Process helpers

struct RunResult {
    var status: Int32
    var stdout: String
    var stderr: String
}

func homeDirectory() -> String {
    ProcessInfo.processInfo.environment["HOME"] ?? NSHomeDirectory()
}

func secretBin() -> String {
    let home = homeDirectory()
    let candidates = [
        "\(home)/.nix-profile/bin/secret",
        "/usr/local/bin/secret",
        "/opt/homebrew/bin/secret",
    ]
    for candidate in candidates where FileManager.default.isExecutableFile(atPath: candidate) {
        return candidate
    }
    return "secret"
}

func toolBin(_ name: String) -> String {
    let home = homeDirectory()
    let candidates = [
        "\(home)/.nix-profile/bin/\(name)",
        "/opt/homebrew/bin/\(name)",
        "/usr/local/bin/\(name)",
        "/usr/bin/\(name)",
    ]
    for candidate in candidates where FileManager.default.isExecutableFile(atPath: candidate) {
        return candidate
    }
    return name
}

func runProcess(
    executable: String,
    arguments: [String],
    cwd: String? = nil,
    input: String? = nil,
    timeout: TimeInterval = 45,
    extraEnvironment: [String: String] = [:]
) -> RunResult {
    let process = Process()
    process.executableURL = URL(fileURLWithPath: executable)
    process.arguments = arguments
    if let cwd {
        process.currentDirectoryURL = URL(fileURLWithPath: cwd)
    }

    var environment = ProcessInfo.processInfo.environment
    let home = homeDirectory()
    environment["HOME"] = home
    environment["PATH"] = "\(home)/.nix-profile/bin:/opt/homebrew/bin:/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin"
    for (key, value) in extraEnvironment {
        environment[key] = value
    }
    process.environment = environment

    let output = Pipe()
    let error = Pipe()
    process.standardOutput = output
    process.standardError = error
    if let input {
        let inputPipe = Pipe()
        process.standardInput = inputPipe
        DispatchQueue.global().async {
            try? inputPipe.fileHandleForWriting.write(contentsOf: Data((input + "\n").utf8))
            try? inputPipe.fileHandleForWriting.close()
        }
    } else {
        process.standardInput = FileHandle.nullDevice
    }

    do {
        try process.run()
    } catch {
        return RunResult(status: 127, stdout: "", stderr: String(describing: error))
    }

    let semaphore = DispatchSemaphore(value: 0)
    DispatchQueue.global().async {
        process.waitUntilExit()
        semaphore.signal()
    }
    if semaphore.wait(timeout: .now() + timeout) == .timedOut {
        process.terminate()
        return RunResult(status: 124, stdout: "", stderr: "timed out")
    }

    let stdout = (try? output.fileHandleForReading.readToEnd()).flatMap { String(data: $0, encoding: .utf8) } ?? ""
    let stderr = (try? error.fileHandleForReading.readToEnd()).flatMap { String(data: $0, encoding: .utf8) } ?? ""
    return RunResult(status: process.terminationStatus, stdout: stdout, stderr: stderr)
}

func runSecret(
    _ arguments: [String],
    cwd: String? = nil,
    input: String? = nil,
    timeout: TimeInterval = 45,
    allowBiometrics: Bool = false
) -> RunResult {
    // SECRET_BIOMETRIC_UNLOCK lets the CLI fall back to the Touch ID-gated
    // session cache when no stored session resolves. Only set on user-
    // initiated actions so background timers never trigger a prompt.
    runProcess(
        executable: secretBin(),
        arguments: arguments,
        cwd: cwd,
        input: input,
        timeout: timeout,
        extraEnvironment: allowBiometrics ? ["SECRET_BIOMETRIC_UNLOCK": "1"] : [:]
    )
}

func runTool(
    _ name: String,
    _ arguments: [String],
    input: String? = nil,
    timeout: TimeInterval = 45
) -> RunResult {
    runProcess(executable: toolBin(name), arguments: arguments, input: input, timeout: timeout)
}

func copyText(_ value: String) -> Bool {
    let result = runProcess(executable: "/usr/bin/pbcopy", arguments: [], input: value, timeout: 5)
    return result.status == 0
}

func openPath(_ path: String) {
    NSWorkspace.shared.open(URL(fileURLWithPath: path))
}

func openTerminal() {
    let terminal = "/System/Applications/Utilities/Terminal.app"
    openPath(FileManager.default.fileExists(atPath: terminal) ? terminal : "/Applications/Utilities/Terminal.app")
}

// MARK: - Models

struct Project: Identifiable, Hashable {
    let name: String
    let dir: String

    var id: String { dir }
    var isGlobal: Bool { name == "global" }
    var configPath: String {
        isGlobal ? "\(dir)/.config/secret/config.json" : "\(dir)/.secret.json"
    }
}

enum SecretItemType: String, CaseIterable, Identifiable {
    case login
    case secureNote = "secure-note"

    var id: String { rawValue }
    var title: String {
        switch self {
        case .login: return "Login / secret"
        case .secureNote: return "Secure Note"
        }
    }
    var field: String {
        switch self {
        case .login: return "password"
        case .secureNote: return "notes"
        }
    }

    var icon: String {
        switch self {
        case .login: return "key.fill"
        case .secureNote: return "doc.text.fill"
        }
    }

    var shortDescription: String {
        switch self {
        case .login: return "Passwords, API keys, tokens, or usernames"
        case .secureNote: return "SSH keys, recovery codes, certificates, or multiline text"
        }
    }

    var guidance: String {
        switch self {
        case .login:
            return "Use Login for one primary credential. Value is what SecretBar copies or injects. Notes are optional context, not the credential itself."
        case .secureNote:
            return "Use Secure Note for multiline sensitive material. Its encrypted Notes field becomes the secret value."
        }
    }
}

struct AliasEntry: Identifiable, Hashable {
    let alias: String
    let project: String
    let configPath: String
    let cwd: String
    let item: String
    let environment: String
    let field: String
    let itemType: String
    let envKey: String
    let tags: [String]
    let expiresAt: String?

    var id: String { "\(project):\(environment):\(alias)" }
    var itemTypeTitle: String { itemType == SecretItemType.secureNote.rawValue ? "Secure Note" : "Login" }
}

struct ImportCandidate: Identifiable {
    let alias: String
    let value: String
    var id: String { alias }
}

struct UsageEntry: Identifiable, Hashable {
    let id: String
    let at: String
    let command: String
    let target: String
    let environment: String
}

struct SecretDiagnostic: Identifiable {
    let id = UUID()
    let title: String
    let message: String
    let recoveryCommand: String?
    let canRepairBitwarden: Bool
}

struct RemoteEntryMetadata: Hashable {
    let status: String
    let itemName: String?
    let source: String?
    let hasTOTP: Bool

    var isUsable: Bool { status == "ok" }
}

enum VaultState {
    case unknown
    case unlocked
    case locked
    case unauthenticated
    case error
}

enum SecretBarTab: String, CaseIterable, Identifiable {
    case create
    case secrets
    case settings

    var id: String { rawValue }
    var title: String {
        switch self {
        case .create: return "Create"
        case .secrets: return "My Secrets"
        case .settings: return "Settings"
        }
    }

    var icon: String {
        switch self {
        case .create: return "plus"
        case .secrets: return "square.stack.3d.up.fill"
        case .settings: return "gearshape.fill"
        }
    }
}

private enum PreferenceKey {
    static let pinnedIDs = "secretbar.pinnedIDs"
    static let pinsEnabled = "secretbar.pinsEnabled"
    static let shortcutsEnabled = "secretbar.shortcutsEnabled"
    static let autoDetectProject = "secretbar.autoDetectProject"
    static let holdToReveal = "secretbar.holdToReveal"
    static let clipboardClearSeconds = "secretbar.clipboardClearSeconds"
    static let expiryWarningDays = "secretbar.expiryWarningDays"
    static let showInMenuBar = "secretbar.showInMenuBar"
    static let showMainWindow = "secretbar.showMainWindow"
}

// MARK: - Model

@MainActor
final class SecretBarModel: ObservableObject {
    static let shared = SecretBarModel()

    @Published var state: VaultState = .unknown
    @Published var projects: [Project] = []
    @Published var entries: [AliasEntry] = []
    @Published var recent: [AliasEntry] = []
    @Published var history: [UsageEntry] = []
    @Published var problems: [String: Int] = [:]
    @Published var problemDetails: [String: [String]] = [:]
    @Published var sessionCreated: String?
    @Published var detectedProjectID: String?
    @Published var contextPath: String?
    @Published var busy = false
    @Published var flash: String?
    @Published var lastError: String?
    @Published var diagnostic: SecretDiagnostic?
    @Published var importCandidates: [ImportCandidate] = []
    @Published var importProject: Project?
    @Published var importEnvironment = "prod"
    @Published var remoteMetadata: [String: RemoteEntryMetadata] = [:]
    /// True when a biometric session cache file exists; Touch ID unlock
    /// needs it seeded by one master-password unlock.
    @Published var biometricCacheAvailable = false
    @Published var remoteValidationComplete = false
    @Published var revealingID: String?
    @Published var revealedValue = ""
    @Published var remoteValidationInProgress = false
    @Published var healthCheckStatus: String?
    @Published var revealError: String?

    @Published var pinnedIDs: Set<String> = Set(UserDefaults.standard.stringArray(forKey: PreferenceKey.pinnedIDs) ?? []) {
        didSet { UserDefaults.standard.set(Array(pinnedIDs).sorted(), forKey: PreferenceKey.pinnedIDs) }
    }
    @Published var pinsEnabled: Bool = SecretBarModel.preferenceBool(PreferenceKey.pinsEnabled, defaultValue: true) {
        didSet { UserDefaults.standard.set(pinsEnabled, forKey: PreferenceKey.pinsEnabled) }
    }
    @Published var shortcutsEnabled: Bool = SecretBarModel.preferenceBool(PreferenceKey.shortcutsEnabled, defaultValue: true) {
        didSet { UserDefaults.standard.set(shortcutsEnabled, forKey: PreferenceKey.shortcutsEnabled) }
    }
    @Published var autoDetectProject: Bool = SecretBarModel.preferenceBool(PreferenceKey.autoDetectProject, defaultValue: true) {
        didSet {
            UserDefaults.standard.set(autoDetectProject, forKey: PreferenceKey.autoDetectProject)
            refreshDetectedProject()
        }
    }
    @Published var holdToReveal: Bool = SecretBarModel.preferenceBool(PreferenceKey.holdToReveal, defaultValue: false) {
        didSet { UserDefaults.standard.set(holdToReveal, forKey: PreferenceKey.holdToReveal) }
    }
    @Published var clipboardClearSeconds: Int = UserDefaults.standard.integer(forKey: PreferenceKey.clipboardClearSeconds) {
        didSet { UserDefaults.standard.set(clipboardClearSeconds, forKey: PreferenceKey.clipboardClearSeconds) }
    }
    @Published var expiryWarningDays: Int = {
        let value = UserDefaults.standard.integer(forKey: PreferenceKey.expiryWarningDays)
        return value == 0 ? 14 : value
    }() {
        didSet { UserDefaults.standard.set(expiryWarningDays, forKey: PreferenceKey.expiryWarningDays) }
    }
    @Published var showInMenuBar: Bool = SecretBarModel.preferenceBool(PreferenceKey.showInMenuBar, defaultValue: true) {
        didSet { UserDefaults.standard.set(showInMenuBar, forKey: PreferenceKey.showInMenuBar) }
    }
    @Published var showMainWindow: Bool = SecretBarModel.preferenceBool(PreferenceKey.showMainWindow, defaultValue: false) {
        didSet { UserDefaults.standard.set(showMainWindow, forKey: PreferenceKey.showMainWindow) }
    }

    private var statusTimer: Timer?
    private var healthTimer: Timer?
    private var flashTask: Task<Void, Never>?
    private var clipboardTask: Task<Void, Never>?
    private var lastUsedByKey: [String: String] = [:]

    private static func preferenceBool(_ key: String, defaultValue: Bool) -> Bool {
        guard UserDefaults.standard.object(forKey: key) != nil else { return defaultValue }
        return UserDefaults.standard.bool(forKey: key)
    }

    func start() {
        refreshEverything()
        guard statusTimer == nil else { return }
        statusTimer = Timer.scheduledTimer(withTimeInterval: 30, repeats: true) { [weak self] _ in
            guard let self else { return }
            Task { @MainActor in
                self.refreshStatus()
                self.refreshIndex()
                self.refreshHistory()
            }
        }
        healthTimer = Timer.scheduledTimer(withTimeInterval: 600, repeats: true) { [weak self] _ in
            guard let self else { return }
            Task { @MainActor in self.refreshHealth() }
        }
    }

    func refreshEverything() {
        setBusy(true)
        Task.detached(priority: .userInitiated) { [weak self] in
            guard let self else { return }
            // Subprocess work stays off the main thread; only state updates
            // hop back, so the UI never beachballs on the secret CLI.
            let newState = Self.classifyVaultState(runSecret(["status", "--check"]))
            if newState == .unlocked {
                // Pull the Bitwarden cache before indexing/health so items
                // created on other machines are visible instead of reported
                // missing.
                _ = runSecret(["pull"], timeout: 90)
            }
            let sessionAge = Self.readSessionAge()
            let cacheAvailable = FileManager.default.fileExists(atPath: homeDirectory() + "/.config/secret/biometric-session")
            await MainActor.run {
                self.state = newState
                self.biometricCacheAvailable = cacheAvailable
                self.refreshIndex()
                self.refreshHistory()
                self.sessionCreated = sessionAge
                self.refreshHealth()
                self.setBusy(false)
            }
        }
    }

    func syncVault() {
        setBusy(true)
        Task.detached(priority: .userInitiated) { [weak self] in
            guard let self else { return }
            let newState = Self.classifyVaultState(runSecret(["status", "--check"]))
            let pulled: RunResult? = newState == .unlocked ? runSecret(["pull"], timeout: 90) : nil
            await MainActor.run {
                self.state = newState
                if let pulled {
                    if pulled.status == 0 {
                        self.flash("vault synced from server")
                    } else {
                        self.showError(title: "Vault sync failed", message: self.resultDetail(pulled, fallback: "secret pull failed"))
                    }
                }
                self.refreshIndex()
                self.refreshHistory()
                self.refreshHealth()
                self.setBusy(false)
            }
        }
    }

    func refreshStatus() {
        Task.detached(priority: .utility) { [weak self] in
            let newState = Self.classifyVaultState(runSecret(["status", "--check"]))
            let model = self
            await MainActor.run { model?.state = newState }
        }
    }

    nonisolated static func classifyVaultState(_ result: RunResult) -> VaultState {
        let output = "\(result.stdout)\n\(result.stderr)".lowercased()
        if result.status == 0 { return .unlocked }
        if output.contains("unauthenticated") { return .unauthenticated }
        if output.contains("locked") { return .locked }
        return .error
    }

    nonisolated static func detailText(_ result: RunResult, fallback: String = "") -> String {
        let detail = result.stderr.trimmingCharacters(in: .whitespacesAndNewlines)
        if !detail.isEmpty { return detail }
        let output = result.stdout.trimmingCharacters(in: .whitespacesAndNewlines)
        return output.isEmpty ? fallback : output
    }

    nonisolated static func readSessionAge() -> String? {
        let process = runProcess(
            executable: "/usr/bin/security",
            arguments: ["find-generic-password", "-a", "bitwarden-session", "-s", "secret-cli"],
            timeout: 5
        )
        guard process.status == 0 else { return nil }
        let pattern = #"20\d\d-\d\d-\d\d[ T]\d\d:\d\d:\d\d"#
        guard let range = process.stdout.range(of: pattern, options: .regularExpression) else { return nil }
        let raw = String(process.stdout[range]).replacingOccurrences(of: "T", with: " ")
        let parser = DateFormatter()
        parser.dateFormat = "yyyy-MM-dd HH:mm:ss"
        parser.locale = Locale(identifier: "en_US_POSIX")
        guard let date = parser.date(from: raw) else { return nil }
        let display = DateFormatter()
        display.dateFormat = "yyyy-MM-dd HH:mm"
        return display.string(from: date)
    }

    /// Authenticates with LocalAuthentication in-process (the app owns a real
    /// foreground GUI context, unlike CLI child processes of menu-bar/agent
    /// apps where the Touch ID prompt fails silently) and reads the file-based
    /// biometric session cache. No keychain ACLs involved: Nix rebuilds change
    /// the binary signature and keychain would demand the login password.
    nonisolated static func readBiometricSessionToken(reason: String) -> String? {
        let context = LAContext()
        var error: NSError?
        let policy: LAPolicy = context.canEvaluatePolicy(.deviceOwnerAuthenticationWithBiometrics, error: &error)
            ? .deviceOwnerAuthenticationWithBiometrics
            : .deviceOwnerAuthentication
        guard context.canEvaluatePolicy(policy, error: &error) else { return nil }
        let semaphore = DispatchSemaphore(value: 0)
        var granted = false
        context.evaluatePolicy(policy, localizedReason: reason) { ok, _ in
            granted = ok
            semaphore.signal()
        }
        _ = semaphore.wait(timeout: .now() + 60)
        guard granted else { return nil }
        let path = homeDirectory() + "/.config/secret/biometric-session"
        guard let data = FileManager.default.contents(atPath: path),
              !data.isEmpty,
              let token = String(data: data, encoding: .utf8) else { return nil }
        return token
    }

    func refreshIndex() {
        let home = homeDirectory()
        let devDir = "\(home)/dev"
        var found: [Project] = []
        if let items = try? FileManager.default.contentsOfDirectory(atPath: devDir) {
            for name in items.sorted() where !name.hasPrefix(".") {
                let dir = "\(devDir)/\(name)"
                var isDirectory: ObjCBool = false
                guard FileManager.default.fileExists(atPath: dir, isDirectory: &isDirectory), isDirectory.boolValue else {
                    continue
                }
                if FileManager.default.fileExists(atPath: "\(dir)/.secret.json") {
                    found.append(Project(name: name, dir: dir))
                }
            }
        }
        found.append(Project(name: "global", dir: home))
        projects = found

        var indexed: [AliasEntry] = []
        for project in found {
            guard let data = try? Data(contentsOf: URL(fileURLWithPath: project.configPath)),
                  let json = try? JSONSerialization.jsonObject(with: data) as? [String: Any]
            else { continue }

            var definitions: [(String, [String: Any], String)] = []
            var baseTags: [String: [String]] = [:]
            if let secrets = json["secrets"] as? [String: Any] {
                definitions += secrets.compactMap { alias, definition in
                    guard let definition = definition as? [String: Any] else { return nil }
                    baseTags[alias] = definition["tags"] as? [String] ?? []
                    return (alias, definition, "prod")
                }
            }
            if let environments = json["environments"] as? [String: Any] {
                for environment in environments.keys.sorted() {
                    guard let environmentObject = environments[environment] as? [String: Any],
                          let secrets = environmentObject["secrets"] as? [String: Any]
                    else { continue }
                    definitions += secrets.compactMap { alias, definition in
                        guard let definition = definition as? [String: Any] else { return nil }
                        return (alias, definition, environment)
                    }
                }
            }

            for (alias, definition, environment) in definitions.sorted(by: { $0.0 == $1.0 ? $0.2 < $1.2 : $0.0 < $1.0 }) {
                guard let item = definition["item"] as? String, !item.isEmpty else { continue }
                indexed.append(AliasEntry(
                    alias: alias,
                    project: project.name,
                    configPath: project.configPath,
                    cwd: project.dir,
                    item: item,
                    environment: environment,
                    field: definition["field"] as? String ?? "password",
                    itemType: definition["type"] as? String ?? "login",
                    envKey: definition["env"] as? String ?? alias,
                    tags: definition["tags"] as? [String] ?? baseTags[alias] ?? [],
                    expiresAt: definition["expiresAt"] as? String
                ))
            }
        }
        entries = indexed
        let currentIDs = Set(indexed.map(\.id))
        remoteMetadata = remoteMetadata.filter { currentIDs.contains($0.key) }
        if state == .unlocked && !indexed.allSatisfy({ remoteMetadata[$0.id] != nil }) {
            remoteValidationComplete = false
        }
        refreshDetectedProject()
        refreshHistory()
    }

    func refreshDetectedProject() {
        guard autoDetectProject else {
            detectedProjectID = nil
            return
        }
        let path = "\(homeDirectory())/.config/secretbar/context"
        contextPath = try? String(contentsOfFile: path, encoding: .utf8).trimmingCharacters(in: .whitespacesAndNewlines)
        guard let contextPath, !contextPath.isEmpty else {
            detectedProjectID = nil
            return
        }
        let candidates = projects
            .filter { !$0.isGlobal && (contextPath == $0.dir || contextPath.hasPrefix("\($0.dir)/")) }
            .sorted { $0.dir.count > $1.dir.count }
        detectedProjectID = candidates.first?.id
    }

    func refreshHistory() {
        let path = "\(homeDirectory())/.config/secret/history.json"
        guard let data = try? Data(contentsOf: URL(fileURLWithPath: path)),
              let json = try? JSONSerialization.jsonObject(with: data) as? [[String: Any]]
        else {
            history = []
            recent = []
            lastUsedByKey = [:]
            return
        }

        let parsed = json.enumerated().compactMap { index, row -> UsageEntry? in
            guard let at = row["at"] as? String,
                  let command = row["cmd"] as? String,
                  let target = row["target"] as? String
            else { return nil }
            return UsageEntry(
                id: "\(index)-\(at)-\(target)",
                at: at,
                command: command,
                target: target,
                environment: row["env"] as? String ?? "prod"
            )
        }.sorted { $0.at > $1.at }
        history = parsed

        var lastUsed: [String: String] = [:]
        for item in parsed where item.command == "get" || item.command == "set" || item.command == "rotate" {
            let key = "\(item.environment):\(item.target)"
            if lastUsed[key] == nil { lastUsed[key] = item.at }
        }
        lastUsedByKey = lastUsed

        var recentAliases: [(String, String)] = []
        for item in parsed where item.command == "get" || item.command == "set" || item.command == "rotate" {
            let key = "\(item.environment):\(item.target)"
            if !recentAliases.contains(where: { $0.0 == key }) { recentAliases.append((key, item.environment)) }
            if recentAliases.count == 8 { break }
        }
        recent = recentAliases.compactMap { key, environment in
            let alias = key.split(separator: ":", maxSplits: 1).last.map(String.init) ?? key
            return entryForAlias(alias, environment: environment)
        }
    }

    private func entryForAlias(_ alias: String, environment: String = "prod") -> AliasEntry? {
        if let detectedProjectID,
           let detected = entries.first(where: { $0.project == detectedProjectID && $0.alias == alias && $0.environment == environment }) {
            return detected
        }
        return entries.first(where: { $0.alias == alias && $0.environment == environment })
    }

    func refreshHealth() {
        guard state == .unlocked else {
            problems = [:]
            problemDetails = [:]
            remoteValidationInProgress = false
            healthCheckStatus = "Unlock the vault before running a health check."
            return
        }

        let entriesToCheck = entries
        remoteValidationComplete = false
        remoteValidationInProgress = true
        healthCheckStatus = "Checking \(entriesToCheck.count) configured item\(entriesToCheck.count == 1 ? "" : "s")…"
        Task.detached(priority: .utility) {
            // Refresh the local vault cache so items created on other machines
            // are not reported as missing.
            _ = runSecret(["pull"], timeout: 60)
            var counts: [String: Int] = [:]
            var details: [String: [String]] = [:]
            var metadata: [String: RemoteEntryMetadata] = [:]
            var failedGroups = 0
            let groups = Dictionary(grouping: entriesToCheck) { entry in
                "\(entry.configPath)\u{0}\(entry.environment)"
            }

            for groupedEntries in groups.values {
                guard let first = groupedEntries.first else { continue }
                var arguments = ["doctor", "--config", first.configPath, "--json"]
                if first.environment != "prod" { arguments += ["--env", first.environment] }
                let result = runSecret(arguments, cwd: first.cwd, timeout: 45)
                guard let data = result.stdout.data(using: .utf8),
                      let rows = try? JSONSerialization.jsonObject(with: data) as? [[String: Any]]
                else {
                    failedGroups += 1
                    continue
                }
                let aliases = Set(rows.compactMap { $0["alias"] as? String })
                let expectedAliases = Set(groupedEntries.map(\.alias))
                if rows.isEmpty || aliases != expectedAliases {
                    failedGroups += 1
                    continue
                }

                for row in rows {
                    guard let alias = row["alias"] as? String,
                          let entry = groupedEntries.first(where: { $0.alias == alias })
                    else { continue }
                    let status = row["status"] as? String ?? "missing"
                    let itemName = (row["itemName"] as? String).flatMap { $0.isEmpty ? nil : $0 }
                    let source = (row["source"] as? String).flatMap { $0.isEmpty ? nil : $0 }
                    let hasTOTP = (row["hasTOTP"] as? String) == "true" || (row["hasTOTP"] as? Bool) == true
                    metadata[entry.id] = RemoteEntryMetadata(
                        status: status,
                        itemName: itemName,
                        source: source,
                        hasTOTP: hasTOTP
                    )
                    if status != "ok" {
                        counts[entry.project, default: 0] += 1
                        details[entry.project, default: []].append(
                            "\(status)\t\(entry.alias)\t\(entry.item)\t\(entry.field)"
                        )
                    }
                }
            }
            let snapshotCounts = counts
            let snapshotDetails = details
            let snapshotMetadata = metadata
            let validationIncomplete = failedGroups > 0
            await MainActor.run {
                self.problems = snapshotCounts
                self.problemDetails = snapshotDetails
                self.remoteMetadata = snapshotMetadata
                self.remoteValidationComplete = !validationIncomplete
                self.remoteValidationInProgress = false
                let issueCount = snapshotCounts.values.reduce(0, +)
                self.healthCheckStatus = validationIncomplete
                    ? "Health check incomplete — configured entries remain visible; try refresh."
                    : issueCount == 0
                    ? "Health check complete — no issues found."
                    : "Health check complete — \(issueCount) issue\(issueCount == 1 ? "" : "s") found."
            }
        }
    }

    nonisolated static func parseProblems(_ text: String) -> Int {
        guard let match = text.range(of: #"[0-9]+ problem\(s\)"#, options: .regularExpression) else { return 0 }
        return Int(text[match].filter(\.isNumber)) ?? 0
    }

    func copy(_ entry: AliasEntry) {
        setBusy(true)
        let arguments = scoped(["get", "--copy", "--config", entry.configPath, entry.alias], entry)
        let cwd = entry.cwd
        let alias = entry.alias
        Task.detached(priority: .userInitiated) { [weak self] in
            let result = runSecret(arguments, cwd: cwd, allowBiometrics: true)
            await MainActor.run { [weak self] in
                guard let self else { return }
                self.setBusy(false)
                guard result.status == 0 else {
                    self.showError(title: "Could not copy \(alias)", message: Self.detailText(result, fallback: "secret get failed"))
                    return
                }
                self.scheduleClipboardClear()
                self.flash("copied \(alias)")
                self.refreshHistory()
            }
        }
    }

    func beginReveal(_ entry: AliasEntry) {
        revealingID = entry.id
        revealedValue = ""
        revealError = nil
        setBusy(true)
        let arguments = scoped(["get", "--config", entry.configPath, entry.alias], entry)
        let cwd = entry.cwd
        Task.detached(priority: .userInitiated) { [weak self] in
            let result = runSecret(arguments, cwd: cwd, allowBiometrics: true)
            await MainActor.run { [weak self] in
                guard let self else { return }
                self.setBusy(false)
                guard self.revealingID == entry.id else { return }
                if result.status == 0 {
                    self.revealedValue = result.stdout.trimmingCharacters(in: .whitespacesAndNewlines)
                } else {
                    self.revealError = "Could not reveal value"
                }
            }
        }
    }

    func endReveal(_ entry: AliasEntry) {
        guard revealingID == entry.id else { return }
        revealingID = nil
        revealedValue = ""
        revealError = nil
    }

    func openSource(_ entry: AliasEntry) {
        setBusy(true)
        let arguments = scoped(["source", "--config", entry.configPath, entry.alias, "--open"], entry)
        let cwd = entry.cwd
        let alias = entry.alias
        Task.detached(priority: .userInitiated) { [weak self] in
            let result = runSecret(arguments, cwd: cwd)
            await MainActor.run { [weak self] in
                guard let self else { return }
                self.setBusy(false)
                if result.status == 0 {
                    self.flash("opened source for \(alias)")
                } else {
                    self.showError(title: "No source for \(alias)", message: Self.detailText(result, fallback: "This item has no source URL."))
                }
            }
        }
    }

    func rotate(_ entry: AliasEntry) {
        setBusy(true)
        let arguments = scoped(["rotate", "--config", entry.configPath, entry.alias, "--force"], entry)
        let cwd = entry.cwd
        let alias = entry.alias
        Task.detached(priority: .userInitiated) { [weak self] in
            let result = runSecret(arguments, cwd: cwd, timeout: 90, allowBiometrics: true)
            await MainActor.run { [weak self] in
                guard let self else { return }
                self.setBusy(false)
                if result.status == 0 {
                    self.scheduleClipboardClear()
                    self.flash("rotated \(alias) — new value copied")
                    self.refreshHistory()
                } else {
                    self.showError(title: "Could not rotate \(alias)", message: Self.detailText(result, fallback: "secret rotate failed"))
                }
            }
        }
    }

    func create(
        alias: String,
        project: Project,
        value: String,
        itemName: String,
        source: String,
        notes: String,
        itemType: SecretItemType,
        expiresAt: String,
        environment: String,
        tags: [String],
        completion: @escaping @MainActor (Bool) -> Void
    ) {
        let cleanAlias = alias.trimmingCharacters(in: .whitespacesAndNewlines)
        let cleanValue = value.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !cleanAlias.isEmpty else {
            showError(title: "Cannot create secret", message: "Enter an alias.")
            completion(false)
            return
        }
        guard !cleanValue.isEmpty else {
            showError(title: "Cannot create secret", message: "Enter a value.")
            completion(false)
            return
        }
        var arguments = ["set", cleanAlias, "--type", itemType.rawValue]
        let cleanEnvironment = environment.trimmingCharacters(in: .whitespacesAndNewlines)
        if !cleanEnvironment.isEmpty && cleanEnvironment != "prod" { arguments += ["--env", cleanEnvironment] }
        if project.isGlobal {
            arguments.append("--global")
        } else {
            arguments += ["--config", project.configPath]
        }
        if !itemName.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty { arguments += ["--name", itemName] }
        if !source.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty { arguments += ["--source", source] }
        if itemType == .login, !notes.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty { arguments += ["--notes", notes] }
        if !expiresAt.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty { arguments += ["--expires-at", expiresAt] }
        let cleanTags = tags.map { $0.trimmingCharacters(in: .whitespacesAndNewlines) }.filter { !$0.isEmpty }
        if !cleanTags.isEmpty { arguments += ["--tags", cleanTags.joined(separator: ",")] }
        let finalArguments = arguments

        setBusy(true)
        let dir = project.dir
        let scopeName = project.isGlobal ? "global" : project.name
        Task.detached(priority: .userInitiated) { [weak self] in
            let result = runSecret(finalArguments, cwd: dir, input: cleanValue, timeout: 90, allowBiometrics: true)
            await MainActor.run { [weak self] in
                guard let self else { return }
                self.setBusy(false)
                guard result.status == 0 else {
                    self.showError(title: "Could not create \(cleanAlias)", message: Self.detailText(result, fallback: "secret set failed"))
                    completion(false)
                    return
                }
                self.flash("created \(cleanAlias) in \(scopeName)")
                self.refreshEverything()
                completion(true)
            }
        }
    }

    func prepareImport(url: URL, project: Project, environment: String) {
        let accessed = url.startAccessingSecurityScopedResource()
        defer { if accessed { url.stopAccessingSecurityScopedResource() } }
        guard let contents = try? String(contentsOf: url, encoding: .utf8) else {
            showError(title: "Could not read dotenv file", message: "SecretBar could not read the selected file.")
            return
        }
        let candidates = contents.split(separator: "\n", omittingEmptySubsequences: false).compactMap { raw -> ImportCandidate? in
            var line = String(raw).trimmingCharacters(in: .whitespacesAndNewlines)
            guard !line.isEmpty, !line.hasPrefix("#") else { return nil }
            if line.hasPrefix("export ") { line.removeFirst("export ".count) }
            guard let separator = line.firstIndex(of: "=") else { return nil }
            let key = String(line[..<separator])
            guard key.range(of: "^[A-Za-z_][A-Za-z0-9_]*$", options: .regularExpression) != nil else { return nil }
            var value = String(line[line.index(after: separator)...]).trimmingCharacters(in: .whitespaces)
            if value.count >= 2 {
                let first = value.first
                let last = value.last
                if (first == "'" && last == "'") || (first == "\"" && last == "\"") {
                    value.removeFirst()
                    value.removeLast()
                }
            }
            return ImportCandidate(alias: key.lowercased().replacingOccurrences(of: "_", with: "-"), value: value)
        }
        guard !candidates.isEmpty else {
            showError(title: "No importable entries", message: "The selected file did not contain simple KEY=value entries.")
            return
        }
        importCandidates = candidates
        importProject = project
        importEnvironment = environment
    }

    func confirmImport() {
        guard let project = importProject else { return }
        let candidates = importCandidates
        let existing = Set(entries.filter { $0.project == project.name && $0.environment == importEnvironment }.map(\.alias))
        let skipped = candidates.filter { existing.contains($0.alias) }.map(\.alias)
        importCandidates = []
        importProject = nil
        setBusy(true)
        let environment = importEnvironment
        let dir = project.dir
        Task.detached(priority: .userInitiated) { [weak self] in
            var builtFailures: [String] = []
            for candidate in candidates where !existing.contains(candidate.alias) {
                var arguments = ["set", candidate.alias]
                if project.isGlobal { arguments.append("--global") } else { arguments += ["--config", project.configPath] }
                if environment != "prod" { arguments += ["--env", environment] }
                let result = runSecret(arguments, cwd: dir, input: candidate.value, timeout: 90)
                if result.status != 0 { builtFailures.append("\(candidate.alias): \(Self.detailText(result, fallback: "failed"))") }
            }
            let failures = builtFailures
            await MainActor.run { [weak self] in
                guard let self else { return }
                self.setBusy(false)
                self.refreshEverything()
                if !failures.isEmpty {
                    self.showError(title: "Import completed with errors", message: ((skipped.isEmpty ? [] : ["Skipped existing aliases: \(skipped.joined(separator: ", "))"]) + failures).joined(separator: "\n"))
                } else if !skipped.isEmpty {
                    self.flash("imported new aliases; skipped existing: \(skipped.joined(separator: ", "))")
                } else {
                    self.flash("imported \(candidates.count) aliases")
                }
            }
        }
    }

    func edit(
        _ entry: AliasEntry,
        itemName: String,
        value: String,
        source: String?,
        notes: String?,
        tags: [String],
        clearSource: Bool,
        clearNotes: Bool,
        completion: @escaping @MainActor (Bool) -> Void
    ) {
        let cleanName = itemName.trimmingCharacters(in: .whitespacesAndNewlines)
        let cleanValue = value.trimmingCharacters(in: .whitespacesAndNewlines)
        let cleanSource = source?.trimmingCharacters(in: .whitespacesAndNewlines)
        let cleanNotes = notes?.trimmingCharacters(in: .whitespacesAndNewlines)
        let cleanTags = tags.map { $0.trimmingCharacters(in: .whitespacesAndNewlines) }.filter { !$0.isEmpty }
        let tagsChanged = cleanTags != entry.tags
        let hasChanges = !cleanName.isEmpty || !cleanValue.isEmpty || tagsChanged || clearSource || cleanSource?.isEmpty == false || clearNotes || cleanNotes?.isEmpty == false
        guard hasChanges else {
            showError(title: "Nothing to save", message: "Enter a change first.")
            completion(false)
            return
        }
        var arguments = scoped(["edit", entry.alias, "--config", entry.configPath, "--force"], entry)
        if !cleanName.isEmpty { arguments += ["--name", itemName] }
        if !cleanValue.isEmpty { arguments += ["--field", entry.field, "--value-stdin"] }
        if clearSource || cleanSource?.isEmpty == false { arguments += ["--source", clearSource ? "" : source ?? ""] }
        if clearNotes || cleanNotes?.isEmpty == false { arguments += ["--notes", clearNotes ? "" : notes ?? ""] }
        if tagsChanged { arguments += ["--tags", cleanTags.joined(separator: ",")] }
        let finalArguments = arguments

        setBusy(true)
        let cwd = entry.cwd
        let alias = entry.alias
        Task.detached(priority: .userInitiated) { [weak self] in
            let result = runSecret(finalArguments, cwd: cwd, input: cleanValue.isEmpty ? nil : cleanValue, timeout: 90, allowBiometrics: true)
            await MainActor.run { [weak self] in
                guard let self else { return }
                self.setBusy(false)
                guard result.status == 0 else {
                    self.showError(title: "Could not edit \(alias)", message: Self.detailText(result, fallback: "secret edit failed"))
                    completion(false)
                    return
                }
                self.flash("updated \(alias)")
                self.refreshEverything()
                completion(true)
            }
        }
    }

    func unlockWithTouchID() {
        setBusy(true)
        Task.detached(priority: .userInitiated) { [weak self] in
            guard let self else { return }
            // Authenticate here in the app (a real foreground GUI context)
            // instead of inside the spawned CLI: LAContext prompts do not
            // present reliably for child processes of menu-bar/agent apps —
            // that is why Touch ID unlock appeared to do nothing.
            guard let token = Self.readBiometricSessionToken(reason: "Unlock SecretBar secrets") else {
                await MainActor.run {
                    self.setBusy(false)
                    self.showError(
                        title: "Touch ID unavailable",
                        message: "No usable Touch ID session cache was found. Unlock with your master password once — that refreshes both caches so Touch ID works afterwards."
                    )
                    self.refreshStatus()
                }
                return
            }
            let result = runSecret(["unlock", "--session-stdin"], input: token, timeout: 120)
            await MainActor.run {
                self.setBusy(false)
                if result.status == 0 {
                    // The CLI already verified the session (daemon verdict
                    // first); an extra status roundtrip here raced with
                    // daemon startup and produced false failures.
                    self.flash("unlocked with Touch ID")
                    self.refreshEverything()
                } else {
                    self.showError(title: "Touch ID unlock failed", message: Self.detailText(result, fallback: "The cached session was rejected. Unlock with your master password once to refresh it."))
                    self.refreshStatus()
                }
            }
        }
    }

    func copyTOTP(_ entry: AliasEntry) {
        setBusy(true)
        let arguments = scoped(["totp", "--copy", "--config", entry.configPath, entry.alias], entry)
        let cwd = entry.cwd
        let alias = entry.alias
        Task.detached(priority: .userInitiated) { [weak self] in
            let result = runSecret(arguments, cwd: cwd, allowBiometrics: true)
            await MainActor.run { [weak self] in
                guard let self else { return }
                self.setBusy(false)
                if result.status == 0 {
                    self.scheduleClipboardClear()
                    self.flash("copied current TOTP for \(alias)")
                    self.refreshHistory()
                } else {
                    self.showError(title: "Could not copy TOTP", message: Self.detailText(result, fallback: "secret totp failed"))
                }
            }
        }
    }

    func unlockWithPassword(_ password: String) {
        guard !password.isEmpty else { return }
        setBusy(true)
        Task.detached(priority: .userInitiated) { [weak self] in
            let result = runSecret(["unlock", "--store"], input: password, timeout: 120)
            let verified = result.status == 0
                && runSecret(["status", "--check"], timeout: 30).status == 0
            await MainActor.run { [weak self] in
                guard let self else { return }
                self.setBusy(false)
                if verified {
                    self.flash("unlocked; session stored")
                    self.refreshEverything()
                } else {
                    self.showError(title: "Password unlock failed", message: Self.detailText(result, fallback: "Bitwarden is still locked."))
                    self.refreshStatus()
                }
            }
        }
    }

    func lock() {
        setBusy(true)
        _ = runSecret(["lock"])
        setBusy(false)
        state = .locked
        flash("vault locked")
    }

    func togglePin(_ entry: AliasEntry) {
        guard pinsEnabled else { return }
        if pinnedIDs.contains(entry.id) {
            pinnedIDs.remove(entry.id)
        } else {
            pinnedIDs.insert(entry.id)
        }
    }

    func clearHistory() {
        let path = "\(homeDirectory())/.config/secret/history.json"
        try? FileManager.default.removeItem(atPath: path)
        refreshHistory()
        flash("usage history cleared")
    }

    func copyDiagnostic(_ diagnostic: SecretDiagnostic) {
        guard let command = diagnostic.recoveryCommand else { return }
        if copyText(command) {
            flash("recovery command copied")
        } else {
            showError(title: "Could not copy command", message: "pbcopy is unavailable. Select the command manually.")
        }
    }

    func repairBitwardenSession() {
        setBusy(true)
        let result = runTool("bw", ["logout"], timeout: 30)
        setBusy(false)
        state = .locked
        let command = "bw login\nsecret unlock --store"
        _ = copyText(command)
        openTerminal()
        if result.status == 0 {
            diagnostic = SecretDiagnostic(
                title: "Bitwarden session reset",
                message: "Bitwarden CLI was logged out. The next steps were copied to the clipboard and Terminal was opened. Complete login there, then return to SecretBar.",
                recoveryCommand: command,
                canRepairBitwarden: false
            )
        } else {
            diagnostic = SecretDiagnostic(
                title: "Bitwarden reset needs attention",
                message: resultDetail(result, fallback: "Could not run bw logout.") + "\n\nThe recovery command was copied to the clipboard.",
                recoveryCommand: command,
                canRepairBitwarden: false
            )
        }
    }

    func showHealthDiagnostics() {
        let lines = problemDetails
            .sorted { $0.key < $1.key }
            .flatMap { project, details in details.map { "\(project): \($0)" } }
        let message = lines.isEmpty
            ? "One or more projects need attention. Unlock the vault and run secret doctor for details."
            : lines.joined(separator: "\n")
        diagnostic = SecretDiagnostic(
            title: "Secret health",
            message: message,
            recoveryCommand: "secret doctor",
            canRepairBitwarden: false
        )
    }

    func showError(title: String, message: String) {
        lastError = message
        let lower = message.lowercased()
        let staleSession = lower.contains("stale secure-storage") || lower.contains("rejected the new session")
        diagnostic = SecretDiagnostic(
            title: title,
            message: message,
            recoveryCommand: staleSession ? "bw logout\nbw login\nsecret unlock --store" : nil,
            canRepairBitwarden: staleSession
        )
    }

    func flash(_ message: String) {
        flash = message
        flashTask?.cancel()
        flashTask = Task { @MainActor [weak self] in
            try? await Task.sleep(nanoseconds: 3_000_000_000)
            if !Task.isCancelled { self?.flash = nil }
        }
    }

    func health(for entry: AliasEntry) -> String {
        if let count = problems[entry.project], count > 0 { return "Needs attention" }
        if let expiresAt = entry.expiresAt,
           let expiry = parseDate(expiresAt) {
            if expiry < Date() { return "Expired" }
            if expiry < Date().addingTimeInterval(TimeInterval(expiryWarningDays * 86_400)) { return "Expires soon" }
        }
        return "OK"
    }

    func hasTOTP(_ entry: AliasEntry) -> Bool {
        remoteMetadata[entry.id]?.isUsable == true && remoteMetadata[entry.id]?.hasTOTP == true
    }

    func hasSource(_ entry: AliasEntry) -> Bool {
        remoteMetadata[entry.id]?.source?.isEmpty == false
    }

    func lastUsed(for entry: AliasEntry) -> String {
        guard let value = lastUsedByKey["\(entry.environment):\(entry.alias)"], let date = parseDate(value) else { return "Never" }
        return formatDate(date)
    }

    func lastUsedDate(_ entry: AliasEntry) -> Date? {
        guard let value = lastUsedByKey["\(entry.environment):\(entry.alias)"] else { return nil }
        return parseDate(value)
    }

    private func scheduleClipboardClear() {
        clipboardTask?.cancel()
        guard clipboardClearSeconds > 0 else { return }
        let expectedChangeCount = NSPasteboard.general.changeCount
        let seconds = clipboardClearSeconds
        clipboardTask = Task { @MainActor [weak self] in
            try? await Task.sleep(nanoseconds: UInt64(seconds) * 1_000_000_000)
            guard !Task.isCancelled, NSPasteboard.general.changeCount == expectedChangeCount else { return }
            NSPasteboard.general.clearContents()
            self?.flash("clipboard cleared")
        }
    }

    private func setBusy(_ value: Bool) {
        busy = value
    }

    private func scoped(_ arguments: [String], _ entry: AliasEntry) -> [String] {
        entry.environment == "prod" ? arguments : arguments + ["--env", entry.environment]
    }

    private func resultDetail(_ result: RunResult, fallback: String) -> String {
        let detail = result.stderr.trimmingCharacters(in: .whitespacesAndNewlines)
        if !detail.isEmpty { return detail }
        let output = result.stdout.trimmingCharacters(in: .whitespacesAndNewlines)
        return output.isEmpty ? fallback : output
    }
}

func parseDate(_ value: String) -> Date? {
    if let date = ISO8601DateFormatter().date(from: value) { return date }
    let formatter = DateFormatter()
    formatter.dateFormat = "yyyy-MM-dd"
    formatter.locale = Locale(identifier: "en_US_POSIX")
    return formatter.date(from: value)
}

func formatDate(_ date: Date) -> String {
    let formatter = DateFormatter()
    formatter.dateFormat = "yyyy-MM-dd HH:mm"
    return formatter.string(from: date)
}

func formatDateShort(_ date: Date) -> String {
    let formatter = DateFormatter()
    formatter.setLocalizedDateFormatFromTemplate("yMMMd")
    return formatter.string(from: date)
}

// MARK: - Reusable views

struct StatusDot: View {
    let state: VaultState

    var body: some View {
        Circle()
            .fill(color)
            .frame(width: 11, height: 11)
    }

    private var color: Color {
        switch state {
        case .unlocked: return .green
        case .locked: return .orange
        case .unauthenticated, .error: return .red
        case .unknown: return .gray
        }
    }
}

struct StatusIcon: View {
    let state: VaultState

    var body: some View {
        Image(systemName: symbol)
    }

    private var symbol: String {
        switch state {
        case .unlocked: return "lock.open.fill"
        case .locked: return "lock.fill"
        case .unauthenticated, .error: return "exclamationmark.triangle.fill"
        case .unknown: return "circle.dashed"
        }
    }
}

struct SecretBarDialogSurface<Content: View>: View {
    let content: Content
    let width: CGFloat
    let height: CGFloat?

    init(width: CGFloat, height: CGFloat? = nil, @ViewBuilder content: () -> Content) {
        self.width = width
        self.height = height
        self.content = content()
    }

    private var highContrast: Bool {
        NSWorkspace.shared.accessibilityDisplayShouldIncreaseContrast
    }

    var body: some View {
        content
            .padding(18)
            .frame(width: width, height: height, alignment: .topLeading)
            .background(Color(nsColor: .controlBackgroundColor))
            .clipShape(RoundedRectangle(cornerRadius: 12, style: .continuous))
            .overlay {
                RoundedRectangle(cornerRadius: 12, style: .continuous)
                    .stroke(Color.primary.opacity(highContrast ? 0.38 : 0.18), lineWidth: highContrast ? 1.5 : 1)
            }
            .shadow(color: .black.opacity(0.38), radius: 18, y: 8)
    }
}

struct MasterPasswordSheet: View {
    @ObservedObject var model: SecretBarModel
    let onDismiss: () -> Void
    @State private var password = ""
    @FocusState private var passwordFocused: Bool

    var body: some View {
        SecretBarDialogSurface(width: 380) {
            VStack(alignment: .leading, spacing: 12) {
                Label("Unlock Bitwarden", systemImage: "lock.open")
                    .font(.title3.weight(.semibold))
                Text("Your password is sent to the native secret CLI and is not stored by SecretBar.")
                    .font(.caption)
                    .foregroundStyle(.secondary)
                SecureField("Master password", text: $password)
                    .textFieldStyle(.roundedBorder)
                    .focused($passwordFocused)
                    .onSubmit { unlock() }
                    .onAppear { passwordFocused = true }
                HStack {
                    Spacer()
                    Button("Cancel") { onDismiss() }
                    Button("Unlock") { unlock() }
                        .keyboardShortcut(.defaultAction)
                        .disabled(model.busy || password.isEmpty)
                }
            }
        }
    }

    private func unlock() {
        let value = password
        password = ""
        onDismiss()
        model.unlockWithPassword(value)
    }
}

struct DiagnosticSheet: View {
    @ObservedObject var model: SecretBarModel
    let diagnostic: SecretDiagnostic
    let onDismiss: () -> Void
    @State private var confirmReset = false

    var body: some View {
        SecretBarDialogSurface(width: 560, height: 390) {
            VStack(alignment: .leading, spacing: 12) {
            HStack {
                Image(systemName: "exclamationmark.triangle.fill").foregroundStyle(.red)
                Text(diagnostic.title).font(.title3.weight(.semibold))
            }
            ScrollView {
                Text(diagnostic.message)
                    .textSelection(.enabled)
                    .frame(maxWidth: .infinity, alignment: .leading)
                    .font(.system(.body, design: .monospaced))
            }
            if let command = diagnostic.recoveryCommand {
                Text("Suggested command")
                    .font(.caption.weight(.semibold))
                    .foregroundStyle(.secondary)
                Text(command)
                    .textSelection(.enabled)
                    .font(.system(.callout, design: .monospaced))
                    .padding(8)
                    .frame(maxWidth: .infinity, alignment: .leading)
                    .background(Color(nsColor: .textBackgroundColor), in: RoundedRectangle(cornerRadius: 6))
            }
            if confirmReset {
                VStack(alignment: .leading, spacing: 8) {
                    Text("Reset the Bitwarden CLI session?").font(.headline)
                    Text("This logs Bitwarden out. You will need to complete bw login again.")
                        .font(.caption)
                        .foregroundStyle(.secondary)
                    HStack {
                        Spacer()
                        Button("Cancel") { confirmReset = false }
                        Button("Log out and open Terminal", role: .destructive) {
                            onDismiss()
                            model.repairBitwardenSession()
                        }
                    }
                }
                .padding(10)
                .background(Color(nsColor: .windowBackgroundColor), in: RoundedRectangle(cornerRadius: 7))
            } else {
                HStack {
                    if diagnostic.recoveryCommand != nil {
                        Button("Copy command") {
                            model.copyDiagnostic(diagnostic)
                            onDismiss()
                        }
                        Button("Open Terminal") {
                            onDismiss()
                            openTerminal()
                        }
                    }
                    if diagnostic.canRepairBitwarden {
                        Button("Reset Bitwarden session", role: .destructive) { confirmReset = true }
                    }
                    Spacer()
                    Button("Dismiss") { onDismiss() }
                }
            }
            }
        }
    }
}

struct SecretEditSheet: View {
    @ObservedObject var model: SecretBarModel
    let entry: AliasEntry
    let onDismiss: () -> Void
    @State private var itemName = ""
    @State private var value = ""
    @State private var source = ""
    @State private var notes = ""
    @State private var tags: [String] = []
    @State private var clearSource = false
    @State private var clearNotes = false

    init(model: SecretBarModel, entry: AliasEntry, onDismiss: @escaping () -> Void) {
        self.model = model
        self.entry = entry
        self.onDismiss = onDismiss
        _itemName = State(initialValue: model.remoteMetadata[entry.id]?.itemName ?? "")
        _source = State(initialValue: model.remoteMetadata[entry.id]?.source ?? "")
        _tags = State(initialValue: entry.tags)
    }

    private var sourceValidationMessage: String? {
        let value = source.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !value.isEmpty, !clearSource else { return nil }
        let url = URL(string: value)
        let scheme = url?.scheme?.lowercased()
        guard url?.host != nil, scheme == "http" || scheme == "https" else {
            return "Source must be an http:// or https:// URL."
        }
        return nil
    }

    var body: some View {
        SecretBarDialogSurface(width: 500, height: 560) {
            VStack(alignment: .leading, spacing: 12) {
                HStack(spacing: 9) {
                    Image(systemName: entry.itemType == SecretItemType.secureNote.rawValue ? "note.text" : "key.fill")
                        .font(.title3)
                        .foregroundStyle(.secondary)
                    VStack(alignment: .leading, spacing: 2) {
                        Text("Edit secret")
                            .font(.title3.weight(.semibold))
                        Text(entry.alias)
                            .font(.system(.caption, design: .monospaced))
                            .foregroundStyle(.secondary)
                    }
                }
                Text("\(entry.project) · known item details are prefilled; blank fields keep their current values")
                    .font(.caption)
                    .foregroundStyle(.secondary)

                ScrollView {
                    VStack(alignment: .leading, spacing: 12) {
                        LabeledContent("Bitwarden item") {
                            TextField("Optional item name", text: $itemName)
                                .textFieldStyle(.roundedBorder)
                        }

                        VStack(alignment: .leading, spacing: 5) {
                            Text(entry.itemType == SecretItemType.secureNote.rawValue ? "Secure Note content" : "New value")
                                .font(.caption.weight(.semibold))
                                .foregroundStyle(.secondary)
                            if entry.itemType == SecretItemType.secureNote.rawValue {
                                TextEditor(text: $value)
                                    .font(.system(.body, design: .monospaced))
                                    .frame(minHeight: 90, maxHeight: 125)
                                    .scrollContentBackground(.hidden)
                                    .padding(5)
                                    .background(Color(nsColor: .textBackgroundColor), in: RoundedRectangle(cornerRadius: 7))
                                    .overlay(alignment: .topLeading) {
                                        if value.isEmpty {
                                            Text("Optional — paste replacement content")
                                                .font(.callout)
                                                .foregroundStyle(.secondary)
                                                .padding(7)
                                                .allowsHitTesting(false)
                                        }
                                    }
                            } else {
                                SecureField("Optional replacement value", text: $value)
                                    .textFieldStyle(.roundedBorder)
                            }
                        }

                        VStack(alignment: .leading, spacing: 5) {
                            Text("Source URL")
                                .font(.caption.weight(.semibold))
                                .foregroundStyle(.secondary)
                            HStack(spacing: 8) {
                                TextField("Optional https:// URL", text: $source)
                                    .textFieldStyle(.roundedBorder)
                                Toggle("Clear", isOn: $clearSource)
                                    .toggleStyle(.checkbox)
                                    .fixedSize()
                            }
                            if let sourceValidationMessage {
                                Label(sourceValidationMessage, systemImage: "exclamationmark.circle")
                                    .font(.caption2)
                                    .foregroundStyle(.orange)
                            }
                        }

                        VStack(alignment: .leading, spacing: 5) {
                            Text("Notes")
                                .font(.caption.weight(.semibold))
                                .foregroundStyle(.secondary)
                            TextEditor(text: $notes)
                                .font(.body)
                                .frame(minHeight: 70, maxHeight: 105)
                                .scrollContentBackground(.hidden)
                                .padding(5)
                                .background(Color(nsColor: .textBackgroundColor), in: RoundedRectangle(cornerRadius: 7))
                                .overlay(alignment: .topLeading) {
                                    if notes.isEmpty {
                                        Text("Optional — leave blank to keep current notes")
                                            .font(.callout)
                                            .foregroundStyle(.secondary)
                                            .padding(7)
                                            .allowsHitTesting(false)
                                    }
                                }
                            Toggle("Clear notes", isOn: $clearNotes)
                                .toggleStyle(.checkbox)
                        }

                        TagEditor(tags: $tags, title: "Tags", suggestions: model.entries.flatMap(\.tags))
                    }
                    .padding(.vertical, 2)
                }

                Divider()
                HStack {
                    Spacer()
                    Button("Cancel") { onDismiss() }
                    Button("Save changes") {
                        model.edit(entry, itemName: itemName, value: value, source: source, notes: notes, tags: tags, clearSource: clearSource, clearNotes: clearNotes) { updated in
                            if updated {
                                onDismiss()
                            }
                        }
                    }
                    .keyboardShortcut(.defaultAction)
                    .disabled(model.busy || sourceValidationMessage != nil)
                }
            }
        }
        .onAppear {
            if model.remoteMetadata[entry.id] == nil {
                model.refreshHealth()
            }
        }
        .onChange(of: model.remoteMetadata[entry.id]) { _, metadata in
            guard let metadata else { return }
            if itemName.isEmpty { itemName = metadata.itemName ?? "" }
            if source.isEmpty { source = metadata.source ?? "" }
        }
    }
}

struct ImportPreviewSheet: View {
    @ObservedObject var model: SecretBarModel
    let onDismiss: () -> Void

    var body: some View {
        SecretBarDialogSurface(width: 430, height: 430) {
            VStack(alignment: .leading, spacing: 12) {
                Label("Import dotenv entries", systemImage: "arrow.down.doc")
                    .font(.title3.weight(.semibold))
                Text("Only aliases and values from the selected file are read. Existing aliases in the selected project/environment are skipped, never overwritten.")
                    .font(.caption)
                    .foregroundStyle(.secondary)
                Text("\(model.importCandidates.count) entries ready for \(model.importProject?.name ?? "project") / \(model.importEnvironment)")
                    .font(.headline)
                ScrollView {
                    LazyVStack(alignment: .leading, spacing: 4) {
                        ForEach(model.importCandidates) { candidate in
                            HStack {
                                Text(candidate.alias).font(.system(.body, design: .monospaced))
                                Spacer()
                                Text("value hidden").font(.caption).foregroundStyle(.secondary)
                            }
                        }
                    }
                }
                HStack {
                    Spacer()
                    Button("Cancel") { model.importCandidates = []; onDismiss() }
                    Button("Create missing secrets") {
                        model.confirmImport()
                        onDismiss()
                    }
                    .keyboardShortcut(.defaultAction)
                    .disabled(model.busy)
                }
            }
        }
    }
}

struct SecretBarConfirmation: View {
    let title: String
    let message: String
    let confirmTitle: String
    let destructive: Bool
    let onConfirm: () -> Void
    let onCancel: () -> Void

    var body: some View {
        SecretBarDialogSurface(width: 430) {
            VStack(alignment: .leading, spacing: 12) {
                Label(title, systemImage: destructive ? "exclamationmark.triangle" : "questionmark.circle")
                    .font(.title3.weight(.semibold))
                Text(message)
                    .font(.callout)
                    .foregroundStyle(.secondary)
                    .fixedSize(horizontal: false, vertical: true)
                HStack {
                    Spacer()
                    Button("Cancel") { onCancel() }
                    if destructive {
                        Button(confirmTitle, role: .destructive) { onConfirm() }
                    } else {
                        Button(confirmTitle) { onConfirm() }
                    }
                }
            }
        }
    }
}

struct TagEditor: View {
    @Binding var tags: [String]
    let title: String
    let suggestions: [String]
    @State private var draft = ""

    private var matchingSuggestions: [String] {
        let needle = draft.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !needle.isEmpty else { return [] }
        return Array(
            Set(suggestions)
                .filter { !$0.isEmpty && !tags.contains($0) && $0.localizedCaseInsensitiveContains(needle) }
                .sorted()
                .prefix(6)
        )
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 7) {
            Text(title)
                .font(.caption.weight(.semibold))
                .foregroundStyle(.secondary)
            if !tags.isEmpty {
                LazyVGrid(columns: [GridItem(.adaptive(minimum: 82), alignment: .leading)], alignment: .leading, spacing: 5) {
                    ForEach(tags, id: \.self) { tag in
                        HStack(spacing: 4) {
                            Text(tag).lineLimit(1)
                            Button {
                                tags.removeAll { $0 == tag }
                            } label: {
                                Image(systemName: "xmark.circle.fill")
                                    .font(.caption2)
                            }
                            .buttonStyle(.plain)
                            .foregroundStyle(.secondary)
                        }
                        .font(.caption)
                        .padding(.horizontal, 7)
                        .padding(.vertical, 4)
                        .background(Color.primary.opacity(0.08), in: Capsule())
                    }
                }
            }
            HStack(spacing: 6) {
                TextField("Add a tag", text: $draft)
                    .textFieldStyle(.plain)
                    .padding(.horizontal, 8)
                    .padding(.vertical, 6)
                    .background(Color.primary.opacity(0.06), in: RoundedRectangle(cornerRadius: 7))
                    .accessibilityLabel("Add tag")
                    .onSubmit(addDraft)
                Button("Add", action: addDraft)
                    .disabled(draft.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty)
            }
            if !matchingSuggestions.isEmpty {
                ScrollView(.horizontal, showsIndicators: false) {
                    HStack(spacing: 5) {
                        ForEach(matchingSuggestions, id: \.self) { suggestion in
                            Button {
                                tags.append(suggestion)
                                draft = ""
                            } label: {
                                Label(suggestion, systemImage: "plus")
                                    .font(.caption2)
                            }
                            .buttonStyle(.bordered)
                            .controlSize(.small)
                            .accessibilityLabel("Add tag \(suggestion)")
                        }
                    }
                }
                .accessibilityElement(children: .contain)
                .accessibilityLabel("Suggested tags")
            }
        }
    }

    private func addDraft() {
        let newTags = draft.split(separator: ",")
            .map { $0.trimmingCharacters(in: .whitespacesAndNewlines) }
            .filter { !$0.isEmpty && !tags.contains($0) }
        guard !newTags.isEmpty else { return }
        tags.append(contentsOf: newTags)
        draft = ""
    }
}

enum SecretListFilter: String, CaseIterable, Identifiable {
    case all
    case recent
    case pinned

    var id: String { rawValue }
    var title: String {
        switch self {
        case .all: return "All"
        case .recent: return "Recent"
        case .pinned: return "Pinned"
        }
    }
    var icon: String {
        switch self {
        case .all: return "square.grid.2x2.fill"
        case .recent: return "clock.fill"
        case .pinned: return "pin.fill"
        }
    }
}

enum SecretSortKey: String, CaseIterable {
    case alias
    case project
    case lastUsed
}

struct SecretBarSurface<Content: View>: View {
    let content: Content
    @Environment(\.accessibilityReduceTransparency) private var reduceTransparency

    private var highContrast: Bool {
        NSWorkspace.shared.accessibilityDisplayShouldIncreaseContrast
    }

    init(@ViewBuilder content: () -> Content) {
        self.content = content()
    }

    var body: some View {
        content
            .padding(12)
            .frame(maxWidth: .infinity, alignment: .leading)
            .background {
                if reduceTransparency {
                    Color(nsColor: .controlBackgroundColor)
                } else {
                    Rectangle().fill(.regularMaterial)
                }
            }
            .clipShape(RoundedRectangle(cornerRadius: 10, style: .continuous))
            .overlay {
                    RoundedRectangle(cornerRadius: 10, style: .continuous)
                    .stroke(
                        Color.primary.opacity(highContrast ? 0.3 : 0.12),
                        lineWidth: highContrast ? 1.5 : 1
                    )
            }
    }
}

// MARK: - Main view

struct SecretBarView: View {
    @EnvironmentObject var model: SecretBarModel
    @Environment(\.openWindow) private var openWindow
    @State private var tab: SecretBarTab = .secrets
    @State private var query = ""
    @State private var listFilter: SecretListFilter = .all
    @State private var sortKey: SecretSortKey = .alias
    @State private var sortAscending = true
    @State private var selectedTag: String?
    @State private var rotating: AliasEntry?
    @State private var editing: AliasEntry?
    @State private var selectedEntryID: String?
    @State private var hoveredEntryID: String?
    @State private var showPasswordSheet = false
    @State private var selectedProjectID = ""
    @State private var createAlias = ""
    @State private var createItemName = ""
    @State private var createValue = ""
    @State private var createSource = ""
    @State private var createNotes = ""
    @State private var createType: SecretItemType = .login
    @State private var createExpiresAt = ""
    @State private var createEnvironment = "prod"
    @State private var createTags: [String] = []
    @State private var showDotEnvImporter = false
    @State private var showImportPreview = false
    @State private var confirmClearHistory = false
    @State private var confirmLock = false
    @FocusState private var searchFocused: Bool
    @FocusState private var listFocused: Bool

    private var selectedEntry: AliasEntry? {
        filteredEntries.first { $0.id == selectedEntryID }
    }

    private var highContrast: Bool {
        NSWorkspace.shared.accessibilityDisplayShouldIncreaseContrast
    }

    private var matchingEntries: [AliasEntry] {
        // Every configured alias stays visible. Vault problems (missing or
        // invalid items) surface as the row's health badge instead of
        // silently dropping entries from the list.
        let sourceEntries = model.entries
        let needle = query.trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
        guard !needle.isEmpty else { return sourceEntries }
        return sourceEntries.filter {
            $0.alias.lowercased().contains(needle) ||
            $0.project.lowercased().contains(needle) ||
            $0.item.lowercased().contains(needle) ||
            $0.field.lowercased().contains(needle) ||
            $0.environment.lowercased().contains(needle) ||
            $0.tags.joined(separator: " ").lowercased().contains(needle)
        }
    }

    private var filteredEntries: [AliasEntry] {
        let queried = matchingEntries
        let tagFiltered = selectedTag.map { tag in queried.filter { $0.tags.contains(tag) } } ?? queried
        switch listFilter {
        case .all:
            return tagFiltered
        case .recent:
            return model.recent.filter { tagFiltered.contains($0) }
        case .pinned:
            return tagFiltered.filter { model.pinnedIDs.contains($0.id) }
        }
    }

    private var availableTags: [String] {
        Array(Set(model.entries.flatMap(\.tags))).sorted()
    }

    private func compareEntries(_ a: AliasEntry, _ b: AliasEntry) -> Bool {
        switch sortKey {
        case .alias:
            return a.alias.localizedStandardCompare(b.alias) == .orderedAscending
        case .project:
            return a.project == b.project ? a.alias < b.alias : a.project < b.project
        case .lastUsed:
            let an = model.lastUsedDate(a) ?? .distantPast
            let bn = model.lastUsedDate(b) ?? .distantPast
            return an == bn ? a.alias < b.alias : an > bn // most recent first by default
        }
    }

    private var sortedEntries: [AliasEntry] {
        filteredEntries.sorted { asc, b in
            sortAscending ? compareEntries(asc, b) : compareEntries(b, asc)
        }
    }

    private var selectedProject: Project? {
        model.projects.first(where: { $0.id == selectedProjectID }) ?? model.projects.first(where: { $0.isGlobal })
    }

    @ViewBuilder
    private var modalOverlay: some View {
        if let diagnostic = model.diagnostic {
            Color.black.opacity(0.5).ignoresSafeArea()
            DiagnosticSheet(model: model, diagnostic: diagnostic) { model.diagnostic = nil }
        } else if let entry = editing {
            Color.black.opacity(0.5).ignoresSafeArea()
            SecretEditSheet(model: model, entry: entry) { editing = nil }
        } else if showPasswordSheet {
            Color.black.opacity(0.5).ignoresSafeArea()
            MasterPasswordSheet(model: model) { showPasswordSheet = false }
        } else if showImportPreview {
            Color.black.opacity(0.5).ignoresSafeArea()
            ImportPreviewSheet(model: model) { showImportPreview = false }
        } else if let entry = rotating {
            Color.black.opacity(0.5).ignoresSafeArea()
            SecretBarConfirmation(
                title: "Rotate \(entry.alias)?",
                message: "Generates a new password in Bitwarden and copies it to the clipboard.",
                confirmTitle: "Rotate and copy new value",
                destructive: true,
                onConfirm: {
                    model.rotate(entry)
                    rotating = nil
                },
                onCancel: { rotating = nil }
            )
        } else if confirmClearHistory {
            Color.black.opacity(0.5).ignoresSafeArea()
            SecretBarConfirmation(
                title: "Clear usage history?",
                message: "History contains aliases, actions, timestamps, and environments only. It never contains values.",
                confirmTitle: "Clear history",
                destructive: true,
                onConfirm: {
                    model.clearHistory()
                    confirmClearHistory = false
                },
                onCancel: { confirmClearHistory = false }
            )
        } else if confirmLock {
            Color.black.opacity(0.5).ignoresSafeArea()
            SecretBarConfirmation(
                title: "Lock the vault?",
                message: "Copying or revealing secrets will require unlocking again.",
                confirmTitle: "Lock vault",
                destructive: false,
                onConfirm: {
                    model.lock()
                    confirmLock = false
                },
                onCancel: { confirmLock = false }
            )
        }
    }

    var body: some View {
        ZStack {
            VStack(alignment: .leading, spacing: 8) {
                header
                Divider()
                tabBar
                Group {
                    switch tab {
                    case .create: createTab
                    case .secrets: secretsTab
                    case .settings: settingsTab
                    }
                }
                .frame(maxWidth: .infinity, maxHeight: .infinity, alignment: .topLeading)
                if let flash = model.flash {
                    Text(flash)
                        .font(.caption)
                        .foregroundStyle(.secondary)
                        .lineLimit(2)
                }
            }
            modalOverlay
        }
        .padding(.horizontal, 14)
        .padding(.vertical, 10)
        .frame(width: 620, height: 700)
        .background(Color(nsColor: .windowBackgroundColor))
        .clipShape(RoundedRectangle(cornerRadius: 8, style: .continuous))
        .overlay {
                RoundedRectangle(cornerRadius: 8, style: .continuous)
                .stroke(
                    Color.primary.opacity(highContrast ? 0.4 : 0.16),
                    lineWidth: highContrast ? 1.5 : 1
                )
        }
        .onAppear {
            model.start()
            selectDetectedProjectIfNeeded()
        }
        .onChange(of: model.detectedProjectID) { _, _ in selectDetectedProjectIfNeeded() }
        .fileImporter(
            isPresented: $showDotEnvImporter,
            allowedContentTypes: [.plainText, .data],
            allowsMultipleSelection: false
        ) { result in
            guard case let .success(urls) = result, let url = urls.first, let project = selectedProject else { return }
            model.prepareImport(url: url, project: project, environment: createEnvironment.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty ? "prod" : createEnvironment)
            showImportPreview = !model.importCandidates.isEmpty
        }
    }

    private var header: some View {
        HStack(spacing: 10) {
            ZStack {
                Image(systemName: "key.fill")
                    .font(.title3.weight(.medium))
                    .foregroundStyle(.secondary)
            }
            .frame(width: 24, height: 30)
            VStack(alignment: .leading, spacing: 1) {
                Text("SecretBar").font(.headline)
                HStack(spacing: 5) {
                    Text(stateLabel.capitalized)
                        .font(.caption)
                        .foregroundStyle(model.state == .unlocked ? .green : .secondary)
                    if let project = model.detectedProjectID,
                       let name = model.projects.first(where: { $0.id == project })?.name,
                       model.autoDetectProject {
                        Text("• \(name)").font(.caption2).foregroundStyle(.secondary)
                    }
                }
            }
            Spacer()
            if model.busy { ProgressView().controlSize(.small) }
            Button { model.refreshEverything() } label: {
                Image(systemName: "arrow.clockwise")
                    .frame(width: 26, height: 26)
            }
            .buttonStyle(.borderless)
            .accessibilityLabel("Sync and refresh secrets")
            .help("Pull from Bitwarden and refresh")
            .disabled(model.busy)
            Menu {
                if model.showMainWindow {
                    Button {
                        openWindow(id: "main")
                        NSApp.activate(ignoringOtherApps: true)
                    } label: {
                        Label("Open Main Window", systemImage: "macwindow")
                    }
                }
                Button { model.syncVault() } label: {
                    Label("Sync vault from server", systemImage: "arrow.triangle.2.circlepath")
                }
                .disabled(model.busy || model.state != .unlocked)
                if model.state == .unlocked {
                    Button { confirmLock = true } label: {
                        Label("Lock vault", systemImage: "lock.fill")
                    }
                }
                Divider()
                Button("Quit SecretBar", role: .destructive) { NSApplication.shared.terminate(nil) }
            } label: {
                Image(systemName: "ellipsis")
                    .frame(width: 26, height: 26)
            }
            .menuStyle(.borderlessButton)
            .accessibilityLabel("SecretBar actions")
            .help("Sync, lock, or quit SecretBar")
            // Fixed-width slot so swapping lock/unlock controls never shifts
            // the rest of the header.
            HStack {
                if model.state == .unlocked {
                    Button { confirmLock = true } label: {
                        Image(systemName: "lock.fill")
                            .frame(width: 26, height: 26)
                    }
                    .buttonStyle(.borderless)
                    .accessibilityLabel("Lock the vault")
                    .help("Lock the vault")
                    .disabled(model.busy)
                } else {
                    Menu {
                        Button { model.unlockWithTouchID() } label: { Label("Unlock with Touch ID", systemImage: "touchid") }
                            .disabled(!model.biometricCacheAvailable)
                            .help(model.biometricCacheAvailable
                                ? "Unlock with Touch ID"
                                : "Seeded after your next master password unlock")
                        Button { showPasswordSheet = true } label: { Label("Unlock with master password…", systemImage: "key") }
                    } label: {
                        Image(systemName: "lock.open.fill")
                            .frame(width: 26, height: 26)
                    }
                    .menuStyle(.borderlessButton)
                    .accessibilityLabel("Unlock the vault")
                    .help("Unlock the vault")
                    .disabled(model.busy)
                }
            }
            .frame(width: 30)
        }
    }

    private var stateLabel: String {
        switch model.state {
        case .unknown: return "secret"
        case .unlocked: return "unlocked"
        case .locked: return "locked"
        case .unauthenticated: return "not logged in"
        case .error: return "error"
        }
    }

    private var createValidationMessage: String? {
        let environment = createEnvironment.trimmingCharacters(in: .whitespacesAndNewlines)
        let source = createSource.trimmingCharacters(in: .whitespacesAndNewlines)
        let expiry = createExpiresAt.trimmingCharacters(in: .whitespacesAndNewlines)
        if !environment.isEmpty && environment.range(of: "^[A-Za-z0-9_-]+$", options: .regularExpression) == nil {
            return "Environment names use letters, numbers, hyphens, or underscores."
        }
        if !source.isEmpty {
            let url = URL(string: source)
            let scheme = url?.scheme?.lowercased()
            if url?.host == nil || (scheme != "http" && scheme != "https") {
                return "Source must be an http:// or https:// URL."
            }
        }
        if !expiry.isEmpty && parseDate(expiry) == nil {
            return "Expiry must use YYYY-MM-DD."
        }
        return nil
    }

    private var canCreate: Bool {
        !createAlias.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty &&
            !createValue.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty &&
            selectedProject != nil &&
            createValidationMessage == nil
    }

    private var createTab: some View {
        VStack(alignment: .leading, spacing: 8) {
            ScrollView {
                VStack(alignment: .leading, spacing: 12) {
                VStack(alignment: .leading, spacing: 3) {
                    Text("Create a secret").font(.title2.weight(.bold))
                    Text("Save one useful credential. SecretBar keeps values off process arguments.")
                        .font(.callout)
                        .foregroundStyle(.secondary)
                }

                SecretBarSurface {
                    VStack(alignment: .leading, spacing: 9) {
                        Label("Where should it live?", systemImage: "tray.full.fill")
                            .font(.headline)
                        Picker("Scope", selection: $selectedProjectID) {
                            ForEach(model.projects) { project in
                                Text(project.isGlobal ? "Global" : project.name).tag(project.id)
                            }
                        }
                        .pickerStyle(.menu)
                        LabeledContent("Environment") {
                            TextField("prod", text: $createEnvironment)
                                .textFieldStyle(.roundedBorder)
                        }
                    }
                }

                SecretBarSurface {
                    VStack(alignment: .leading, spacing: 9) {
                        Label("What kind of secret?", systemImage: "square.stack.3d.up.fill")
                            .font(.headline)
                        HStack(spacing: 8) {
                            ForEach(SecretItemType.allCases) { type in
                                Button {
                                    createType = type
                                } label: {
                                    VStack(alignment: .leading, spacing: 4) {
                                        Label(type.title, systemImage: type.icon)
                                            .font(.callout.weight(.semibold))
                                            .foregroundStyle(.primary)
                                        Text(type.shortDescription)
                                            .font(.caption2)
                                            .foregroundStyle(.secondary)
                                            .lineLimit(2)
                                    }
                                    .frame(maxWidth: .infinity, minHeight: 48, alignment: .leading)
                                    .padding(9)
                                    .background(
                                        createType == type ? Color.primary.opacity(0.13) : Color.primary.opacity(0.045),
                                        in: RoundedRectangle(cornerRadius: 8, style: .continuous)
                                    )
                                    .overlay {
                                        RoundedRectangle(cornerRadius: 8, style: .continuous)
                                            .stroke(
                                                createType == type ? Color.primary.opacity(0.42) : Color.primary.opacity(0.1),
                                                lineWidth: createType == type ? 1.5 : 1
                                            )
                                    }
                                }
                                .buttonStyle(.plain)
                                .accessibilityAddTraits(createType == type ? .isSelected : [])
                                .accessibilityLabel(type.title)
                                .accessibilityHint(type.guidance)
                            }
                        }
                        Text(createType.guidance)
                            .font(.caption)
                            .foregroundStyle(.secondary)
                    }
                }

                SecretBarSurface {
                    VStack(alignment: .leading, spacing: 9) {
                        Label("Secret details", systemImage: "pencil.and.outline")
                            .font(.headline)
                        LabeledContent("Alias") {
                            TextField("e.g. github-token", text: $createAlias)
                                .textFieldStyle(.roundedBorder)
                        }
                        LabeledContent("Bitwarden item") {
                            TextField("Optional", text: $createItemName)
                                .textFieldStyle(.roundedBorder)
                        }
                        if createType == .secureNote {
                            TextEditor(text: $createValue)
                                .font(.system(.body, design: .monospaced))
                                .frame(minHeight: 105, maxHeight: 150)
                                .scrollContentBackground(.hidden)
                                .padding(5)
                                .background(Color(nsColor: .textBackgroundColor), in: RoundedRectangle(cornerRadius: 7))
                                .overlay(alignment: .topLeading) {
                                    if createValue.isEmpty {
                                        Text("Paste multiline secret value…")
                                            .font(.callout)
                                            .foregroundStyle(.secondary)
                                            .padding(7)
                                            .allowsHitTesting(false)
                                    }
                                }
                        } else {
                            LabeledContent("Value") {
                                SecureField("Required", text: $createValue)
                                    .textFieldStyle(.roundedBorder)
                            }
                            TextEditor(text: $createNotes)
                                .font(.body)
                                .frame(minHeight: 65, maxHeight: 95)
                                .scrollContentBackground(.hidden)
                                .padding(5)
                                .background(Color(nsColor: .textBackgroundColor), in: RoundedRectangle(cornerRadius: 7))
                                .overlay(alignment: .topLeading) {
                                    if createNotes.isEmpty {
                                        Text("Optional notes: owner, rotation cadence, or setup hint…")
                                            .font(.callout)
                                            .foregroundStyle(.secondary)
                                            .padding(7)
                                            .allowsHitTesting(false)
                                    }
                                }
                        }
                    }
                }

                SecretBarSurface {
                    VStack(alignment: .leading, spacing: 9) {
                        Label("Useful context", systemImage: "tag.fill")
                            .font(.headline)
                        LabeledContent("Source") {
                            TextField("Optional URL", text: $createSource)
                                .textFieldStyle(.roundedBorder)
                        }
                        LabeledContent("Expiry") {
                            TextField("Optional YYYY-MM-DD", text: $createExpiresAt)
                                .textFieldStyle(.roundedBorder)
                        }
                        TagEditor(tags: $createTags, title: "Tags help you find secrets later", suggestions: availableTags)
                    }
                }

            }
            .padding(.bottom, 12)
        }
        Divider()
        HStack {
            Button("Import .env…") { showDotEnvImporter = true }
                .buttonStyle(.bordered)
            if let validation = createValidationMessage {
                Label(validation, systemImage: "exclamationmark.circle")
                    .font(.caption2)
                    .foregroundStyle(.orange)
                    .lineLimit(2)
            }
            Spacer()
            Button {
                guard let project = selectedProject else {
                    model.showError(title: "Cannot create secret", message: "No project scope is available.")
                    return
                }
                model.create(alias: createAlias, project: project, value: createValue, itemName: createItemName, source: createSource, notes: createNotes, itemType: createType, expiresAt: createExpiresAt, environment: createEnvironment, tags: createTags) { created in
                    guard created else { return }
                    createAlias = ""
                    createItemName = ""
                    createValue = ""
                    createSource = ""
                    createNotes = ""
                    createExpiresAt = ""
                    createEnvironment = "prod"
                    createTags = []
                    createType = .login
                    tab = .secrets
                }
            } label: {
                Label("Create secret", systemImage: "plus")
            }
            .buttonStyle(.borderedProminent)
            .keyboardShortcut(.defaultAction)
            .disabled(model.busy || model.state != .unlocked || !canCreate)
        }
    }
    }

    private var secretsTab: some View {
        VStack(alignment: .leading, spacing: 8) {
            HStack(alignment: .firstTextBaseline) {
                VStack(alignment: .leading, spacing: 2) {
                    Text("My Secrets").font(.title2.weight(.bold))
                    Text("Fast, focused access to credentials you actually use.")
                        .font(.caption)
                        .foregroundStyle(.secondary)
                }
                Spacer()
                if model.problems.contains(where: { $0.value > 0 }) {
                    Button { model.showHealthDiagnostics() } label: {
                        Label(healthSummary, systemImage: "exclamationmark.triangle.fill")
                            .font(.caption.weight(.semibold))
                            .foregroundStyle(.orange)
                    }
                    .buttonStyle(.plain)
                }
            }
            searchField
            HStack(spacing: 8) {
                HStack(spacing: 2) {
                    ForEach(SecretListFilter.allCases) { filter in
                        filterPill(filter)
                    }
                }
                .padding(2)
                .background(Color.black.opacity(0.1), in: RoundedRectangle(cornerRadius: 8, style: .continuous))
                Spacer()
                Menu {
                    Button { selectedTag = nil } label: {
                        Label("All tags", systemImage: selectedTag == nil ? "checkmark" : "tag")
                    }
                    if !availableTags.isEmpty { Divider() }
                    ForEach(availableTags, id: \.self) { tag in
                        Button { selectedTag = tag } label: {
                            Label(tag, systemImage: selectedTag == tag ? "checkmark" : "tag")
                        }
                    }
                } label: {
                    Label(selectedTag ?? "Tags", systemImage: "tag.fill")
                        .font(.caption.weight(.semibold))
                }
                .menuStyle(.borderlessButton)
                .padding(.horizontal, 5)
                .accessibilityLabel(selectedTag.map { "Filter by tag \($0)" } ?? "Filter by tag")
            }

            if model.remoteValidationInProgress {
                HStack(spacing: 6) {
                    ProgressView().controlSize(.small)
                    Text("Checking vault…").font(.caption).foregroundStyle(.secondary)
                }
            }

            ScrollView {
                LazyVStack(alignment: .leading, spacing: 0) {
                    HStack(spacing: 10) {
                        sortHeader("Secret", .alias)
                            .frame(maxWidth: .infinity, alignment: .leading)
                        sortHeader("Project", .project, width: 104)
                        sortHeader("Last used", .lastUsed, width: 92)
                        Text("").frame(width: 58)
                    }
                    .padding(.horizontal, 6)
                    .padding(.bottom, 4)
                    Divider()
                    if sortedEntries.isEmpty {
                        emptySecretsState.padding(.top, 12)
                    } else {
                        ForEach(sortedEntries) { entry in
                            entryCard(entry)
                        }
                    }
                }
                .padding(.vertical, 2)
            }
            if let selectedEntry {
                Button("Copy selected value") { model.copy(selectedEntry) }
                    .keyboardShortcut(.defaultAction)
                    .accessibilityHidden(true)
                    .frame(width: 0, height: 0)
                    .opacity(0)
            }
        }
        .focusable()
        .focusEffectDisabled()
        .focused($listFocused)
        .onAppear { listFocused = true }
        .onMoveCommand { moveSelection($0) }
        .onExitCommand {
            if searchFocused {
                searchFocused = false
            } else {
                selectedEntryID = nil
            }
        }
    }

    private var searchField: some View {
        HStack(spacing: 8) {
            Image(systemName: "magnifyingglass")
                .foregroundStyle(.secondary)
            TextField("Search aliases, projects, items, tags…", text: $query)
                .textFieldStyle(.plain)
                .focused($searchFocused)
                .accessibilityLabel("Search secrets")
            if !query.isEmpty {
                Button { query = "" } label: { Image(systemName: "xmark.circle.fill") }
                    .buttonStyle(.plain)
                    .foregroundStyle(.secondary)
                    .accessibilityLabel("Clear search")
            }
            Button("⌘K") { searchFocused = true }
                .buttonStyle(.plain)
                .font(.caption2.weight(.semibold))
                .foregroundStyle(.secondary)
                .keyboardShortcut("k", modifiers: [.command])
                .accessibilityLabel("Focus search")
        }
        .padding(.horizontal, 10)
        .padding(.vertical, 8)
        .background(Color.black.opacity(0.12), in: RoundedRectangle(cornerRadius: 7, style: .continuous))
        .overlay { RoundedRectangle(cornerRadius: 7, style: .continuous).stroke(Color.primary.opacity(0.12)) }
    }

    private func filterPill(_ filter: SecretListFilter) -> some View {
        Button {
            listFilter = filter
        } label: {
            Label(filter.title, systemImage: filter.icon)
                .font(.caption.weight(.semibold))
                .frame(maxWidth: .infinity)
        }
        .buttonStyle(.borderless)
        .padding(.vertical, 5)
        .background(listFilter == filter ? Color.primary.opacity(0.12) : Color.clear, in: RoundedRectangle(cornerRadius: 6, style: .continuous))
        .accessibilityAddTraits(listFilter == filter ? .isSelected : [])
    }

    private func sortHeader(_ title: String, _ key: SecretSortKey, width: CGFloat? = nil) -> some View {
        Button {
            if sortKey == key {
                sortAscending.toggle()
            } else {
                sortKey = key
                sortAscending = true
            }
        } label: {
            HStack(spacing: 3) {
                Text(title).font(.caption2.weight(.bold))
                if sortKey == key {
                    Image(systemName: sortAscending ? "chevron.up" : "chevron.down")
                        .font(.system(size: 8, weight: .bold))
                }
            }
            .foregroundStyle(sortKey == key ? Color.primary : Color.secondary)
        }
        .buttonStyle(.plain)
        .frame(width: width, alignment: .leading)
        .accessibilityLabel("Sort by \(title)")
    }

    private func moveSelection(_ direction: MoveCommandDirection) {
        let entries = sortedEntries
        guard !entries.isEmpty else { return }
        guard let selectedEntryID, let currentIndex = entries.firstIndex(where: { $0.id == selectedEntryID }) else {
            self.selectedEntryID = entries.first?.id
            return
        }
        let nextIndex: Int
        switch direction {
        case .up:
            nextIndex = max(0, currentIndex - 1)
        case .down:
            nextIndex = min(entries.count - 1, currentIndex + 1)
        default:
            return
        }
        self.selectedEntryID = entries[nextIndex].id
    }

    private var emptySecretsState: some View {
        VStack(alignment: .leading, spacing: 8) {
            Image(systemName: model.state == .unlocked ? "magnifyingglass" : "lock.fill")
                .font(.title2)
                .foregroundStyle(.secondary)
            Text(
                model.state == .unlocked && !model.remoteValidationComplete
                    ? "Checking vault items…"
                    : model.entries.isEmpty
                        ? "No secrets discovered yet"
                        : "No matching secrets"
            )
            .font(.headline)
            Text(
                model.entries.isEmpty
                    ? "Create one here or add a value-free .secret.json to a project in ~/dev."
                    : "Try another search, tag, or filter. Entries with vault problems are flagged, not hidden."
            )
            .font(.caption)
            .foregroundStyle(.secondary)
            if !query.isEmpty || selectedTag != nil || listFilter != .all {
                Button("Clear filters") {
                    query = ""
                    selectedTag = nil
                    listFilter = .all
                }
                .buttonStyle(.bordered)
            }
        }
        .padding(.vertical, 20)
        .frame(maxWidth: .infinity, alignment: .leading)
    }

    private var settingsTab: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 14) {
                VStack(alignment: .leading, spacing: 2) {
                    Text("Settings").font(.title2.weight(.bold))
                    Text("Tune SecretBar to your security and accessibility preferences.")
                        .font(.caption)
                        .foregroundStyle(.secondary)
                }
                settingsSection("How to choose a secret") {
                    Text("Login")
                        .font(.callout.weight(.semibold))
                    Text("Use for API keys, passwords, tokens, or usernames. The value is the credential SecretBar copies or injects.")
                        .font(.caption)
                        .foregroundStyle(.secondary)
                    Text("Secure Note")
                        .font(.callout.weight(.semibold))
                    Text("Use for multiline sensitive material such as SSH keys, recovery codes, certificates, or private documents. Its Notes field is the secret value.")
                        .font(.caption)
                        .foregroundStyle(.secondary)
                    Text("Notes and source are metadata. Tags are local labels for finding secrets. TOTP appears only when the remote Login item has a TOTP seed.")
                        .font(.caption)
                        .foregroundStyle(.secondary)
                }
                settingsSection("Security") {
                    settingToggle("Hold to reveal values", isOn: Binding(get: { model.holdToReveal }, set: { model.holdToReveal = $0 }))
                    Text("When enabled, hold the eye button on a secret row to view its value. Values are never copied or recorded.")
                        .font(.caption)
                        .foregroundStyle(.secondary)
                }
                settingsSection("Clipboard") {
                    Picker("Clear copied values", selection: Binding(get: { model.clipboardClearSeconds }, set: { model.clipboardClearSeconds = $0 })) {
                        Text("Disabled").tag(0)
                        Text("30 seconds").tag(30)
                        Text("1 minute").tag(60)
                        Text("5 minutes").tag(300)
                    }
                    Text("Copy is immediate. SecretBar clears only if the clipboard has not changed since the copy.")
                        .font(.caption)
                        .foregroundStyle(.secondary)
                }
                settingsSection("Appearance and shortcuts") {
                    settingToggle("Show menu bar icon", isOn: Binding(get: { model.showInMenuBar }, set: { model.showInMenuBar = $0 }))
                    Text("When off, reopen SecretBar via Spotlight or the secretbar command. Changing this takes effect on next launch.")
                        .font(.caption)
                        .foregroundStyle(.secondary)
                    settingToggle("Show main window", isOn: Binding(get: { model.showMainWindow }, set: { model.showMainWindow = $0 }))
                        .disabled(!model.showInMenuBar)
                    Text(model.showInMenuBar
                        ? "Off by default. Closing the window keeps SecretBar running in the menu bar. Changing this takes effect on next launch."
                        : "The main window is required when the menu bar icon is disabled.")
                        .font(.caption)
                        .foregroundStyle(.secondary)
                    settingToggle("Enable pinned favorites", isOn: Binding(get: { model.pinsEnabled }, set: { model.pinsEnabled = $0 }))
                    settingToggle("Enable keyboard shortcuts", isOn: Binding(get: { model.shortcutsEnabled }, set: { model.shortcutsEnabled = $0 }))
                    Text("Shortcuts apply while SecretBar is open: ⌘1 Create, ⌘2 My Secrets, ⌘3 Settings.")
                        .font(.caption)
                        .foregroundStyle(.secondary)
                    Text("SecretBar follows macOS Reduce Transparency and Increase Contrast settings.")
                        .font(.caption)
                        .foregroundStyle(.secondary)
                }
                settingsSection("Project discovery") {
                    settingToggle("Detect the active repository", isOn: Binding(get: { model.autoDetectProject }, set: { model.autoDetectProject = $0 }))
                    if let contextPath = model.contextPath, !contextPath.isEmpty {
                        Text("Context: \(contextPath)").font(.caption).foregroundStyle(.secondary).lineLimit(1)
                    } else {
                        Text("Shell context has not reported a repository yet.").font(.caption).foregroundStyle(.secondary)
                    }
                    HStack {
                        Button("Open ~/dev") { openPath("\(homeDirectory())/dev") }
                        Button("Open global config") { openPath("\(homeDirectory())/.config/secret") }
                    }
                    ForEach(model.projects) { project in
                        HStack {
                            Text(project.isGlobal ? "Global" : project.name)
                            Spacer()
                            Button("Open") { openPath(project.configPath) }
                        }
                        .font(.caption)
                    }
                }
                settingsSection("Health") {
                    Stepper("Warn before expiry: \(model.expiryWarningDays) days", value: Binding(get: { model.expiryWarningDays }, set: { model.expiryWarningDays = $0 }), in: 1...365)
                    Button {
                        model.refreshHealth()
                    } label: {
                        Label("Run health check", systemImage: "stethoscope")
                    }
                    .disabled(model.remoteValidationInProgress)
                    if let healthCheckStatus = model.healthCheckStatus {
                        HStack(spacing: 6) {
                            if model.remoteValidationInProgress {
                                ProgressView().controlSize(.small)
                            } else {
                                Image(systemName: healthCheckStatus.contains("no issues") ? "checkmark.circle" : "info.circle")
                            }
                            Text(healthCheckStatus)
                        }
                        .font(.caption)
                        .foregroundStyle(.secondary)
                    }
                    if !model.problemDetails.isEmpty {
                        Button("Show health details") { model.showHealthDiagnostics() }
                    }
                }
                settingsSection("Usage history") {
                    if model.history.isEmpty {
                        Text("No usage recorded yet.").font(.caption).foregroundStyle(.secondary)
                    } else {
                        ForEach(Array(model.history.prefix(8))) { item in
                            HStack {
                                Text(item.command).font(.system(.caption, design: .monospaced)).frame(width: 52, alignment: .leading)
                                Text(item.target).font(.system(.caption, design: .monospaced)).lineLimit(1)
                                Spacer()
                                Text(formatHistoryDate(item.at)).font(.caption2).foregroundStyle(.secondary)
                            }
                        }
                        Button("Clear usage history", role: .destructive) { confirmClearHistory = true }
                    }
                    Text("Only aliases, actions, timestamps, and environments are stored; values are never recorded.")
                        .font(.caption)
                        .foregroundStyle(.secondary)
                }
                settingsSection("Diagnostics") {
                    HStack {
                        StatusDot(state: model.state)
                        Text(stateLabel)
                        Spacer()
                        Button("Refresh") { model.refreshEverything() }
                    }
                    if let sessionCreated = model.sessionCreated {
                        Text("Stored session: \(sessionCreated)").font(.caption).foregroundStyle(.secondary)
                    }
                    Button("Run secret doctor") { model.showHealthDiagnostics() }
                    if model.lastError != nil {
                        Button("Show last error") {
                            model.showError(title: "Last SecretBar error", message: model.lastError ?? "No error recorded.")
                        }
                    }
                }
                settingsSection("Application") {
                    Button("Quit SecretBar", role: .destructive) { NSApplication.shared.terminate(nil) }
                }
            }
        }
    }

    private func settingToggle(_ title: String, isOn: Binding<Bool>) -> some View {
        Toggle(title, isOn: isOn).toggleStyle(.switch)
    }

    private func settingsSection<Content: View>(_ title: String, @ViewBuilder content: () -> Content) -> some View {
        SecretBarSurface {
            VStack(alignment: .leading, spacing: 8) {
                Text(title).font(.headline)
                content()
            }
        }
    }

    private func sectionTitle(_ title: String) -> some View {
        Text(title).font(.caption2).foregroundStyle(.secondary)
    }

    private func entryCard(_ entry: AliasEntry) -> some View {
        let isSecureNote = entry.itemType == SecretItemType.secureNote.rawValue
        let health = model.health(for: entry)
        let isSelected = selectedEntryID == entry.id
        let isHovered = hoveredEntryID == entry.id
        let lastUsed = model.lastUsedDate(entry).map(formatDateShort) ?? "never"

        return HStack(spacing: 10) {
            HStack(spacing: 8) {
                Image(systemName: isSecureNote ? SecretItemType.secureNote.icon : SecretItemType.login.icon)
                    .font(.body.weight(.medium))
                    .foregroundStyle(.secondary)
                    .frame(width: 28, height: 28)
                    .background(Color.primary.opacity(0.08), in: RoundedRectangle(cornerRadius: 7, style: .continuous))
                    .accessibilityHidden(true)

                VStack(alignment: .leading, spacing: 2) {
                    HStack(spacing: 5) {
                        Text(entry.alias)
                            .font(.body.weight(.semibold))
                            .lineLimit(1)
                        if health != "OK" {
                            Image(systemName: "exclamationmark.triangle.fill")
                                .font(.caption2)
                                .foregroundStyle(.orange)
                                .help(health)
                        }
                        if model.pinsEnabled, model.pinnedIDs.contains(entry.id) {
                            Image(systemName: "pin.fill")
                                .font(.caption2)
                                .foregroundStyle(.secondary)
                            .accessibilityLabel("Pinned")
                        }
                    }
                    if model.revealingID == entry.id {
                        Group {
                            if let revealError = model.revealError {
                                Text(revealError)
                                    .foregroundStyle(.orange)
                            } else if model.revealedValue.isEmpty {
                                Text("Reading value…")
                                    .foregroundStyle(.secondary)
                            } else {
                                Text(model.revealedValue)
                                    .textSelection(.enabled)
                                    .lineLimit(3)
                                    .fixedSize(horizontal: false, vertical: true)
                            }
                        }
                        .font(.caption2.monospaced())
                    } else {
                        Text(entry.item).font(.caption2).foregroundStyle(.tertiary).lineLimit(1)
                    }
                }
            }
            .frame(maxWidth: .infinity, alignment: .leading)

            VStack(alignment: .leading, spacing: 1) {
                Text(entry.project).font(.caption2).lineLimit(1)
                if entry.environment != "prod" {
                    Text(entry.environment).font(.caption2).foregroundStyle(.tertiary).lineLimit(1)
                }
            }
            .frame(width: 104, alignment: .leading)

            Text(lastUsed)
                .font(.caption2.monospacedDigit())
                .foregroundStyle(.secondary)
                .frame(width: 92, alignment: .leading)

            HStack(spacing: 5) {
                if model.holdToReveal {
                    Button {} label: {
                        Image(systemName: model.revealingID == entry.id ? "eye.fill" : "eye")
                    }
                    .buttonStyle(.borderless)
                    .onLongPressGesture(minimumDuration: 0.35, maximumDistance: 24, pressing: { isPressing in
                        if isPressing {
                            model.beginReveal(entry)
                        } else {
                            model.endReveal(entry)
                        }
                    }, perform: {})
                    .accessibilityLabel("Hold to view \(entry.alias)")
                    .help("Hold to view value")
                }
                Button { model.copy(entry) } label: {
                    Image(systemName: "doc.on.doc")
                }
                .disabled(model.busy || model.state != .unlocked)
                .accessibilityLabel("Copy \(entry.alias)")
                .help("Copy value")

                Menu {
                    Button("Edit…") { editing = entry }
                        .disabled(model.busy || model.state != .unlocked)
                    if model.pinsEnabled {
                        Button(model.pinnedIDs.contains(entry.id) ? "Unpin" : "Pin") { model.togglePin(entry) }
                    }
                    if model.hasSource(entry) { Button("Open source URL") { model.openSource(entry) } }
                    if model.hasTOTP(entry) { Button("Copy current TOTP") { model.copyTOTP(entry) } }
                    Button("Rotate and copy new value") { rotating = entry }
                } label: {
                    Image(systemName: "ellipsis")
                }
                .menuStyle(.borderlessButton)
                .accessibilityLabel("More actions for \(entry.alias)")
            }
            .buttonStyle(.borderless)
            .opacity(isHovered ? 1 : 0.72)
            .frame(width: 82, alignment: .trailing)
        }
        .padding(.horizontal, 6)
        .padding(.vertical, 8)
        .background(
            isSelected
                ? Color.primary.opacity(0.12)
                : isHovered ? Color.primary.opacity(0.06) : Color.clear,
            in: RoundedRectangle(cornerRadius: 7, style: .continuous)
        )
        .overlay(alignment: .bottom) { Divider().opacity(0.55) }
        .contentShape(Rectangle())
        .accessibilityAddTraits(isSelected ? .isSelected : [])
        .accessibilityHint("Press Return to copy. Double-click to edit.")
        .onHover { hovering in
            if hovering {
                hoveredEntryID = entry.id
            } else if hoveredEntryID == entry.id {
                hoveredEntryID = nil
            }
        }
        .onTapGesture(count: 2) { editing = entry }
        .onTapGesture { selectedEntryID = entry.id }
        .contextMenu {
            if model.pinsEnabled { Button(model.pinnedIDs.contains(entry.id) ? "Unpin" : "Pin") { model.togglePin(entry) } }
            Button("Edit…") { editing = entry }
            if model.hasSource(entry) { Button("Open source URL") { model.openSource(entry) } }
            if model.hasTOTP(entry) { Button("Copy current TOTP") { model.copyTOTP(entry) } }
            Button("Rotate and copy new value") { rotating = entry }
        }
    }

    @ViewBuilder
    private var tabBar: some View {
        HStack(spacing: 0) {
            tabButton(.create, key: "1")
            tabButton(.secrets, key: "2")
            tabButton(.settings, key: "3")
        }
        .frame(maxWidth: .infinity)
        .padding(2)
        .background(Color.black.opacity(0.1), in: RoundedRectangle(cornerRadius: 8, style: .continuous))
    }

    @ViewBuilder
    private func tabButton(_ section: SecretBarTab, key: KeyEquivalent) -> some View {
        let button = Button {
            tab = section
        } label: {
            Label(section.title, systemImage: section.icon)
                .labelStyle(.titleAndIcon)
                .font(.caption.weight(.semibold))
                .frame(maxWidth: .infinity)
                .padding(.vertical, 6)
                .contentShape(Rectangle())
                .background(tab == section ? Color.primary.opacity(0.12) : Color.clear, in: RoundedRectangle(cornerRadius: 6, style: .continuous))
        }
        .buttonStyle(.plain)
        .frame(maxWidth: .infinity)
        .accessibilityAddTraits(tab == section ? .isSelected : [])
        .accessibilityLabel(section.title)
        if model.shortcutsEnabled {
            button.keyboardShortcut(key, modifiers: [.command])
        } else {
            button
        }
    }

    private var healthSummary: String {
        let total = model.problems.values.filter { $0 > 0 }.reduce(0, +)
        return "\(total) health problem\(total == 1 ? "" : "s")"
    }

    private func healthColor(_ value: String) -> Color {
        switch value {
        case "OK": return .secondary
        case "Expires soon": return .orange
        default: return .red
        }
    }

    private func formatHistoryDate(_ value: String) -> String {
        guard let date = parseDate(value) else { return value }
        return formatDate(date)
    }

    private func selectDetectedProjectIfNeeded() {
        if let detected = model.detectedProjectID, model.autoDetectProject {
            selectedProjectID = detected
        } else if selectedProjectID.isEmpty {
            selectedProjectID = model.projects.first(where: { $0.isGlobal })?.id ?? model.projects.first?.id ?? ""
        }
    }
}

@MainActor
final class SecretBarAppDelegate: NSObject, NSApplicationDelegate {
    let statusItemController = SecretBarStatusItemController()

    func applicationDidFinishLaunching(_ notification: Notification) {
        SecretBarModel.shared.start()
        let showInMenuBar = UserDefaults.standard.object(forKey: "secretbar.showInMenuBar") == nil
            ? true
            : UserDefaults.standard.bool(forKey: "secretbar.showInMenuBar")
        // LSUIElement keeps the Dock clean at launch (menu bar agent app). The
        // regular policy is only restored when the menu bar icon is disabled,
        // so that mode keeps the Dock as its entry point.
        NSApp.setActivationPolicy(showInMenuBar ? .accessory : .regular)
        if showInMenuBar {
            statusItemController.start(model: SecretBarModel.shared)
        }
        // Launchd/activation autostarts pass SECRETBAR_AUTOSTART=1; the app
        // should sit in the background then, not throw a window on screen.
        // A manual `open` (Spotlight, `secretbar`) keeps the window up.
        if ProcessInfo.processInfo.environment["SECRETBAR_AUTOSTART"] == "1" {
            DispatchQueue.main.asyncAfter(deadline: .now() + 0.4) { [weak self] in
                self?.mainWindow()?.orderOut(nil)
            }
        }
    }

    // Dock click with no visible windows brings the main window back. Only
    // reachable when the menu bar icon is disabled (.regular policy); with
    // the menu bar icon on the app runs as an accessory with no Dock icon.
    func applicationShouldHandleReopen(_ sender: NSApplication, hasVisibleWindows flag: Bool) -> Bool {
        if flag { return true }
        mainWindow()?.makeKeyAndOrderFront(nil)
        return false
    }

    func applicationShouldTerminateAfterLastWindowClosed(_ sender: NSApplication) -> Bool {
        false
    }

    private func mainWindow() -> NSWindow? {
        NSApp.windows.first { $0.title == "SecretBar" || $0.identifier?.rawValue.contains("main") == true }
    }
}

@main
enum SecretBarEntry {
    // The menu bar icon toggle needs a relaunch because SwiftUI Scene bodies
    // cannot conditionally include a MenuBarExtra reliably across toolchains;
    // choosing the layout here keeps each scene list unconditional.
    static func main() {
        let defaults = UserDefaults.standard
        let showInMenuBar = defaults.object(forKey: "secretbar.showInMenuBar") == nil
            ? true
            : defaults.bool(forKey: "secretbar.showInMenuBar")
        let showMainWindow = defaults.object(forKey: "secretbar.showMainWindow") == nil
            ? false
            : defaults.bool(forKey: "secretbar.showMainWindow")
        if showInMenuBar {
            if showMainWindow {
                SecretBarCombinedApp.main()
            } else {
                SecretBarMenuBarApp.main()
            }
        } else {
            SecretBarWindowApp.main()
        }
    }
}

private struct SecretBarMenuBarApp: App {
    @NSApplicationDelegateAdaptor(SecretBarAppDelegate.self) private var appDelegate
    @StateObject private var model = SecretBarModel.shared

    var body: some Scene {
        // The status item owns the only user-facing panel in this mode. The
        // empty scene keeps SwiftUI's App contract without registering a
        // Settings scene, whose default window can appear unexpectedly.
        _EmptyScene()
    }
}

private struct SecretBarWindowApp: App {
    @NSApplicationDelegateAdaptor(SecretBarAppDelegate.self) private var appDelegate
    @StateObject private var model = SecretBarModel.shared

    var body: some Scene {
        Window("SecretBar", id: "main") {
            SecretBarView().environmentObject(model)
        }
        .defaultSize(width: 640, height: 720)
    }
}

private struct SecretBarCombinedApp: App {
    @NSApplicationDelegateAdaptor(SecretBarAppDelegate.self) private var appDelegate
    @StateObject private var model = SecretBarModel.shared

    var body: some Scene {
        Window("SecretBar", id: "main") {
            SecretBarView().environmentObject(model)
        }
        .defaultSize(width: 640, height: 720)
    }
}
