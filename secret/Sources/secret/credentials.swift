import Foundation

// MARK: - Credential helpers

/// Git and Docker credential helpers over the same alias registry: a host (or
/// host/path) maps to an alias in the config's `integrations` block, so CI and
/// `docker login` read the vault instead of a copy in `~/.git-credentials` or
/// the Docker keychain.
///
/// ```json
/// {
///   "integrations": {
///     "git":    { "github.com": "GH_TOKEN", "gitlab.com/work": { "alias": "GITLAB_TOKEN", "username": "oauth2" } },
///     "docker": { "ghcr.io": "GHCR_TOKEN" }
///   }
/// }
/// ```

struct IntegrationTarget {
    var match: String
    var alias: String
    var username: String?
}

/// The scopes in precedence order, last wins (the same order `loadDefinitions`
/// merges them in).
func configScopePaths(selectedConfig: String?) -> [String] {
    [userConfigPath, selectedConfig ?? findProjectConfig(), findProjectLocalConfig()].compactMap { $0 }
}

func integrationTargets(_ kind: String, selectedConfig: String?) -> [IntegrationTarget] {
    var targets: [String: IntegrationTarget] = [:]
    for path in configScopePaths(selectedConfig: selectedConfig) where exists(path) {
        guard let config = readConfig(path) as J?, let entries = config.get("integrations")?.get(kind)?.pairs() else { continue }
        for (match, value) in entries {
            if let alias = value.string() {
                targets[match.lowercased()] = IntegrationTarget(match: match, alias: alias, username: nil)
                continue
            }
            guard let object = value.pairs() else { continue }
            var alias = ""
            var username: String?
            for (key, child) in object {
                switch key {
                case "alias": alias = child.string() ?? ""
                case "username": username = child.string()
                default: break
                }
            }
            if alias.isEmpty { fail("integration \(kind) entry '\(match)' needs an alias") }
            targets[match.lowercased()] = IntegrationTarget(match: match, alias: alias, username: username)
        }
    }
    return targets.values.sorted { $0.match < $1.match }
}

/// Host-only, then host/path prefix (longest match wins), then a `"*"` entry.
func matchIntegrationTarget(_ targets: [IntegrationTarget], host: String, path: String?) -> IntegrationTarget? {
    let host = host.lowercased()
    let trimmedPath = path?.trimmingCharacters(in: CharacterSet(charactersIn: "/"))
    let full = [host, trimmedPath].compactMap { $0 }.joined(separator: "/")
    let candidates = targets.filter { target in
        let match = target.match.lowercased()
        return match == host || match == full || (!match.isEmpty && full.hasPrefix(match.hasSuffix("/") ? match : match + "/"))
    }
    if let best = candidates.max(by: { $0.match.count < $1.match.count }) { return best }
    return targets.first { $0.match == "*" }
}

func integrationValue(alias: String, definition: SecretDefinition, items: [JSON]?) async -> String {
    let backend = backend(for: definition)
    await backend.requireUnlocked()
    guard let value = await backend.value(for: definition, items: backend.id == vaultBackend.id ? items : nil) else {
        fail("integration alias \(alias) has no readable value")
    }
    return value
}

func gitCredentialRequest() -> [String: String] {
    var fields: [String: String] = [:]
    while let line = readLine(strippingNewline: true) {
        if line.isEmpty { break }
        guard let separator = line.firstIndex(of: "=") else { continue }
        fields[String(line[..<separator])] = String(line[line.index(after: separator)...])
    }
    return fields
}

/// `secret git-credential get` answers the git credential protocol on stdout:
/// `username=…` and `password=…`. `store` and `erase` are accepted no-ops: the
/// value lives in the vault, so there is nothing to record or forget.
func runGitCredential(action: String, selectedConfig: String?) async {
    let request = gitCredentialRequest()
    switch action {
    case "get":
        guard let host = request["host"], !host.isEmpty else { fail("git-credential get needs a host=") }
        let hostname = host.split(separator: ":").first.map(String.init) ?? host
        let targets = integrationTargets("git", selectedConfig: selectedConfig)
        let target = matchIntegrationTarget(targets, host: host, path: request["path"])
            ?? matchIntegrationTarget(targets, host: hostname, path: request["path"])
        guard let target else {
            // No mapping is not a failure: git falls through to the next helper.
            exit(0)
        }
        let loaded = loadDefinitions(configPath: selectedConfig, environment: "prod", allowUnknownEnvironment: true)
        let definition = await definitionForRead(target.alias, loaded)
        let value = await integrationValue(alias: target.alias, definition: definition, items: await vaultBackend.items())
        let username = request["username"] ?? target.username ?? "x-access-token"
        recordHistory(entry: HistoryEntry(at: isoNow(), cmd: "git-credential", target: target.alias, env: "prod"))
        print("username=\(username)")
        print("password=\(value)")
    case "store", "erase":
        // The vault already holds the value; nothing to record or forget.
        exit(0)
    default:
        fail("git-credential expects get, store or erase (got \(action))")
    }
}

func dockerCredentialServerURL() -> String {
    guard let raw = readStdinAll().data(using: .utf8), let parsed = (try? JSONSerialization.jsonObject(with: raw)) as? [String: Any] else {
        fail("docker-credential expects a JSON object on stdin with ServerURL")
    }
    return (parsed["ServerURL"] as? String) ?? ""
}

func dockerCredentialLookup(server: String, selectedConfig: String?) async -> IntegrationTarget? {
    let targets = integrationTargets("docker", selectedConfig: selectedConfig)
    let candidates = [
        server,
        server.replacingOccurrences(of: "https://", with: ""),
        server.replacingOccurrences(of: "https://index.docker.io/v1/", with: "index.docker.io"),
    ]
    for candidate in candidates {
        let host = candidate.split(separator: "/").first.map(String.init) ?? candidate
        if let target = matchIntegrationTarget(targets, host: candidate, path: nil) ?? matchIntegrationTarget(targets, host: host, path: nil) {
            return target
        }
    }
    return nil
}

func runDockerCredential(action: String, selectedConfig: String?) async {
    switch action {
    case "get":
        let server = dockerCredentialServerURL()
        guard !server.isEmpty else { fail("docker-credential get needs a ServerURL") }
        guard let target = await dockerCredentialLookup(server: server, selectedConfig: selectedConfig) else {
            fail("no docker integration maps \(server) to an alias (add one under integrations.docker)")
        }
        let loaded = loadDefinitions(configPath: selectedConfig, environment: "prod", allowUnknownEnvironment: true)
        let definition = await definitionForRead(target.alias, loaded)
        let value = await integrationValue(alias: target.alias, definition: definition, items: await vaultBackend.items())
        recordHistory(entry: HistoryEntry(at: isoNow(), cmd: "docker-credential", target: target.alias, env: "prod"))
        let payload: [String: String] = [
            "ServerURL": server,
            "Username": target.username ?? "token",
            "Secret": value,
        ]
        let data = try? JSONSerialization.data(withJSONObject: payload, options: [.sortedKeys])
        print(String(data: data ?? Data(), encoding: .utf8) ?? "{}")
    case "list":
        var rows: [String: String] = [:]
        for target in integrationTargets("docker", selectedConfig: selectedConfig) where target.match != "*" {
            rows[target.match] = target.username ?? "token"
        }
        let data = try? JSONSerialization.data(withJSONObject: rows, options: [.sortedKeys])
        print(String(data: data ?? Data(), encoding: .utf8) ?? "{}")
    case "store", "erase":
        exit(0)
    default:
        fail("docker-credential expects get, list, store or erase (got \(action))")
    }
}
