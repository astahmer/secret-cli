import Foundation

// Pluggable vault bridge. Bitwarden is currently the only adapter, but the
// command layer talks to vaults exclusively through this interface so other
// backends (pass, 1Password, macOS Keychain, ...) can slot in without
// touching command dispatch.
//
// Item payloads are backend-shaped JSON documents; the generic helpers in
// util.swift (itemFor/itemField/formatCreatedAt/valueFor) intentionally work
// on the Bitwarden item shape since it remains the canonical representation.

protocol VaultBackend {
    /// Stable identifier, matches the "backend" key in the global config.
    var id: String { get }
    /// Human-readable name for errors and help text.
    var displayName: String { get }

    // MARK: Session lifecycle

    func authState() async -> (authenticated: Bool, unlocked: Bool)
    /// Interactive master-secret prompt; returns a fresh session token.
    func interactiveUnlock() async -> String
    func sessionValid(_ token: String) async -> Bool
    /// Start the long-lived service holding an unlocked session, if the
    /// backend supports one. Returns false when unavailable or rejected.
    func startSessionDaemon(token: String) async -> Bool
    func stopSessionDaemon()
    /// Short label for diagnostics ("up"/"down").
    func daemonSummary() async -> String
    func lock() async
    func requireUnlocked() async

    // MARK: Read

    /// All items incl. metadata (name, id, creationDate, fields).
    func items() async -> [JSON]?
    func syncCache() async
    /// Current one-time code for an item's TOTP seed.
    func totp(itemName: String) -> String

    // MARK: Mutations (payloads are backend-shaped items)

    func createItem(_ payload: JSON) async
    func updateItem(id: String, _ payload: JSON) async
    func deleteItem(id: String, fallbackName: String) async
}

func runBwInput(_ args: [String], input: String) -> String {
    guard let bw = pathTo("bw") else { fail("could not run Bitwarden CLI (is 'bw' installed?)") }
    let r = runCommand(bw, args, input: input)
    if r.status != 0 {
        let detail = r.stderr.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty
            ? r.stdout.trimmingCharacters(in: .whitespacesAndNewlines)
            : r.stderr.trimmingCharacters(in: .whitespacesAndNewlines)
        fail("Bitwarden CLI request failed: \(detail.isEmpty ? "no output" : String(detail.prefix(300)))")
    }
    return r.stdout.trimmingCharacters(in: .whitespacesAndNewlines)
}


struct BitwardenBackend: VaultBackend {
    let id = "bitwarden"
    let displayName = "Bitwarden"

    func authState() async -> (authenticated: Bool, unlocked: Bool) {
        await currentAuthState()
    }

    func interactiveUnlock() async -> String {
        runBwUnlock()
    }

    func sessionValid(_ token: String) async -> Bool {
        let check = runCommand(pathTo("bw") ?? "bw", ["status"], env: envWithSession(token))
        return check.status == 0
            && jsonObject(check.stdout)?["status"] as? String == "unlocked"
    }

    func startSessionDaemon(token: String) async -> Bool {
        guard daemonEnabled() else { return false }
        return await daemonStart()
    }

    func stopSessionDaemon() {
        daemonStop()
    }

    func daemonSummary() async -> String {
        (await daemonStatus()) == "unlocked" ? "up" : "down"
    }

    func lock() async {
        runBw(["lock"])
        daemonStop()
    }

    func requireUnlocked() async {
        await bitwardenRequireUnlocked()
    }

    func items() async -> [JSON]? {
        await vaultItems()
    }

    func syncCache() async {
        if !(await daemonMutate(method: "POST", path: "/sync")) {
            runBw(["sync"])
            daemonStop()
        }
    }

    func totp(itemName: String) -> String {
        runBw(["get", "totp", itemName])
    }

    func createItem(_ payload: JSON) async {
        if !(await daemonMutate(method: "POST", path: "/object/item", payload: payload)) {
            runBwInput(["create", "item"], input: Data(jStringify(anyToJ(payload), pretty: false).utf8).base64EncodedString())
            daemonStop()
        }
    }

    func updateItem(id: String, _ payload: JSON) async {
        if !(await daemonMutate(method: "PUT", path: "/object/item/\(id)", payload: payload)) {
            runBwInput(["edit", "item", id], input: Data(jStringify(anyToJ(payload), pretty: false).utf8).base64EncodedString())
            daemonStop()
        }
    }

    func deleteItem(id: String, fallbackName: String) async {
        if !(await daemonMutate(method: "DELETE", path: "/object/item/\(id)")) {
            runBw(["delete", "item", fallbackName])
            daemonStop()
        }
    }
}

// MARK: - Backend selection

let availableBackends = ["bitwarden", "keychain"]

/// Selected once per invocation from the global config's top-level
/// `"backend"` key; defaults to Bitwarden.
func activeBackend() -> VaultBackend {
    let requested: String
    if let raw = try? String(contentsOfFile: userConfigPath, encoding: .utf8),
       let json = jsonObject(raw),
       let configured = json["backend"] as? String, !configured.isEmpty {
        requested = configured
    } else {
        requested = "bitwarden"
    }
    switch requested {
    case "bitwarden": return BitwardenBackend()
    case "keychain": return KeychainBackend()
    default:
        fail("unknown vault backend '\(requested)' (available: \(availableBackends.joined(separator: ", ")))")
    }
}

/// Process-wide backend instance; selection reads only a small local config
/// so lazy initialization stays cheap for non-vault commands.
let vaultBackend: VaultBackend = activeBackend()
