import Foundation

// 1Password adapter. Items are read and written through the official `op`
// CLI, so every operation inherits its auth model (`op signin`, service
// accounts, Touch ID via the app integration, OP_SERVICE_ACCOUNT_TOKEN).
//
// Item references follow the `op://vault/item/field` grammar already used by
// everything else in the 1Password ecosystem, so a config that names
// `op://Personal/OpenAI/api_key` reads the same item `op` documents, and
// `item` values that are plain names resolve in the default vault.
//
// Payloads crossing this adapter stay in the canonical Bitwarden item shape
// (name/id/login.password/notes/fields) so the command layer is unchanged;
// the translation happens here, in both directions.

let opDefaultVault = "Private"

struct OnePasswordBackend: VaultBackend {
    let id = "1password"
    let displayName = "1Password"

    private var vault: String {
        let configured = env("SECRET_ONEPASSWORD_VAULT") ?? ""
        return configured.isEmpty ? opDefaultVault : configured
    }

    // MARK: - op invocation

    private func requireOp() -> String {
        guard let op = pathTo("op") else {
            fail("1Password CLI (op) was not found on PATH — install it from https://developer.1password.com/docs/cli/ or `brew install 1password-cli`")
        }
        return op
    }

    /// Runs `op` with the inherited environment; a missing session or a
    /// rejected one surfaces as `op`'s own message, which names the fix.
    private func runOp(_ args: [String], input: String? = nil) -> String {
        let op = requireOp()
        let result = runCommand(op, args, input: input)
        guard result.status == 0 else {
            let detail = result.stderr.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty
                ? result.stdout.trimmingCharacters(in: .whitespacesAndNewlines)
                : result.stderr.trimmingCharacters(in: .whitespacesAndNewlines)
            fail("1Password CLI request failed: \(detail.isEmpty ? "no output" : String(detail.prefix(300)))")
        }
        return result.stdout
    }

    /// `op item list/item get` JSON is a superset of the canonical shape:
    /// `id`, `title`, `created_at`, `vault`, `fields[]`. Map it once, here.
    private func canonical(_ raw: JSON) -> JSON {
        var item: JSON = [:]
        if let id = raw["id"] as? String { item["id"] = id }
        let title = (raw["title"] as? String) ?? (raw["name"] as? String) ?? ""
        item["name"] = title
        item["title"] = title
        if let created = raw["created_at"] as? String { item["creationDate"] = created }
        if let vaultName = (raw["vault"] as? JSON)?["name"] as? String { item["vault"] = vaultName }
        var login: JSON = [:]
        var custom: [Any] = []
        for case let field as JSON in (raw["fields"] as? [Any]) ?? [] {
            guard let label = field["label"] as? String else { continue }
            let value = (field["value"] as? String) ?? ""
            let section = ((field["section"] as? JSON)?["label"] as? String) ?? ""
            switch (section, label) {
            case ("", "username"), ("", "user name"): login["username"] = value
            case ("", "password"): login["password"] = value
            case ("", "notesPlain"): item["notes"] = value
            default: custom.append(["name": label, "value": value, "type": 0])
            }
        }
        if !login.isEmpty { item["login"] = login }
        if !custom.isEmpty { item["fields"] = custom }
        return item
    }

    private func reference(_ itemName: String, field: String) -> String {
        // A config may already carry a full `op://` reference; anything else is
        // a title in the configured (or default) vault.
        if itemName.hasPrefix("op://") { return field == "password" ? itemName : "\(itemName)/\(field)" }
        let fieldRef = field == "password" ? "password" : field.hasPrefix("custom:") ? String(field.dropFirst(7)) : field
        return "op://\(vault)/\(itemName)/\(fieldRef)"
    }

    // MARK: - Session lifecycle

    /// `op` owns sign-in. A successful read proves the session; there is no
    /// separate lock the CLI could hold, so unlock is a no-op that reports why.
    func authState() async -> (authenticated: Bool, unlocked: Bool) {
        guard let op = pathTo("op") else { return (authenticated: false, unlocked: false) }
        let result = runCommand(op, ["vault", "list", "--format=json"])
        let ok = result.status == 0
        return (authenticated: ok, unlocked: ok)
    }

    func interactiveUnlock() async -> String { "" }
    func sessionValid(_ token: String) async -> Bool { token.isEmpty }
    func startSessionDaemon(token: String) async -> Bool { false }
    func stopSessionDaemon() {}
    func daemonSummary() async -> String { "n/a" }
    func lock() async {
        _ = pathTo("op").map { runCommand($0, ["signout"]) }
    }

    func requireUnlocked() async {
        guard let op = pathTo("op") else {
            fail("1Password CLI (op) was not found on PATH — install it from https://developer.1password.com/docs/cli/")
        }
        let result = runCommand(op, ["vault", "list", "--format=json"])
        guard result.status == 0 else {
            let detail = result.stderr.trimmingCharacters(in: .whitespacesAndNewlines)
            fail("1Password is not unlocked (\(String(detail.prefix(200)))) — run 'op signin', or set OP_SERVICE_ACCOUNT_TOKEN for automation")
        }
    }

    // MARK: - Read

    func items() async -> [JSON]? {
        guard let op = pathTo("op") else { return nil }
        let listed = runCommand(op, ["item", "list", "--format=json"])
        guard listed.status == 0 else { return nil }
        guard let rows = jsonParse(listed.stdout) as? [Any] else { return nil }
        // Metadata only: values are read per alias through `value(for:)`, so a
        // listing never fetches one item per row.
        return rows.compactMap { $0 as? JSON }.map(canonical)
    }

    func syncCache() async {}

    /// `op://vault/title/field` references resolve through `op read`, the
    /// documented single-value read: a config can point at any 1Password item
    /// without exporting or copying vault values into the config.
    func value(for definition: SecretDefinition, items: [JSON]?) async -> String? {
        _ = items
        guard let op = pathTo("op") else { return nil }
        let target = reference(definition.item, field: definition.field ?? "password")
        let result = runCommand(op, ["read", target])
        let value = result.stdout.trimmingCharacters(in: .whitespacesAndNewlines)
        guard result.status == 0, !value.isEmpty, !placeholderValues.contains(value) else { return nil }
        return value
    }

    func totp(itemName: String) -> String {
        // `op item get <ref> --otp` accepts the same `op://` reference as reads.
        let target = itemName.hasPrefix("op://") ? itemName.split(separator: "/").prefix(4).joined(separator: "/") : "op://\(vault)/\(itemName)"
        return runOp(["item", "get", target, "--otp"]).trimmingCharacters(in: .whitespacesAndNewlines)
    }

    // MARK: - Mutations

    /// `op item create` then, when a field isn't the password, `op item edit`
    /// for the remaining fields: the CLI's create template only carries the
    /// login's password inline.
    func createItem(_ payload: JSON) async {
        let name = payload["name"] as? String ?? ""
        guard !name.isEmpty else { fail("1Password backend requires an item title") }
        // A config that names an existing `op://` item is editing that item,
        // not creating a new one: the reference is the address.
        if name.hasPrefix("op://") {
            let segments = name.split(separator: "/").map(String.init)
            if let title = segments.count >= 3 ? segments[2] : nil {
                let edits = editArguments(payload, skippingPassword: false)
                if !edits.isEmpty { _ = runOp(["item", "edit", title, "--vault", vault] + edits) }
                return
            }
        }
        let password = (payload["login"] as? JSON)?["password"] as? String
        var args = ["item", "create", "--category=login", "--title", name, "--vault", vault, "--format=json"]
        if let password, !password.isEmpty { args.append("--password=\(password)") }
        let created = runOp(args)
        guard let raw = jsonParse(created) as? JSON, let id = raw["id"] as? String else { return }
        let edits = editArguments(payload, skippingPassword: true)
        if !edits.isEmpty { _ = runOp(["item", "edit", id, "--vault", vault] + edits) }
    }

    func updateItem(id: String, _ payload: JSON) async {
        let edits = editArguments(payload, skippingPassword: false)
        guard !edits.isEmpty else { return }
        _ = runOp(["item", "edit", id, "--vault", vault] + edits)
    }

    func deleteItem(id: String, fallbackName: String) async {
        _ = runOp(["item", "delete", id, "--vault", vault])
    }

    private func editArguments(_ payload: JSON, skippingPassword: Bool) -> [String] {
        var args: [String] = []
        if let username = (payload["login"] as? JSON)?["username"] as? String, !username.isEmpty {
            args.append("username=\(username)")
        }
        if skippingPassword == false, let password = (payload["login"] as? JSON)?["password"] as? String, !password.isEmpty {
            args.append("password=\(password)")
        }
        if let notes = payload["notes"] as? String, !notes.isEmpty {
            args.append("notesPlain=\(notes)")
        }
        for case let field as JSON in ((payload["fields"] as? [Any]) ?? []) {
            guard let name = field["name"] as? String, let value = field["value"] as? String else { continue }
            args.append("\(name)[text]=\(value)")
        }
        return args
    }
}
