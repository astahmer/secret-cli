import Foundation
#if canImport(Security)
import Security
#endif

/// macOS Keychain adapter. Stores each alias's primary secret as a generic
/// password item (account = item name) under a per-installation service name.
/// No sessions, no daemon, no network: reads are local and instant.
///
/// Limitations vs Bitwarden: one secret value per item (the primary field —
/// password/username/notes/first custom field), no TOTP, no sharing. Ideal
/// for low-sensitivity local-only secrets; set `"backend": "keychain"` in the
/// global config to select it.
struct KeychainBackend: VaultBackend {
    let id = "keychain"
    let displayName = "macOS Keychain"

    private var service: String {
        let configured = env("SECRET_KEYCHAIN_SERVICE") ?? ""
        return configured.isEmpty ? "dev.astahmer.secret" : configured
    }

    func authState() async -> (authenticated: Bool, unlocked: Bool) {
        (authenticated: true, unlocked: true)
    }

    func interactiveUnlock() async -> String { "" }
    func sessionValid(_ token: String) async -> Bool { true }
    func startSessionDaemon(token: String) async -> Bool { false }
    func stopSessionDaemon() {}
    func daemonSummary() async -> String { "n/a" }
    func lock() async {}
    func requireUnlocked() async {}

    func items() async -> [JSON]? {
        #if canImport(Security)
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecReturnAttributes as String: true,
            kSecReturnData as String: true,
            kSecMatchLimit as String: kSecMatchLimitAll,
        ]
        var result: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &result)
        if status == errSecItemNotFound { return [] }
        guard status == errSecSuccess, let list = result as? [[String: Any]] else { return nil }
        let isoFormatter = ISO8601DateFormatter()
        return list.compactMap { entry -> JSON? in
            guard let account = entry[kSecAttrAccount as String] as? String else { return nil }
            let value = (entry[kSecValueData as String] as? Data).flatMap { String(data: $0, encoding: .utf8) } ?? ""
            let created = (entry[kSecAttrCreationDate as String] as? Date).map(isoFormatter.string(from:)) ?? ""
            return [
                "id": account,
                "name": account,
                "creationDate": created,
                "login": ["password": value],
                "fields": [] as [JSON],
            ]
        }
        #else
        return nil
        #endif
    }

    func syncCache() async {}

    func totp(itemName: String) -> String {
        fail("the keychain backend does not support TOTP")
    }

    func createItem(_ payload: JSON) async {
        let name = payload["name"] as? String ?? ""
        guard !name.isEmpty else {
            fail("keychain backend requires an item name")
        }
        let value = primarySecret(from: payload)
        #if canImport(Security)
        var query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: name,
        ]
        SecItemDelete(query as CFDictionary)
        query[kSecValueData as String] = Data(value.utf8)
        query[kSecAttrAccessible as String] = kSecAttrAccessibleWhenUnlockedThisDeviceOnly
        let status = SecItemAdd(query as CFDictionary, nil)
        if status != errSecSuccess {
            fail("keychain add failed for \(name) (osstatus \(status))")
        }
        #endif
    }

    func updateItem(id: String, _ payload: JSON) async {
        let value = primarySecret(from: payload)
        #if canImport(Security)
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: id,
        ]
        let update: [String: Any] = [
            kSecValueData as String: Data(value.utf8),
        ]
        let status = SecItemUpdate(query as CFDictionary, update as CFDictionary)
        if status == errSecItemNotFound {
            fail("keychain item not found: \(id)")
        } else if status != errSecSuccess {
            fail("keychain update failed for \(id) (osstatus \(status))")
        }
        #endif
    }

    func deleteItem(id: String, fallbackName: String) async {
        #if canImport(Security)
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: id,
        ]
        SecItemDelete(query as CFDictionary)
        #endif
    }

    /// The canonical payload is Bitwarden-shaped; pick the first meaningful
    /// value (password → username → notes → first custom field).
    private func primarySecret(from payload: JSON) -> String {
        if let login = payload["login"] as? JSON {
            if let password = login["password"] as? String, !password.isEmpty { return password }
            if let username = login["username"] as? String, !username.isEmpty { return username }
        }
        if let notes = payload["notes"] as? String, !notes.isEmpty { return notes }
        if let fields = payload["fields"] as? [Any] {
            for case let field as JSON in fields {
                if let value = field["value"] as? String, !value.isEmpty { return value }
            }
        }
        return ""
    }
}
