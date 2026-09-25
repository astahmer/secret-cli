import Foundation
#if canImport(LocalAuthentication) && canImport(Security)
import LocalAuthentication
import Security
#endif

// Folded-in secret-unlock-helper: Touch ID-gated session caching, run
// in-process. The cache is a plain 0600 file under ~/.config/secret rather
// than an ACL-gated keychain item: keychain ACLs bind to the creating
// binary's signature, so every rebuild of the Nix packages triggered
// login-password prompts and silent access failures. The gate here is the
// LocalAuthentication evaluation performed immediately before any read.

let helperService = "secret-cli"
let helperAccount = "biometric-session"
let biometricCachePath = "\(configDir)/biometric-session"

func helperBinaryPath() -> String? {
    pathTo("secret-unlock-helper")
}

/// Best-effort removal of the legacy ACL-gated keychain item; it caused
/// per-signature password prompts after every rebuild.
func helperClearLegacyKeychain() {
    #if os(macOS)
    SecItemDelete([
        kSecClass as String: kSecClassGenericPassword,
        kSecAttrService as String: helperService,
        kSecAttrAccount as String: helperAccount,
    ] as CFDictionary)
    #endif
}

func helperClearSession() {
    try? FileManager.default.removeItem(atPath: biometricCachePath)
    helperClearLegacyKeychain()
}

func helperSessionStore(_ token: String) -> Bool {
    // A legacy secret-unlock-helper binary on PATH still wins (old installs,
    // test fixtures); delegate storage to it when present.
    if let helper = helperBinaryPath() {
        let r = runCommand(helper, ["store", token])
        if r.status == 0 { return true }
    }
    helperClearLegacyKeychain()
    return FileManager.default.createFile(
        atPath: biometricCachePath,
        contents: Data(token.utf8),
        attributes: [.posixPermissions: 0o600]
    )
}

func helperSessionRead() -> String? {
    // Legacy helper binary first (old installs, test fixtures).
    if let helper = helperBinaryPath() {
        let r = runCommand(helper, [])
        if r.status == 0 {
            let token = r.stdout.trimmingCharacters(in: .whitespacesAndNewlines)
            if !token.isEmpty { return token }
        }
    }
    guard let data = FileManager.default.contents(atPath: biometricCachePath), !data.isEmpty else {
        return nil
    }
    #if os(macOS)
    if env("SECRET_NO_BIOMETRICS") != nil { return nil }
    let context = LAContext()
    var authError: NSError?
    // Prefer finger-only; fall back to device auth on Macs without
    // biometrics enrolled so the cache remains usable.
    let policy: LAPolicy = context.canEvaluatePolicy(.deviceOwnerAuthenticationWithBiometrics, error: &authError)
        ? .deviceOwnerAuthenticationWithBiometrics
        : .deviceOwnerAuthentication
    guard context.canEvaluatePolicy(policy, error: &authError) else { return nil }
    let semaphore = DispatchSemaphore(value: 0)
    var authenticated = false
    context.evaluatePolicy(policy, localizedReason: "Unlock secrets with Touch ID") { granted, _ in
        authenticated = granted
        semaphore.signal()
    }
    if semaphore.wait(timeout: .now() + 60) == .timedOut {
        return nil
    }
    guard authenticated else { return nil }
    #endif
    return String(data: data, encoding: .utf8)
}

// Touch ID confirmation for dangerous mutations; falls back to a plain
// [y/N] prompt when biometrics are unavailable or disabled.
func touchIDAvailable() -> Bool {
    #if os(macOS)
    if env("SECRET_NO_BIOMETRICS") != nil { return false }
    return LAContext().canEvaluatePolicy(.deviceOwnerAuthentication, error: nil)
    #else
    return false
    #endif
}

func confirmTouchID(reason: String) -> Bool {
    #if os(macOS)
    let context = LAContext()
    var authError: NSError?
    guard context.canEvaluatePolicy(.deviceOwnerAuthentication, error: &authError) else {
        return false
    }
    let semaphore = DispatchSemaphore(value: 0)
    var granted = false
    context.evaluatePolicy(.deviceOwnerAuthentication, localizedReason: reason) { ok, _ in
        granted = ok
        semaphore.signal()
    }
    if semaphore.wait(timeout: .now() + 30) == .timedOut {
        return false
    }
    return granted
    #else
    return false
    #endif
}
