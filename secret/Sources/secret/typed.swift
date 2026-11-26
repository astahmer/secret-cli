import Foundation

// MARK: - Typed aliases

/// Optional declaration-level checks, the gap the typed-schema tools (varlock,
/// secretspec) cover: an alias may say what its value must look like, and
/// `env` / `run` refuse to hand a command a value that does not match.
///
/// ```json
/// { "STRIPE_KEY": { "item": "…", "field": "password", "expect": "string(startsWith=sk-)" },
///   "PORT":       { "item": "…", "field": "password", "expect": "port" },
///   "API_URL":    { "item": "…", "field": "password", "expect": "url" },
///   "MODE":       { "item": "…", "field": "password", "expect": "enum:dev,staging,prod" } }
/// ```
///
/// The check reports the alias and the failing rule, never the value.

struct TypedRule {
    var kind: String
    var argument: String?
}

func parseTypedRule(_ raw: String) -> TypedRule {
    let trimmed = raw.trimmingCharacters(in: .whitespaces)
    guard let open = trimmed.firstIndex(of: "("), trimmed.hasSuffix(")") else {
        if let colon = trimmed.firstIndex(of: ":"), trimmed[..<colon].lowercased() == "enum" {
            return TypedRule(kind: "enum", argument: String(trimmed[trimmed.index(after: colon)...]))
        }
        return TypedRule(kind: trimmed.lowercased(), argument: nil)
    }
    let kind = String(trimmed[..<open]).lowercased()
    let body = String(trimmed[trimmed.index(after: open)..<trimmed.index(before: trimmed.endIndex)])
    if let equals = body.firstIndex(of: "=") {
        return TypedRule(kind: kind, argument: "\(body[body.index(after: equals)...])")
    }
    return TypedRule(kind: kind, argument: body)
}

/// nil when the value satisfies the rule, otherwise a message naming the rule.
func typedRuleFailure(_ rule: TypedRule, value: String) -> String? {
    let trimmed = value.trimmingCharacters(in: .whitespaces)
    switch rule.kind {
    case "", "string":
        if let prefix = rule.argument, let equals = prefix.firstIndex(of: "=") {
            _ = equals
        }
        if let argument = rule.argument, argument.contains("=") {
            let parts = argument.split(separator: "=", maxSplits: 1).map(String.init)
            let operatorName = parts[0].lowercased()
            let expected = parts.count > 1 ? parts[1] : ""
            switch operatorName {
            case "startswith": return trimmed.hasPrefix(expected) ? nil : "must start with \(expected)"
            case "endswith": return trimmed.hasSuffix(expected) ? nil : "must end with \(expected)"
            case "contains": return trimmed.contains(expected) ? nil : "must contain \(expected)"
            case "length": return trimmed.count == Int(expected) ?? -1 ? nil : "must be \(expected) characters"
            default: return "unknown string rule \(operatorName)"
            }
        }
        return trimmed.isEmpty ? "must not be empty" : nil
    case "nonempty":
        return trimmed.isEmpty ? "must not be empty" : nil
    case "url":
        guard let url = URL(string: trimmed), let scheme = url.scheme, ["http", "https", "postgres", "postgresql", "redis", "mysql", "amqp", "file"].contains(scheme.lowercased()), url.host != nil || scheme == "file" else {
            return "must be a URL with a scheme and host"
        }
        return nil
    case "email":
        return trimmed.contains("@") && trimmed.contains(".") && !trimmed.contains(" ") ? nil : "must be an email address"
    case "port":
        guard let port = Int(trimmed), port >= 1, port <= 65535 else { return "must be a port number between 1 and 65535" }
        return nil
    case "number":
        return Double(trimmed) == nil ? "must be a number" : nil
    case "integer":
        return Int(trimmed) == nil ? "must be an integer" : nil
    case "boolean":
        return ["true", "false", "1", "0", "yes", "no"].contains(trimmed.lowercased()) ? nil : "must be true/false, 1/0 or yes/no"
    case "json":
        return parseJSONOrdered(trimmed) == nil ? "must be valid JSON" : nil
    case "base64":
        return Data(base64Encoded: trimmed) == nil ? "must be base64" : nil
    case "uuid":
        return UUID(uuidString: trimmed) == nil ? "must be a UUID" : nil
    case "enum":
        let allowed = (rule.argument ?? "").split(separator: ",").map { $0.trimmingCharacters(in: .whitespaces) }
        return allowed.contains(trimmed) ? nil : "must be one of \(allowed.joined(separator: ", "))"
    default:
        return "unknown type rule \(rule.kind) (use string, nonempty, url, email, port, number, integer, boolean, json, base64, uuid or enum:a,b)"
    }
}

/// Checked at the injection boundary: `env` and `run` fail before a command
/// sees a value that violates its declared type.
func requireTypedValue(_ definition: SecretDefinition, alias: String, value: String) {
    guard let raw = definition.type, !raw.isEmpty else { return }
    let rule = parseTypedRule(raw)
    guard let failure = typedRuleFailure(rule, value: value) else { return }
    fail("\(alias) does not match its declared type \(raw): \(failure)")
}

/// `lint` can check rule syntax without the vault.
func typedRuleIssues(alias: String, raw: String) -> [String] {
    let rule = parseTypedRule(raw)
    let known = ["string", "nonempty", "url", "email", "port", "number", "integer", "boolean", "json", "base64", "uuid", "enum"]
    guard known.contains(rule.kind) else { return ["\(alias): unknown type \(raw)"] }
    return []
}

/// An alias with a past `expiresAt` must not be injected: the value is the one
/// somebody meant to rotate. `--allow-expired` is the explicit override.
func requireNotExpired(_ definition: SecretDefinition, alias: String, allowed: Bool) {
    guard !allowed, let raw = definition.expiresAt, let expiry = parseExpiry(raw), expiry < Date() else { return }
    fail("\(alias) expired on \(raw): rotate it with 'secret rotate \(alias)' or extend it with 'secret edit \(alias) --expires-at <date>'; pass --allow-expired to inject it anyway")
}
