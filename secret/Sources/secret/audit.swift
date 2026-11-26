import Foundation
#if canImport(Darwin)
import Darwin
#elseif canImport(Glibc)
import Glibc
#endif

let secretVersion = "2.3.1"

// MARK: - Audit log

/// Command-wide audit context, filled by `run()` from `--caller`/`--reason`
/// (or `SECRET_CALLER`/`SECRET_REASON`). Records carry metadata only: values
/// are never written to the audit log.
struct AuditContext {
    var command = "help"
    var target = ""
    var environment = "prod"
    var caller: String?
    var reason: String?
    var source = "cli"
}

var auditContext = AuditContext()

/// `~/.local/state/secret/audit.log` (XDG state dir on macOS too, matching the
/// tool's other per-user state). Override with `SECRET_AUDIT_FILE`; disable with
/// `SECRET_NO_AUDIT=1`.
let auditDir = env("SECRET_AUDIT_DIR") ?? "\(home)/.local/state/secret"
let auditPath = env("SECRET_AUDIT_FILE") ?? "\(auditDir)/audit.log"
let auditMaxBytes = 5 * 1024 * 1024
let auditKeepFiles = 3
let auditErrorLimit = 300

func auditEnabled() -> Bool { env("SECRET_NO_AUDIT") != "1" }

func resolvedCaller(_ explicit: String?) -> String {
    if let explicit, !explicit.isEmpty { return explicit }
    if let fromEnv = env("SECRET_CALLER"), !fromEnv.isEmpty { return fromEnv }
    return "cli"
}

func resolvedReason(_ explicit: String?) -> String? {
    if let explicit, !explicit.isEmpty { return explicit }
    if let fromEnv = env("SECRET_REASON"), !fromEnv.isEmpty { return fromEnv }
    return nil
}

func auditText(_ text: String, limit: Int = 300) -> String {
    let trimmed = text.trimmingCharacters(in: .whitespacesAndNewlines)
    return trimmed.count <= limit ? trimmed : String(trimmed.prefix(limit))
}

func appendAll(_ fd: Int32, _ data: Data) {
    data.withUnsafeBytes { buffer in
        guard let base = buffer.baseAddress else { return }
        var written = 0
        while written < buffer.count {
            let result = write(fd, base.advanced(by: written), buffer.count - written)
            if result <= 0 { break }
            written += result
        }
    }
}

func rotateAuditIfNeeded(_ path: String) {
    let fileManager = FileManager.default
    guard let attributes = try? fileManager.attributesOfItem(atPath: path),
          let size = attributes[.size] as? NSNumber, size.intValue >= auditMaxBytes else { return }
    for index in stride(from: auditKeepFiles, through: 1, by: -1) {
        let destination = "\(path).\(index)"
        try? fileManager.removeItem(atPath: destination)
        let source = index == 1 ? path : "\(path).\(index - 1)"
        if fileManager.fileExists(atPath: source) {
            try? fileManager.moveItem(atPath: source, toPath: destination)
        }
    }
}

func auditWrite(
    outcome: String,
    error: String? = nil,
    command: String? = nil,
    target: String? = nil,
    environment: String? = nil
) {
    guard auditEnabled() else { return }
    let path = auditPath
    let directory = (path as NSString).deletingLastPathComponent
    let fileManager = FileManager.default
    if !fileManager.fileExists(atPath: directory) {
        try? fileManager.createDirectory(
            atPath: directory,
            withIntermediateDirectories: true,
            attributes: [.posixPermissions: 0o700]
        )
    }
    rotateAuditIfNeeded(path)
    var pairs: [(String, J)] = [
        ("v", .num(1)),
        ("at", .str(isoNow())),
        ("command", .str(command ?? auditContext.command)),
        ("target", .str(target ?? auditContext.target)),
        ("environment", .str(environment ?? auditContext.environment)),
        ("outcome", .str(outcome)),
        ("caller", .str(auditContext.caller ?? resolvedCaller(nil))),
        ("source", .str(auditContext.source)),
        ("cwd", .str(FileManager.default.currentDirectoryPath)),
        ("pid", .num(Double(getpid()))),
    ]
    if let reason = auditContext.reason, !reason.isEmpty {
        pairs.append(("reason", .str(auditText(reason))))
    }
    if let error, !error.isEmpty {
        pairs.append(("error", .str(auditText(error, limit: auditErrorLimit))))
    }
    let line = jStringify(J.obj(pairs), pretty: false) + "\n"
    let fd = open(path, O_CREAT | O_WRONLY | O_APPEND, 0o600)
    guard fd >= 0 else { return }
    defer { close(fd) }
    _ = fchmod(fd, 0o600)
    appendAll(fd, Data(line.utf8))
}

func printAudit(count: Int, json: Bool) {
    let fileManager = FileManager.default
    guard fileManager.fileExists(atPath: auditPath), let raw = readFile(auditPath) else {
        writeErr("secret audit: no records yet — run a secret command first\n")
        return
    }
    let lines = raw.split(separator: "\n").map(String.init).filter { !$0.isEmpty }
    let shown = Array(lines.suffix(max(0, count)))
    if json {
        let records = shown.compactMap { parseJSONOrdered($0) }
        print(jStringify(.arr(records), pretty: false))
        return
    }
    for line in shown {
        guard let record = parseJSONOrdered(line) else { continue }
        let at = record.get("at")?.string() ?? ""
        let caller = record.get("caller")?.string() ?? ""
        let command = record.get("command")?.string() ?? ""
        let target = record.get("target")?.string() ?? ""
        let outcome = record.get("outcome")?.string() ?? ""
        print("\(at)\t\(caller)\t\(command)\t\(target)\t\(outcome)")
    }
    writeErr("secret audit: last \(shown.count) of \(lines.count) record(s) from \(auditPath) (no values are ever logged)\n")
}
