import Foundation

// MARK: - Leak scan

/// `secret scan [paths…]` looks for configured secret values inside files and
/// reports the alias, file and line — never the value itself.
let scanSkipDirectories: Set<String> = [
    ".git", ".jj", ".build", ".swiftpm", "node_modules", "DerivedData",
    "dist", "build", ".next", ".turbo", ".cache", ".pnpm-store", "vendor",
    ".venv", "__pycache__", ".mypy_cache", "target",
]
let scanMaxFileBytes = 4 * 1024 * 1024
let scanMinValueLength = 6

struct ScanHit: Hashable {
    var path: String
    var line: Int
    var alias: String
}

func scanNeedles(_ loaded: LoadedConfig, _ onlyAliases: [String]) async -> [(alias: String, value: String)] {
    let names = onlyAliases.isEmpty ? loaded.ordered.map(\.alias) : onlyAliases
    let items = await vaultBackend.items()
    var needles: [(alias: String, value: String)] = []
    var seen = Set<String>()
    for alias in names {
        guard let definition = loaded.definitions[alias] else {
            if !onlyAliases.isEmpty {
                writeErr("secret scan: skipping \(alias) — not declared in any config\n")
            }
            continue
        }
        guard let value = resolveOptional(items, definition),
              value.count >= scanMinValueLength,
              value != "true", value != "false"
        else { continue }
        guard seen.insert(value).inserted else { continue }
        needles.append((alias, value))
    }
    return needles
}

func isBinary(_ data: Data) -> Bool {
    data.prefix(4096).contains(0)
}

func lineNumber(in data: Data, at offset: Int) -> Int {
    guard offset > 0 else { return 1 }
    var line = 1
    var index = 0
    while index < offset {
        if data[index] == 0x0A { line += 1 }
        index += 1
    }
    return line
}

func scanFile(
    path: String,
    needles: [(alias: String, value: String)],
    into hits: inout Set<ScanHit>
) -> Int {
    let fileManager = FileManager.default
    guard let attributes = try? fileManager.attributesOfItem(atPath: path) else { return 0 }
    guard (attributes[.type] as? FileAttributeType) == .typeRegular else { return 0 }
    guard let size = attributes[.size] as? NSNumber, size.intValue <= scanMaxFileBytes else { return 0 }
    guard let data = fileManager.contents(atPath: path), !isBinary(data) else { return 0 }
    var matched = 0
    for needle in needles where data.range(of: Data(needle.value.utf8)) != nil {
        var search = data.startIndex
        while search < data.endIndex, let range = data.range(of: Data(needle.value.utf8), in: search..<data.endIndex) {
            hits.insert(ScanHit(path: path, line: lineNumber(in: data, at: range.lowerBound), alias: needle.alias))
            matched += 1
            search = range.upperBound
        }
    }
    return matched
}

func walkForLeaks(
    _ path: String,
    needles: [(alias: String, value: String)],
    into hits: inout Set<ScanHit>,
    filesScanned: inout Int
) {
    let fileManager = FileManager.default
    var isDirectory: ObjCBool = false
    guard fileManager.fileExists(atPath: path, isDirectory: &isDirectory) else {
        writeErr("secret scan: no such path: \(path)\n")
        return
    }
    if !isDirectory.boolValue {
        filesScanned += 1
        _ = scanFile(path: path, needles: needles, into: &hits)
        return
    }
    let url = URL(fileURLWithPath: path)
    guard let entries = try? fileManager.contentsOfDirectory(
        at: url,
        includingPropertiesForKeys: [.isDirectoryKey, .isSymbolicLinkKey],
        options: []
    ) else { return }
    for entry in entries {
        let name = entry.lastPathComponent
        if scanSkipDirectories.contains(name) { continue }
        let values = try? entry.resourceValues(forKeys: [.isDirectoryKey, .isSymbolicLinkKey])
        if values?.isSymbolicLink == true { continue }
        if values?.isDirectory == true {
            walkForLeaks(entry.path, needles: needles, into: &hits, filesScanned: &filesScanned)
        } else {
            filesScanned += 1
            _ = scanFile(path: entry.path, needles: needles, into: &hits)
        }
    }
}

func scanSecrets(
    loaded: LoadedConfig,
    paths: [String],
    onlyAliases: [String],
    json: Bool
) async -> Int32 {
    let needles = await scanNeedles(loaded, onlyAliases)
    guard !needles.isEmpty else {
        warn("scan: no resolvable configured value to search for — unlock the vault or check the alias list")
        return 0
    }
    var hits = Set<ScanHit>()
    var filesScanned = 0
    for path in paths {
        walkForLeaks(path, needles: needles, into: &hits, filesScanned: &filesScanned)
    }
    let ordered = hits.sorted { $0.path == $1.path ? $0.line < $1.line : $0.path < $1.path }
    if json {
        let items = ordered.map { hit -> J in
            .obj([("path", .str(hit.path)), ("line", .num(Double(hit.line))), ("alias", .str(hit.alias))])
        }
        print(jStringify(.arr(items), pretty: false))
    } else {
        for hit in ordered {
            print("\(hit.path):\(hit.line)\talias=\(hit.alias)")
        }
    }
    if ordered.isEmpty {
        success("scan: no configured value found in \(filesScanned) file(s)")
        return 0
    }
    let files = Set(ordered.map(\.path)).count
    writeErr(errColor("31", "secret scan: \(ordered.count) match(es) for \(Set(ordered.map(\.alias)).count) alias(es) in \(files) of \(filesScanned) file(s) — remove the value and rotate it\n"))
    return 1
}
