import Foundation

// Ordered JSON: TS object-key insertion order matters for CLI output
// (env/list/print rows), so configs are parsed into ordered key/value pairs.

enum J {
    indirect case obj([(String, J)])
    indirect case arr([J])
    case str(String)
    case num(Double)
    case bool(Bool)
    case null

    var isObject: Bool { if case .obj = self { return true } else { return false } }

    func get(_ key: String) -> J? {
        if case .obj(let pairs) = self { return pairs.first { $0.0 == key }?.1 }
        return nil
    }

    func pairs() -> [(String, J)]? {
        if case .obj(let pairs) = self { return pairs } else { return nil }
    }

    func items() -> [J]? {
        if case .arr(let items) = self { return items } else { return nil }
    }

    func string() -> String? {
        if case .str(let s) = self { return s } else { return nil }
    }

    var asDouble: Double? {
        if case .num(let n) = self { return n } else { return nil }
    }

    var asBool: Bool? {
        if case .bool(let b) = self { return b } else { return nil }
    }
}

func parseJSONOrdered(_ text: String) -> J? {
    let chars = Array(text)
    var i = 0

    func skipWS() {
        while i < chars.count {
            let c = chars[i]
            if c == " " || c == "\t" || c == "\n" || c == "\r" { i += 1 } else { break }
        }
    }

    func consume(_ word: String) -> Bool {
        let end = i + word.count
        guard end <= chars.count else { return false }
        if String(chars[i..<end]) == word {
            i = end
            return true
        }
        return false
    }

    func parseString() -> J? {
        i += 1
        var out = ""
        while i < chars.count {
            let c = chars[i]
            if c == "\"" {
                i += 1
                return .str(out)
            }
            if c == "\\" {
                i += 1
                guard i < chars.count else { return nil }
                switch chars[i] {
                case "\"": out += "\""; i += 1
                case "\\": out += "\\"; i += 1
                case "/": out += "/"; i += 1
                case "n": out += "\n"; i += 1
                case "t": out += "\t"; i += 1
                case "r": out += "\r"; i += 1
                case "b": out += "\u{8}"; i += 1
                case "f": out += "\u{C}"; i += 1
                case "u":
                    i += 1
                    guard i + 4 <= chars.count,
                          let scalar = UInt32(String(chars[i..<i + 4]), radix: 16),
                          let uni = Unicode.Scalar(scalar)
                    else { return nil }
                    out += String(Character(uni))
                    i += 4
                default: return nil
                }
            } else {
                out.append(c)
                i += 1
            }
        }
        return nil
    }

    func parseNumber() -> J? {
        let start = i
        if i < chars.count, chars[i] == "-" { i += 1 }
        while i < chars.count {
            let c = chars[i]
            if c.isNumber || c == "." || c == "e" || c == "E" || c == "+" || c == "-" {
                i += 1
            } else {
                break
            }
        }
        guard i > start, let d = Double(String(chars[start..<i])) else { return nil }
        return .num(d)
    }

    func parseValue() -> J? {
        skipWS()
        guard i < chars.count else { return nil }
        switch chars[i] {
        case "{": return parseObject()
        case "[": return parseArray()
        case "\"": return parseString()
        case "t": return consume("true") ? .bool(true) : nil
        case "f": return consume("false") ? .bool(false) : nil
        case "n": return consume("null") ? .null : nil
        default: return parseNumber()
        }
    }

    func parseArray() -> J? {
        i += 1
        var items: [J] = []
        skipWS()
        if i < chars.count, chars[i] == "]" { i += 1; return .arr(items) }
        while true {
            guard let value = parseValue() else { return nil }
            items.append(value)
            skipWS()
            guard i < chars.count else { return nil }
            if chars[i] == "," { i += 1; continue }
            if chars[i] == "]" { i += 1; return .arr(items) }
            return nil
        }
    }

    func parseObject() -> J? {
        i += 1
        var pairs: [(String, J)] = []
        skipWS()
        if i < chars.count, chars[i] == "}" { i += 1; return .obj(pairs) }
        while true {
            skipWS()
            guard i < chars.count, chars[i] == "\"", let key = parseString()?.string() else { return nil }
            skipWS()
            guard i < chars.count, chars[i] == ":" else { return nil }
            i += 1
            guard let value = parseValue() else { return nil }
            pairs.append((key, value))
            skipWS()
            guard i < chars.count else { return nil }
            if chars[i] == "," { i += 1; continue }
            if chars[i] == "}" { i += 1; return .obj(pairs) }
            return nil
        }
    }

    guard let value = parseValue() else { return nil }
    skipWS()
    return i == chars.count ? value : nil
}

// TS-style JSON stringify: 2-space indent, `"key": value` spacing.
func jStringify(_ j: J, pretty: Bool = true, indent: Int = 0) -> String {
    switch j {
    case .obj(let pairs):
        if pairs.isEmpty { return "{}" }
        if pretty {
            let pad = String(repeating: " ", count: indent)
            let inner = String(repeating: " ", count: indent + 2)
            let body = pairs
                .map { "\(inner)\"\(jsonEscape($0.0))\": \(jStringify($0.1, pretty: true, indent: indent + 2))" }
                .joined(separator: ",\n")
            return "{\n\(body)\n\(pad)}"
        }
        return "{" + pairs.map { "\"\(jsonEscape($0.0))\":\(jStringify($0.1, pretty: false))" }.joined(separator: ",") + "}"
    case .arr(let items):
        if items.isEmpty { return "[]" }
        if pretty {
            let pad = String(repeating: " ", count: indent)
            let inner = String(repeating: " ", count: indent + 2)
            let body = items
                .map { "\(inner)\(jStringify($0, pretty: true, indent: indent + 2))" }
                .joined(separator: ",\n")
            return "[\n\(body)\n\(pad)]"
        }
        return "[" + items.map { jStringify($0, pretty: false) }.joined(separator: ",") + "]"
    case .str(let s): return "\"\(jsonEscape(s))\""
    case .num(let n):
        if n == n.rounded(), abs(n) < 1e15 { return String(Int64(n)) }
        return String(n)
    case .bool(let b): return b ? "true" : "false"
    case .null: return "null"
    }
}

func jsonEscape(_ s: String) -> String {
    var out = ""
    for c in s {
        switch c {
        case "\"": out += "\\\""
        case "\\": out += "\\\\"
        case "\n": out += "\\n"
        case "\t": out += "\\t"
        case "\r": out += "\\r"
        default:
            if c.unicodeScalars.allSatisfy({ $0.value < 0x20 }) {
                out += String(format: "\\u%04x", c.unicodeScalars.first?.value ?? 0)
            } else {
                out.append(c)
            }
        }
    }
    return out
}

func jToAny(_ j: J) -> Any {
    switch j {
    case .obj(let pairs): return Dictionary(uniqueKeysWithValues: pairs.map { ($0.0, jToAny($0.1)) })
    case .arr(let items): return items.map(jToAny)
    case .str(let s): return s
    case .num(let n): return n
    case .bool(let b): return b
    case .null: return NSNull()
    }
}

// JSONSerialization escapes "/" as "\/" (valid but unlike TS JSON.stringify);
// payloads that the fake bw/daemon log by substring must use this writer.
func anyToJ(_ value: Any) -> J {
    if let dict = value as? JSON {
        return .obj(dict.keys.sorted().map { ($0, anyToJ(dict[$0]!)) })
    }
    if let array = value as? [Any] {
        return .arr(array.map(anyToJ))
    }
    if let string = value as? String { return .str(string) }
    if value is NSNull { return .null }
    if let number = value as? NSNumber {
        if CFGetTypeID(number) == CFBooleanGetTypeID() { return .bool(number.boolValue) }
        return .num(number.doubleValue)
    }
    return .null
}
