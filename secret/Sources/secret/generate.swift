import Foundation
#if canImport(Darwin)
import Darwin
#elseif canImport(Glibc)
import Glibc
#endif

// MARK: - Generation

/// Stands in for the generator the comparison put us behind on (secretspec's
/// password/token/UUID/passphrase/hex kinds): one command that prints exactly
/// one value, so a caller can pipe it without a template.

enum SecretKind: String, CaseIterable {
    case password
    case token
    case hex
    case base64
    case uuid
    case passphrase

    static func parse(_ raw: String) -> SecretKind? {
        switch raw.lowercased() {
        case "password", "pw": return .password
        case "token", "api": return .token
        case "hex": return .hex
        case "base64", "b64": return .base64
        case "uuid", "guid": return .uuid
        case "passphrase", "diceware": return .passphrase
        default: return nil
        }
    }
}

let passwordUpper = Array("ABCDEFGHJKLMNPQRSTUVWXYZ")
let passwordLower = Array("abcdefghijkmnopqrstuvwxyz")
let passwordDigits = Array("23456789")
let passwordSymbols = Array("!@#$%^&*()-_=+[]{}")
let tokenAlphabet = Array("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789")

/// Uniformly random index below `bound`, drawn from the platform CSPRNG.
func secureRandomIndex(_ bound: Int) -> Int {
    precondition(bound > 0)
    var generator = SystemRandomNumberGenerator()
    return Int.random(in: 0..<bound, using: &generator)
}

func secureRandomBytes(_ count: Int) -> [UInt8] {
    var generator = SystemRandomNumberGenerator()
    return (0..<count).map { _ in UInt8.random(in: 0...255, using: &generator) }
}

func randomPassword(length: Int, symbols: Bool) -> String {
    // At least one of each required class, then fill and shuffle.
    var alphabet = passwordUpper + passwordLower + passwordDigits + (symbols ? passwordSymbols : [])
    var characters: [Character] = [
        passwordUpper[secureRandomIndex(passwordUpper.count)],
        passwordLower[secureRandomIndex(passwordLower.count)],
        passwordDigits[secureRandomIndex(passwordDigits.count)],
    ]
    if symbols { characters.append(passwordSymbols[secureRandomIndex(passwordSymbols.count)]) }
    if characters.count > length {
        characters = Array(characters.prefix(length))
        alphabet = passwordLower + passwordDigits
    }
    while characters.count < length {
        characters.append(alphabet[secureRandomIndex(alphabet.count)])
    }
    for index in stride(from: characters.count - 1, through: 1, by: -1) {
        characters.swapAt(index, secureRandomIndex(index + 1))
    }
    return String(characters)
}

func randomToken(length: Int) -> String {
    String((0..<length).map { _ in tokenAlphabet[secureRandomIndex(tokenAlphabet.count)] })
}

func randomHex(bytes: Int) -> String {
    secureRandomBytes(bytes).map { String(format: "%02x", $0) }.joined()
}

func randomBase64(bytes: Int) -> String {
    Data(secureRandomBytes(bytes)).base64EncodedString()
}

/// Words for passphrases: the system dictionary when present (14+ bits per
/// word), otherwise a compact built-in list.
func passphraseWords(count: Int, separator: String, mixInNumber: Bool) -> String {
    let words = dictionaryWords()
    var chosen: [String] = (0..<count).map { _ in words[secureRandomIndex(words.count)] }
    if mixInNumber, let position = chosen.indices.randomElement() {
        chosen[position] += String(Int.random(in: 10...99))
    }
    if let position = chosen.indices.randomElement(), let first = chosen[position].first {
        chosen[position] = first.uppercased() + chosen[position].dropFirst()
    }
    return chosen.joined(separator: separator)
}

var cachedDictionaryWords: [String]?

func dictionaryWords() -> [String] {
    if let cachedDictionaryWords { return cachedDictionaryWords }
    for path in ["/usr/share/dict/words", "/usr/dict/words"] {
        guard let text = readFile(path) else { continue }
        let words = text
            .split(whereSeparator: \.isNewline)
            .map { $0.trimmingCharacters(in: .whitespaces).lowercased() }
            .filter { word in word.count >= 4 && word.count <= 8 && word.allSatisfy { $0.isLetter && $0.isASCII } }
        if words.count >= 1024 {
            cachedDictionaryWords = words
            return words
        }
    }
    cachedDictionaryWords = fallbackPassphraseWords
    return fallbackPassphraseWords
}

let fallbackPassphraseWords: [String] = [
    "acorn", "amber", "anchor", "apple", "april", "arbor", "atlas", "autumn",
    "bamboo", "barrel", "basin", "beacon", "beetle", "bellow", "birch", "bishop",
    "blanket", "blossom", "boulder", "bramble", "breeze", "bridge", "bronze", "brook",
    "cabin", "cactus", "camera", "candle", "canoe", "canyon", "carbon", "carrot",
    "castle", "cedar", "cello", "cherry", "chimney", "cinder", "circle", "citrus",
    "clover", "cobalt", "coffee", "comet", "copper", "coral", "cotton", "crane",
    "crater", "crimson", "crystal", "cyclone", "dahlia", "daisy", "dawn", "delta",
    "denim", "desert", "diamond", "dolphin", "dragon", "drift", "dynamo", "eagle",
    "earth", "ember", "emerald", "engine", "falcon", "fathom", "feather", "fern",
    "fiber", "field", "fjord", "flame", "flint", "forest", "fossil", "fountain",
    "galaxy", "garden", "garnet", "geyser", "ginger", "glacier", "glider", "granite",
    "grove", "harbor", "hazel", "heron", "hollow", "horizon", "hunter", "indigo",
    "island", "ivory", "jade", "jasper", "jungle", "juniper", "kayak", "kernel",
    "kettle", "kitten", "lagoon", "lantern", "lattice", "lava", "lemon", "leopard",
    "lilac", "linen", "lizard", "lobster", "lotus", "lumber", "lunar", "lynx",
    "magnet", "mahogany", "mammoth", "maple", "marble", "marina", "meadow", "medal",
    "melon", "meteor", "minted", "mist", "monsoon", "moose", "mosaic", "moss",
    "nectar", "nickel", "night", "nimbus", "noble", "north", "nugget", "oasis",
    "ocean", "olive", "onyx", "opal", "orbit", "orchid", "osprey", "otter",
    "oxygen", "paddle", "palace", "palm", "panda", "pantry", "paper", "parrot",
    "pebble", "pelican", "penguin", "pepper", "petal", "phantom", "pigeon", "pillar",
    "pilot", "pine", "pioneer", "pixel", "planet", "plasma", "plum", "pollen",
    "poplar", "poppy", "prairie", "prism", "puffin", "pumpkin", "quartz", "quill",
    "rabbit", "radar", "rafter", "rain", "raven", "reef", "ripple", "river",
    "robin", "rocket", "rosemary", "ruby", "rudder", "rustic", "saddle", "saffron",
    "sage", "salmon", "sapphire", "scout", "sequoia", "shadow", "shell", "sierra",
    "silver", "slate", "solar", "sparrow", "spruce", "stellar", "stone", "storm",
    "summit", "sunset", "surge", "swallow", "sycamore", "tango", "teal", "temple",
    "thicket", "thistle", "thunder", "tiger", "timber", "topaz", "tower", "trail",
    "tulip", "tundra", "turquoise", "umber", "valley", "velvet", "vessel", "violet",
    "vortex", "wagtail", "walnut", "water", "weaver", "whale", "willow", "winter",
    "wolf", "wombat", "yarrow", "zenith", "zephyr", "zodiac",
]

/// One generated value for `secret generate`; the caller decides where it goes.
func generateSecret(kind: SecretKind, length: Int, words: Int, separator: String, symbols: Bool, number: Bool) -> String {
    switch kind {
    case .password: return randomPassword(length: length, symbols: symbols)
    case .token: return randomToken(length: length)
    case .hex: return randomHex(bytes: max(4, length / 2))
    case .base64: return randomBase64(bytes: max(8, length * 3 / 4))
    case .uuid: return UUID().uuidString.lowercased()
    case .passphrase: return passphraseWords(count: max(3, words), separator: separator, mixInNumber: number)
    }
}
