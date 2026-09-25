import Foundation
#if canImport(Darwin)
import Darwin
#elseif canImport(Glibc)
import Glibc
#endif

// Like Node, do not die when a downstream pipe (e.g. `secret ... | head`)
// closes early: writes then just fail silently.
signal(SIGPIPE, SIG_IGN)

// MARK: - Options

struct Options {
    var command: String = "help"
    var positional: [String] = []
    var configPath: String?
    var outputPath: String?
    var envName: String?
    var required: [String] = []
    var optional: [String] = []
    var copy = false
    var check = false
    var generate = false
    var force = false
    var export = false
    var json = false
    var all = false
    var diff = false
    var dry = false
    var dryRun = false
    var merge = false
    var source: String?
    var name: String?
    var notes: String?
    var field: String?
    var itemType: String?
    var expiresAt: String?
    var tags: String?
    var valueStdin = false
    var openURL = false
    var global = false
    var helper = false
    var store = false
    var sessionStdin = false
    var ci = false
}

let commandAliases: [String: String] = [
    "st": "status",
    "ls": "list",
    "check": "doctor",
    "g": "get",
    "s": "set",
    "add": "set",
    "delete": "rm",
    "remove": "rm",
    "sync": "pull",
    "so": "source",
    "pu": "pull",
    "e": "env",
    "d": "doctor",
    "pr": "print",
]

func configPathValue(_ value: String) -> String {
    if value.hasPrefix("/") { return value }
    return URL(fileURLWithPath: value, relativeTo: URL(fileURLWithPath: FileManager.default.currentDirectoryPath))
        .standardizedFileURL.path
}

func parseOptions(_ argv: [String]) -> Options {
    var options = Options()
    var positional: [String] = []
    var selectedConfig: String?
    var outputPath: String?
    var selectedEnv: String?
    var required: [String] = []
    var optional: [String] = []

    var index = 0
    while index < argv.count {
        let argument = argv[index]
        if argument == "--config" {
            index += 1
            guard index < argv.count else { fail("--config requires a file path") }
            selectedConfig = configPathValue(argv[index])
        } else if argument == "--output" {
            index += 1
            guard index < argv.count else { fail("--output requires a file path") }
            outputPath = configPathValue(argv[index])
        } else if argument == "--env" {
            index += 1
            guard index < argv.count else { fail("--env requires a name") }
            let value = argv[index]
            if value.range(of: "^[A-Za-z0-9_-]+$", options: .regularExpression) == nil {
                fail("invalid environment name: \(value)")
            }
            selectedEnv = value
        } else if argument == "--required" {
            index += 1
            guard index < argv.count else { fail("--required needs alias names") }
            required += argv[index].split(separator: ",").map {
                $0.trimmingCharacters(in: .whitespaces)
            }.filter { !$0.isEmpty }
        } else if argument == "--optional" {
            index += 1
            guard index < argv.count else { fail("--optional needs alias names") }
            optional += argv[index].split(separator: ",").map {
                $0.trimmingCharacters(in: .whitespaces)
            }.filter { !$0.isEmpty }
        } else if argument == "--copy" {
            options.copy = true
        } else if argument == "--check" {
            options.check = true
        } else if argument == "--generate" {
            options.generate = true
        } else if argument == "--force" || argument == "-f" {
            options.force = true
        } else if argument == "--global" || argument == "-g" {
            options.global = true
        } else if argument == "--helper" {
            options.helper = true
        } else if argument == "--session-stdin" {
            options.sessionStdin = true
        } else if argument == "--ci" {
            options.ci = true
        } else if argument == "--export" {
            options.export = true
        } else if argument == "--json" {
            options.json = true
        } else if argument == "--all" {
            options.all = true
        } else if argument == "--diff" {
            options.diff = true
        } else if argument == "--dry" {
            options.dry = true
        } else if argument == "--dry-run" {
            options.dryRun = true
        } else if argument == "--merge" {
            options.merge = true
        } else if argument == "--source" {
            index += 1
            guard index < argv.count else { fail("--source requires a URL") }
            options.source = argv[index]
        } else if argument == "--name" {
            index += 1
            guard index < argv.count else { fail("--name requires an item name") }
            options.name = argv[index]
        } else if argument == "--notes" {
            index += 1
            guard index < argv.count else { fail("--notes requires text (use an empty string to clear notes)") }
            options.notes = argv[index]
        } else if argument == "--field" {
            index += 1
            guard index < argv.count else { fail("--field requires a field name") }
            options.field = argv[index]
        } else if argument == "--type" {
            index += 1
            guard index < argv.count else { fail("--type requires login or secure-note") }
            options.itemType = argv[index]
        } else if argument == "--expires-at" {
            index += 1
            guard index < argv.count else { fail("--expires-at requires an ISO date") }
            options.expiresAt = argv[index]
        } else if argument == "--tags" {
            index += 1
            guard index < argv.count else { fail("--tags requires comma-separated names") }
            options.tags = argv[index]
        } else if argument == "--value-stdin" {
            options.valueStdin = true
        } else if argument == "--open" {
            options.openURL = true
        } else if argument == "--store" {
            options.store = true
        } else if argument == "-h" || argument == "--help" {
            positional.append(argument)
        } else if argument == "--" {
            positional += argv[(index + 1)...]
            break
        } else if argument.hasPrefix("--") {
            fail("unknown option: \(argument)")
        } else {
            positional.append(argument)
        }
        index += 1
    }

    options.command = positional.first ?? "help"
    options.positional = Array(positional.dropFirst())
    options.configPath = selectedConfig
    options.outputPath = outputPath
    options.envName = selectedEnv
    options.required = required
    options.optional = optional
    return options
}

// MARK: - Help

let commandHelpText: [String: String] = [
    "status": """
    Usage: secret status [--check]

    Check Bitwarden auth state and print the next command to run.

      --check   Exit nonzero when not unlocked
    """,
    "unlock": """
    Usage: secret unlock [--store]

    Unlock and print a session token. A session already present in the
    environment (e.g. the one bw login prints) is reused without prompting.

      --store   Persist the session (macOS keychain, or ~/.config/secret/session)
      --helper  Get the session via Touch ID (macOS; built in, no extra binary)

    Run 'secret unlock --store' once to cache the session; afterwards
    'secret unlock --helper' unlocks with Touch ID instead of the master
    password.
    """,
    "lock": """
    Usage: secret lock

    Lock the vault, clear any stored session, and stop the daemon.
    """,
    "list": """
    Usage: secret list [--env NAME] [--json]

    List configured aliases. Created dates are fetched only on a TTY.

      --env NAME   Environment overrides (default: prod)
      --json       Machine-readable rows on stdout
    """,
    "search": """
    Usage: secret search <term> [--json]

    Find aliases by alias, item, or env key across scopes (no values).
    """,
    "get": """
    Usage: secret get <alias> [--copy] [--env NAME]

    Print exactly one configured value.

      --copy       Copy to the clipboard instead of stdout
      --env NAME   Environment override (default: prod)
    """,
    "set": """
    Usage: secret set [<alias>] [--generate] [--force] [--source URL] [--name NAME] [--notes TEXT] [--type login|secure-note] [--expires-at DATE] [--tags TAGS] [--global]

    Prompt (hidden) for a value and write it to Bitwarden. A missing alias is
    added to the project config and created in the vault; with no alias at all,
    you are prompted for one.

      --generate   Generate a random password instead of prompting
      --force, -f  Overwrite an existing item without confirmation
      --source URL Attach a source URL (stored as a custom "source" field)
      --type TYPE  Create or update a Bitwarden Login or Secure Note item
      --expires-at DATE  Store an ISO expiry date in the config for health warnings
      --tags TAGS  Store comma-separated app tags in the config
      --global, -g Add a new alias to the global config instead of the project one
    """,
    "edit": """
    Usage: secret edit [<alias>] [--name NAME] [--field FIELD] [--source URL] [--notes TEXT] [--tags TAGS] [--force]

    Edit one or more Bitwarden item fields or local alias tags without changing the configured alias.
    With no field flags, prompt for name, value, source, notes, or a custom field.
    Use --value-stdin for a non-interactive value update.
    """,
    "id": """
    Usage: secret id <alias>

    Print the resolved Bitwarden item id (no value).
    """,
    "totp": """
    Usage: secret totp <alias> [--copy]

    Print the current TOTP code.
    """,
    "source": """
    Usage: secret source <alias> [url] [--open]

    Print the secret's source URL (a custom "source" field on the vault item),
    or set it when a url is given. --open opens the URL in the browser.
    """,
    "pull": """
    Usage: secret pull

    Refresh the local vault cache from the server (bw sync).
    """,
    "pin": """
    Usage: secret pin <alias>

    Replace the config item name with its resolved id.
    """,
    "rotate": """
    Usage: secret rotate <alias> [--force] [--copy]

    Generate a new password and overwrite the item; delivers the new value.
    """,
    "rm": """
    Usage: secret rm <alias> [--force] [--global]

    Delete the vault item (config entry kept). Falls back to unsetting the alias
    when the item does not exist in the vault. --global unsets from the global
    config instead of the project one.
    """,
    "unset": """
    Usage: secret unset <alias> [--global]

    Remove an alias from the project config (or the global config with --global).
    """,
    "mv": """
    Usage: secret mv <alias> <new>

    Rename an alias in the project or user config.
    """,
    "init": """
    Usage: secret init [--force] [alias..]

    Scaffold a .secret.json template; optional aliases to prefill.
    """,
    "env": """
    Usage: secret env [--output FILE] [--env NAME] [--export] [--merge] [--diff|--dry|--dry-run] [--required a,b,c] [--optional a,b,c]

    Generate dotenv from the project config. Strict by default: every alias must
    resolve. Pass --optional to warn-and-skip unresolved aliases.

      --output FILE     Atomically write the dotenv to FILE (mode 0600)
      --env NAME        Environment overrides (default: prod)
      --export          Print shell export lines instead of dotenv
                        (direnv: put `eval "$(secret env --export)"` in .envrc)
      --merge           Upsert alias keys into an existing dotenv; keep other keys
                        (--output defaults to ./.env). Incompatible with --export.
      --diff, --dry, --dry-run
                        Show key-level added/changed/removed without printing values
      --required a,b,c  Fail unless these aliases are in the config
      --optional a,b,c  Warn and skip aliases that cannot resolve
    """,
    "run": """
    Usage: secret run [--optional a,b,c] -- <cmd...>

    Inject project aliases into a command's environment. Strict by default;
    --optional warns and skips unresolved aliases.

    Leak guard: everything the command writes to stdout/stderr is filtered,
    replacing known secret values with [scrubbed] before it reaches the
    terminal or logs.
    """,
    "print": """
    Usage: secret print [project|global|local] [--all] [--json]

    Show aliases without touching the vault.
    """,
    "global": """
    Usage: secret global [add|unset <alias>] [--json]

    Show the global (user) scope aliases (same as secret print global), or
    delegate: secret global add <alias> = secret set --global <alias>, and
    secret global unset <alias> = secret unset --global <alias>.
    """,
    "prune": """
    Usage: secret prune [--dry-run] [--global]

    Remove config aliases whose vault items no longer exist. --dry-run only lists
    them; --global prunes the user config instead of the project one.
    """,
    "lint": """
    Usage: secret lint [--config FILE] [--json]

    Validate configs offline: items, env keys, collisions (no vault).
    """,
    "doctor": """
    Usage: secret doctor [--json] [--ci]

    Validate configs, vault state, alias resolvability, and expiry. --json emits
    machine-readable rows with remote item metadata and TOTP availability.
    --ci (or the `secret check` alias) is non-interactive, prints only problems
    plus a summary line, and exits 1 when any problem is found — suitable for
    CI and pre-push hooks.
    """,
    "recent": """
    Usage: secret recent [--json]

    Show recently used aliases.
    """,
    "history": """
    Usage: secret history [--json]

    Show recent secret commands (aliases only, no values).
    """,
]

func printHelp() {
    print("""
    Usage: secret <status|unlock|lock|list|search|get|set|edit|id|totp|source|pull|pin|rotate|rm|unset|mv|init|env|run|print|global|prune|lint|doctor|recent|history> [options]

    Commands:
      status (st)         Check Bitwarden auth state and print the next command to run
      unlock              Unlock and print a session token (--store persists it)
      lock                Lock the vault and clear any stored session
      list (ls)           List configured aliases (vault touched only for created dates on a TTY)
      search <term>       Find aliases by alias, item, or env key across scopes (no values)
      get (g) <alias>     Print exactly one configured value
      set (s, add) [<alias>]
                          Prompt (hidden) a value and write it to Bitwarden; a missing
                          alias is added to the config and created in the vault
      edit <alias>         Edit the item name, configured value, source, notes, or a custom field
      id <alias>          Print the resolved Bitwarden item id (no value)
      totp <alias>        Print the current TOTP code (--copy to clipboard)
      source (so) <alias> [url]
                          Print the secret's source URL, or set it when a url is given
      pull (pu, sync)     Refresh the local vault cache from the server (bw sync)
      pin <alias>         Replace the config item name with its resolved id
      rotate <alias>      Generate a new password and overwrite the item (confirm unless --force); delivers the new value
      rm (delete, remove) <alias>
                          Delete the vault item (confirm unless --force); falls back
                          to unset when the item does not exist in the vault
      unset <alias>       Remove an alias from the project or user config
      mv <alias> <new>    Rename an alias in the project or user config
      init [alias..]      Scaffold a .secret.json template; optional aliases to prefill
      env (e)             Generate dotenv from the project config
      run <cmd...>        Inject project aliases into a command's environment (secret run -- npm test)
      print (pr) [scope]  Show aliases in project (default), global, or local; --all merges scopes
      global              Show the global (user) scope aliases
      prune [--dry-run]   Remove config aliases whose vault items no longer exist
      lint                Validate configs offline: items, env keys, collisions (no vault)
      doctor (d)          Validate configs, Bitwarden state, and alias resolvability
      recent              Show recently used aliases
      history             Show recent secret commands

    Options:
      --config FILE       Use FILE instead of ./.secret.json
      --output FILE       With env: atomically write dotenv to FILE (mode 0600)
      --env NAME          With env/list/get/set: environment overrides (default: prod)
      --required a,b,c    With env: fail unless these aliases are in the project config
      --optional a,b,c    With env/run: warn and skip aliases that are undeclared or cannot resolve
      --copy              With get: copy the value to the clipboard instead of stdout
      --check             With status: exit nonzero when not unlocked
      --export            With env: print shell export lines instead of dotenv
      --json              With list/print/history/recent: machine-readable JSON on stdout
      --all               With print: merge project, global, and local scopes
      --merge             With env: upsert alias keys into an existing dotenv (keep other keys)
      --diff, --dry, --dry-run
                          With env: show key-level added/changed/removed without printing values (default target ./.env)
      -h, --help          Show this help; accepted after any command
      --store             With unlock: persist the session token to ~/.config/secret/session (mode 0600)
      --helper            With unlock: get the session via Touch ID (macOS)
      --generate          With set: generate a random password instead of prompting
      --force, -f         With set: overwrite an existing item without confirmation
      --source URL        With set: attach a source URL (custom "source" field)
      --name NAME         With set/edit: change the Bitwarden item name
      --notes TEXT        With set/edit: set or clear Bitwarden notes
      --field FIELD       With set/edit: choose the value field (password, username, notes, custom:name)
      --type TYPE         With set: choose login or secure-note item type
      --expires-at DATE   With set: record an ISO expiry date in the config
      --tags TAGS         With set/edit: record comma-separated local alias tags
      --value-stdin       With edit: read the new value from stdin without putting it in argv
      --open              With source: open the source URL in the browser
      --global, -g        With set/unset/rm: operate on the global config

    Config precedence (later wins):
      ~/.config/secret/config.json    personal global aliases
      ./.secret.json                  project aliases
      ./.secret.local.json            local overrides (gitignored)

    Start with 'secret status', then 'secret list' to see aliases, and
    'secret env --output .env' to generate a project .env file.
    Use 'secret print' to inspect a single scope without vault access.
    """)
}

// MARK: - Row helpers

struct PrintRow {
    var alias: String
    var scope: String
    var env: String
    var item: String
    var field: String
    var envKey: String
}

func rowJSON(_ pairs: [(String, String)]) -> String {
    "{" + pairs.map { "\"\(jsonEscape($0.0))\":\"\(jsonEscape($0.1))\"" }.joined(separator: ",") + "}"
}

let scopeOrder: [String: Int] = ["project": 0, "global": 1, "local": 2]

func configRows(_ config: J, scope: String) -> [PrintRow] {
    var rows: [PrintRow] = []
    func addDefinitions(_ definitions: [(String, J)], envName: String) {
        for (alias, value) in definitions {
            var item = ""
            var field: String?
            var envKey: String?
            for (key, val) in value.pairs() ?? [] {
                switch key {
                case "item": item = val.string() ?? ""
                case "field": field = val.string()
                case "env": envKey = val.string()
                default: break
                }
            }
            if item.isEmpty { fail("invalid definition for \(alias)") }
            let definition = SecretDefinition(item: item, field: field, envKey: envKey)
            rows.append(PrintRow(
                alias: alias,
                scope: scope,
                env: envName,
                item: item,
                field: field ?? "password",
                envKey: dotenvKey(alias, definition)
            ))
        }
    }
    addDefinitions(config.get("secrets")?.pairs() ?? [], envName: "prod")
    let environments = (config.get("environments")?.pairs() ?? []).sorted { $0.0 < $1.0 }
    for (envName, environment) in environments {
        addDefinitions(environment.get("secrets")?.pairs() ?? [], envName: envName)
    }
    return rows
}

func scopeRows(_ scope: String, _ filePath: String?) -> [PrintRow] {
    guard let filePath, exists(filePath) else { return [] }
    return configRows(readConfig(filePath), scope: scope)
}

func sortRows(_ rows: inout [PrintRow]) {
    rows.sort { a, b in
        if a.alias != b.alias { return a.alias < b.alias }
        let aScope = scopeOrder[a.scope] ?? 3
        let bScope = scopeOrder[b.scope] ?? 3
        if aScope != bScope { return aScope < bScope }
        return a.env < b.env
    }
}

func emitRows(_ rows: [PrintRow], json: Bool, includeScope: Bool) {
    if json {
        let items = rows.map { row -> String in
            if includeScope {
                return rowJSON([
                    ("alias", row.alias),
                    ("scope", row.scope),
                    ("env", row.env),
                    ("item", row.item),
                    ("field", row.field),
                    ("envKey", row.envKey),
                ])
            }
            return rowJSON([
                ("alias", row.alias),
                ("env", row.env),
                ("item", row.item),
                ("field", row.field),
                ("envKey", row.envKey),
            ])
        }
        print("[" + items.joined(separator: ",") + "]")
    } else if includeScope {
        for row in rows {
            print([row.alias, row.scope, row.env, row.item, row.field, row.envKey].joined(separator: "\t"))
        }
    } else {
        for row in rows {
            print([row.alias, row.env, row.item, row.field, row.envKey].joined(separator: "\t"))
        }
    }
}

func printConfig(scope: String, filePath: String, json: Bool) {
    if !exists(filePath) { fail("no config file for \(scope) scope: \(filePath)") }
    var rows = configRows(readConfig(filePath), scope: scope)
    sortRows(&rows)
    emitRows(rows, json: json, includeScope: false)
    writeErr("secret print: \(rows.count) aliases in \(scope) scope (\(filePath)). next: secret get <alias>, or secret env --output .env\n")
}

func printScope(scope: String, selectedConfig: String?, json: Bool) {
    if scope == "project" {
        let projectPath = selectedConfig ?? findProjectConfig()
        guard let projectPath else {
            fail("no .secret.json found (searched up to $HOME) — run 'secret init' to scaffold one, or pass --config FILE")
        }
        printConfig(scope: "project", filePath: projectPath, json: json)
    } else if scope == "global" {
        printConfig(scope: "global", filePath: userConfigPath, json: json)
    } else if scope == "local" {
        guard let localPath = findProjectLocalConfig() else {
            fail("no .secret.local.json found (searched up to $HOME) — create one for machine-local overrides")
        }
        printConfig(scope: "local", filePath: localPath, json: json)
    } else {
        fail("unknown scope: \(scope) (available: project, global, local)")
    }
}

func mergedRows(_ selectedConfig: String?) -> [PrintRow] {
    let projectPath = selectedConfig ?? findProjectConfig()
    var rows = [
        scopeRows("project", projectPath),
        scopeRows("global", userConfigPath),
        scopeRows("local", findProjectLocalConfig()),
    ].flatMap { $0 }
    sortRows(&rows)
    return rows
}

func printAllScopes(_ selectedConfig: String?, json: Bool) {
    let rows = mergedRows(selectedConfig)
    emitRows(rows, json: json, includeScope: true)
    writeErr("secret print: \(rows.count) aliases across project, global, and local scopes. next: secret get <alias>, or secret env --output .env\n")
}

func searchAliases(_ query: String, _ selectedConfig: String?, json: Bool) {
    let needle = query.lowercased()
    let rows = mergedRows(selectedConfig).filter { row in
        row.alias.lowercased().contains(needle)
            || row.item.lowercased().contains(needle)
            || row.envKey.lowercased().contains(needle)
    }
    if rows.isEmpty {
        writeErr("secret search: no matches for '\(query)'. next: try another term, or 'secret print --all'\n")
        exit(1)
    }
    emitRows(rows, json: json, includeScope: true)
    writeErr("secret search: \(rows.count) match(es) for '\(query)'. next: secret get <alias>\n")
}

// MARK: - lint

struct LintProblem {
    var scope: String
    var alias: String
    var message: String
}

func lint(_ selectedConfig: String?, json: Bool) {
    let projectPath = selectedConfig ?? findProjectConfig()
    let sources: [(scope: String, filePath: String?)] = [
        ("project", projectPath),
        ("global", userConfigPath),
        ("local", findProjectLocalConfig()),
    ]
    var problems: [LintProblem] = []
    var envKeys: [String: (scope: String, alias: String)] = [:]
    var count = 0

    for source in sources {
        guard let filePath = source.filePath, exists(filePath) else { continue }
        let config = readConfig(filePath)
        func addDefinitions(_ definitions: [(String, J)], envName: String) {
            for (alias, value) in definitions {
                count += 1
                var item = ""
                var field: String?
                var envKey: String?
                for (key, val) in value.pairs() ?? [] {
                    switch key {
                    case "item": item = val.string() ?? ""
                    case "field": field = val.string()
                    case "env": envKey = val.string()
                    default: break
                    }
                }
                if item.isEmpty {
                    problems.append(LintProblem(scope: source.scope, alias: alias, message: "invalid definition (missing item)"))
                    continue
                }
                if envName != "prod" {
                    if envName.range(of: "^[A-Za-z0-9_-]+$", options: .regularExpression) == nil {
                        problems.append(LintProblem(scope: source.scope, alias: alias, message: "invalid environment name: \(envName)"))
                    }
                }
                let key = envKey ?? alias
                if key.range(of: "^[A-Za-z_][A-Za-z0-9_]*$", options: .regularExpression) == nil {
                    problems.append(LintProblem(
                        scope: source.scope,
                        alias: alias,
                        message: "invalid dotenv key (add an explicit \"env\" field)"
                    ))
                    continue
                }
                if let previous = envKeys[key], previous.alias != alias {
                    problems.append(LintProblem(
                        scope: source.scope,
                        alias: alias,
                        message: "dotenv key \(key) collides with \(previous.scope):\(previous.alias) (last wins silently)"
                    ))
                } else {
                    envKeys[key] = (source.scope, alias)
                }
                _ = field
            }
        }
        addDefinitions(config.get("secrets")?.pairs() ?? [], envName: "prod")
        let environments = (config.get("environments")?.pairs() ?? []).sorted { $0.0 < $1.0 }
        for (envName, environment) in environments {
            addDefinitions(environment.get("secrets")?.pairs() ?? [], envName: envName)
        }
    }

    if json {
        let items = problems.map { problem -> String in
            rowJSON([
                ("scope", problem.scope),
                ("alias", problem.alias),
                ("message", problem.message),
            ])
        }
        print("[" + items.joined(separator: ",") + "]")
    } else {
        for problem in problems {
            print("\(problem.scope)\t\(problem.alias)\t\(problem.message)")
        }
    }
    if !problems.isEmpty {
        fflush(stdout)
        writeErr("secret lint: \(problems.count) problem(s) across \(count) alias(es). next: fix the config, or run 'secret doctor' for vault checks\n")
        exit(1)
    }
    fflush(stdout)
    writeErr("secret lint: clean — \(count) alias(es) across project, global, and local. next: secret doctor, or secret env --output .env\n")
}

// MARK: - init

func initProjectConfig(force: Bool, aliases: [String]) {
    let filePath = "\(FileManager.default.currentDirectoryPath)/\(projectConfigName)"
    if exists(filePath) && !force {
        fail(".secret.json already exists (use --force to overwrite): \(filePath)")
    }
    let prefix = (FileManager.default.currentDirectoryPath as NSString).lastPathComponent
    var secrets: [(String, J)] = []
    for alias in aliases {
        if alias.range(of: "^[A-Za-z_][A-Za-z0-9_]*$", options: .regularExpression) == nil {
            fail("invalid alias name: \(alias) (letters, digits, underscore, hyphen; must not start with a digit)")
        }
        secrets.append((alias, .obj([
            ("item", .str("\(prefix)/\(kebab(alias))")),
            ("field", .str("password")),
        ])))
    }
    if aliases.isEmpty {
        secrets.append(("EXAMPLE", .obj([
            ("item", .str("\(prefix)/example")),
            ("field", .str("password")),
        ])))
    }
    writeAtomic(filePath, jStringify(.obj([("secrets", .obj(secrets))])) + "\n")
    if aliases.isEmpty {
        writeErr("secret: created \(filePath); replace EXAMPLE, then run 'secret env --output .env'\n")
    } else {
        writeErr("secret: created \(filePath) with \(aliases.count) alias(es); then run 'secret env --output .env'\n")
    }
}

// MARK: - Value resolution and mutations

func dotenvValue(_ value: String) -> String {
    "'\(value.replacingOccurrences(of: "'", with: "'\\''"))'"
}

func parseExpiry(_ value: String) -> Date? {
    let plain = DateFormatter()
    plain.dateFormat = "yyyy-MM-dd"
    plain.locale = Locale(identifier: "en_US_POSIX")
    if let date = plain.date(from: value) { return date }
    return ISO8601DateFormatter().date(from: value)
}

func resolveRequired(_ items: [JSON]?, _ alias: String, _ definition: SecretDefinition) async -> String {
    if items == nil {
        await vaultBackend.requireUnlocked()
        fail("could not read vault items (bw list items failed)")
    }
    guard let item = itemFor(items, definition.item) else {
        if items?.isEmpty == true {
            warn("hint: the vault is empty — create items with 'secret set <alias>', or check the account/server in bw config")
        }
        fail("item not found for \(alias): \(definition.item)")
    }
    guard let value = valueFor(item, definition) else { fail("missing or invalid value for \(alias)") }
    return value
}

func resolveOptional(_ items: [JSON]?, _ definition: SecretDefinition) -> String? {
    valueFor(itemFor(items, definition.item), definition)
}

func getValue(_ alias: String, _ definition: SecretDefinition) async -> String {
    let items = await vaultBackend.items()
    return await resolveRequired(items, alias, definition)
}

func setValue(
    _ alias: String,
    _ definition: SecretDefinition,
    _ value: String,
    _ force: Bool,
    _ source: String?,
    name: String? = nil,
    notes: String? = nil,
    itemType: String? = nil,
    biometricConfirm: Bool = false
) async {
    await vaultBackend.requireUnlocked()
    let field = definition.field ?? "password"
    let items = await vaultBackend.items()
    let item = itemFor(items, definition.item)
    if item == nil {
        var payload = newItem(
            name: name ?? definition.item,
            field: field,
            value: value,
            itemType: itemType ?? definition.itemType
        )
        if let notes, field != "notes" { setItemField(&payload, "notes", notes) }
        if let source { setItemField(&payload, "custom:source", source) }
        await vaultBackend.createItem(payload)
        success("created item \(definition.item)")
        return
    }
    guard let id = item!["id"] as? String else { fail("Bitwarden item for \(alias) has no id") }
    if !force {
        if isatty(0) != 1 { fail("item already exists; pass --force to overwrite") }
        let created = formatCreatedAt(item?["creationDate"] as? String ?? "")
        let confirmed = biometricConfirm
            ? confirmDangerous("Overwrite \(definition.item) (created at \(created))?", reason: "Overwrite \(definition.item) in Bitwarden")
            : confirmPrompt("Overwrite \(definition.item) (created at \(created))?")
        if !confirmed { fail("aborted; use --force to overwrite without confirmation") }
    }
    var payload = jsonObject(jsonString(item!)) ?? [:]
    setItemField(&payload, field, value)
    if let itemType { payload["type"] = itemTypeCode(itemType) }
    if let name { payload["name"] = name }
    if let notes { setItemField(&payload, "notes", notes) }
    if let source { setItemField(&payload, "custom:source", source) }
    await vaultBackend.updateItem(id: id, payload)
    success("updated item \(definition.item)")
}

func editItem(
    alias: String,
    definition: SecretDefinition,
    value: String?,
    field: String?,
    source: String?,
    name: String?,
    notes: String?,
    force: Bool
) async {
    guard value != nil || source != nil || name != nil || notes != nil else {
        fail("edit needs a field change (name, value, source, notes, or --field)")
    }
    await vaultBackend.requireUnlocked()
    let items = await vaultBackend.items()
    guard let item = itemFor(items, definition.item) else {
        fail("item not found for \(alias): \(definition.item)")
    }
    guard let id = item["id"] as? String else { fail("Bitwarden item for \(alias) has no id") }
    if !force {
        if isatty(0) != 1 { fail("edit requires confirmation; pass --force from a non-interactive caller") }
        let label = (item["name"] as? String) ?? definition.item
        let confirmed = confirmDangerous("Edit \(label)?", reason: "Edit \(label) in Bitwarden")
        if !confirmed { fail("aborted; pass --force to edit without confirmation") }
    }
    var payload = jsonObject(jsonString(item)) ?? [:]
    if let value { setItemField(&payload, field ?? definition.field ?? "password", value) }
    if let name { payload["name"] = name }
    if let source { setItemField(&payload, "custom:source", source) }
    if let notes { setItemField(&payload, "notes", notes) }
    await vaultBackend.updateItem(id: id, payload)
    success("edited \(alias)")
}

func deliverValue(_ value: String, _ alias: String) {
    if copyToClipboard(value) {
        success("copied \(alias) to clipboard")
    } else {
        print(value)
        warn("clipboard unavailable, printed \(alias) value above")
    }
}

func copyToClipboardOrFail(_ value: String) {
    if !copyToClipboard(value) {
        #if os(macOS)
        let candidates = ["pbcopy"]
        #else
        let candidates = ["wl-copy", "xclip"]
        #endif
        fail("no clipboard tool available (tried \(candidates.joined(separator: ", ")))")
    }
}

func confirmDangerous(_ label: String, reason: String) -> Bool {
    if touchIDAvailable() {
        return confirmTouchID(reason: reason)
    }
    return confirmPrompt(label)
}

func openInBrowser(_ url: String) {
    #if os(macOS)
    let r = runCommand(pathTo("open") ?? "/usr/bin/open", [url])
    #else
    let r = runCommand(pathTo("xdg-open") ?? "xdg-open", [url])
    #endif
    if r.status != 0 {
        fail("could not open \(url)")
    }
    success("opened \(url)")
}

func replacePairKey(_ key: String, _ value: J, in obj: J) -> J {
    let pairs = obj.pairs() ?? []
    return .obj(pairs.map { $0.0 == key ? (key, value) : $0 })
}

// MARK: - doctor

func doctor(_ definitions: [(alias: String, definition: SecretDefinition)], json: Bool, ci: Bool = false) async {
    let current = await vaultBackend.authState()
    if !current.authenticated {
        if json { print("[]") }
        else { print("bitwarden: unauthenticated — run: bw login, then secret unlock --store") }
        exit(1)
    }
    if !current.unlocked {
        if json { print("[]") }
        else { print("bitwarden: locked — unlock with: secret unlock --store") }
        exit(1)
    }
    if !json && !ci {
        print("bitwarden: unlocked")
        if env("SECRET_DAEMON") == "0" {
            print("daemon\tdisabled")
        } else {
            print("daemon\t\(await vaultBackend.daemonSummary())")
        }
    }

    var problems = 0
    if ci { setenv("SECRET_NO_PROMPT", "1", 1) }
    var jsonRows: [String] = []
    let items = await vaultBackend.items()
    var expiringSoon: [String] = []
    for (alias, definition) in definitions {
        let field = definition.field ?? "password"
        if let item = itemFor(items, definition.item) {
            let value = itemField(item, field)
            let valid = if let value = value as? String {
                !value.isEmpty && !placeholderValues.contains(value)
            } else {
                false
            }
            var status = valid ? "ok" : "invalid"
            if valid, let expiresText = definition.expiresAt, let expiry = parseExpiry(expiresText) {
                if expiry < Date() {
                    status = "expired"
                    problems += 1
                } else if expiry < Date().addingTimeInterval(14 * 86_400) {
                    expiringSoon.append(alias)
                }
            }
            let itemName = item["name"] as? String ?? definition.item
            let source = itemField(item, "custom:source") as? String ?? ""
            let hasTOTP = ((item["login"] as? JSON)?["totp"] as? String)?.isEmpty == false
            if json {
                jsonRows.append(rowJSON([
                    ("alias", alias),
                    ("item", definition.item),
                    ("field", field),
                    ("status", status),
                    ("itemName", itemName),
                    ("source", source),
                    ("hasTOTP", hasTOTP ? "true" : "false"),
                ]))
            } else if status == "ok" {
                if !ci { print("ok\t\(alias)\t\(definition.item)\t\(field)") }
            } else {
                print("\(status) value\t\(alias)\t\(definition.item)\t\(field)")
                if status == "invalid" { problems += 1 } // expired already counted
            }
        } else {
            if json {
                jsonRows.append(rowJSON([
                    ("alias", alias),
                    ("item", definition.item),
                    ("field", field),
                    ("status", "missing"),
                    ("itemName", ""),
                    ("source", ""),
                    ("hasTOTP", "false"),
                ]))
            } else {
                print("missing\t\(alias)\t\(definition.item)")
            }
            problems += 1
        }
    }

    if json { print("[" + jsonRows.joined(separator: ",") + "]") }
    for alias in expiringSoon where !ci {
        warn("expiring soon: \(alias)")
    }
    let total = definitions.count
    let summary = "secret \(ci ? "check" : "doctor"): \(total - problems)/\(total) aliases ok, \(problems) problem(s)"
    if problems > 0 {
        warn(summary)
    } else {
        success(summary)
    }
    if problems > 0 { exit(1) }
}

// MARK: - Biometric session bootstrap

// When no session is resolvable (no BW_SESSION, no stored keychain session),
// fall back to the Touch ID-gated cache. Only offered in interactive
// contexts so headless scripts and timers never block on a biometric prompt:
// a TTY on stdin, or SECRET_BIOMETRIC_UNLOCK=1 which SecretBar sets on
// user-initiated actions only.
func maybeBootstrapBiometricSession() {
    if (env("BW_SESSION") ?? "").isEmpty == false { return }
    guard readSession() == nil else { return }
    guard env("SECRET_NO_BIOMETRICS") == nil else { return }
    guard isatty(0) == 1 || env("SECRET_BIOMETRIC_UNLOCK") == "1" else { return }
    guard let token = helperSessionRead(), !token.isEmpty else { return }
    let check = runCommand(pathTo("bw") ?? "bw", ["status"], env: envWithSession(token))
    var valid = false
    if check.status == 0,
       let data = jsonObject(check.stdout),
       (data["status"] as? String) == "unlocked" {
        valid = true
    }
    if valid {
        setenv("BW_SESSION", token, 1)
    } else {
        // Stale token: drop the cache so the next `unlock --helper`
        // re-stores a fresh one instead of failing forever.
        helperClearSession()
    }
}

// MARK: - Dispatch

func run() async {
    var options = parseOptions(Array(CommandLine.arguments.dropFirst()))
    options.command = commandAliases[options.command] ?? options.command
    // `secret check` is doctor in CI mode: non-interactive, expiry-aware.
    if options.command == "doctor", CommandLine.arguments.dropFirst().first == "check" {
        options.ci = true
    }
    if options.command == "global" && options.positional.first == "add" {
        options.command = "set"
        options.global = true
        options.positional = Array(options.positional.dropFirst())
    } else if options.command == "global" && options.positional.first == "unset" {
        options.command = "unset"
        options.global = true
        options.positional = Array(options.positional.dropFirst())
    }
    let environment = options.envName ?? "prod"
    let loaded = options.command == "lint"
        ? LoadedConfig(definitions: [:], ordered: [], selectedAliases: nil)
        : loadDefinitions(configPath: options.configPath, environment: environment, allowUnknownEnvironment: options.command == "set")

    let wantsHelp =
        options.command == "help"
        || options.command == "--help"
        || options.command == "-h"
        || options.positional.contains("-h")
        || options.positional.contains("--help")
    if wantsHelp {
        let requested = ([options.command] + options.positional)
            .filter { $0 != "-h" && $0 != "--help" && $0 != "help" }
            .first { commandHelpText[$0] != nil }
        if let requested {
            print(commandHelpText[requested] ?? "")
        } else {
            printHelp()
        }
        return
    }

    let vaultTouchingCommands: Set<String> = [
        "get", "set", "edit", "id", "totp", "source", "pin", "rotate",
        "rm", "unset", "mv", "env", "run", "doctor", "pull", "list",
    ]
    if vaultTouchingCommands.contains(options.command) {
        maybeBootstrapBiometricSession()
    }

    switch options.command {
    case "status":
        let current = await vaultBackend.authState()
        if current.unlocked {
            let daemonUp = await vaultBackend.daemonSummary() == "up"
            print(outColor("32", "unlocked — ready. next: secret list, or secret env --output .env\(daemonUp ? " (daemon up)" : "")"))
        } else {
            print(outColor("33", current.authenticated
                ? "locked — unlock with: secret unlock --store"
                : "unauthenticated — run: bw login, then secret unlock --store"))
            if let session = env("BW_SESSION"), !session.isEmpty {
                warn("a session token is present but bw rejects it — run 'bw logout && bw login' once to repair, then 'secret unlock --store'")
            }
            if readSession() != nil {
                warn("stored session is stale — refresh with 'secret unlock --store'")
            }
            if options.check { exit(1) }
        }

    case "unlock":
        // `unlock` always means "obtain a fresh session". An inherited
        // BW_SESSION is deliberately ignored: shells keep exporting stale
        // tokens long after logout/login rotated them, which turned
        // 'secret unlock --store' into an unreachable error.
        let token: String
        if options.sessionStdin {
            // SecretBar authenticates with LocalAuthentication in-process (a
            // spawned CLI cannot reliably present the Touch ID prompt from a
            // menu-bar/agent context) and hands over the cached token here.
            let line = readLine() ?? ""
            token = line.trimmingCharacters(in: .whitespacesAndNewlines)
            if token.isEmpty {
                fail("--session-stdin requires a session token on stdin")
            }
        } else if options.helper {
            guard let helperToken = helperSessionRead() else {
                fail("Touch ID unlock unavailable — run 'secret unlock --store' once to cache the session, or use 'secret unlock'")
            }
            token = helperToken
        } else {
            token = await vaultBackend.interactiveUnlock()
        }
        if token.isEmpty {
            fail(options.helper
                ? "Touch ID unlock returned no session token"
                : "bw unlock returned no session token")
        }
        if options.helper || options.sessionStdin {
            setenv("BW_SESSION", token, 1)
            // Daemon verdict first: direct `bw status` can report locked due
            // to transient secure-storage state even when a serve daemon
            // started with this session works fine.
            if await vaultBackend.startSessionDaemon(token: token) {
                _ = helperSessionStore(token)
                success(options.sessionStdin
                    ? "unlocked with Touch ID session; secret daemon ready"
                    : "unlocked with Touch ID; secret daemon ready")
                return
            }
            let rejected = !(await vaultBackend.sessionValid(token))
            if rejected {
                // A rejected cached token must not be re-stored and reported
                // as success; drop it and point at the fix.
                helperClearSession()
                fail("cached session was rejected — unlock with your master password once ('secret unlock --store') to refresh the caches")
            }
            // Keep the plain stored session in sync too so non-interactive
            // callers (wrapper restore) see the same fresh token.
            if options.sessionStdin {
                storeSession(token)
                _ = helperSessionStore(token)
                success("unlocked with Touch ID; cached behind Touch ID")
                return
            }
            // Plain --helper without a daemon: hand the token to the caller
            // (the shell wrapper exports it for the session).
            _ = helperSessionStore(token)
            print(token)
            return
        }
        if !(await vaultBackend.sessionValid(token)) {
            // A fresh interactive token rejected by a plain status check is
            // usually transient secure-storage state; still store it — the
            // daemon handoff below is what actually matters.
            warn("bw status did not confirm the new session (stale secure-storage state) — continuing; commands go through the secret daemon")
        }
        vaultBackend.stopSessionDaemon()
        if options.store {
            storeSession(token)
            _ = helperSessionStore(token)
            success("unlocked; session stored (clear with 'secret lock')")
        } else {
            print(token)
        }

    case "lock":
        await vaultBackend.lock()
        let hadSession = readSession() != nil
        clearSession()
        // The Touch ID cache is kept: if the old token is still accepted,
        // post-lock commands re-unlock through a fresh biometric prompt;
        // if bw invalidated it, the bootstrap stale-check removes it.
        writeErr(hadSession ? "secret: vault locked; stored session cleared\n" : "secret: vault locked\n")

    case "list":
        let entries = loaded.ordered
        if options.json {
            // Best-effort vault metadata for UI consumers: created dates and
            // source resolve only when a session is available; keys are
            // always present so parsing stays uniform.
            let authState = await vaultBackend.authState()
            var itemIndex: [String: JSON] = [:]
            if authState.unlocked, let items = await vaultBackend.items() {
                for item in items {
                    // pinned configs reference items by id; fresh ones by name
                    if let name = item["name"] as? String { itemIndex[name] = item }
                    if let itemId = item["id"] as? String { itemIndex[itemId] = item }
                }
            }
            let items = entries.map { alias, definition -> String in
                let item = itemIndex[definition.item]
                let source = item.flatMap { itemField($0, "custom:source") as? String } ?? ""
                let hasTOTP = ((item?["login"] as? JSON)?["totp"] as? String)?.isEmpty == false
                return rowJSON([
                    ("alias", alias),
                    ("item", definition.item),
                    ("field", definition.field ?? "password"),
                    ("envKey", dotenvKey(alias, definition)),
                    ("createdAt", item?["creationDate"] as? String ?? ""),
                    ("source", source),
                    ("hasTOTP", hasTOTP ? "true" : "false"),
                ])
            }
            print("[" + items.joined(separator: ",") + "]")
        } else if outIsTTY() {
            let header = ["ALIAS", "ITEM", "FIELD", "CREATED AT", "SOURCE"]
            let items = await vaultBackend.items()
            var hidden = 0
            var rows: [[String]] = []
            for (alias, definition) in entries {
                let created = itemCreationDate(items, definition.item)
                if created == "-" { hidden += 1 }
                let entry = itemFor(items, definition.item)
                let source = entry.flatMap { itemField($0, "custom:source") as? String }
                rows.append([
                    alias,
                    definition.item,
                    definition.field ?? "password",
                    created,
                    (source != nil && !source!.isEmpty) ? source! : "-",
                ])
            }
            let widths = header.enumerated().map { column, cell -> Int in
                max(cell.count, rows.map { $0[column].count }.max() ?? 0)
            }
            func pad(_ value: String, _ width: Int) -> String {
                value + String(repeating: " ", count: max(0, width - value.count))
            }
            print(outColor("1;36", header.enumerated()
                .map { pad($0.element, widths[$0.offset]) }
                .joined(separator: "  ")))
            for row in rows {
                print(row.enumerated()
                    .map { pad($0.element, widths[$0.offset]) }
                    .joined(separator: "  "))
            }
            if hidden > 0 {
                warn("created date hidden for \(hidden) item(s) — unlock the vault to show dates")
            }
        } else {
            for (alias, definition) in entries {
                print("\(alias)\t\(definition.item)\t\(definition.field ?? "password")")
            }
        }
        writeErr("secret: \(entries.count) aliases configured. next: secret get <alias>, or secret env --output .env\n")

    case "get":
        guard let alias = options.positional.first else {
            fail("get requires an alias, e.g. secret get github-token (see 'secret list')")
        }
        guard let definition = loaded.definitions[alias] else { fail("unknown alias: \(alias) (see 'secret list')") }
        let value = await getValue(alias, definition)
        recordHistory(entry: HistoryEntry(at: isoNow(), cmd: "get", target: alias, env: environment))
        if options.copy {
            copyToClipboardOrFail(value)
            success("copied \(alias) to clipboard")
        } else {
            print(value)
        }

    case "set":
        var alias = options.positional.first
        if alias == nil {
            if isatty(0) != 1 { fail("set requires an alias, e.g. secret set github-token (see 'secret list')") }
            let entered = promptLine("Alias name")
            if entered.isEmpty || !validAlias(entered) {
                fail("invalid alias name: \(entered) (letters, digits, underscore, hyphen; must not start with a digit)")
            }
            alias = entered
        }
        let aliasValue = alias!
        let filePath = options.global
            ? userConfigPath
            : (options.configPath ?? findProjectConfig() ?? "\(FileManager.default.currentDirectoryPath)/\(projectConfigName)")
        let targetConfig = exists(filePath) ? readConfig(filePath) : nil
        var definition = targetConfig.flatMap { definitionInConfig($0, aliasValue, environment: environment) }
        if definition == nil {
            if !validAlias(aliasValue) {
                fail("invalid alias name: \(aliasValue) (letters, digits, underscore, hyphen; must not start with a digit)")
            }
            let prefix = options.global
                ? "global"
                : URL(fileURLWithPath: filePath).deletingLastPathComponent().lastPathComponent
            let item = options.name ?? "\(prefix)/\(kebab(aliasValue))"
            let newField = options.field ?? (options.itemType == "secure-note" ? "notes" : "password")
            var definitionPairs: [(String, J)] = [
                ("item", .str(item)),
                ("field", .str(newField)),
                ("env", .str(scream(aliasValue))),
            ]
            if let itemType = options.itemType { definitionPairs.append(("type", .str(itemType))) }
            if let expiresAt = options.expiresAt { definitionPairs.append(("expiresAt", .str(expiresAt))) }
            let tags = options.tags?.split(separator: ",").map { String($0).trimmingCharacters(in: .whitespacesAndNewlines) }.filter { !$0.isEmpty } ?? []
            if !tags.isEmpty { definitionPairs.append(("tags", .arr(tags.map { .str($0) }))) }
            let newDefinition = J.obj(definitionPairs)
            let updated = addDefinitionToConfig(exists(filePath) ? readConfig(filePath) : nil, alias: aliasValue, definition: newDefinition, environment: environment)
            writeAtomic(filePath, jStringify(updated) + "\n")
            info("added \(aliasValue) (\(item)) to \(filePath)")
            definition = SecretDefinition(item: item, field: newField, itemType: options.itemType, expiresAt: options.expiresAt, tags: tags)
        }
        let value = options.generate
            ? await generatePassword()
            : promptHidden("Enter value for \(aliasValue)")
        if value.isEmpty || placeholderValues.contains(value) {
            fail("refusing empty or placeholder value for \(aliasValue)")
        }
        var source = options.source
        if source == nil && isatty(0) == 1 {
            let entered = promptLine("Source URL (optional)")
            if !entered.isEmpty { source = entered }
        }
        var notes = options.notes
        if notes == nil && isatty(0) == 1 {
            notes = promptLine("Notes (optional)")
        }
        await setValue(
            aliasValue,
            definition!,
            value,
            options.force,
            source,
            name: options.name,
            notes: notes,
            itemType: options.itemType
        )
        recordHistory(entry: HistoryEntry(at: isoNow(), cmd: "set", target: aliasValue, env: environment))
        success("set \(aliasValue) (\(definition!.item), \(definition!.field ?? "password"))")
        if options.generate {
            if options.copy {
                copyToClipboardOrFail(value)
                success("copied \(aliasValue) to clipboard")
            } else {
                deliverValue(value, aliasValue)
            }
        }

    case "edit":
        var alias = options.positional.first
        if alias == nil {
            if isatty(0) != 1 { fail("edit requires an alias, e.g. secret edit github-token") }
            alias = promptLine("Alias name")
        }
        let aliasValue = alias!
        guard let definition = loaded.definitions[aliasValue] else {
            fail("unknown alias: \(aliasValue) (see 'secret list')")
        }
        var field = options.field
        var value: String?
        var name = options.name
        var source = options.source
        var notes = options.notes
        var tags = options.tags
        let hasItemChange = field != nil || name != nil || source != nil || notes != nil
        let hasExplicitChange = hasItemChange || tags != nil
        if !hasExplicitChange {
            if isatty(0) != 1 { fail("edit needs a field (use --name, --field, --source, --notes, or --tags)") }
            let choice = promptLine("Edit (name/value/source/notes/tags/custom:field)")
            switch choice {
            case "name": name = promptLine("Item name")
            case "value":
                field = definition.field ?? "password"
                value = promptHidden("New \(field!) value")
            case "source": source = promptLine("Source URL (empty clears it)")
            case "notes": notes = promptLine("Notes (empty clears them)")
            case "tags": tags = promptLine("Tags (comma-separated; empty clears them)")
            default:
                if choice.hasPrefix("custom:") && choice.count > "custom:".count {
                    field = choice
                    value = promptHidden("New \(choice) value")
                } else {
                    fail("choose name, value, source, notes, tags, or custom:<field>")
                }
            }
        } else if field != nil {
            value = options.valueStdin ? readStdinAll().trimmingCharacters(in: .whitespacesAndNewlines) : promptHidden("New \(field!) value")
        }
        if hasItemChange || field != nil {
            await editItem(
                alias: aliasValue,
                definition: definition,
                value: value,
                field: field,
                source: source,
                name: name,
                notes: notes,
                force: options.force
            )
        }
        if let tags {
            guard let configPath = options.configPath ?? findProjectConfig() else {
                fail("cannot edit tags without a project config")
            }
            let normalizedTags = tags.split(separator: ",").map { String($0).trimmingCharacters(in: .whitespacesAndNewlines) }.filter { !$0.isEmpty }
            updateAliasTags(aliasValue, normalizedTags, configPath: configPath, environment: environment)
            success("updated tags for \(aliasValue)")
        }
        recordHistory(entry: HistoryEntry(at: isoNow(), cmd: "edit", target: aliasValue, env: environment))

    case "id":
        guard let alias = options.positional.first else {
            fail("id requires an alias, e.g. secret id github-token (see 'secret list')")
        }
        guard let definition = loaded.definitions[alias] else { fail("unknown alias: \(alias) (see 'secret list')") }
        let items = await vaultBackend.items()
        guard let item = itemFor(items, definition.item) else {
            await vaultBackend.requireUnlocked()
            fail("item not found for \(alias): \(definition.item)")
        }
        guard let id = item["id"] as? String else { fail("Bitwarden item for \(alias) has no id") }
        recordHistory(entry: HistoryEntry(at: isoNow(), cmd: "id", target: alias, env: environment))
        print(id)

    case "totp":
        guard let alias = options.positional.first else {
            fail("totp requires an alias, e.g. secret totp github-token (see 'secret list')")
        }
        guard let definition = loaded.definitions[alias] else { fail("unknown alias: \(alias) (see 'secret list')") }
        await vaultBackend.requireUnlocked()
        let code = vaultBackend.totp(itemName: definition.item)
        recordHistory(entry: HistoryEntry(at: isoNow(), cmd: "totp", target: alias, env: environment))
        if options.copy {
            copyToClipboardOrFail(code)
            success("copied \(alias) totp code to clipboard")
        } else {
            print(code)
        }

    case "source":
        guard let alias = options.positional.first else {
            fail("source requires an alias, e.g. secret source github-token")
        }
        guard let definition = loaded.definitions[alias] else { fail("unknown alias: \(alias) (see 'secret list')") }
        let url = options.positional.count > 1 ? options.positional[1] : nil
        let items = await vaultBackend.items()
        guard let item = itemFor(items, definition.item) else {
            await vaultBackend.requireUnlocked()
            fail("item not found for \(alias): \(definition.item)")
        }
    if let url {
        guard var payload = jsonObject(jsonString(item)) else { fail("Bitwarden item for \(alias) is invalid") }
        setItemField(&payload, "custom:source", url)
            let id = payload["id"] as? String ?? ""
            await vaultBackend.updateItem(id: id, payload)
        if options.openURL {
            openInBrowser(url)
        } else {
            success("source set for \(alias)")
        }
    } else {
        let value = itemField(item, "custom:source")
        if options.openURL {
            guard let value = value as? String, !value.isEmpty else {
                fail("no source URL stored for \(alias) — set one with 'secret source \(alias) <url>'")
            }
            openInBrowser(value)
        } else {
            if let value = value as? String, !value.isEmpty {
                print(value)
            } else {
                print("")
            }
        }
    }

    case "pull":
        await vaultBackend.requireUnlocked()
        await vaultBackend.syncCache()
        recordHistory(entry: HistoryEntry(at: isoNow(), cmd: "pull", target: "", env: environment))
        success("vault cache pulled from server")

    case "pin":
        guard let alias = options.positional.first else {
            fail("pin requires an alias, e.g. secret pin github-token (see 'secret list')")
        }
        if loaded.definitions[alias] == nil { fail("unknown alias: \(alias) (see 'secret list')") }
        guard let holder = configWithAlias(
            alias,
            projectPath: options.configPath ?? findProjectConfig(),
            localPath: findProjectLocalConfig()
        ) else {
            fail("alias \(alias) is not in a project, local, or user config (see 'secret print --all')")
        }
        await vaultBackend.requireUnlocked()
        var itemNames: [String] = []
        if let item = holder.config.get("secrets")?.get(alias)?.get("item")?.string() {
            itemNames.append(item)
        }
        for (_, environmentValue) in holder.config.get("environments")?.pairs() ?? [] {
            if let item = environmentValue.get("secrets")?.get(alias)?.get("item")?.string() {
                itemNames.append(item)
            }
        }
        let items = await vaultBackend.items()
        var ids: [String: String] = [:]
        for item in itemNames {
            guard let entry = itemFor(items, item) else { fail("item not found for \(alias): \(item)") }
            guard let id = entry["id"] as? String else { fail("Bitwarden item has no id: \(item)") }
            ids[item] = id
        }
        var rootPairs = holder.config.pairs() ?? []
        rootPairs = rootPairs.map { key, value in
            switch key {
            case "secrets":
                var pairs = value.pairs() ?? []
                pairs = pairs.map { name, definition in
                    if name == alias, let old = definition.get("item")?.string(), let new = ids[old] {
                        return (name, replacePairKey("item", .str(new), in: definition))
                    }
                    return (name, definition)
                }
                return (key, J.obj(pairs))
            case "environments":
                let envPairs = value.pairs()?.map { envName, envValue -> (String, J) in
                    var secrets = envValue.get("secrets")?.pairs() ?? []
                    secrets = secrets.map { name, definition in
                        if name == alias, let old = definition.get("item")?.string(), let new = ids[old] {
                            return (name, replacePairKey("item", .str(new), in: definition))
                        }
                        return (name, definition)
                    }
                    let updated = envValue.pairs()?.map { k, v in
                        k == "secrets" ? ("secrets", J.obj(secrets)) : (k, v)
                    } ?? []
                    return (envName, J.obj(updated))
                }
                return (key, J.obj(envPairs ?? []))
            default:
                return (key, value)
            }
        }
        writeAtomic(holder.filePath, jStringify(.obj(rootPairs)) + "\n")
        recordHistory(entry: HistoryEntry(at: isoNow(), cmd: "pin", target: alias, env: environment))
        writeErr("secret: pinned \(alias) in \(holder.filePath)\n")

    case "rotate":
        guard let alias = options.positional.first else {
            fail("rotate requires an alias, e.g. secret rotate github-token (see 'secret list')")
        }
        guard let definition = loaded.definitions[alias] else { fail("unknown alias: \(alias) (see 'secret list')") }
        let value = await generatePassword()
        await setValue(alias, definition, value, options.force, nil, biometricConfirm: true)
        recordHistory(entry: HistoryEntry(at: isoNow(), cmd: "rotate", target: alias, env: environment))
        success("rotated \(alias) (\(definition.item), \(definition.field ?? "password"))")
        if options.copy {
            copyToClipboardOrFail(value)
            success("copied \(alias) to clipboard")
        } else {
            deliverValue(value, alias)
        }

    case "rm":
        guard let alias = options.positional.first else {
            fail("rm requires an alias, e.g. secret rm github-token (see 'secret list')")
        }
        guard let definition = loaded.definitions[alias] else { fail("unknown alias: \(alias) (see 'secret list')") }
        let items = await vaultBackend.items()
        guard let item = itemFor(items, definition.item) else {
            await vaultBackend.requireUnlocked()
            if items != nil {
                unsetAlias(alias, options.global ? userConfigPath : options.configPath, quiet: true)
                info("item not found in vault — removed \(alias) from config")
                recordHistory(entry: HistoryEntry(at: isoNow(), cmd: "rm", target: alias, env: environment))
                return
            }
            fail("item not found for \(alias): \(definition.item)")
        }
        let name = (item["name"] as? String) ?? definition.item
        if !options.force {
            if isatty(0) != 1 { fail("refusing to delete \(name) without confirmation; pass --force") }
            let confirmed = confirmDangerous("Delete item \(name)?", reason: "Delete \(name) from Bitwarden")
            if !confirmed { fail("aborted; use --force to delete without confirmation") }
        }
        guard let id = item["id"] as? String else { fail("Bitwarden item for \(alias) has no id") }
        await vaultBackend.deleteItem(id: id, fallbackName: definition.item)
        recordHistory(entry: HistoryEntry(at: isoNow(), cmd: "rm", target: alias, env: environment))
        success("deleted item \(definition.item) for \(alias) (config entry kept)")

    case "unset":
        guard let alias = options.positional.first else {
            fail("unset requires an alias, e.g. secret unset github-token (see 'secret list')")
        }
        unsetAlias(alias, options.global ? userConfigPath : options.configPath)
        recordHistory(entry: HistoryEntry(at: isoNow(), cmd: "unset", target: alias, env: environment))

    case "mv":
        guard let from = options.positional.first else {
            fail("mv requires an alias, e.g. secret mv github-token gh-token (see 'secret list')")
        }
        guard options.positional.count > 1 else {
            fail("mv requires the new alias name, e.g. secret mv github-token gh-token")
        }
        let to = options.positional[1]
        moveAlias(from, to, options.configPath)
        recordHistory(entry: HistoryEntry(at: isoNow(), cmd: "mv", target: "\(from) -> \(to)", env: environment))

    case "init":
        initProjectConfig(force: options.force, aliases: options.positional)

    case "env":
        guard let selected = loaded.selectedAliases, !selected.isEmpty else {
            fail("env requires .secret.json or --config FILE with a secrets map; see docs/bitwarden.md")
        }
        let missingRequired = options.required.filter { !selected.contains($0) }
        if !missingRequired.isEmpty {
            fail("required alias(es) not in project config: \(missingRequired.joined(separator: ", ")) (add them to .secret.json)")
        }
        let optionalSet = Set(options.optional)
        for alias in optionalSet where loaded.definitions[alias] == nil {
            writeErr("secret: \(alias) is not declared (optional, skipping)\n")
        }
        let items = await vaultBackend.items()
        if items != nil {
            let missing = selected.filter { candidate in
                guard let definition = loaded.definitions[candidate] else { return false }
                return !optionalSet.contains(candidate) && resolveOptional(items, definition) == nil
            }
            if !missing.isEmpty {
                warn("hint: pass --optional \(missing.joined(separator: ",")) to skip unresolved aliases")
            }
        }
        var lines: [String] = []
        for alias in selected {
            guard let definition = loaded.definitions[alias] else { fail("unknown alias: \(alias)") }
            let key = dotenvKey(alias, definition)
            if optionalSet.contains(alias) {
                guard let value = resolveOptional(items, definition) else {
                    warn("skipping \(alias) (optional, unresolved)")
                    continue
                }
                if let source = resolveOptional(items, SecretDefinition(item: definition.item, field: "custom:source")) {
                    lines.append("# source: \(source)")
                }
                let formatted = dotenvValue(value)
                lines.append(options.export ? "export \(key)=\(formatted)" : "\(key)=\(formatted)")
                continue
            }
            let value = dotenvValue(await resolveRequired(items, alias, definition))
            if let source = resolveOptional(items, SecretDefinition(item: definition.item, field: "custom:source")) {
                lines.append("# source: \(source)")
            }
            lines.append(options.export ? "export \(key)=\(value)" : "\(key)=\(value)")
        }
        if options.merge && options.export {
            fail("--merge cannot be combined with --export")
        }
        let incoming = incomingDotenvVars(lines)
        let incomingKeys = Set(incoming.map(\.key))
        let target = options.outputPath ?? "\(FileManager.default.currentDirectoryPath)/.env"
        let previousText = readFile(target) ?? ""
        let previousKeys = dotenvKeySet(previousText)
        let output: String
        if options.merge {
            output = mergeDotenv(existing: previousText, incoming: incoming)
        } else {
            output = lines.joined(separator: "\n") + "\n"
        }
        let nextKeys = dotenvKeySet(output)
        if options.diff || options.dry || options.dryRun {
            let added = incomingKeys.subtracting(previousKeys).sorted()
            let removed = options.merge ? [String]() : previousKeys.subtracting(nextKeys).sorted()
            let changed = incomingKeys.intersection(previousKeys).filter { key in
                let old = previousText.split(separator: "\n").compactMap { line -> String? in
                    dotenvAssignment(String(line))?.key == key ? String(line) : nil
                }.last
                let neu = incoming.first { $0.key == key }?.assignment
                return old != neu
            }.sorted()
            for key in removed { print(outColor("31", "- \(key)")) }
            for key in changed { print(outColor("33", "~ \(key)")) }
            for key in added { print(outColor("32", "+ \(key)")) }
            let kept = options.merge ? previousKeys.subtracting(incomingKeys).count : 0
            recordHistory(entry: HistoryEntry(at: isoNow(), cmd: "env", target: "\(target) (diff)", env: environment))
            info(
                "env --diff: \(added.count) added, \(changed.count) changed, \(removed.count) removed"
                    + (options.merge ? ", \(kept) other keys kept" : "")
                    + " for \(target) (keys only, no values)"
            )
            return
        }
        recordHistory(entry: HistoryEntry(at: isoNow(), cmd: "env", target: options.outputPath ?? (options.merge ? target : "stdout"), env: environment))
        if options.merge {
            writeAtomic(target, output)
            success("merged \(incoming.count) aliases into \(target) (mode 0600)")
        } else if let outputPath = options.outputPath {
            writeAtomic(outputPath, output)
            success("wrote \(lines.count) aliases (env \(environment)) to \(outputPath) (mode 0600)")
        } else {
            print(output, terminator: "")
        }

    case "run":
        guard let selected = loaded.selectedAliases, !selected.isEmpty else {
            fail("run requires .secret.json or --config FILE with a secrets map; see docs/bitwarden.md")
        }
        guard let command = options.positional.first else {
            fail("run requires a command, e.g. secret run -- npm test")
        }
        let args = Array(options.positional.dropFirst())
        var envVars: [String: String] = [:]
        let optionalSet = Set(options.optional)
        for alias in optionalSet where loaded.definitions[alias] == nil {
            writeErr("secret: \(alias) is not declared (optional, skipping)\n")
        }
        let items = await vaultBackend.items()
        if items != nil {
            let missing = selected.filter { candidate in
                guard let definition = loaded.definitions[candidate] else { return false }
                return !optionalSet.contains(candidate) && resolveOptional(items, definition) == nil
            }
            if !missing.isEmpty {
                warn("hint: pass --optional \(missing.joined(separator: ",")) to skip unresolved aliases")
            }
        }
        for alias in selected {
            guard let definition = loaded.definitions[alias] else { fail("unknown alias: \(alias)") }
            let key = dotenvKey(alias, definition)
            if optionalSet.contains(alias) {
                guard let value = resolveOptional(items, definition) else {
                    warn("skipping \(alias) (optional, unresolved)")
                    continue
                }
                envVars[key] = value
                continue
            }
            envVars[key] = await resolveRequired(items, alias, definition)
        }
        recordHistory(entry: HistoryEntry(at: isoNow(), cmd: "run", target: command, env: environment))
        var mergedEnv = ProcessInfo.processInfo.environment
        for (key, value) in envVars { mergedEnv[key] = value }
        let commandPath = command.contains("/") ? command : (pathTo(command) ?? command)
        // Leak guard: values injected into the environment are also scrubbed
        // from everything the command writes to stdout/stderr.
        let status = runCommandScrubbed(commandPath, args, env: mergedEnv, secrets: envVars.sorted { $0.key < $1.key })
        exit(status == 0 ? 0 : status)

    case "print":
        if options.all {
            printAllScopes(options.configPath, json: options.json)
            recordHistory(entry: HistoryEntry(at: isoNow(), cmd: "print", target: "all", env: environment))
        } else {
            let scope = options.positional.first ?? "project"
            printScope(scope: scope, selectedConfig: options.configPath, json: options.json)
            recordHistory(entry: HistoryEntry(at: isoNow(), cmd: "print", target: scope, env: environment))
        }

    case "global":
        printScope(scope: "global", selectedConfig: options.configPath, json: options.json)
        recordHistory(entry: HistoryEntry(at: isoNow(), cmd: "global", target: "global", env: environment))

    case "prune":
        guard let selected = loaded.selectedAliases, !selected.isEmpty else {
            fail("prune requires .secret.json or --config FILE with a secrets map; see docs/bitwarden.md")
        }
        let items = await vaultBackend.items()
        if items == nil {
            await vaultBackend.requireUnlocked()
            fail("could not read vault items — cannot prune")
        }
        let missing = selected.filter { alias in
            itemFor(items, loaded.definitions[alias]?.item ?? "") == nil
        }
        for alias in missing {
            let definition = loaded.definitions[alias]!
            if options.dryRun {
                info("would remove \(alias) (\(definition.item))")
            } else {
                unsetAlias(alias, options.global ? userConfigPath : options.configPath, quiet: true)
            }
        }
        if options.dryRun {
            if missing.count > 0 {
                warn("prune: \(missing.count) alias(es) would be removed")
            } else {
                info("prune: no aliases missing from the vault")
            }
        } else if missing.count > 0 {
            success("pruned \(missing.count) alias(es) from config")
        } else {
            info("prune: no aliases missing from the vault")
        }
        recordHistory(entry: HistoryEntry(at: isoNow(), cmd: "prune", target: missing.joined(separator: ","), env: environment))

    case "search":
        guard let query = options.positional.first else {
            fail("search requires a term, e.g. secret search token (matches alias, item, env key)")
        }
        searchAliases(query, options.configPath, json: options.json)
        recordHistory(entry: HistoryEntry(at: isoNow(), cmd: "search", target: query, env: environment))

    case "lint":
        lint(options.configPath, json: options.json)

    case "doctor":
        await doctor(loaded.ordered, json: options.json, ci: options.ci)

    case "recent":
        printRecent(json: options.json)

    case "history":
        printHistory(json: options.json)

    default:
        fail("unknown command: \(options.command)")
    }
}

var rawArgs = CommandLine.arguments
rawArgs.removeFirst()
if rawArgs.first == "__secret-keepalive", rawArgs.count >= 2 {
    keepaliveLoop(socket: rawArgs[1])
}

await run()
