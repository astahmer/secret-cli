# Secret CLI and SecretBar

A value-minimizing secret manager for configured aliases, with a native Swift CLI and a macOS menu-bar companion.

## Install

Nothing to clone, nothing to build.

```sh
brew install astahmer/tap/secret     # recommended
```

Or the standalone installer (universal binary, Apple Silicon and Intel,
checksum-verified, no clone and no build):

```sh
curl -sSfL https://raw.githubusercontent.com/astahmer/secret-cli/main/install.sh | sh
```

It installs to `/usr/local/bin` when writable, else `~/.local/bin`; pin a version
with `SECRET_VERSION=v2.1.1`, relocate with `SECRET_INSTALL_DIR`.

Nix users get it from [nixfiles](https://github.com/astahmer/nixfiles), which packages the same source.

## Components

- `secret/` — CLI for scoped alias lookup, vault operations, project environment injection, session management, health checks, leak scanning, an audit trail and an MCP server for agents. Backends: Bitwarden, 1Password and the macOS Keychain, selectable per alias.
- `secretbar/` — SecretBar.app, a macOS interface for searching configured aliases, copying values, unlocking, and reviewing vault health. It invokes the `secret` executable.

The clients work with configured aliases. They do not enumerate an entire vault as an implicit discovery mechanism. Values stay in the selected backend unless a user action returns or copies one.

## Backends, including per alias

`backend` in the global config picks the default (`bitwarden`, `1password`,
`keychain`), and an alias may override it, so one config mixes providers:

```json
{
  "secrets": {
    "STRIPE_KEY": { "item": "op://Personal/Stripe/api_key", "field": "custom:api_key", "env": "STRIPE_KEY", "backend": "1password" },
    "DATABASE_URL": { "item": "app/db", "field": "password", "env": "DATABASE_URL" },
    "LOCAL_TOKEN": { "item": "local-token", "field": "password", "env": "LOCAL_TOKEN", "backend": "keychain" }
  }
}
```

1Password items are addressed with the normal `op://vault/item/field`
reference and read through `op read`, so `op signin`, a service account
(`OP_SERVICE_ACCOUNT_TOKEN`) or the desktop app's Touch ID all work unchanged.
`secret set` on such an alias edits that item (`op item edit`); writes to a
reference never create a duplicate. `SECRET_ONEPASSWORD_VAULT` sets the vault
name for configs that name a bare item, and `SECRET_BACKEND` forces one backend
for a single invocation.

## Generation, credential helpers and typed values

```sh
secret generate --kind password --length 40
secret generate --kind passphrase --words 5
secret generate --kind token|hex|base64|uuid
```

Git and Docker credential helpers read the vault instead of a copy on disk:

```json
{
  "integrations": {
    "git":    { "github.com": "GH_TOKEN",
                "gitlab.com/work": { "alias": "GITLAB_TOKEN", "username": "oauth2" } },
    "docker": { "ghcr.io": { "alias": "GHCR_TOKEN", "username": "astahmer" } }
  }
}
```

```sh
git config --global credential.https://github.com.helper '!secret git-credential'
# ~/.docker/config.json: { "credsStore": "secret" }  (symlink `secret` as docker-credential-secret)
```

An alias may declare what its value must look like; `env` and `run` refuse a
value that does not match, without printing it:

```json
{ "PORT":    { "item": "app", "field": "port",    "expect": "port" },
  "API_URL": { "item": "app", "field": "url",     "expect": "url" },
  "MODE":    { "item": "app", "field": "mode",    "expect": "enum:dev,staging,prod" },
  "STRIPE":  { "item": "app", "field": "stripe",  "expect": "string(startsWith=sk-)" } }
```

Rules: `string`, `nonempty`, `url`, `email`, `port`, `number`, `integer`,
`boolean`, `json`, `base64`, `uuid`, `enum:a,b`, and
`string(startsWith=…|endsWith=…|contains=…|length=N)`. `secret lint` checks the
rule syntax offline; `secret doctor` reports a value that fails at runtime.

## Giving secrets to an agent

An agent must never learn a value. Three supported paths, in order of preference:

```sh
secret mcp                              # MCP server: metadata + env-injected, scrubbed runs
secret run -- npm test                  # inject aliases into one command, scrub its output
SECRET_DENY_PLAINTEXT_GET=1 secret get x # refuses plaintext reads in agent shells
```

`secret mcp` speaks Model Context Protocol over stdin/stdout and exposes four tools:

| Tool | What it answers |
| --- | --- |
| `secret_list` | Which aliases exist, their item, field, env key, expiry — never values |
| `secret_check` | Whether one alias resolves right now, without returning it |
| `secret_status` | Backend, auth state, unlock state, audit path |
| `secret_run` | Run a command with the project's values injected; exact value bytes in stdout/stderr become `[scrubbed]`, output capped at 512 KiB, 60 s default timeout |

Wire it into an agent config instead of granting `secret get`:

```json
{ "mcpServers": { "secret": { "command": "secret", "args": ["mcp"] } } }
```

## Audit trail

Every command appends one JSONL record to `~/.local/state/secret/audit.log`
(mode 0600, rotated at 5 MiB, three generations). Records carry the command,
alias, environment, caller, reason, working directory, pid and outcome — never a
value.

```sh
secret --caller ci --reason deploy get DATABASE_URL
secret audit --json
```

The caller defaults to `cli`, or to `$SECRET_CALLER`. The MCP server records
caller `mcp`. Turn it off with `SECRET_NO_AUDIT=1`; relocate it with
`SECRET_AUDIT_FILE` or `SECRET_AUDIT_DIR`.

## Leak scan

```sh
secret scan .                  # current directory
secret scan src --alias STRIPE_KEY --json
```

Resolves every configured alias and searches files for its current value,
excluding `.git`, `node_modules`, build output, binaries and files over 4 MiB.
It prints `file:line` and the alias — never the value — and exits 1 on a hit.

## Requirements

- Swift 5.9 or newer to build from source.
- macOS 14 or newer for SecretBar.
- A configured backend for CLI operations. Bitwarden mode uses the official `bw` CLI.

## Build from source

```sh
cd secret && swift build -c release
cd secretbar && swift build -c release   # needs a full Xcode toolchain (SwiftUI macros)
```

Release artifacts: `scripts/package.sh --universal --formula` builds the
universal CLI tarball, checksums and the Homebrew formula. Pushing a `v*` tag
runs `.github/workflows/release.yml`, which publishes the tarball and updates
the tap when `HOMEBREW_TAP_TOKEN` is set. `tests/e2e.py` is the end-to-end suite
(fake `bw`, isolated config): `python3 tests/e2e.py` after a release build.
`tests/bench-mcp.mjs` compares per-call CLI subprocesses against one long-lived
`secret mcp` server (`BENCH_WORKERS=1,4,8 node tests/bench-mcp.mjs`).

## Repository layout

```
secret/       Swift Package for the CLI
secretbar/    Swift Package and app metadata for SecretBar
scripts/      release packaging
```

Nix packaging and machine-specific integration live in [nixfiles](https://github.com/astahmer/nixfiles). That repository supplies the backend tools, installs the binaries, and configures shell and login-session behavior.

## Environment

| Variable | Effect |
| --- | --- |
| `SECRET_CONFIG_DIR` | Override `~/.config/secret` (config, session, daemon state) |
| `SECRET_BACKEND` | Force `bitwarden` or `keychain` for one invocation |
| `SECRET_AUDIT_FILE`, `SECRET_AUDIT_DIR` | Move the audit log |
| `SECRET_NO_AUDIT=1` | Disable audit records |
| `SECRET_DENY_PLAINTEXT_GET=1` | Refuse `get` without `--copy` |
| `SECRET_CALLER`, `SECRET_REASON` | Default audit caller/reason |
| `SECRET_DAEMON=0` | Skip the `bw serve` daemon |
| `SECRET_NO_BIOMETRICS=1` | Never prompt for Touch ID |

## Security

Do not commit vault values, session tokens, local alias configuration, or authentication state. Project alias files should contain references and metadata only. Use the backend to store values.
