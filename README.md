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
with `SECRET_VERSION=v2.1.0`, relocate with `SECRET_INSTALL_DIR`.

Nix users get it from [nixfiles](https://github.com/astahmer/nixfiles), which packages the same source.

## Components

- `secret/` — CLI for scoped alias lookup, vault operations, project environment injection, session management, health checks, leak scanning, an audit trail and an MCP server for agents. It supports Bitwarden and the macOS Keychain backend.
- `secretbar/` — SecretBar.app, a macOS interface for searching configured aliases, copying values, unlocking, and reviewing vault health. It invokes the `secret` executable.

The clients work with configured aliases. They do not enumerate an entire vault as an implicit discovery mechanism. Values stay in the selected backend unless a user action returns or copies one.

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
