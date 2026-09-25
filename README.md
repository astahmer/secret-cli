# Secret CLI and SecretBar

A value-minimizing secret manager for configured aliases, with a native Swift CLI and a macOS menu-bar companion.

## Components

- `secret/` — CLI for scoped alias lookup, vault operations, project environment injection, session management, and health checks. It supports Bitwarden and the macOS Keychain backend.
- `secretbar/` — SecretBar.app, a macOS interface for searching configured aliases, copying values, unlocking, and reviewing vault health. It invokes the `secret` executable.

The clients work with configured aliases. They do not enumerate an entire vault as an implicit discovery mechanism. Values stay in the selected backend unless a user action returns or copies one.

## Requirements

- Swift 5.9 or newer.
- macOS 14 or newer for SecretBar.
- A configured backend for CLI operations. Bitwarden mode uses the official `bw` CLI.
- SecretBar requires a compatible `secret` CLI available to the app.

## Build

Build the CLI:

```sh
cd secret
swift build -c release
```

Build SecretBar on macOS:

```sh
cd secretbar
swift build -c release
```

## Repository layout

```
secret/       Swift Package for the CLI
secretbar/    Swift Package and app metadata for SecretBar
```

Nix packaging and machine-specific integration live in [nixfiles](https://github.com/astahmer/nixfiles). That repository supplies the backend tools, installs the binaries, and configures shell and login-session behavior.

## Security

Do not commit vault values, session tokens, local alias configuration, or authentication state. Project alias files should contain references and metadata only. Use the backend to store values.
