#!/usr/bin/env python3
"""End-to-end tests for the secret CLI.

Self-contained: writes a fake `bw` into a temp PATH entry and isolates config,
audit and daemon state with SECRET_CONFIG_DIR, so no real vault is touched.
Run from the repo root after `cd secret && swift build -c release`:

    python3 tests/e2e.py
"""
import json
import re
import os
import shutil
import stat as statmod
import subprocess
import sys
import tempfile

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
BIN = os.environ.get("BIN", os.path.join(REPO, "secret", ".build", "release", "secret"))
FAKE_BW = os.path.join(REPO, "tests", "fake-bw")
FAKE_OP = os.path.join(REPO, "tests", "fake-op")

failures = []


def check(label, condition, detail=""):
    if condition:
        print("PASS " + label)
    else:
        print("FAIL %s %s" % (label, detail))
        failures.append(label)


def main():
    work = tempfile.mkdtemp(prefix="secrete2e.")
    bin_dir = os.path.join(work, "bin")
    proj = os.path.join(work, "proj")
    os.makedirs(bin_dir)
    os.makedirs(proj)
    shutil.copy(FAKE_BW, os.path.join(bin_dir, "bw"))
    os.chmod(os.path.join(bin_dir, "bw"), 0o755)

    env = dict(os.environ)
    env.update({
        "PATH": bin_dir + ":" + env["PATH"],
        "OP_FAKE_STATE": os.path.join(work, "op-state.json"),
        "BW_FAKE_STATE": os.path.join(work, "bw-state.json"),
        "SECRET_CONFIG_DIR": os.path.join(work, "config"),
        "SECRET_AUDIT_FILE": os.path.join(work, "audit.log"),
        "SECRET_NO_BIOMETRICS": "1",
        "SECRET_DAEMON": "0",
    })
    env.pop("BW_SESSION", None)
    env.pop("SECRET_BACKEND", None)

    def run(args, stdin=None, extra=None):
        run_env = dict(env)
        if extra:
            run_env.update(extra)
        return subprocess.run(
            [BIN] + args, cwd=proj, env=run_env, input=stdin,
            capture_output=True, text=True,
        )

    with open(os.path.join(proj, ".secret.json"), "w") as handle:
        json.dump({"secrets": {
            "E2E_TOKEN": {"item": "e2e-token", "field": "password", "env": "E2E_TOKEN"},
            "E2E_OTHER": {"item": "e2e-other", "field": "password", "env": "E2E_OTHER"},
        }}, handle)

    run(["set", "E2E_TOKEN", "--force"], "synthetic-e2e-value-abc123\n")
    run(["set", "E2E_OTHER", "--force"], "synthetic-other-value-zzz999\n")

    out = run(["version"]).stdout.strip()
    check("version", out == "secret 2.5.0", out)

    result = run(["get", "E2E_TOKEN"])
    check("get", result.stdout.strip() == "synthetic-e2e-value-abc123", result.stderr)

    run(["--caller", "e2e-agent", "--reason", "smoke test", "get", "E2E_TOKEN"])
    audit_out = run(["audit", "--json"]).stdout
    records = json.loads(audit_out)
    check("audit caller", any(r.get("caller") == "e2e-agent" for r in records))
    check("audit reason", any(r.get("reason") == "smoke test" for r in records))
    check("audit value-free", "synthetic-e2e-value-abc123" not in audit_out)
    check("audit has outcome+cwd", all("outcome" in r and "cwd" in r for r in records))
    mode = statmod.S_IMODE(os.stat(os.path.join(work, "audit.log")).st_mode)
    check("audit mode 0600", mode == 0o600, oct(mode))

    denied = run(["get", "E2E_TOKEN"], extra={"SECRET_DENY_PLAINTEXT_GET": "1"})
    check("deny get", denied.returncode != 0 and "disabled" in denied.stderr, denied.stderr)
    denied_audit = run(["audit", "--json"]).stdout
    check("deny is audited", "plaintext reads are disabled" in denied_audit)

    src = os.path.join(proj, "src")
    os.makedirs(src)
    clean = run(["scan", "."])
    check("scan clean", clean.returncode == 0, clean.stderr)
    with open(os.path.join(src, "leak.ts"), "w") as handle:
        handle.write('const token = "synthetic-other-value-zzz999";\n')
    dirty = run(["scan", "."])
    check("scan exit 1", dirty.returncode == 1, dirty.stderr)
    check("scan hit line+alias", "src/leak.ts:1" in dirty.stdout and "E2E_OTHER" in dirty.stdout, dirty.stdout)
    check("scan value-free", "synthetic-other-value-zzz999" not in dirty.stdout + dirty.stderr)
    only = run(["scan", ".", "--alias", "E2E_TOKEN", "--json"])
    check("scan --alias filter", json.loads(only.stdout) == [], only.stdout)
    unresolvable = run(["scan", ".", "--alias", "NOT_DECLARED", "--json"])
    check("scan unresolved is not a false clean", unresolvable.returncode == 2, unresolvable.stderr)
    shutil.rmtree(src)

    messages = [
        {"jsonrpc": "2.0", "id": 1, "method": "initialize",
         "params": {"protocolVersion": "2024-11-05", "capabilities": {},
                    "clientInfo": {"name": "e2e", "version": "0"}}},
        {"jsonrpc": "2.0", "method": "notifications/initialized"},
        {"jsonrpc": "2.0", "id": 2, "method": "tools/list"},
        {"jsonrpc": "2.0", "id": 3, "method": "tools/call",
         "params": {"name": "secret_list", "arguments": {}}},
        {"jsonrpc": "2.0", "id": 4, "method": "tools/call",
         "params": {"name": "secret_check", "arguments": {"alias": "E2E_TOKEN"}}},
        {"jsonrpc": "2.0", "id": 5, "method": "tools/call",
         "params": {"name": "secret_run",
                    "arguments": {"command": ["/bin/sh", "-lc", 'printf %s "$E2E_TOKEN"']}}},
        {"jsonrpc": "2.0", "id": 6, "method": "tools/call",
         "params": {"name": "secret_run",
                    "arguments": {"command": ["/bin/sh", "-lc", "echo boom >&2; exit 3"]}}},
        {"jsonrpc": "2.0", "id": 7, "method": "tools/call",
         "params": {"name": "nope", "arguments": {}}},
    ]
    mcp_input = "\n".join(json.dumps(m) for m in messages) + "\n"
    mcp_raw = run(["mcp"], mcp_input).stdout
    replies = {}
    for line in mcp_raw.splitlines():
        if not line.strip():
            continue
        payload = json.loads(line)
        replies[payload.get("id")] = payload

    def text_of(reply_id):
        return replies[reply_id]["result"]["content"][0]["text"]

    check("mcp initialize", replies[1]["result"]["serverInfo"]["version"] == "2.5.0")
    names = [tool["name"] for tool in replies[2]["result"]["tools"]]
    check("mcp tools/list", set(names) == {"secret_list", "secret_check", "secret_status", "secret_scan", "secret_run"}, names)
    listing = json.loads(text_of(3))
    check("mcp list metadata", listing["count"] == 2)
    check("mcp list value-free", "synthetic-" not in mcp_raw)
    check("mcp check available", json.loads(text_of(4))["available"] is True, text_of(4))
    run_result = json.loads(text_of(5))
    check("mcp run scrubs stdout", run_result["stdout"] == "[scrubbed]", run_result["stdout"])
    check("mcp run value-free", "synthetic-e2e-value-abc123" not in mcp_raw)
    check("mcp run injected", run_result["injectedAliases"] == ["E2E_TOKEN", "E2E_OTHER"], run_result["injectedAliases"])
    failing = json.loads(text_of(6))
    check("mcp run exit code", failing["exitCode"] == 3, failing)
    check("mcp run stderr passed", "boom" in failing["stderr"], failing)
    check("mcp unknown tool", "unknown tool" in text_of(7), text_of(7))
    mcp_audit = run(["audit", "--json"]).stdout
    check("mcp audited", '"caller":"mcp"' in mcp_audit or 'mcp:run' in mcp_audit, mcp_audit[-300:])

    # --- 1Password backend through a fake `op`, plus a per-alias backend mix
    op_state = os.path.join(work, "op-state.json")
    with open(op_state, "w") as handle:
        json.dump({"items": {"id-1": {"id": "id-1", "title": "OpenAI", "vault": "Personal", "custom": {"api_key": "sk-op-fake-value"}}}, "next": 2}, handle)
    shutil.copy(FAKE_OP, os.path.join(bin_dir, "op"))
    os.chmod(os.path.join(bin_dir, "op"), 0o755)
    op_env = {"OP_FAKE_STATE": op_state, "SECRET_ONEPASSWORD_VAULT": "Personal"}
    with open(os.path.join(proj, ".secret.json"), "w") as handle:
        json.dump({"secrets": {
            "OP_KEY": {"item": "op://Personal/OpenAI/api_key", "field": "custom:api_key", "env": "OP_KEY", "backend": "1password"},
        }}, handle)
    op_get = run(["get", "OP_KEY"], extra=op_env)
    check("1password read via op", op_get.stdout.strip() == "sk-op-fake-value", op_get.stderr)
    op_list = run(["list", "--json"], extra=op_env)
    check("1password metadata", "op://Personal/OpenAI/api_key" in op_list.stdout, op_list.stdout)
    op_totp = run(["totp", "OP_KEY"], extra=op_env)
    check("1password totp", op_totp.stdout.strip() == "123456", op_totp.stderr)
    op_set = run(["set", "OP_KEY", "--force"], "sk-op-updated\n", extra=op_env)
    check("1password write updates the referenced item", op_set.returncode == 0, op_set.stderr)
    op_after = run(["get", "OP_KEY"], extra=op_env)
    check("1password write round-trips", op_after.stdout.strip() == "sk-op-updated", op_after.stdout + op_after.stderr)
    with open(os.path.join(proj, ".secret.json"), "w") as handle:
        json.dump({"secrets": {
            "OP_KEY": {"item": "op://Personal/OpenAI/api_key", "field": "custom:api_key", "env": "OP_KEY", "backend": "1password"},
            "E2E_TOKEN": {"item": "e2e-token", "field": "password", "env": "E2E_TOKEN"},
        }}, handle)
    mixed = run(["env", "--export"], extra=op_env)
    check("per-alias backend mix resolves both", "OP_KEY=" in mixed.stdout and "E2E_TOKEN=" in mixed.stdout, mixed.stderr)

    # --- adopt: declare an existing vault item without re-entering its value
    with open(os.path.join(proj, ".secret.json"), "w") as handle:
        json.dump({"secrets": {}}, handle)
    with open(env["BW_FAKE_STATE"], "w") as handle:
        json.dump({"items": [{"id": "u1", "name": "global/orphan-token", "login": {"password": "orphan-value"}}], "next": 2}, handle)
    unaliased = run(["unaliased", "--json"])
    check("unaliased lists the orphan", json.loads(unaliased.stdout)[0]["alias"] == "orphan-token", unaliased.stdout)
    adopted = run(["adopt", "orphan-token", "--global", "--expect", "nonempty"])
    check("adopt declares the alias", adopted.returncode == 0, adopted.stderr)
    check("adopt writes the item", "global/orphan-token" in open(os.path.join(work, "config", "config.json")).read())
    check("adopt keeps the value readable", run(["get", "orphan-token"]).stdout.strip() == "orphan-value")
    check("adopt removes it from unaliased", json.loads(run(["unaliased", "--json"]).stdout) == [])
    check("adopt refuses a duplicate", run(["adopt", "orphan-token", "--global"]).returncode != 0)
    check("adopt refuses an unknown item", run(["adopt", "ghost", "--global"]).returncode != 0)

    # --- expiry enforcement + metadata editing
    with open(os.path.join(proj, ".secret.json"), "w") as handle:
        json.dump({"secrets": {
            "STALE": {"item": "stale", "field": "password", "env": "STALE", "expiresAt": "2020-01-01"},
            "FRESH": {"item": "fresh", "field": "password", "env": "FRESH"},
        }}, handle)
    with open(env["BW_FAKE_STATE"], "w") as handle:
        json.dump({"items": [
            {"id": "s1", "name": "stale", "login": {"password": "stale-value"}},
            {"id": "f1", "name": "fresh", "login": {"password": "fresh-value"}},
        ], "next": 3}, handle)
    blocked = run(["env", "--export"])
    check("expired alias blocks env", blocked.returncode != 0 and "STALE expired on 2020-01-01" in blocked.stderr, blocked.stderr)
    check("expired message names the fix", "secret rotate STALE" in blocked.stderr)
    allowed = run(["env", "--export", "--allow-expired"])
    check("--allow-expired injects it anyway", "STALE=" in allowed.stdout, allowed.stdout + allowed.stderr)
    ran = run(["run", "--", "/usr/bin/true"])
    check("expired alias blocks run", ran.returncode != 0 and "STALE" in ran.stderr, ran.stderr)
    check("edit --expect writes the rule", run(["edit", "FRESH", "--expect", "string(startsWith=fresh-)"]).returncode == 0)
    check("edit --expect is in the config", '"expect": "string(startsWith=fresh-)"' in open(os.path.join(proj, ".secret.json")).read())
    check("edit --expect empty clears it", run(["edit", "FRESH", "--expect", ""]).returncode == 0 and '"expect"' not in open(os.path.join(proj, ".secret.json")).read())
    check("edit --backend writes the override", run(["edit", "FRESH", "--backend", "keychain"]).returncode == 0 and '"backend": "keychain"' in open(os.path.join(proj, ".secret.json")).read())

    # --- mcp: secret_scan reports a leak without the value
    with open(os.path.join(proj, ".secret.json"), "w") as handle:
        json.dump({"secrets": {"FRESH": {"item": "fresh", "field": "password", "env": "FRESH"}}}, handle)
    with open(os.path.join(proj, "leak.txt"), "w") as handle:
        handle.write("token=fresh-value\n")
    scan_messages = [
        {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}},
        {"jsonrpc": "2.0", "id": 2, "method": "tools/call", "params": {"name": "secret_scan", "arguments": {"paths": ["."]}}},
    ]
    scan_raw = run(["mcp"], "\n".join(json.dumps(m) for m in scan_messages) + "\n").stdout
    scan_reply = next(json.loads(line) for line in scan_raw.splitlines() if '"id":2' in line)
    scan_payload = json.loads(scan_reply["result"]["content"][0]["text"])
    check("mcp scan finds the leak", scan_payload["matches"] >= 1 and any(h["alias"] == "FRESH" for h in scan_payload["hits"]), scan_payload)
    check("mcp scan never prints the value", "fresh-value" not in scan_raw)
    check("mcp scan flags an error for an agent", scan_reply["result"].get("isError") is True)
    os.remove(os.path.join(proj, "leak.txt"))

    # --- generate kinds
    for kind, pattern in (("password", r"[!-~]{40}"), ("token", r"[A-Za-z0-9]{40}"), ("hex", r"[0-9a-f]{40}"), ("uuid", r"[0-9a-f-]{36}")):
        generated = run(["generate", "--kind", kind, "--length", "40"]).stdout.strip()
        check(f"generate {kind}", re.fullmatch(pattern, generated) is not None, generated)
    phrase = run(["generate", "--kind", "passphrase", "--words", "4"]).stdout.strip()
    check("generate passphrase", len(phrase.split("-")) == 4, phrase)
    check("generate is random", run(["generate"]).stdout.strip() != run(["generate"]).stdout.strip())
    check("generate gen alias", re.fullmatch(r"[A-Za-z0-9]{8}", run(["gen", "--kind", "token", "--length", "8"]).stdout.strip()) is not None)

    # --- credential helpers over integrations
    with open(os.path.join(proj, ".secret.json"), "w") as handle:
        json.dump({
            "secrets": {
                "GH_TOKEN": {"item": "gh", "field": "password", "env": "GH_TOKEN"},
                "GITLAB_TOKEN": {"item": "gl", "field": "password", "env": "GITLAB_TOKEN"},
                "GHCR_TOKEN": {"item": "ghcr", "field": "password", "env": "GHCR_TOKEN"},
                "PORTS": {"item": "port-ok", "field": "password", "env": "PORTS", "expect": "port"},
                "BAD_PORT": {"item": "port-bad", "field": "password", "env": "BAD_PORT", "expect": "port"},
            },
            "integrations": {
                "git": {"github.com": "GH_TOKEN", "gitlab.com/work": {"alias": "GITLAB_TOKEN", "username": "oauth2"}},
                "docker": {"ghcr.io": {"alias": "GHCR_TOKEN", "username": "someone"}},
            },
        }, handle)
    with open(env["BW_FAKE_STATE"], "w") as handle:
        json.dump({"items": [
            {"id": "1", "name": "gh", "login": {"password": "gh-secret-1"}},
            {"id": "2", "name": "gl", "login": {"password": "gl-secret-2"}},
            {"id": "3", "name": "ghcr", "login": {"password": "ghcr-secret-3"}},
            {"id": "4", "name": "port-ok", "login": {"password": "8080"}},
            {"id": "5", "name": "port-bad", "login": {"password": "70000"}},
        ], "next": 6}, handle)
    git_get = run(["git-credential", "get"], "protocol=https\nhost=github.com\npath=astahmer/repo.git\n\n")
    check("git-credential get", git_get.stdout.split("\n")[:2] == ["username=x-access-token", "password=gh-secret-1"], git_get.stdout + git_get.stderr)
    git_path = run(["git-credential", "get"], "protocol=https\nhost=gitlab.com\npath=work/repo.git\n\n")
    check("git-credential path + username", "username=oauth2" in git_path.stdout and "gl-secret-2" in git_path.stdout, git_path.stdout)
    unmapped = run(["git-credential", "get"], "protocol=https\nhost=example.com\n\n")
    check("git-credential unmapped falls through", unmapped.returncode == 0 and unmapped.stdout.strip() == "", unmapped.stdout)
    docker_get = run(["docker-credential", "get"], '{"ServerURL":"ghcr.io"}')
    payload = json.loads(docker_get.stdout)
    check("docker-credential get", payload == {"ServerURL": "ghcr.io", "Username": "someone", "Secret": "ghcr-secret-3"}, docker_get.stdout)
    check("docker-credential list", json.loads(run(["docker-credential", "list"], "{}").stdout).get("ghcr.io") == "someone")
    check("docker-credential unmapped fails", run(["docker-credential", "get"], '{"ServerURL":"registry.example.com"}').returncode != 0)

    # --- typed values
    typed_ok = run(["env", "--export", "--optional", "BAD_PORT"])
    check("typed rule passes a valid value", "PORTS=" in typed_ok.stdout, typed_ok.stdout + typed_ok.stderr)
    typed_bad = run(["env", "--export"])
    check("typed rule blocks a bad value", typed_bad.returncode != 0 and "BAD_PORT" in typed_bad.stderr and "port" in typed_bad.stderr, typed_bad.stderr)
    check("typed failure never prints the value", "70000" not in typed_bad.stderr + typed_bad.stdout)

    shutil.rmtree(work)
    print("ALL PASS" if not failures else "FAILURES: %s" % ", ".join(failures))
    return 0 if not failures else 1


if __name__ == "__main__":
    sys.exit(main())
