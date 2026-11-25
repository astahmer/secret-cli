#!/usr/bin/env python3
"""End-to-end tests for the secret CLI.

Self-contained: writes a fake `bw` into a temp PATH entry and isolates config,
audit and daemon state with SECRET_CONFIG_DIR, so no real vault is touched.
Run from the repo root after `cd secret && swift build -c release`:

    python3 tests/e2e.py
"""
import json
import os
import shutil
import stat as statmod
import subprocess
import sys
import tempfile

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
BIN = os.environ.get("BIN", os.path.join(REPO, "secret", ".build", "release", "secret"))
FAKE_BW = os.path.join(REPO, "tests", "fake-bw")

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
    check("version", out == "secret 2.1.2", out)

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

    check("mcp initialize", replies[1]["result"]["serverInfo"]["version"] == "2.1.2")
    names = [tool["name"] for tool in replies[2]["result"]["tools"]]
    check("mcp tools/list", set(names) == {"secret_list", "secret_check", "secret_status", "secret_run"}, names)
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

    shutil.rmtree(work)
    print("ALL PASS" if not failures else "FAILURES: %s" % ", ".join(failures))
    return 0 if not failures else 1


if __name__ == "__main__":
    sys.exit(main())
