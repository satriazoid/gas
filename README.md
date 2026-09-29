# Guardian Agent Sandbox (`gas`)

A tiny CLI wrapper that runs AI coding agents (Hermes, OpenCode, OMP, Claude
Code, Codex…) behind a filesystem policy, so an agent can never read your SSH
keys, `.env` files, browser data or tax documents — not even on prompt
injection.

Implements the PRD in `prd-Guardian Agent Sandbox.md`.

- Static Go binary, no daemon, no container runtime
- Whitelist directories + blacklist glob patterns, evaluated fail-closed
- Blocked accesses are answered with a fake `ENOENT`/`EACCES`, so the agent
  keeps working and never learns the real layout
- Every denial is appended to `~/.gas/logs/access_denied.log` (JSON lines,
  size-rotated)
- Linux: kernel-level mount/pid/user namespace jail. Windows/macOS: policy
  engine + stdio filter + process containment

## Install

```bash
# Linux / macOS
go build -trimpath -ldflags "-s -w" -o gas ./cmd/gas && sudo install -m755 gas /usr/local/bin/gas

# Windows
go build -trimpath -ldflags "-s -w" -o bin\gas.exe .\cmd\gas

# all targets at once
make all-cross
```

Requires Go ≥ 1.22. No cgo.

## Quick start

```bash
cd ~/projects/my-app
gas init                      # writes ~/.gas/config.yaml and ./.gasignore
gas doctor                    # self-test: 15 policy assertions + capabilities
gas contract . --force         # install the agent rule block into ./AGENTS.md
gas check /etc/passwd          # DENY (exit 126) — hook this into your agent
gas run hermes                 # launch the agent inside the sandbox
gas run --read-only opencode   # no writes at all
gas status                     # effective policy + block counters
gas log --tail 20              # recent audit entries
```

## How enforcement reaches the agent

`gas run` injects a contract into the child process:

| Variable | Meaning |
|---|---|
| `GAS_SANDBOX=1` | the agent is sandboxed; refuse to operate if unset rules |
| `GAS_PROJECT` | the only directory the agent may read |
| `GAS_CHECK` | executable command: `gas check [--op read\|write\|exec] PATH` |
| `GAS_LOG` | audit log path |
| `GAS_POLICY_FILE` | `.gasignore` in use |

An agent integration resolves every file tool through `$GAS_CHECK` and treats
exit code `126` as "not found / permission denied" without echoing the reason.
See `docs/integrations.md` for drop-in snippets per agent.

Modes:

- `namespace` (Linux, auto when available) — the agent is pivoted into a tmpfs
  root where only the allow-listed directories are bind-mounted; `/proc/sys`,
  `/etc/shadow`, `~/.ssh` and everything else are simply *not there*. Any
  process the agent spawns inherits the jail, which closes the shell-bypass
  gap noted in the PRD risk table.
- `policy` (default on Windows/macOS) — env contract + `gas check` + audit.
  The job object (Windows) / process tree kill keeps the agent contained.
- `filter` — additionally pipes the agent's stdio JSON through the policy
  matcher and rewrites denied tool calls into fake errors.

## Policy file

Global `~/.gas/config.yaml` plus per-project `.gasignore`. Both are merged and
**a project file can only tighten, never loosen, the global policy** —
`read_only` and `fail_closed` stay true once set.

```yaml
# .gasignore
project_allow_roots: [".", "../shared-libs"]
project_internal_deny: ["**/node_modules/.bin/**", "**/.git/hooks/**"]
writable_paths: ["**/src/**/*.go", "**/README.md"]
read_only: false
```

Evaluation order (first match wins):

1. empty / unresolvable path → **deny**
2. `global_deny_patterns` → **deny**
3. `project_internal_deny` → **deny**
4. `exec` → allow-list, then anything inside the white box
5. `write` → `read_only` blocks all; otherwise only `writable_paths`
6. `read` → inside an allow root → **allow**
7. everything else → **deny**

Deny rules are also checked against the symlink-resolved path, so a symlink
inside the project pointing at `~/.ssh` is still blocked.

## Audit log

`~/.gas/logs/access_denied.log`, one JSON object per line:

```json
{"ts":"2026-09-29T10:15:22Z","action":"blocked","agent":"hermes","op":"read",
 "path":"c:/users/jejo/.ssh/id_rsa","reason":"global_deny","rule":"**/.ssh/**",
 "scope":"global","source":"cli-check"}
```

Rotates at `audit.max_size_mb` (default 5 MB) with `max_backups` (default 3).
Set `notify.webhook_url` to POST each block to a bot bridge (Telegram, Slack).

## Escape hatch

`gas run --unsafe <agent>` disables the sandbox, prints a loud banner and
records an `action:"bypass"` entry. Use it only for critical debugging.

## Exit codes

| Code | Meaning |
|---|---|
| 0 | success / access allowed |
| 1 | blocked or runtime error |
| 2 | usage error |
| 126 | `gas check` verdict: denied (POSIX "cannot execute") |

## Layout

```
cmd/gas/              CLI: run, check, init, status, log, policy, doctor
internal/config/      global + project policy loading and merging
internal/policy/      allow-list / deny-list decision engine
internal/audit/       JSONL audit log, rotation, stats, webhook notify
internal/proxy/       stdio JSON tool-call filter (fake errors)
internal/isolation/   Linux namespaces / Windows job object / portable mode
docs/design.md        architecture, threat model, known limits
docs/integrations.md  per-agent wiring (Hermes, OpenCode, OMP, MCP)
```

## Status

Phase 1 (policy engine, config, audit, CLI, Windows containment) and Phase 2
(Linux namespace isolation, audit logging) are implemented and tested. Phase 3
items still open: Telegram notification bridge out of the box, localhost
dashboard, packaged releases. Network egress restrictions are parsed and
reported but **not enforced** yet — see `docs/design.md`.
