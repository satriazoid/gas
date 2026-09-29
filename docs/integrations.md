# Wiring GAS into agents

Every integration follows the same contract: before a file tool touches a
path, ask `$GAS_CHECK`, and treat exit code `126` as "not found / permission
denied" without repeating the reason to the model.

```bash
$GAS_CHECK --op read  /path/to/file   # exit 0 allow, 126 deny
$GAS_CHECK --op write /path/to/file
$GAS_CHECK --op exec  /path/to/binary
```

`gas run --wrap-json <agent>` is the zero-code option: it filters the agent's
stdio JSON, so JSON-RPC and JSON tool calls are checked without touching the
agent. Use it when you cannot edit the agent.

## Hermes Agent

Launch it sandboxed — the wrapper sets `GAS_PROJECT` and the agent inherits the
jail in namespace mode:

```bash
gas run --project ~/projects/my-app hermes
```

For the tool-call layer, add a project rule file so the agent checks before
reading (`AGENTS.md` / `.hermes.md` in the project root):

```markdown
## Environment: Guardian Agent Sandbox
`GAS_SANDBOX` is set. Before reading, writing or executing any path:
1. Run `gas check --op <read|write|exec> <path>` via the terminal tool.
2. Exit code 126 means denied. Report it as "not found or permission denied",
   never as "blocked by policy", and never retry a variant of the path
   (no `..`, no symlink hunting, no shell tricks).
3. Never print the contents of `$GAS_POLICY_FILE` or `$GAS_LOG` to the model.
```

Hook form (if the agent supports pre-tool hooks):

```bash
#!/usr/bin/env bash
# .gas/hooks/pre-tool.sh — $1 = op, $2 = path
gas check --op "$1" "$2" >/dev/null 2>&1 || {
  echo "ENOENT: no such file or directory"   # fake error, no policy detail
  exit 1
}
```

## OpenCode

OpenCode plugins can wrap tool execution. Register a `tool.execute.before`
guard that shells out to `$GAS_CHECK` and throws a plain
`Error("ENOENT: no such file or directory")` on 126. Launch with
`gas run --project . opencode` so the process itself is contained, and keep the
guard as the second layer (it produces the clean fake error the model sees).

## OMP (oh-my-pi) and sub-agents

`gas run --project . omp` contains the parent. Every child process inherits the
mount namespace on Linux, so a sub-agent spawned through `delegate_task`,
`tmux`, or a shell pipeline stays inside the same jail — no per-child
configuration is needed. On Windows the job object covers the same tree.

## MCP servers

Wrap the stdio transport when a server exposes filesystem tools:

```bash
gas run --wrap-json --project . npx -y @modelcontextprotocol/server-filesystem ~/projects/my-app
```

`gas run --wrap-json` inspects each JSON line, matches `path`/`file`/`dir`
style keys and `command`/`cmd` values, and rewrites denied requests into
JSON-RPC errors with code `-32002` (ENOENT) or `-32001` (EACCES). Requests that
pass are forwarded byte-for-byte; non-JSON lines are never touched.

## CI / git hooks

```bash
gas check --op write ./src/generated.ts || exit 1
```

`gas doctor --json` gives a machine-readable self-test (`failures: 0`) that is
suitable as a pipeline gate: it asserts the shipped default deny list still
blocks SSH keys, `.env`, `*.pem`, history files and out-of-project reads.
