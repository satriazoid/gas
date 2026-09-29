# GAS — design and threat model

## Layers

```
user ──► gas run <agent>
           │
           ├─ config.Load(project)        global config.yaml + .gasignore merged
           ├─ policy.New(cfg)             deny lists / allow roots / write globs compiled
           ├─ isolation.Resolve(mode)     fails closed if the requested mode is unavailable
           │
           ├─ Linux  : clone(CLONE_NEWUSER|NEWNS|NEWPID|NEWUTS) → __sandbox-init
           │             tmpfs root, bind-mount only the allow roots,
           │             pivot_root, PR_SET_NO_NEW_PRIVS, exec agent
           ├─ Windows: CreateProcess + job object (KILL_ON_JOB_CLOSE),
           │             GAS_* env contract injected
           └─ filter : job/policy mode + stdio JSON filter (proxy.Filter)
```

The decision engine (`internal/policy`) is shared by every mode and by
`gas check`, so there is exactly one place where "is this path allowed?" is
answered.

## Why two mechanisms

A policy engine alone cannot stop `bash -c "cat ~/.ssh/id_rsa"`, because the
agent's shell bypasses the tool-call path (PRD risk table, first row).

- On Linux the kernel closes that hole: the file is not mounted inside the new
  mount namespace, so *any* process the agent forks gets `ENOENT`.
- On Windows there is no equivalent unprivileged primitive without a filesystem
  filter driver (minifilter). GAS therefore does what is actually available:
  (a) the `GAS_CHECK` contract for tool calls, (b) the stdio filter for
  JSON-RPC/JSON tool traffic, (c) a job object so the whole tree dies with the
  wrapper, and (d) a complete audit trail. A shell command typed directly into
  an agent that ignores the contract is *logged but not blocked* — this is a
  documented limitation, not a silent hole. Windows-side hardening options are
  tracked below.

Detection of a forged policy file: the project may only add restrictions
(`config.Merge` ORs the booleans and appends lists), so a repo that ships a
malicious `.gasignore` cannot widen `read_only` or drop global deny patterns.

## Fail-closed behaviour

| Situation | Result |
|---|---|
| `--mode namespace` on a host without user namespaces, no `--allow-degrade` | agent is **not started**, exit 1 |
| empty allow list reaching `__sandbox-init` | init exits 3 before exec |
| `pivot_root` / bind mount failure | init exits non-zero, agent never runs |
| policy engine sees an empty path | deny |
| unparsable config file | `gas run` refuses to start |

## Data flow of a blocked read

1. Agent asks for `~/.ssh/id_rsa`.
2. Tool-call path (contract or filter): `gas check` / `proxy.Filter` returns a
   fake `ENOENT` — identical to what a missing file looks like, so the agent
   cannot distinguish "sandboxed" from "not there".
3. The denial is appended to `~/.gas/logs/access_denied.log` with op, path,
   reason, matched rule and scope.
4. Optional webhook POST (`notify.webhook_url`) for real-time alerting.

Namespace mode short-circuits steps 1–2: the kernel returns the error, and the
access never reaches GAS. Only the wrapper's own audit entries exist for that
mode, which is why `audit.log_allowed` exists for debugging.

## Known limits

- **Network restrictions are not enforced.** `network.*` is parsed, reported by
  `gas policy --json` and reserved for a future `LD_PRELOAD`/WinDivert layer.
  Do not rely on it today.
- **Windows without a filter driver**: see above; kernel-level blocking needs a
  minifilter, which contradicts the "no installer, single static binary" goal.
- **Namespace mode and user toolchains**: the jail contains only the allow
  roots plus `/proc`, `/tmp`, `/dev`. Cross-compiling Rust/Go or running
  `npm install` needs `--allow-system-libs` and extra `allow_roots`
  (`/usr`, `/home/<user>/.cargo`, `~/.npm`) — that trades isolation for
  convenience, so prefer letting the *host* build and jailing only the
  agent's editing session.
- **`--unsafe` is a real bypass**: it is audited and banner-printed, but it does
  disable everything.
- Env vars are advisory for foreign agents. An agent that ignores `GAS_CHECK`
  is not protected on Windows/macOS; prefer Linux namespace mode there.

## Roadmap

Phase 3 (per PRD): Telegram block notifications, localhost dashboard, AUR +
signed Windows release artifacts, optional `LD_PRELOAD` interposer for Linux
processes that cannot be namespaced, and a Windows minifilter prototype behind
a build tag.
