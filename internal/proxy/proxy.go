// Package proxy implements the stdio filter described in FR-3 Mode B: it
// inspects JSON messages travelling between an agent and its host (or an MCP
// server) and replaces any request that touches a denied path with a synthetic
// error, so the real filesystem layout is never revealed.
package proxy

import (
	"encoding/json"
	"strings"

	"github.com/satriazoid/gas/internal/audit"
	"github.com/satriazoid/gas/internal/config"
	"github.com/satriazoid/gas/internal/policy"
)

// pathKeys are the JSON keys whose string value is treated as a filesystem
// path.
var pathKeys = map[string]bool{
	"path": true, "paths": true, "file": true, "filepath": true, "file_path": true,
	"filename": true, "file_name": true, "dir": true, "directory": true, "folder": true,
	"target": true, "source": true, "dest": true, "destination": true, "cwd": true,
	"project_path": true, "abs_path": true, "relative_path": true,
}

// opKeys are the JSON keys that hint at the operation being requested.
var opKeys = map[string]bool{
	"op": true, "operation": true, "action": true, "tool": true, "tool_name": true,
	"toolname": true, "name": true, "method": true, "func": true, "function": true,
	"command": true, "cmd": true, "type": true,
}

// commandKeys are keys whose value is a shell command line.
var commandKeys = map[string]bool{"command": true, "cmd": true, "shell": true, "argv_line": true}

var writeHints = []string{"write", "edit", "create", "delete", "remove", "move", "rename", "mkdir", "touch", "patch", "append", "chmod", "truncate", "insert", "replace"}
var execHints = []string{"exec", "shell", "bash", "sh", "run", "spawn", "system", "popen", "subprocess"}

// Filter is a stateful (but concurrency-safe by caller) stdio filter.
type Filter struct {
	eng      *policy.Engine
	log      *audit.Logger
	agent    string
	fakeMode string
}

// New builds a filter for the given policy.
func New(eng *policy.Engine, log *audit.Logger, agent string) *Filter {
	fake := config.FakeNotFound
	if cfg := eng.Config(); cfg != nil && cfg.FakeError != "" {
		fake = cfg.FakeError
	}
	return &Filter{eng: eng, log: log, agent: agent, fakeMode: fake}
}

// Handle inspects one protocol line. It returns the bytes to forward (nil when
// the message must be dropped) and whether the message was blocked.
func (f *Filter) Handle(line []byte) (out []byte, blocked bool) {
	trimmed := strings.TrimSpace(string(line))
	if trimmed == "" || (trimmed[0] != '{' && trimmed[0] != '[') {
		return line, false
	}
	var msg any
	if err := json.Unmarshal([]byte(trimmed), &msg); err != nil {
		return line, false
	}

	targets := collectTargets(msg)
	if len(targets) == 0 {
		return line, false
	}
	op := detectOp(msg)
	for _, t := range targets {
		targetOp := op
		if t.forceOp != "" {
			targetOp = t.forceOp
		}
		d := f.eng.Decide(t.value, targetOp)
		if d.Allowed {
			if f.log != nil && f.log.Enabled() {
				f.log.Record(audit.Entry{Action: audit.ActionAllowed, Op: string(targetOp), Path: d.Path, Reason: d.Reason, Rule: d.Rule, Scope: d.Scope, Source: "proxy", Agent: f.agent})
			}
			continue
		}
		if f.log != nil {
			f.log.Block(audit.Entry{Action: audit.ActionBlocked, Op: string(targetOp), Path: d.Path, Reason: d.Reason, Rule: d.Rule, Scope: d.Scope, Source: "proxy", Agent: f.agent, Detail: "stdio filter"})
		}
		return f.fakeError(msg, d), true
	}
	return line, false
}

type target struct {
	value   string
	forceOp policy.Op
}

func collectTargets(v any) []target {
	var out []target
	var walk func(v any, key string)
	walk = func(v any, key string) {
		switch t := v.(type) {
		case map[string]any:
			for k, val := range t {
				lk := strings.ToLower(k)
				switch tv := val.(type) {
				case string:
					switch {
					case commandKeys[lk]:
						for _, tok := range tokens(tv) {
							if looksLikePath(tok) {
								out = append(out, target{value: tok, forceOp: policy.OpRead})
							}
						}
					case pathKeys[lk]:
						for _, p := range splitPaths(tv) {
							out = append(out, target{value: p})
						}
					}
				default:
					walk(val, lk)
				}
			}
		case []any:
			for _, item := range t {
				switch iv := item.(type) {
				case string:
					if pathKeys[key] {
						out = append(out, target{value: iv})
					}
				default:
					walk(item, key)
				}
			}
		}
	}
	walk(v, "")
	return out
}

// detectOp infers the operation from the message content.
func detectOp(v any) policy.Op {
	op := policy.OpRead
	var walk func(v any)
	walk = func(v any) {
		switch t := v.(type) {
		case map[string]any:
			for k, val := range t {
				lk := strings.ToLower(k)
				s, ok := val.(string)
				if ok && opKeys[lk] {
					ls := strings.ToLower(s)
					for _, h := range execHints {
						if strings.Contains(ls, h) {
							op = policy.OpExec
							return
						}
					}
					for _, h := range writeHints {
						if strings.Contains(ls, h) {
							op = policy.OpWrite
							return
						}
					}
				}
				walk(val)
			}
		case []any:
			for _, item := range t {
				walk(item)
			}
		}
	}
	walk(v)
	return op
}

func tokens(s string) []string {
	return strings.FieldsFunc(s, func(r rune) bool {
		return r == ' ' || r == '\t' || r == '\n' || r == '\'' || r == '"' || r == ';' || r == '|' || r == '&' || r == '(' || r == ')'
	})
}

func looksLikePath(tok string) bool {
	if tok == "" || strings.HasPrefix(tok, "-") {
		return false
	}
	return strings.ContainsAny(tok, `/\`) || strings.HasPrefix(tok, "~") || strings.HasPrefix(tok, ".") || strings.Contains(tok, ":")
}

func splitPaths(v string) []string {
	if v == "" {
		return nil
	}
	if strings.ContainsAny(v, "\n") {
		var out []string
		for _, p := range strings.Split(v, "\n") {
			if s := strings.TrimSpace(p); s != "" {
				out = append(out, s)
			}
		}
		return out
	}
	return []string{v}
}

// fakeError builds the synthetic reply handed back to the caller.
func (f *Filter) fakeError(msg any, d policy.Decision) []byte {
	code := -32002
	message := "ENOENT: no such file or directory"
	if f.fakeMode == config.FakePermissionDenied {
		code = -32001
		message = "EACCES: permission denied"
	}
	payload := map[string]any{
		"error": map[string]any{
			"code":    code,
			"message": message,
		},
	}
	if obj, ok := msg.(map[string]any); ok {
		if id, hasID := obj["id"]; hasID {
			payload["jsonrpc"] = "2.0"
			payload["id"] = id
		} else if _, isToolResult := obj["result"]; isToolResult {
			payload = map[string]any{
				"error":   message,
				"blocked": true,
			}
		}
	}
	out, err := json.Marshal(payload)
	if err != nil {
		return []byte(`{"error":"ENOENT: no such file or directory"}`)
	}
	return out
}

// Decide is exposed for integrations that only need the verdict.
func (f *Filter) Decide(path string, op policy.Op) policy.Decision {
	return f.eng.Decide(path, op)
}

// LogPath returns the audit log path for operator messages.
func (f *Filter) LogPath() string {
	if f == nil || f.log == nil {
		return ""
	}
	return f.log.Path()
}

// Stats returns the audit summary.
func (f *Filter) Stats() audit.Stats {
	if f == nil || f.log == nil {
		return audit.Stats{}
	}
	return f.log.Stats()
}
