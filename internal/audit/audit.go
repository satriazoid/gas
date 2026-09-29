// Package audit writes the GAS access log and rotates it.
package audit

import (
	"bufio"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/satriazoid/gas/internal/config"
)

// Actions recorded in the log.
const (
	ActionBlocked = "blocked"
	ActionAllowed = "allowed"
	ActionBypass  = "bypass"
	ActionStart   = "start"
	ActionExit    = "exit"
	ActionDegrade = "degrade"
)

// Entry is one audit record (JSON line).
type Entry struct {
	TS     time.Time `json:"ts"`
	Action string    `json:"action"`
	Agent  string    `json:"agent,omitempty"`
	PID    int       `json:"pid,omitempty"`
	Op     string    `json:"op,omitempty"`
	Path   string    `json:"path,omitempty"`
	Reason string    `json:"reason,omitempty"`
	Rule   string    `json:"rule,omitempty"`
	Scope  string    `json:"scope,omitempty"`
	Source string    `json:"source,omitempty"`
	Detail string    `json:"detail,omitempty"`
}

// PathCount is a path frequency used by Stats.
type PathCount struct {
	Path  string `json:"path"`
	Count int    `json:"count"`
}

// Stats summarizes the audit log.
type Stats struct {
	Path      string         `json:"path"`
	SizeBytes int64          `json:"size_bytes"`
	Total     int            `json:"total"`
	Blocked   int            `json:"blocked"`
	Allowed   int            `json:"allowed"`
	Bypass    int            `json:"bypass"`
	ByReason  map[string]int `json:"by_reason"`
	ByOp      map[string]int `json:"by_op"`
	TopPaths  []PathCount    `json:"top_paths"`
	Last      *Entry         `json:"last,omitempty"`
	Last24h   int            `json:"blocked_24h"`
	FirstSeen time.Time      `json:"first_seen,omitempty"`
}

// Logger appends audit entries and rotates the file.
type Logger struct {
	path       string
	enabled    bool
	logAllowed bool
	maxBytes   int64
	maxBackups int
	agent      string

	webhook string
	on      map[string]bool

	mu     sync.Mutex
	client *http.Client
}

// New builds a logger from cfg. A nil-safe no-op logger is returned when
// logging is disabled.
func New(cfg *config.Config, agent string) *Logger {
	if cfg == nil {
		cfg = config.Default()
	}
	l := &Logger{
		path:       cfg.LogPath(),
		enabled:    cfg.AuditEnabled(),
		logAllowed: cfg.Audit.LogAllowed,
		maxBackups: cfg.Audit.MaxBackups,
		agent:      agent,
		webhook:    cfg.Notify.WebhookURL,
		on:         map[string]bool{},
		client:     &http.Client{Timeout: 5 * time.Second},
	}
	if l.maxBackups <= 0 {
		l.maxBackups = 3
	}
	l.maxBytes = int64(cfg.Audit.MaxSizeMB) * 1024 * 1024
	if l.maxBytes <= 0 {
		l.maxBytes = 5 * 1024 * 1024
	}
	for _, a := range cfg.Notify.On {
		l.on[strings.TrimSpace(a)] = true
	}
	return l
}

// Path returns the audit log path.
func (l *Logger) Path() string { return l.path }

// Enabled reports whether entries are being written.
func (l *Logger) Enabled() bool { return l != nil && l.enabled }

// Block records a denied access (always logged, even when log_allowed is off).
func (l *Logger) Block(ev Entry) { l.write(ev, true) }

// Event records a non-blocking lifecycle event.
func (l *Logger) Event(action string, ev Entry) {
	ev.Action = action
	l.write(ev, action == ActionBypass || action == ActionDegrade)
}

// Record writes an arbitrary entry, honouring log_allowed.
func (l *Logger) Record(ev Entry) { l.write(ev, ev.Action != ActionAllowed) }

func (l *Logger) write(ev Entry, force bool) {
	if l == nil || !l.enabled {
		return
	}
	if ev.Action == ActionAllowed && !l.logAllowed {
		return
	}
	if ev.Action == "" {
		ev.Action = ActionBlocked
	}
	if ev.TS.IsZero() {
		ev.TS = time.Now().UTC()
	}
	if ev.Agent == "" {
		ev.Agent = l.agent
	}
	if ev.PID == 0 {
		ev.PID = os.Getpid()
	}
	line, err := json.Marshal(ev)
	if err != nil {
		return
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if err := os.MkdirAll(filepath.Dir(l.path), 0o700); err != nil {
		return
	}
	l.rotateLocked()
	f, err := os.OpenFile(l.path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		return
	}
	_, _ = f.Write(append(line, '\n'))
	_ = f.Close()
	if force && l.webhook != "" && l.notifyWanted(ev.Action) {
		go l.notify(ev)
	}
}

func (l *Logger) notifyWanted(action string) bool {
	if len(l.on) == 0 {
		return action == ActionBlocked
	}
	return l.on[action]
}

func (l *Logger) rotateLocked() {
	fi, err := os.Stat(l.path)
	if err != nil || fi.Size() < l.maxBytes {
		return
	}
	_ = os.Remove(fmt.Sprintf("%s.%d", l.path, l.maxBackups))
	for i := l.maxBackups - 1; i >= 1; i-- {
		_ = os.Rename(fmt.Sprintf("%s.%d", l.path, i), fmt.Sprintf("%s.%d", l.path, i+1))
	}
	_ = os.Rename(l.path, l.path+".1")
}

// notify posts a blocked event to the configured webhook (fire and forget).
func (l *Logger) notify(ev Entry) {
	body, err := json.Marshal(map[string]any{
		"text": fmt.Sprintf("GAS blocked %s on %s (%s)", ev.Op, ev.Path, ev.Reason),
		"gas":  ev,
	})
	if err != nil {
		return
	}
	req, err := http.NewRequest(http.MethodPost, l.webhook, strings.NewReader(string(body)))
	if err != nil {
		return
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := l.client.Do(req)
	if err != nil {
		return
	}
	_ = resp.Body.Close()
}

// Tail returns the last n entries (newest last).
func (l *Logger) Tail(n int) []Entry {
	if l == nil || n <= 0 {
		return nil
	}
	f, err := os.Open(l.path)
	if err != nil {
		return nil
	}
	defer f.Close()
	ring := make([]Entry, 0, n)
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for sc.Scan() {
		var ev Entry
		if err := json.Unmarshal(sc.Bytes(), &ev); err != nil {
			continue
		}
		if len(ring) == n {
			copy(ring, ring[1:])
			ring = ring[:n-1]
		}
		ring = append(ring, ev)
	}
	return ring
}

// Stats aggregates the whole audit log.
func (l *Logger) Stats() Stats {
	st := Stats{
		Path:     l.path,
		ByReason: map[string]int{},
		ByOp:     map[string]int{},
	}
	if l == nil {
		return st
	}
	if fi, err := os.Stat(l.path); err == nil {
		st.SizeBytes = fi.Size()
	}
	f, err := os.Open(l.path)
	if err != nil {
		return st
	}
	defer f.Close()
	counts := map[string]int{}
	cutoff := time.Now().UTC().Add(-24 * time.Hour)
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for sc.Scan() {
		var ev Entry
		if err := json.Unmarshal(sc.Bytes(), &ev); err != nil {
			continue
		}
		st.Total++
		switch ev.Action {
		case ActionBlocked:
			st.Blocked++
			if ev.TS.After(cutoff) {
				st.Last24h++
			}
			if ev.Reason != "" {
				st.ByReason[ev.Reason]++
			}
			if ev.Op != "" {
				st.ByOp[ev.Op]++
			}
			if ev.Path != "" {
				counts[ev.Path]++
			}
		case ActionAllowed:
			st.Allowed++
		case ActionBypass:
			st.Bypass++
		}
		if st.FirstSeen.IsZero() || ev.TS.Before(st.FirstSeen) {
			st.FirstSeen = ev.TS
		}
		last := ev
		st.Last = &last
	}
	for p, c := range counts {
		st.TopPaths = append(st.TopPaths, PathCount{Path: p, Count: c})
	}
	sort.Slice(st.TopPaths, func(i, j int) bool {
		if st.TopPaths[i].Count != st.TopPaths[j].Count {
			return st.TopPaths[i].Count > st.TopPaths[j].Count
		}
		return st.TopPaths[i].Path < st.TopPaths[j].Path
	})
	if len(st.TopPaths) > 10 {
		st.TopPaths = st.TopPaths[:10]
	}
	return st
}
