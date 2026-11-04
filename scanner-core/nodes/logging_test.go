package nodes

import (
	"bytes"
	"log/slog"
	"strings"
	"testing"
)

func captureLogs(t *testing.T) *bytes.Buffer {
	t.Helper()
	var buf bytes.Buffer
	orig := log
	log = slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug}))
	t.Cleanup(func() { log = orig })
	return &buf
}

func countLines(buf *bytes.Buffer, level, msg string) int {
	n := 0
	for _, line := range strings.Split(buf.String(), "\n") {
		if strings.Contains(line, "level="+level) && strings.Contains(line, `msg="`+msg+`"`) {
			n++
		}
	}
	return n
}

// TestAddNodeLogsInfoOnlyOnChange is the node-side counterpart to the
// container reconcile-noise fix.
//
// Kubernetes replays node events every ~30-90s (the AddNode body already
// documents this, which is why scans are gated on isNew). The log line was not
// gated the same way, so on a 6-node cluster it emitted 1,621 lines in 11
// hours — about 540 per node — none of which reflected a change.
func TestAddNodeLogsInfoOnlyOnChange(t *testing.T) {
	m := NewManager()
	n := Node{
		Name:         "kubeadm-worker-1",
		Hostname:     "kubeadm-worker-1",
		OSRelease:    "Ubuntu 22.04.3 LTS",
		Architecture: "amd64",
	}

	buf := captureLogs(t)

	m.AddNode(n)
	if got := countLines(buf, "INFO", "add node"); got != 1 {
		t.Errorf("first add: want 1 INFO line, got %d\n%s", got, buf)
	}

	// Replayed events for an unchanged node must not reach Info.
	buf.Reset()
	for i := 0; i < 10; i++ {
		m.AddNode(n)
	}
	if got := countLines(buf, "INFO", "add node"); got != 0 {
		t.Errorf("unchanged replays: want 0 INFO lines, got %d\n%s", got, buf)
	}
	if got := countLines(buf, "DEBUG", "add node"); got != 10 {
		t.Errorf("unchanged replays: want 10 DEBUG lines, got %d\n%s", got, buf)
	}

	// A genuine change — here a kernel upgrade, which is exactly the kind of
	// event that matters for host vulnerability scanning — must still surface.
	buf.Reset()
	upgraded := n
	upgraded.KernelVersion = "6.8.0-45-generic"
	m.AddNode(upgraded)
	if got := countLines(buf, "INFO", "add node"); got != 1 {
		t.Errorf("changed node: want 1 INFO line, got %d\n%s", got, buf)
	}
}
