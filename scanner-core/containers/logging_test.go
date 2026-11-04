package containers

import (
	"bytes"
	"log/slog"
	"strings"
	"testing"
)

// captureLogs swaps the package logger for one writing into a buffer at Debug
// level, so a test can see both the Info and Debug branches and tell them
// apart. The original is restored on cleanup.
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

// TestAddContainerLogsInfoOnlyOnChange pins the fix for reconcile log noise.
//
// The Kubernetes watch re-adds every known container on each reconcile pass
// (~5 minutes). AddContainer logged every one of those at Info, which on the
// kubeadm cluster produced 15,948 lines in 11 hours while only 12 reflected a
// real change — 95% of the scan-server's entire log volume. The practical cost
// was not disk: it collapsed the `kubectl logs` window to ~11 hours, so
// genuinely useful lines (vulnerability database load timings, scan errors)
// rotated out before anyone could read them.
//
// Info must therefore mean "something changed". Repeats belong at Debug.
func TestAddContainerLogsInfoOnlyOnChange(t *testing.T) {
	m := NewManager()
	c := Container{
		ID:    ContainerID{Namespace: "default", Pod: "web-1", Name: "app"},
		Image: ImageID{Reference: "nginx:1.21", Digest: "sha256:aaa"},
	}

	buf := captureLogs(t)

	// First sighting is real news.
	m.AddContainer(c)
	if got := countLines(buf, "INFO", "add container"); got != 1 {
		t.Errorf("first add: want 1 INFO line, got %d\n%s", got, buf)
	}

	// Ten reconcile passes over an unchanged container must stay silent at Info.
	buf.Reset()
	for i := 0; i < 10; i++ {
		m.AddContainer(c)
	}
	if got := countLines(buf, "INFO", "add container"); got != 0 {
		t.Errorf("unchanged re-adds: want 0 INFO lines, got %d\n%s", got, buf)
	}
	if got := countLines(buf, "DEBUG", "add container"); got != 10 {
		t.Errorf("unchanged re-adds: want 10 DEBUG lines, got %d\n%s", got, buf)
	}

	// A new digest under the same key is a real change and must still surface,
	// including what it moved from — this is the case the noise was hiding.
	buf.Reset()
	moved := c
	moved.Image.Digest = "sha256:bbb"
	m.AddContainer(moved)
	if got := countLines(buf, "INFO", "container image changed"); got != 1 {
		t.Errorf("digest change: want 1 INFO line, got %d\n%s", got, buf)
	}
	if !strings.Contains(buf.String(), "previous_digest=sha256:aaa") {
		t.Errorf("digest change: want previous_digest in output, got:\n%s", buf)
	}

	// The manager must still hold the updated container, not just log about it.
	if got, ok := m.GetContainer("default", "web-1", "app"); !ok || got.Image.Digest != "sha256:bbb" {
		t.Errorf("state after digest change: got %+v ok=%v", got, ok)
	}
}

// TestRemoveContainerLogsInfoOnlyWhenTracked covers the matching path: a
// removal for something never tracked is a no-op repeat, not an event.
func TestRemoveContainerLogsInfoOnlyWhenTracked(t *testing.T) {
	m := NewManager()
	id := ContainerID{Namespace: "default", Pod: "web-1", Name: "app"}
	m.AddContainer(Container{ID: id, Image: ImageID{Reference: "nginx:1.21", Digest: "sha256:aaa"}})

	buf := captureLogs(t)

	m.RemoveContainer(id)
	if got := countLines(buf, "INFO", "remove container"); got != 1 {
		t.Errorf("tracked removal: want 1 INFO line, got %d\n%s", got, buf)
	}

	buf.Reset()
	m.RemoveContainer(id)
	if got := countLines(buf, "INFO", "remove container"); got != 0 {
		t.Errorf("repeat removal: want 0 INFO lines, got %d\n%s", got, buf)
	}
	if got := countLines(buf, "DEBUG", "remove container"); got != 1 {
		t.Errorf("repeat removal: want 1 DEBUG line, got %d\n%s", got, buf)
	}
}
