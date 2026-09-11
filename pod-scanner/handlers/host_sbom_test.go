package handlers

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/anchore/syft/syft"
	"github.com/anchore/syft/syft/format"
	"github.com/anchore/syft/syft/format/syftjson"
	"github.com/anchore/syft/syft/source"
)

// tinyHostTree builds a directory small enough to catalogue in a test but real
// enough for syft to produce a valid SBOM. Pointing HostPath at it exercises
// the whole handler rather than a stubbed encoder.
func tinyHostTree(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()

	// A dpkg status file gives syft actual OS packages to find, so the SBOM is
	// not trivially empty.
	statusDir := filepath.Join(dir, "var", "lib", "dpkg")
	if err := os.MkdirAll(statusDir, 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	status := "Package: tiny-pkg\nStatus: install ok installed\nArchitecture: arm64\nVersion: 1.2.3-1\n\n"
	if err := os.WriteFile(filepath.Join(statusDir, "status"), []byte(status), 0o644); err != nil {
		t.Fatalf("write status: %v", err)
	}
	return dir
}

// TestHostSBOMHandlerStreamsValidJSON covers the streaming response path.
//
// The handler used to call format.Encode, which collects the whole document
// into a bytes.Buffer and hands back a []byte — 80MB on a real host, allocated
// at the point where memory is tightest. It now encodes straight to the
// ResponseWriter. This asserts the observable consequences: the body is still
// valid syft JSON, and Content-Length is gone because the size is not known
// until the encode completes.
func TestHostSBOMHandlerStreamsValidJSON(t *testing.T) {
	cfg := HostSBOMConfig{
		HostPath:      tinyHostTree(t),
		Timeout:       2 * time.Minute,
		AutoDetectNFS: false,
	}

	req := httptest.NewRequest(http.MethodGet, "/host-sbom", nil)
	req.Header.Set("X-Node-Name", "test-node")
	rec := httptest.NewRecorder()

	HostSBOMHandler(cfg)(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body: %s", rec.Code, rec.Body.String())
	}

	// Absent Content-Length is the point, not an oversight: it is what allows
	// the body to be streamed instead of buffered. Go falls back to chunked
	// transfer encoding, and the only consumer (k8s-scan-server) reads with
	// io.ReadAll.
	if cl := rec.Header().Get("Content-Length"); cl != "" {
		t.Errorf("Content-Length = %q, want empty; setting it would require "+
			"buffering the whole SBOM to learn its size", cl)
	}
	if ct := rec.Header().Get("Content-Type"); ct != "application/json" {
		t.Errorf("Content-Type = %q, want application/json", ct)
	}

	body := rec.Body.Bytes()
	if len(body) == 0 {
		t.Fatal("empty body")
	}

	// Streaming must not corrupt or truncate the document.
	var doc map[string]any
	if err := json.Unmarshal(body, &doc); err != nil {
		t.Fatalf("response is not valid JSON (%v); first 200 bytes: %q", err, body[:min(200, len(body))])
	}
	for _, key := range []string{"artifacts", "source", "descriptor"} {
		if _, ok := doc[key]; !ok {
			t.Errorf("SBOM is missing the %q field; this does not look like syft JSON", key)
		}
	}
}

// TestStreamedEncodeMatchesBufferedEncode pins the thing that would be easiest
// to get wrong silently: that writing through the ResponseWriter produces the
// same bytes as the format.Encode path it replaced. Same encoder, same Encode
// method, different writer — so they should agree exactly, and a divergence
// would mean the wire format changed for every consumer.
func TestStreamedEncodeMatchesBufferedEncode(t *testing.T) {
	dir := tinyHostTree(t)

	src, err := syft.GetSource(t.Context(), dir, syft.DefaultGetSourceConfig())
	if err != nil {
		t.Fatalf("GetSource: %v", err)
	}
	defer func() { _ = src.Close() }()

	sbomCfg := syft.DefaultCreateSBOMConfig()
	sbomCfg.Search.Scope = source.AllLayersScope
	s, err := syft.CreateSBOM(t.Context(), src, sbomCfg)
	if err != nil {
		t.Fatalf("CreateSBOM: %v", err)
	}

	buffered, err := format.Encode(*s, syftjson.NewFormatEncoder())
	if err != nil {
		t.Fatalf("buffered encode: %v", err)
	}

	var streamed bytes.Buffer
	counter := &countingWriter{w: &streamed}
	if err := syftjson.NewFormatEncoder().Encode(counter, *s); err != nil {
		t.Fatalf("streamed encode: %v", err)
	}

	if !bytes.Equal(buffered, streamed.Bytes()) {
		t.Errorf("streamed encode differs from buffered encode (%d vs %d bytes)",
			len(buffered), streamed.Len())
	}
	if counter.n != int64(streamed.Len()) {
		t.Errorf("countingWriter counted %d bytes but %d were written; the logged "+
			"SBOM size would be wrong", counter.n, streamed.Len())
	}
}
