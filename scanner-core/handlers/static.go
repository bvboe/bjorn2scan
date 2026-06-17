package handlers

import (
	"io/fs"
	"net/http"

	scanner_core "github.com/bvboe/b2s-go/scanner-core"
)


// RegisterStaticHandlers registers handlers for serving the embedded web UI
func RegisterStaticHandlers(mux *http.ServeMux) {
	// Get the static subdirectory from embedded FS
	staticFS, err := fs.Sub(scanner_core.WebContent, "static")
	if err != nil {
		log.Warn("failed to access embedded static content", "error", err)
		return
	}

	// Serve the embedded files at root
	fileServer := http.FileServer(http.FS(staticFS))
	mux.Handle("/", fileServer)

	log.Info("static web UI registered", "path", "/")
}
