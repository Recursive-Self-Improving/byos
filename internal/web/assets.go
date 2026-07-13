package web

import (
	"bytes"
	"embed"
	"io/fs"
	"net/http"
	"path/filepath"
	"time"
)

//go:embed templates/*.html static/*
var assets embed.FS

func (h *Handler) handleStatic(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("file")
	if !fs.ValidPath(name) || filepath.Base(name) != name {
		http.NotFound(w, r)
		return
	}
	body, err := fs.ReadFile(assets, "static/"+name)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	switch filepath.Ext(name) {
	case ".css":
		w.Header().Set("Content-Type", "text/css; charset=utf-8")
	case ".js":
		w.Header().Set("Content-Type", "text/javascript; charset=utf-8")
	default:
		w.Header().Set("Content-Type", "application/octet-stream")
	}
	http.ServeContent(w, r, name, time.Time{}, bytes.NewReader(body))
}
