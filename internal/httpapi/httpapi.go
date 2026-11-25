// Package httpapi serves env-registry's only HTTP routes: the Executor open
// edge and the probes. Every other path is 404.
package httpapi

import (
	"context"
	"net/http"

	"github.com/go-chi/chi/v5"

	"github.com/pandops/flowai-env-registry/internal/service"
)

// Opener serves the open edge.
type Opener interface {
	Open(ctx context.Context, rawTaskID, authorization string) service.OpenResult
}

// Readiness reports whether the service can serve.
type Readiness interface {
	Ready(ctx context.Context) error
}

var notFound = []byte(`{"code":"not_found","message":"not found","request_id":null}`)

// NewRouter returns the HTTP handler.
func NewRouter(o Opener, r Readiness) http.Handler {
	mux := chi.NewRouter()
	write := func(w http.ResponseWriter, status int, body []byte) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "no-store")
		w.WriteHeader(status)
		_, _ = w.Write(body)
	}
	mux.NotFound(func(w http.ResponseWriter, _ *http.Request) { write(w, http.StatusNotFound, notFound) })
	mux.MethodNotAllowed(func(w http.ResponseWriter, _ *http.Request) { write(w, http.StatusNotFound, notFound) })
	mux.Get("/v1/livez", func(w http.ResponseWriter, _ *http.Request) { write(w, http.StatusOK, []byte(`{"status":"ok"}`)) })
	mux.Get("/v1/readyz", func(w http.ResponseWriter, req *http.Request) {
		if err := r.Ready(req.Context()); err != nil {
			write(w, http.StatusServiceUnavailable, []byte(`{"status":"unavailable"}`))
			return
		}
		write(w, http.StatusOK, []byte(`{"status":"ok"}`))
	})
	if o != nil {
		mux.Get("/v1/tasks/{task_id}/launch-parameters/open", func(w http.ResponseWriter, req *http.Request) {
			res := o.Open(req.Context(), chi.URLParam(req, "task_id"), req.Header.Get("Authorization"))
			write(w, res.Status, res.Body)
		})
	}
	return mux
}
