package stub

import (
	"net/http"

	"github.com/vnoiram/mirage-chaff/internal/catalog"
)

// Serve writes the named catalog decoy for r, handling CORS so that preflighted
// ad/measurement endpoints still succeed (design doc §A CORS). If the catalog
// entry is missing it falls back to a safe 204.
//
// No upstream is contacted — this is the most private action.
func Serve(w http.ResponseWriter, r *http.Request, cat *catalog.Catalog, name string) {
	applyCORS(w, r)

	// CORS preflight: answer here without touching the catalog.
	if r.Method == http.MethodOptions {
		w.Header().Set("Content-Length", "0")
		w.WriteHeader(http.StatusNoContent)
		return
	}

	if cat == nil || cat.Render(w, name) != nil {
		w.WriteHeader(http.StatusNoContent)
	}
}

// applyCORS reflects the request Origin so cross-origin ad/beacon calls that
// expect permissive CORS do not fail closed. Credentials are allowed only when
// an explicit Origin is echoed (never with "*").
func applyCORS(w http.ResponseWriter, r *http.Request) {
	origin := r.Header.Get("Origin")
	h := w.Header()
	if origin != "" {
		h.Set("Access-Control-Allow-Origin", origin)
		h.Set("Vary", "Origin")
		h.Set("Access-Control-Allow-Credentials", "true")
	} else {
		h.Set("Access-Control-Allow-Origin", "*")
	}
	if r.Method == http.MethodOptions {
		reqMethod := r.Header.Get("Access-Control-Request-Method")
		if reqMethod == "" {
			reqMethod = "GET, POST, OPTIONS"
		}
		h.Set("Access-Control-Allow-Methods", reqMethod)
		if reqHeaders := r.Header.Get("Access-Control-Request-Headers"); reqHeaders != "" {
			h.Set("Access-Control-Allow-Headers", reqHeaders)
		}
		h.Set("Access-Control-Max-Age", "600")
	}
}
