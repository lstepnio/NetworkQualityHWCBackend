package api

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"net/http"
	"strconv"

	"github.com/lstepnio/NetworkQualityHWCBackend/internal/store"
)

// AppVersionHandler serves the device-facing GET /v1/app/version. Mirrors
// the CertConfigHandler pattern: load the active row, set ETag from the
// document bytes, honor If-None-Match for 304, set Cache-Control.
//
// The 426 response in the contract is reserved for a server-side hard
// floor on X-App-Version-Code (e.g. "we have known data-loss bugs in
// builds < N; refuse to serve them"). Not implemented yet — there's no
// configured floor, so every otherwise-valid request gets 200. Adding it
// later is a single ENV var + four lines.
type AppVersionHandler struct {
	store *store.AppVersionStore
}

func NewAppVersionHandler(s *store.AppVersionStore) *AppVersionHandler {
	return &AppVersionHandler{store: s}
}

func (h *AppVersionHandler) Get(w http.ResponseWriter, r *http.Request) {
	// X-App-Version-Code is required so the server *could* enforce a
	// hard floor in the future. For now we just validate the header is
	// well-formed; misuse is a 400, not a 426.
	if v := r.Header.Get("X-App-Version-Code"); v != "" {
		if n, err := strconv.Atoi(v); err != nil || n < 1 {
			writeError(w, http.StatusBadRequest, "X-App-Version-Code header must be an integer >= 1")
			return
		}
	} else {
		writeError(w, http.StatusBadRequest, "X-App-Version-Code header is required")
		return
	}

	m, err := h.store.GetActive(r.Context())
	if errors.Is(err, store.ErrNoActiveAppVersion) {
		writeError(w, http.StatusServiceUnavailable, "no active app version manifest")
		return
	}
	if err != nil {
		writeError(w, http.StatusInternalServerError, "store error")
		return
	}

	etag := computeAppVersionETag(m.Document)
	w.Header().Set("ETag", etag)

	if match := r.Header.Get("If-None-Match"); match != "" && match == etag {
		w.WriteHeader(http.StatusNotModified)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "private, max-age=3600")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(m.Document)
}

func computeAppVersionETag(document []byte) string {
	sum := sha256.Sum256(document)
	return `"` + hex.EncodeToString(sum[:]) + `"`
}
