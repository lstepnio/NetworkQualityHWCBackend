package api

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"net/http"
	"strconv"

	"github.com/lstepnio/NetworkQualityHWCBackend/internal/store"
)

// minSchemaVersion is the lowest X-Schema-Version this server still serves.
// Bump when the contract introduces a non-additive change that older clients
// cannot consume; older clients then receive 426.
const minSchemaVersion = 1

type CertConfigHandler struct {
	store *store.CertConfigStore
}

func NewCertConfigHandler(s *store.CertConfigStore) *CertConfigHandler {
	return &CertConfigHandler{store: s}
}

func (h *CertConfigHandler) Get(w http.ResponseWriter, r *http.Request) {
	clientSchema, err := strconv.Atoi(r.Header.Get("X-Schema-Version"))
	if err != nil || clientSchema < 1 {
		writeError(w, http.StatusBadRequest, "X-Schema-Version header must be an integer >= 1")
		return
	}
	if clientSchema < minSchemaVersion {
		writeError(w, http.StatusUpgradeRequired, "client schema too old")
		return
	}

	cfg, err := h.store.GetActiveForDevice(r.Context(), store.DeviceTarget{
		Manufacturer:     r.Header.Get("X-Device-Manufacturer"),
		Model:            r.Header.Get("X-Device-Model"),
		BuildFingerprint: r.Header.Get("X-Device-Build-Fingerprint"),
	})
	if errors.Is(err, store.ErrNoActiveConfig) {
		writeError(w, http.StatusServiceUnavailable, "no active configuration")
		return
	}
	if err != nil {
		writeError(w, http.StatusInternalServerError, "store error")
		return
	}

	etag := computeETag(cfg.Document)
	w.Header().Set("ETag", etag)

	if match := r.Header.Get("If-None-Match"); match != "" && match == etag {
		w.WriteHeader(http.StatusNotModified)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "private, max-age=3600")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(cfg.Document)
}

func computeETag(document []byte) string {
	sum := sha256.Sum256(document)
	return `"` + hex.EncodeToString(sum[:]) + `"`
}
