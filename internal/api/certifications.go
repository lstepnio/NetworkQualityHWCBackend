package api

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"regexp"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/lstepnio/NetworkQualityHWCBackend/internal/pii"
	"github.com/lstepnio/NetworkQualityHWCBackend/internal/store"
)

var uuidRe = regexp.MustCompile(`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$`)

type CertificationsHandler struct {
	store  *store.CertificationsStore
	pii    *pii.Hasher
	logger *slog.Logger
}

func NewCertificationsHandler(s *store.CertificationsStore, h *pii.Hasher, logger *slog.Logger) *CertificationsHandler {
	return &CertificationsHandler{store: s, pii: h, logger: logger}
}

func (h *CertificationsHandler) Post(w http.ResponseWriter, r *http.Request) {
	raw, err := io.ReadAll(r.Body)
	if err != nil {
		var maxErr *http.MaxBytesError
		if errors.As(err, &maxErr) {
			writeError(w, http.StatusRequestEntityTooLarge, "payload exceeds 256 KB")
			return
		}
		writeError(w, http.StatusBadRequest, "could not read body: "+err.Error())
		return
	}

	var parsed map[string]any
	dec := json.NewDecoder(bytesReader(raw))
	dec.UseNumber()
	if err := dec.Decode(&parsed); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON: "+err.Error())
		return
	}

	cert, problems := buildCertification(parsed, raw)
	if len(problems) > 0 {
		writeError(w, http.StatusBadRequest, "validation failed", problems...)
		return
	}

	h.pii.Redact(parsed)
	canonical, err := json.Marshal(parsed)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "re-serialize failed")
		return
	}
	cert.Payload = canonical

	// Re-extract the PII-affected hot-path columns from the redacted map so
	// what lands in those columns matches what's in the JSONB payload.
	cert.HSN = strPtr(getString(parsed, "identity", "hsn"))
	cert.EthernetMac = strPtr(getString(parsed, "identity", "ethernetMac"))

	outcome, err := h.store.Upsert(r.Context(), cert)
	if err != nil {
		h.logger.Error("upsert", slog.String("err", err.Error()),
			slog.String("certification_id", cert.CertificationID))
		writeError(w, http.StatusInternalServerError, "store error")
		return
	}

	switch outcome {
	case store.UpsertCreated:
		writeJSON(w, http.StatusCreated, canonical)
	case store.UpsertDuplicate:
		// Per SPEC §4.2: 200 echoes the stored record. Stored == canonical
		// since we just inserted-or-matched; serve the canonical we built.
		writeJSON(w, http.StatusOK, canonical)
	case store.UpsertConflict:
		h.logger.Warn("payload_hash conflict",
			slog.String("certification_id", cert.CertificationID),
			slog.String("device_id", cert.DeviceID))
		writeError(w, http.StatusConflict, "certificationId exists with a different payload_hash")
	}
}

func (h *CertificationsHandler) Get(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	if !uuidRe.MatchString(id) {
		writeError(w, http.StatusBadRequest, "id must be a UUID")
		return
	}
	cert, err := h.store.Get(r.Context(), id)
	if errors.Is(err, store.ErrCertNotFound) {
		writeError(w, http.StatusNotFound, "no such certification")
		return
	}
	if err != nil {
		writeError(w, http.StatusInternalServerError, "store error")
		return
	}
	writeJSON(w, http.StatusOK, cert.Payload)
}

func writeJSON(w http.ResponseWriter, status int, body []byte) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_, _ = w.Write(body)
}

// buildCertification extracts the structured fields needed for the database
// row from the parsed JSON body, validates the small required envelope, and
// computes payload_hash on the *raw* (pre-redaction) bytes so duplicate
// detection is byte-stable for the client.
func buildCertification(parsed map[string]any, raw []byte) (*store.Certification, []ErrorDetail) {
	var problems []ErrorDetail

	mustString := func(path string, parts ...string) string {
		v := getString(parsed, parts...)
		if v == "" {
			problems = append(problems, ErrorDetail{Path: path, Msg: "required"})
		}
		return v
	}
	mustUUID := func(path string, parts ...string) string {
		v := getString(parsed, parts...)
		if !uuidRe.MatchString(v) {
			problems = append(problems, ErrorDetail{Path: path, Msg: "must be a UUID"})
		}
		return v
	}
	mustTime := func(path string, parts ...string) time.Time {
		s := getString(parsed, parts...)
		if s == "" {
			problems = append(problems, ErrorDetail{Path: path, Msg: "required"})
			return time.Time{}
		}
		t, err := time.Parse(time.RFC3339, s)
		if err != nil {
			problems = append(problems, ErrorDetail{Path: path, Msg: "must be RFC 3339 timestamp"})
			return time.Time{}
		}
		return t
	}

	certID := mustUUID("certificationId", "certificationId")
	deviceID := mustUUID("deviceId", "deviceId")
	schemaVer, ok := getInt(parsed, "schemaVersion")
	if !ok || schemaVer < 1 {
		problems = append(problems, ErrorDetail{Path: "schemaVersion", Msg: "must be integer >= 1"})
	}
	configVer := mustString("configVersion", "configVersion")
	startedAt := mustTime("startedAt", "startedAt")
	completedAt := mustTime("completedAt", "completedAt")

	transport := mustString("network.transport", "network", "transport")
	achievedTier := mustString("result.achievedTier", "result", "achievedTier")

	if len(problems) > 0 {
		return nil, problems
	}

	hash := sha256.Sum256(raw)
	cert := &store.Certification{
		CertificationID:    certID,
		DeviceID:           deviceID,
		SchemaVersion:      schemaVer,
		ConfigVersion:      strPtr(configVer),
		StartedAt:          startedAt,
		CompletedAt:        completedAt,
		AchievedTier:       achievedTier,
		Transport:          transport,
		PayloadHash:        hex.EncodeToString(hash[:]),
		HardwareSerial:     strPtr(getString(parsed, "identity", "hardwareSerial")),
		MarginalMetric:     strPtr(getString(parsed, "result", "marginalMetric")),
		WidevineLevel:      strPtr(getString(parsed, "capabilities", "drm", "widevineSecurityLevel")),
		ThermalStatus:      strPtr(getString(parsed, "capabilities", "thermal", "status")),
		HDRTypes:           getStringSlice(parsed, "capabilities", "display", "hdrTypes"),
		DisplayMaxHeight:   intPtr(displayMaxHeight(parsed)),
		DownloadSteadyMbps: floatPtr(getNumber(parsed, "metrics", "download", "steadyMbps")),
		UploadSteadyMbps:   floatPtr(getNumber(parsed, "metrics", "upload", "steadyMbps")),
		LatencyMedianMs:    intPtrOrNil(getInt(parsed, "metrics", "latency", "medianMs")),
	}
	return cert, nil
}

func displayMaxHeight(parsed map[string]any) int {
	max := 0
	if modes, ok := getArray(parsed, "capabilities", "display", "supportedModes"); ok {
		for _, m := range modes {
			mm, ok := m.(map[string]any)
			if !ok {
				continue
			}
			if h, ok2 := getInt(mm, "heightPx"); ok2 && h > max {
				max = h
			}
		}
	}
	if max == 0 {
		if h, ok := getInt(parsed, "capabilities", "display", "heightPx"); ok {
			max = h
		}
	}
	return max
}
