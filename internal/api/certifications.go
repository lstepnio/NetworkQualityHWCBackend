package api

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/lstepnio/NetworkQualityHWCBackend/internal/asn"
	"github.com/lstepnio/NetworkQualityHWCBackend/internal/pii"
	"github.com/lstepnio/NetworkQualityHWCBackend/internal/store"
)

var uuidRe = regexp.MustCompile(`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$`)

type CertificationsHandler struct {
	store  *store.CertificationsStore
	pii    *pii.Hasher
	asn    asn.Lookup
	logger *slog.Logger
}

func NewCertificationsHandler(s *store.CertificationsStore, h *pii.Hasher, a asn.Lookup, logger *slog.Logger) *CertificationsHandler {
	if a == nil {
		a = asn.Noop{}
	}
	return &CertificationsHandler{store: s, pii: h, asn: a, logger: logger}
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
	// HSN is no longer redacted (it's the join key to the account system,
	// per the May 2026 policy update) — the hot-path column carries the
	// plain value the device reported.
	cert.HSN = strPtr(getString(parsed, "identity", "hsn"))
	cert.EthernetMac = strPtr(getString(parsed, "identity", "ethernetMac"))
	cert.PublicIP = strPtr(getString(parsed, "network", "publicIp"))

	// Server-derived signals: request source IP (hashed) and the AS behind
	// it. The STB also reports a publicIp via STUN; we trust the request-
	// observed IP more (no STB-side spoofing surface) but store both so the
	// dashboard can surface mismatches.
	if remoteIP := extractRequestIP(r); remoteIP != "" {
		hashed := h.pii.Hash(remoteIP)
		cert.RequestIPHash = &hashed

		// ASN lookup runs in-band with a 500ms budget (set by the
		// constructor's Cymru timeout). Soft-failure: on any error we log
		// at debug and leave isp_asn / isp_name null. The cert still
		// lands.
		if asn, name, err := h.asn.Lookup(r.Context(), remoteIP); err != nil {
			h.logger.Debug("asn lookup failed",
				slog.String("err", err.Error()),
				slog.String("certification_id", cert.CertificationID))
		} else if asn > 0 {
			cert.ISPAsn = &asn
			if name != "" {
				cert.ISPName = &name
			}
		}
	}

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

// extractRequestIP returns the source IP of the request — preferring the
// first (client-most) hop in X-Forwarded-For when set by a trusted proxy,
// falling back to r.RemoteAddr stripped of its port. Returns the empty
// string when neither parses as a valid IP. The result is the input to
// PII hashing + ASN lookup; we don't store it in plaintext anywhere.
func extractRequestIP(r *http.Request) string {
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		// XFF format: "client, proxy1, proxy2". Take the first hop.
		first := strings.TrimSpace(strings.SplitN(xff, ",", 2)[0])
		if ip := net.ParseIP(first); ip != nil {
			return ip.String()
		}
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		host = r.RemoteAddr
	}
	if ip := net.ParseIP(host); ip != nil {
		return ip.String()
	}
	return ""
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

	// Optional timestamp: returns (nil, ok=true) when absent. ok=false on
	// presence-but-malformed; the rule name surfaces in the 400 body so
	// the client logs are useful.
	optTime := func(rulePath string, parts ...string) (*time.Time, bool) {
		s := getString(parsed, parts...)
		if s == "" {
			return nil, true
		}
		t, err := time.Parse(time.RFC3339, s)
		if err != nil {
			problems = append(problems, ErrorDetail{Path: rulePath, Msg: "must be RFC 3339 timestamp"})
			return nil, false
		}
		return &t, true
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
	enqueuedAt, _ := optTime("enqueuedAt", "enqueuedAt") // contract v1.1.0+, optional
	submittedAt, _ := optTime("submittedAt", "submittedAt")

	transport := mustString("network.transport", "network", "transport")
	achievedTier := mustString("result.achievedTier", "result", "achievedTier")

	// Cross-field rules. Each one is named so a 400 body's `details[*].path`
	// tells the client exactly which assertion failed. Clock skew on the
	// STB is real (no NTP sometimes), so a 60s tolerance keeps near-misses
	// from rejecting otherwise-valid payloads.
	const skew = 60 * time.Second
	if !startedAt.IsZero() && !completedAt.IsZero() && completedAt.Before(startedAt) {
		problems = append(problems, ErrorDetail{
			Path: "completedAt_after_startedAt",
			Msg:  "completedAt must be >= startedAt",
		})
	}
	if submittedAt != nil && !completedAt.IsZero() && submittedAt.Before(completedAt.Add(-skew)) {
		problems = append(problems, ErrorDetail{
			Path: "submittedAt_near_completedAt",
			Msg:  "submittedAt must be >= completedAt - 60s",
		})
	}
	if enqueuedAt != nil && !completedAt.IsZero() && enqueuedAt.Before(completedAt.Add(-skew)) {
		problems = append(problems, ErrorDetail{
			Path: "enqueuedAt_near_completedAt",
			Msg:  "enqueuedAt must be >= completedAt - 60s",
		})
	}
	// receivedAt is effectively "right now" — the row hasn't been inserted
	// yet, so we compare against the wall clock. The client can't be from
	// the future modulo skew tolerance.
	receivedAt := time.Now().UTC()
	if submittedAt != nil && submittedAt.After(receivedAt.Add(skew)) {
		problems = append(problems, ErrorDetail{
			Path: "submittedAt_before_receivedAt",
			Msg:  "submittedAt must be <= now + 60s (request can't be from the future)",
		})
	}

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
		EnqueuedAt:         enqueuedAt,
		SubmittedAt:        submittedAt,
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
