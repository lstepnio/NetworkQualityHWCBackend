package api

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strconv"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/lstepnio/NetworkQualityHWCBackend/internal/store"
)

// AdminHandler exposes /admin/* endpoints for the dashboard. The shape of
// these endpoints is internal to this codebase + dashboard pair (no contract
// repo); breaking changes are coordinated via PR.
type AdminHandler struct {
	certs   *store.CertificationsStore
	configs *store.CertConfigStore
	pii     publicIPHasher
}

// publicIPHasher is the small slice of *pii.Hasher we need — accept any
// hasher with a Hash method so tests can fake it without dragging in the
// pii package's keying.
type publicIPHasher interface {
	Hash(value string) string
}

func NewAdminHandler(certs *store.CertificationsStore, configs *store.CertConfigStore, hasher publicIPHasher) *AdminHandler {
	return &AdminHandler{certs: certs, configs: configs, pii: hasher}
}

// adminListResponse wraps a paginated list. items is always an array (never
// null) so the dashboard can iterate without a guard.
type adminListResponse struct {
	Items  any `json:"items"`
	Total  int `json:"total"`
	Limit  int `json:"limit"`
	Offset int `json:"offset"`
}

type adminCertSummary struct {
	CertificationID    string     `json:"certificationId"`
	DeviceID           string     `json:"deviceId"`
	HSN                *string    `json:"hsn,omitempty"`
	ConfigVersion      *string    `json:"configVersion,omitempty"`
	StartedAt          time.Time  `json:"startedAt"`
	CompletedAt        time.Time  `json:"completedAt"`
	AchievedTier       string     `json:"achievedTier"`
	MarginalMetric     *string    `json:"marginalMetric,omitempty"`
	Transport          string     `json:"transport"`
	WidevineLevel      *string    `json:"widevineLevel,omitempty"`
	HDRTypes           []string   `json:"hdrTypes"`
	DisplayMaxHeight   *int       `json:"displayMaxHeight,omitempty"`
	ThermalStatus      *string    `json:"thermalStatus,omitempty"`
	DownloadSteadyMbps *float64   `json:"downloadSteadyMbps,omitempty"`
	UploadSteadyMbps   *float64   `json:"uploadSteadyMbps,omitempty"`
	LatencyMedianMs    *int       `json:"latencyMedianMs,omitempty"`
	PublicIPHash       *string    `json:"publicIpHash,omitempty"` // never the raw IP — already redacted
	EnqueuedAt         *time.Time `json:"enqueuedAt,omitempty"`   // contract v1.1.0+; null for older clients
	SubmittedAt        *time.Time `json:"submittedAt,omitempty"`
	QueueDelaySeconds  *int64     `json:"queueDelaySeconds,omitempty"` // submittedAt - completedAt; null when submittedAt is null
	ReceivedAt         time.Time  `json:"receivedAt"`
}

func toSummary(s store.ListSummary) adminCertSummary {
	hdr := s.HDRTypes
	if hdr == nil {
		hdr = []string{}
	}
	return adminCertSummary{
		CertificationID:    s.CertificationID,
		DeviceID:           s.DeviceID,
		HSN:                s.HSN,
		ConfigVersion:      s.ConfigVersion,
		StartedAt:          s.StartedAt,
		CompletedAt:        s.CompletedAt,
		AchievedTier:       s.AchievedTier,
		MarginalMetric:     s.MarginalMetric,
		Transport:          s.Transport,
		WidevineLevel:      s.WidevineLevel,
		HDRTypes:           hdr,
		DisplayMaxHeight:   s.DisplayMaxHeight,
		ThermalStatus:      s.ThermalStatus,
		DownloadSteadyMbps: s.DownloadSteadyMbps,
		UploadSteadyMbps:   s.UploadSteadyMbps,
		LatencyMedianMs:    s.LatencyMedianMs,
		PublicIPHash:       s.PublicIP,
		EnqueuedAt:         s.EnqueuedAt,
		SubmittedAt:        s.SubmittedAt,
		QueueDelaySeconds:  queueDelay(s.CompletedAt, s.SubmittedAt),
		ReceivedAt:         s.ReceivedAt,
	}
}

// queueDelay returns submittedAt - completedAt in whole seconds, or nil
// when submittedAt is null (older-client payload). Negative deltas (clock
// skew, validated within 60s tolerance at ingest) round to zero so the
// dashboard never has to render "delivered -3s later".
func queueDelay(completedAt time.Time, submittedAt *time.Time) *int64 {
	if submittedAt == nil {
		return nil
	}
	d := int64(submittedAt.Sub(completedAt).Seconds())
	if d < 0 {
		d = 0
	}
	return &d
}

func (h *AdminHandler) ListCertifications(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	filter := store.ListFilter{
		Tier:          q.Get("tier"),
		DeviceID:      q.Get("deviceId"),
		ConfigVersion: q.Get("configVersion"),
		HSN:           q.Get("hsn"),
		QueuedOnly:    q.Get("queuedOnly") == "true",
		Limit:         atoiOr(q.Get("limit"), 50),
		Offset:        atoiOr(q.Get("offset"), 0),
	}
	// Caller types the raw IP in the search box; we hash it server-side
	// (the column is the peppered SHA-256, not the plaintext) so the search
	// stays exact-match without leaking IPs over the wire.
	if pip := q.Get("publicIp"); pip != "" {
		filter.PublicIPHash = h.pii.Hash(pip)
	}
	if v := q.Get("from"); v != "" {
		if t, err := time.Parse(time.RFC3339, v); err == nil {
			filter.From = &t
		}
	}
	if v := q.Get("to"); v != "" {
		if t, err := time.Parse(time.RFC3339, v); err == nil {
			filter.To = &t
		}
	}

	rows, total, err := h.certs.List(r.Context(), filter)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "list error")
		return
	}
	items := make([]adminCertSummary, 0, len(rows))
	for _, c := range rows {
		items = append(items, toSummary(c))
	}
	writeJSONValue(w, http.StatusOK, adminListResponse{
		Items:  items,
		Total:  total,
		Limit:  filter.Limit,
		Offset: filter.Offset,
	})
}

func (h *AdminHandler) GetCertification(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	if !uuidRe.MatchString(id) {
		writeError(w, http.StatusBadRequest, "id must be a UUID")
		return
	}
	c, err := h.certs.Get(r.Context(), id)
	if errors.Is(err, store.ErrCertNotFound) {
		writeError(w, http.StatusNotFound, "no such certification")
		return
	}
	if err != nil {
		writeError(w, http.StatusInternalServerError, "store error")
		return
	}

	var payload any
	_ = json.Unmarshal(c.Payload, &payload)
	writeJSONValue(w, http.StatusOK, map[string]any{
		"summary": toSummary(store.ListSummary{
			CertificationID:    c.CertificationID,
			DeviceID:           c.DeviceID,
			HSN:                c.HSN,
			ConfigVersion:      c.ConfigVersion,
			StartedAt:          c.StartedAt,
			CompletedAt:        c.CompletedAt,
			AchievedTier:       c.AchievedTier,
			MarginalMetric:     c.MarginalMetric,
			Transport:          c.Transport,
			WidevineLevel:      c.WidevineLevel,
			HDRTypes:           c.HDRTypes,
			DisplayMaxHeight:   c.DisplayMaxHeight,
			ThermalStatus:      c.ThermalStatus,
			DownloadSteadyMbps: c.DownloadSteadyMbps,
			UploadSteadyMbps:   c.UploadSteadyMbps,
			LatencyMedianMs:    c.LatencyMedianMs,
			PublicIP:           c.PublicIP,
			EnqueuedAt:         c.EnqueuedAt,
			SubmittedAt:        c.SubmittedAt,
			ReceivedAt:         c.ReceivedAt,
		}),
		"payloadHash": c.PayloadHash,
		"payload":     payload,
	})
}

// QueueStats reports the queue-delay distribution over a configurable
// window. Spikes here usually mean the publish API was unavailable for
// some segment of the fleet. Only rows with a non-null submitted_at
// participate (older-client payloads carry no submission timestamp).
func (h *AdminHandler) QueueStats(w http.ResponseWriter, r *http.Request) {
	hours := atoiOr(r.URL.Query().Get("windowHours"), 24)
	if hours < 1 {
		hours = 1
	}
	if hours > 24*30 {
		hours = 24 * 30 // cap at 30 days
	}
	stats, err := h.certs.QueueStats(r.Context(), hours)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "store error")
		return
	}
	writeJSONValue(w, http.StatusOK, map[string]any{
		"windowHours":   hours,
		"sampleSize":    stats.SampleSize,
		"medianSeconds": stats.MedianSeconds,
		"p95Seconds":    stats.P95Seconds,
		"maxSeconds":    stats.MaxSeconds,
	})
}

type adminConfigSummary struct {
	ConfigVersion string    `json:"configVersion"`
	SchemaVersion int       `json:"schemaVersion"`
	IsActive      bool      `json:"isActive"`
	CreatedAt     time.Time `json:"createdAt"`
	Document      any       `json:"document,omitempty"`
}

func (h *AdminHandler) ListCertConfigs(w http.ResponseWriter, r *http.Request) {
	rows, err := h.configs.ListAll(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, "list error")
		return
	}
	includeDoc := r.URL.Query().Get("includeDocument") == "true"
	items := make([]adminConfigSummary, 0, len(rows))
	for _, c := range rows {
		s := adminConfigSummary{
			ConfigVersion: c.ConfigVersion,
			SchemaVersion: c.SchemaVersion,
			IsActive:      c.IsActive,
			CreatedAt:     c.CreatedAt,
		}
		if includeDoc {
			var doc any
			_ = json.Unmarshal(c.Document, &doc)
			s.Document = doc
		}
		items = append(items, s)
	}
	writeJSONValue(w, http.StatusOK, adminListResponse{
		Items:  items,
		Total:  len(items),
		Limit:  len(items),
		Offset: 0,
	})
}

func (h *AdminHandler) GetCertConfig(w http.ResponseWriter, r *http.Request) {
	v := chi.URLParam(r, "version")
	c, err := h.configs.GetByVersion(r.Context(), v)
	if errors.Is(err, store.ErrConfigNotFound) {
		writeError(w, http.StatusNotFound, "no such config")
		return
	}
	if err != nil {
		writeError(w, http.StatusInternalServerError, "store error")
		return
	}
	var doc any
	_ = json.Unmarshal(c.Document, &doc)
	writeJSONValue(w, http.StatusOK, adminConfigSummary{
		ConfigVersion: c.ConfigVersion,
		SchemaVersion: c.SchemaVersion,
		IsActive:      c.IsActive,
		CreatedAt:     c.CreatedAt,
		Document:      doc,
	})
}

// CreateCertConfig accepts a full CertConfig document, validates the
// envelope, and inserts it as inactive. Activation is a separate call so
// the operator can write the draft, review it, then atomically swap the
// active row.
func (h *AdminHandler) CreateCertConfig(w http.ResponseWriter, r *http.Request) {
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

	var doc map[string]any
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	if err := dec.Decode(&doc); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON: "+err.Error())
		return
	}

	problems := validateCertConfigEnvelope(doc)
	if len(problems) > 0 {
		writeError(w, http.StatusBadRequest, "validation failed", problems...)
		return
	}

	cv := doc["configVersion"].(string)
	sv, _ := doc["schemaVersion"].(json.Number).Int64()

	// Re-serialize so what we store is canonical (sorted keys via map
	// marshal) regardless of how the caller formatted their JSON.
	canonical, err := json.Marshal(doc)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "re-serialize failed")
		return
	}

	if err := h.configs.Insert(r.Context(), cv, int(sv), canonical); err != nil {
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) && pgErr.Code == "23505" {
			writeError(w, http.StatusConflict, "config_version already exists")
			return
		}
		writeError(w, http.StatusInternalServerError, "store error")
		return
	}

	c, err := h.configs.GetByVersion(r.Context(), cv)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "store error after insert")
		return
	}
	var docOut any
	_ = json.Unmarshal(c.Document, &docOut)
	writeJSONValue(w, http.StatusCreated, adminConfigSummary{
		ConfigVersion: c.ConfigVersion,
		SchemaVersion: c.SchemaVersion,
		IsActive:      c.IsActive,
		CreatedAt:     c.CreatedAt,
		Document:      docOut,
	})
}

// ActivateCertConfig flips is_active on the named config. Inside one
// transaction the previously active row is cleared, so there is always
// exactly one active config (enforced by the partial unique index too).
func (h *AdminHandler) ActivateCertConfig(w http.ResponseWriter, r *http.Request) {
	v := chi.URLParam(r, "version")
	if err := h.configs.Activate(r.Context(), v); err != nil {
		if errors.Is(err, store.ErrConfigNotFound) {
			writeError(w, http.StatusNotFound, "no such config")
			return
		}
		writeError(w, http.StatusInternalServerError, "store error")
		return
	}
	c, err := h.configs.GetByVersion(r.Context(), v)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "store error after activate")
		return
	}
	var docOut any
	_ = json.Unmarshal(c.Document, &docOut)
	writeJSONValue(w, http.StatusOK, adminConfigSummary{
		ConfigVersion: c.ConfigVersion,
		SchemaVersion: c.SchemaVersion,
		IsActive:      c.IsActive,
		CreatedAt:     c.CreatedAt,
		Document:      docOut,
	})
}

// validateCertConfigEnvelope checks the small set of top-level fields we
// need to insert a valid row. Deeper structural validation (per-tier
// thresholds, server URLs, etc.) is intentionally deferred to the client
// — the dashboard's structured editor is the right place to enforce those
// rules; this admin endpoint trusts inputs from authenticated callers.
func validateCertConfigEnvelope(doc map[string]any) []ErrorDetail {
	var problems []ErrorDetail

	cv, _ := doc["configVersion"].(string)
	if cv == "" {
		problems = append(problems, ErrorDetail{Path: "configVersion", Msg: "required, non-empty string"})
	}

	sv, ok := doc["schemaVersion"].(json.Number)
	if !ok {
		problems = append(problems, ErrorDetail{Path: "schemaVersion", Msg: "required, integer >= 1"})
	} else if n, err := sv.Int64(); err != nil || n < 1 {
		problems = append(problems, ErrorDetail{Path: "schemaVersion", Msg: "must be integer >= 1"})
	}

	for _, key := range []string{"servers", "tiers"} {
		arr, ok := doc[key].([]any)
		if !ok {
			problems = append(problems, ErrorDetail{Path: key, Msg: "required array"})
		} else if len(arr) == 0 {
			problems = append(problems, ErrorDetail{Path: key, Msg: "must contain at least one entry"})
		}
	}

	for _, key := range []string{"tests", "uploadResults"} {
		if _, ok := doc[key].(map[string]any); !ok {
			problems = append(problems, ErrorDetail{Path: key, Msg: "required object"})
		}
	}

	return problems
}

func atoiOr(s string, def int) int {
	if n, err := strconv.Atoi(s); err == nil {
		return n
	}
	return def
}

func writeJSONValue(w http.ResponseWriter, status int, body any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(body)
}
