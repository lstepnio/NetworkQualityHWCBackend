package api

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strconv"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/lstepnio/NetworkQualityHWCBackend/internal/store"
)

var sha256Re = regexp.MustCompile(`^[0-9a-f]{64}$`)

// AdminHandler exposes /admin/* endpoints for the dashboard. The shape of
// these endpoints is internal to this codebase + dashboard pair (no contract
// repo); breaking changes are coordinated via PR.
type AdminHandler struct {
	certs       *store.CertificationsStore
	configs     *store.CertConfigStore
	appVersions *store.AppVersionStore
	pii         publicIPHasher
}

// publicIPHasher is the small slice of *pii.Hasher we need — accept any
// hasher with a Hash method so tests can fake it without dragging in the
// pii package's keying.
type publicIPHasher interface {
	Hash(value string) string
}

func NewAdminHandler(
	certs *store.CertificationsStore,
	configs *store.CertConfigStore,
	appVersions *store.AppVersionStore,
	hasher publicIPHasher,
) *AdminHandler {
	return &AdminHandler{certs: certs, configs: configs, appVersions: appVersions, pii: hasher}
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
	WifiRating         *string    `json:"wifiRating,omitempty"`  // null on Ethernet or older clients
	WifiRssiDbm        *int       `json:"wifiRssiDbm,omitempty"` // negative integer; -50 stronger than -80
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
		WifiRating:         s.WifiRating,
		WifiRssiDbm:        s.WifiRssiDbm,
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
		SortBy:        q.Get("sort"),
		SortDir:       q.Get("dir"),
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
	ConfigVersion          string    `json:"configVersion"`
	SchemaVersion          int       `json:"schemaVersion"`
	IsActive               bool      `json:"isActive"`
	CreatedAt              time.Time `json:"createdAt"`
	Document               any       `json:"document,omitempty"`
	TargetManufacturer     *string   `json:"targetManufacturer,omitempty"`
	TargetModel            *string   `json:"targetModel,omitempty"`
	TargetBuildFingerprint *string   `json:"targetBuildFingerprint,omitempty"`
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
			ConfigVersion:          c.ConfigVersion,
			SchemaVersion:          c.SchemaVersion,
			IsActive:               c.IsActive,
			CreatedAt:              c.CreatedAt,
			TargetManufacturer:     c.TargetManufacturer,
			TargetModel:            c.TargetModel,
			TargetBuildFingerprint: c.TargetBuildFingerprint,
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
		ConfigVersion:          c.ConfigVersion,
		SchemaVersion:          c.SchemaVersion,
		IsActive:               c.IsActive,
		CreatedAt:              c.CreatedAt,
		Document:               doc,
		TargetManufacturer:     c.TargetManufacturer,
		TargetModel:            c.TargetModel,
		TargetBuildFingerprint: c.TargetBuildFingerprint,
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

	targetManufacturer := stringPtrFromDoc(doc, "targetManufacturer")
	targetModel := stringPtrFromDoc(doc, "targetModel")
	targetBuildFingerprint := stringPtrFromDoc(doc, "targetBuildFingerprint")

	if err := h.configs.Insert(r.Context(), cv, int(sv), canonical,
		targetManufacturer, targetModel, targetBuildFingerprint); err != nil {
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
		ConfigVersion:          c.ConfigVersion,
		SchemaVersion:          c.SchemaVersion,
		IsActive:               c.IsActive,
		CreatedAt:              c.CreatedAt,
		Document:               docOut,
		TargetManufacturer:     c.TargetManufacturer,
		TargetModel:            c.TargetModel,
		TargetBuildFingerprint: c.TargetBuildFingerprint,
	})
}

// stringPtrFromDoc reads an optional string field from an admin POST
// envelope. Returns nil when the key is absent, JSON null, the empty
// string, or any non-string type — callers should validate type
// upstream (see validateCertConfigEnvelope). Trimming empty-string to
// nil matches the docker-compose / curl ergonomic of "absent ==
// empty string", and keeps the DB selector NULL rather than "" which
// would never match any device.
func stringPtrFromDoc(doc map[string]any, key string) *string {
	raw, ok := doc[key]
	if !ok || raw == nil {
		return nil
	}
	s, ok := raw.(string)
	if !ok || s == "" {
		return nil
	}
	return &s
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
		ConfigVersion:          c.ConfigVersion,
		SchemaVersion:          c.SchemaVersion,
		IsActive:               c.IsActive,
		CreatedAt:              c.CreatedAt,
		Document:               docOut,
		TargetManufacturer:     c.TargetManufacturer,
		TargetModel:            c.TargetModel,
		TargetBuildFingerprint: c.TargetBuildFingerprint,
	})
}

// validateCertConfigEnvelope checks the top-level fields plus the
// numeric ranges inside `tests.*` that the Android RuntimeConfig enforces
// via `require(...)`. Mirroring those ranges here means a dashboard
// mistake (e.g. playback.durationSec=1) is rejected with a 400 instead
// of being accepted and then bricking every STB that fetches the config.
//
// Ranges below MUST stay in sync with
// NetworkQualityHWC/.../config/RuntimeConfig.kt — drift here means the
// backend accepts configs that the app then rejects.
//
// As of contract v1.4.0, `servers[]`, `tests.latency`, and the per-phase
// `durationSec`/`perRequestBytes`/`warmupFraction` keys are deprecated:
// nothing on the Android side reads them, so we no longer require them
// or validate their ranges. Existing pre-v1.4.0 configs in the DB still
// validate because we don't reject unknown keys.
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

	if arr, ok := doc["tiers"].([]any); !ok {
		problems = append(problems, ErrorDetail{Path: "tiers", Msg: "required array"})
	} else if len(arr) == 0 {
		problems = append(problems, ErrorDetail{Path: "tiers", Msg: "must contain at least one entry"})
	}

	// Optional v2.2.0 targeting selectors. Any of these can be omitted,
	// null, or a string up to 255 chars. The DB column is sized for 255;
	// anything longer is almost certainly a mistake (Android fingerprints
	// run ~70-120 chars).
	for _, key := range []string{"targetManufacturer", "targetModel", "targetBuildFingerprint"} {
		raw, present := doc[key]
		if !present || raw == nil {
			continue
		}
		s, ok := raw.(string)
		if !ok {
			problems = append(problems, ErrorDetail{Path: key, Msg: "must be string or null"})
			continue
		}
		if len(s) > 255 {
			problems = append(problems, ErrorDetail{Path: key, Msg: "exceeds 255 characters"})
		}
	}

	for _, key := range []string{"tests", "uploadResults"} {
		if _, ok := doc[key].(map[string]any); !ok {
			problems = append(problems, ErrorDetail{Path: key, Msg: "required object"})
		}
	}

	if tests, ok := doc["tests"].(map[string]any); ok {
		problems = append(problems, validateTestsRanges(tests)...)
	}

	// wifiLinkQuality + healthAssessment are OPTIONAL in the wire
	// format (clients fall back per-field to bundled defaults when
	// absent). But IF present, every field must be in range and the
	// ordering invariants must hold — otherwise the client would
	// silently drop the bad value and the operator wouldn't know
	// their tuning didn't take effect.
	if wifi, ok := doc["wifiLinkQuality"].(map[string]any); ok {
		problems = append(problems, validateWifiLinkQuality(wifi)...)
	}
	if hh, ok := doc["healthAssessment"].(map[string]any); ok {
		problems = append(problems, validateHealthAssessment(hh)...)
	}

	// killswitch is optional. When present, must be an object with a
	// boolean `enabled` and (optionally) a string `reason`. We're strict
	// about the boolean type — a typo like `"enabled": "yes"` would be
	// silently parsed as `true` by some JSON libraries and engage the
	// killswitch unintentionally. Reject the whole config in that case
	// so the operator notices.
	if ks, ok := doc["killswitch"].(map[string]any); ok {
		problems = append(problems, validateKillswitch(ks)...)
	}

	return problems
}

func validateKillswitch(o map[string]any) []ErrorDetail {
	const ctx = "killswitch"
	var problems []ErrorDetail

	enabled, present := o["enabled"]
	if !present {
		problems = append(problems, ErrorDetail{Path: ctx + ".enabled", Msg: "required boolean"})
	} else if _, ok := enabled.(bool); !ok {
		problems = append(problems, ErrorDetail{Path: ctx + ".enabled", Msg: "must be boolean (true/false), not a string or number"})
	}

	if reason, present := o["reason"]; present {
		// Allow explicit null; reject anything else that isn't a string.
		if reason != nil {
			if _, ok := reason.(string); !ok {
				problems = append(problems, ErrorDetail{Path: ctx + ".reason", Msg: "must be string or null"})
			}
		}
	}

	return problems
}

// validateWifiLinkQuality mirrors WifiLinkQualityConfig.init in
// RuntimeConfig.kt. The ordering invariant
// (excellent > strong > good) is the part that makes the bands
// well-defined; without it the boundary semantics are nonsense.
func validateWifiLinkQuality(o map[string]any) []ErrorDetail {
	const ctx = "wifiLinkQuality"
	var problems []ErrorDetail
	problems = append(problems, checkIntRange(o, ctx+".excellentRssiMin", "excellentRssiMin", -100, 0)...)
	problems = append(problems, checkIntRange(o, ctx+".strongRssiMin", "strongRssiMin", -100, 0)...)
	problems = append(problems, checkIntRange(o, ctx+".goodRssiMin", "goodRssiMin", -100, 0)...)
	problems = append(problems, checkFloatRange(o, ctx+".rateAdaptationDegradedThreshold", "rateAdaptationDegradedThreshold", 0.0, 1.0)...)

	// Only check ordering if all three RSSI values parsed cleanly.
	ex := asInt(o["excellentRssiMin"])
	st := asInt(o["strongRssiMin"])
	gd := asInt(o["goodRssiMin"])
	if ex != nil && st != nil && gd != nil {
		if !(*ex > *st && *st > *gd) {
			problems = append(problems, ErrorDetail{
				Path: ctx,
				Msg:  fmt.Sprintf("ordering invariant violated: need excellentRssiMin > strongRssiMin > goodRssiMin, got %d > %d > %d", *ex, *st, *gd),
			})
		}
	}
	return problems
}

// validateHealthAssessment mirrors HealthAssessmentConfig.init in
// RuntimeConfig.kt.
func validateHealthAssessment(o map[string]any) []ErrorDetail {
	const ctx = "healthAssessment"
	var problems []ErrorDetail
	problems = append(problems, checkIntRange(o, ctx+".excellentMin", "excellentMin", 1, 100)...)
	problems = append(problems, checkIntRange(o, ctx+".strongMin", "strongMin", 1, 100)...)
	problems = append(problems, checkIntRange(o, ctx+".goodMin", "goodMin", 1, 100)...)
	// > 1.0 — exclusive minimum.
	if v, ok := o["topTierStretchUpFactor"]; !ok {
		problems = append(problems, ErrorDetail{Path: ctx + ".topTierStretchUpFactor", Msg: "required number > 1.0"})
	} else if num, ok := v.(json.Number); !ok {
		problems = append(problems, ErrorDetail{Path: ctx + ".topTierStretchUpFactor", Msg: "must be number > 1.0"})
	} else if f, err := num.Float64(); err != nil || !(f > 1.0) {
		problems = append(problems, ErrorDetail{Path: ctx + ".topTierStretchUpFactor", Msg: fmt.Sprintf("must be number > 1.0, got %s", num.String())})
	}
	problems = append(problems, checkFloatRange(o, ctx+".topTierStretchDownFactor", "topTierStretchDownFactor", 0.0, 1.0)...)

	ex := asInt(o["excellentMin"])
	st := asInt(o["strongMin"])
	gd := asInt(o["goodMin"])
	if ex != nil && st != nil && gd != nil {
		if !(*ex > *st && *st > *gd) {
			problems = append(problems, ErrorDetail{
				Path: ctx,
				Msg:  fmt.Sprintf("ordering invariant violated: need excellentMin > strongMin > goodMin, got %d > %d > %d", *ex, *st, *gd),
			})
		}
	}
	return problems
}

// asInt is a tolerant int extractor for cross-field ordering checks.
// Returns nil on any failure — the per-field range check has already
// emitted the specific error for that case.
func asInt(v any) *int64 {
	num, ok := v.(json.Number)
	if !ok {
		return nil
	}
	n, err := num.Int64()
	if err != nil {
		return nil
	}
	return &n
}

// validateTestsRanges enforces the numeric ranges that
// RuntimeConfig.kt's `require(...)` calls would otherwise turn into a
// fatal parse failure on the STB. As of contract v1.4.0 the only
// per-phase knob still consumed is `parallel`; `durationSec`,
// `perRequestBytes`, `warmupFraction`, and the entire `latency`
// section are deprecated and ignored.
func validateTestsRanges(tests map[string]any) []ErrorDetail {
	var problems []ErrorDetail

	checkThroughput := func(phase string) {
		section, ok := tests[phase].(map[string]any)
		if !ok {
			problems = append(problems, ErrorDetail{
				Path: "tests." + phase, Msg: "required object",
			})
			return
		}
		problems = append(problems, checkIntRange(section, "tests."+phase+".parallel", "parallel", 1, 16)...)
	}
	checkThroughput("download")
	checkThroughput("upload")

	if playback, ok := tests["playback"].(map[string]any); ok {
		problems = append(problems, checkIntRange(playback, "tests.playback.durationSec", "durationSec", 5, 120)...)
		if url, ok := playback["manifestUrl"].(string); !ok || url == "" {
			problems = append(problems, ErrorDetail{Path: "tests.playback.manifestUrl", Msg: "required, non-empty string"})
		}
	} else {
		problems = append(problems, ErrorDetail{Path: "tests.playback", Msg: "required object"})
	}

	return problems
}

func checkIntRange(section map[string]any, path, key string, lo, hi int64) []ErrorDetail {
	v, ok := section[key]
	if !ok {
		return []ErrorDetail{{Path: path, Msg: fmt.Sprintf("required integer in [%d,%d]", lo, hi)}}
	}
	num, ok := v.(json.Number)
	if !ok {
		return []ErrorDetail{{Path: path, Msg: fmt.Sprintf("must be integer in [%d,%d]", lo, hi)}}
	}
	n, err := num.Int64()
	if err != nil || n < lo || n > hi {
		return []ErrorDetail{{Path: path, Msg: fmt.Sprintf("must be integer in [%d,%d], got %s", lo, hi, num.String())}}
	}
	return nil
}

func checkInt64Range(section map[string]any, path, key string, lo, hi int64) []ErrorDetail {
	return checkIntRange(section, path, key, lo, hi)
}

func checkFloatRange(section map[string]any, path, key string, lo, hi float64) []ErrorDetail {
	v, ok := section[key]
	if !ok {
		return []ErrorDetail{{Path: path, Msg: fmt.Sprintf("required number in [%g,%g]", lo, hi)}}
	}
	num, ok := v.(json.Number)
	if !ok {
		return []ErrorDetail{{Path: path, Msg: fmt.Sprintf("must be number in [%g,%g]", lo, hi)}}
	}
	f, err := num.Float64()
	if err != nil || f < lo || f > hi {
		return []ErrorDetail{{Path: path, Msg: fmt.Sprintf("must be number in [%g,%g], got %s", lo, hi, num.String())}}
	}
	return nil
}

// --- App-version-manifest admin endpoints -------------------------------

type adminAppVersionSummary struct {
	LatestVersionCode      int        `json:"latestVersionCode"`
	LatestVersionName      string     `json:"latestVersionName"`
	MinRequiredVersionCode int        `json:"minRequiredVersionCode"`
	PublishedAt            *time.Time `json:"publishedAt,omitempty"`
	IsActive               bool       `json:"isActive"`
	CreatedAt              time.Time  `json:"createdAt"`
	Document               any        `json:"document,omitempty"`
}

func (h *AdminHandler) ListAppVersions(w http.ResponseWriter, r *http.Request) {
	rows, err := h.appVersions.ListAll(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, "list error")
		return
	}
	includeDoc := r.URL.Query().Get("includeDocument") == "true"
	items := make([]adminAppVersionSummary, 0, len(rows))
	for _, c := range rows {
		s := adminAppVersionSummary{
			LatestVersionCode:      c.LatestVersionCode,
			LatestVersionName:      c.LatestVersionName,
			MinRequiredVersionCode: c.MinRequiredVersionCode,
			PublishedAt:            c.PublishedAt,
			IsActive:               c.IsActive,
			CreatedAt:              c.CreatedAt,
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

func (h *AdminHandler) GetAppVersion(w http.ResponseWriter, r *http.Request) {
	code, err := strconv.Atoi(chi.URLParam(r, "versionCode"))
	if err != nil || code < 1 {
		writeError(w, http.StatusBadRequest, "versionCode must be a positive integer")
		return
	}
	c, err := h.appVersions.GetByVersionCode(r.Context(), code)
	if errors.Is(err, store.ErrAppVersionNotFound) {
		writeError(w, http.StatusNotFound, "no such app version")
		return
	}
	if err != nil {
		writeError(w, http.StatusInternalServerError, "store error")
		return
	}
	var doc any
	_ = json.Unmarshal(c.Document, &doc)
	writeJSONValue(w, http.StatusOK, adminAppVersionSummary{
		LatestVersionCode:      c.LatestVersionCode,
		LatestVersionName:      c.LatestVersionName,
		MinRequiredVersionCode: c.MinRequiredVersionCode,
		PublishedAt:            c.PublishedAt,
		IsActive:               c.IsActive,
		CreatedAt:              c.CreatedAt,
		Document:               doc,
	})
}

func (h *AdminHandler) CreateAppVersion(w http.ResponseWriter, r *http.Request) {
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
	problems, parsed := validateAppVersionManifest(doc)
	if len(problems) > 0 {
		writeError(w, http.StatusBadRequest, "validation failed", problems...)
		return
	}

	canonical, err := json.Marshal(doc)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "re-serialize failed")
		return
	}

	if err := h.appVersions.Insert(
		r.Context(),
		parsed.versionCode, parsed.versionName, parsed.minRequiredCode,
		parsed.publishedAt, canonical,
	); err != nil {
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) && pgErr.Code == "23505" {
			writeError(w, http.StatusConflict, "latestVersionCode already exists")
			return
		}
		writeError(w, http.StatusInternalServerError, "store error")
		return
	}

	c, err := h.appVersions.GetByVersionCode(r.Context(), parsed.versionCode)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "store error after insert")
		return
	}
	var docOut any
	_ = json.Unmarshal(c.Document, &docOut)
	writeJSONValue(w, http.StatusCreated, adminAppVersionSummary{
		LatestVersionCode:      c.LatestVersionCode,
		LatestVersionName:      c.LatestVersionName,
		MinRequiredVersionCode: c.MinRequiredVersionCode,
		PublishedAt:            c.PublishedAt,
		IsActive:               c.IsActive,
		CreatedAt:              c.CreatedAt,
		Document:               docOut,
	})
}

func (h *AdminHandler) ActivateAppVersion(w http.ResponseWriter, r *http.Request) {
	code, err := strconv.Atoi(chi.URLParam(r, "versionCode"))
	if err != nil || code < 1 {
		writeError(w, http.StatusBadRequest, "versionCode must be a positive integer")
		return
	}
	if err := h.appVersions.Activate(r.Context(), code); err != nil {
		if errors.Is(err, store.ErrAppVersionNotFound) {
			writeError(w, http.StatusNotFound, "no such app version")
			return
		}
		writeError(w, http.StatusInternalServerError, "store error")
		return
	}
	c, err := h.appVersions.GetByVersionCode(r.Context(), code)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "store error after activate")
		return
	}
	var docOut any
	_ = json.Unmarshal(c.Document, &docOut)
	writeJSONValue(w, http.StatusOK, adminAppVersionSummary{
		LatestVersionCode:      c.LatestVersionCode,
		LatestVersionName:      c.LatestVersionName,
		MinRequiredVersionCode: c.MinRequiredVersionCode,
		PublishedAt:            c.PublishedAt,
		IsActive:               c.IsActive,
		CreatedAt:              c.CreatedAt,
		Document:               docOut,
	})
}

type parsedAppVersionEnvelope struct {
	versionCode     int
	versionName     string
	minRequiredCode int
	publishedAt     *time.Time
}

// validateAppVersionManifest enforces the schema constraints declared in
// the contract's AppVersionManifest (v1.2.0): required scalars, the SHA-256
// regex, monotonic minRequired <= latest, https-or-http apkUrl. The dashboard
// will eventually do field-level form validation; this surface is the
// authoritative bouncer.
func validateAppVersionManifest(doc map[string]any) ([]ErrorDetail, parsedAppVersionEnvelope) {
	var problems []ErrorDetail
	var out parsedAppVersionEnvelope

	mustInt := func(path string) (int, bool) {
		n, ok := doc[path].(json.Number)
		if !ok {
			problems = append(problems, ErrorDetail{Path: path, Msg: "required integer"})
			return 0, false
		}
		i, err := n.Int64()
		if err != nil || i < 1 {
			problems = append(problems, ErrorDetail{Path: path, Msg: "must be integer >= 1"})
			return 0, false
		}
		return int(i), true
	}
	mustString := func(path string) string {
		s, _ := doc[path].(string)
		if s == "" {
			problems = append(problems, ErrorDetail{Path: path, Msg: "required, non-empty string"})
		}
		return s
	}
	mustSha := func(path string) {
		s, _ := doc[path].(string)
		if !sha256Re.MatchString(s) {
			problems = append(problems, ErrorDetail{Path: path, Msg: "must match ^[0-9a-f]{64}$"})
		}
	}

	if _, ok := mustInt("schemaVersion"); !ok {
		_ = ok
	}
	out.versionName = mustString("latestVersionName")
	lvc, lvcOk := mustInt("latestVersionCode")
	mrc, mrcOk := mustInt("minRequiredVersionCode")
	if lvcOk && mrcOk && mrc > lvc {
		problems = append(problems, ErrorDetail{
			Path: "minRequiredVersionCode",
			Msg:  "must be <= latestVersionCode",
		})
	}
	out.versionCode = lvc
	out.minRequiredCode = mrc

	if u := mustString("apkUrl"); u != "" {
		// Accept http/https — production policy is HTTPS but staging/dev
		// often uses plain HTTP. The client side enforces HTTPS in release
		// builds via the network security config.
		if len(u) < 7 || (u[:7] != "http://" && (len(u) < 8 || u[:8] != "https://")) {
			problems = append(problems, ErrorDetail{Path: "apkUrl", Msg: "must be an http(s) URL"})
		}
	}

	if n, ok := doc["apkSizeBytes"].(json.Number); ok {
		if i, err := n.Int64(); err != nil || i < 1 {
			problems = append(problems, ErrorDetail{Path: "apkSizeBytes", Msg: "must be integer >= 1"})
		}
	} else {
		problems = append(problems, ErrorDetail{Path: "apkSizeBytes", Msg: "required integer"})
	}

	mustSha("apkSha256")
	mustSha("signingCertSha256")

	if v, ok := doc["publishedAt"].(string); ok && v != "" {
		if t, err := time.Parse(time.RFC3339, v); err != nil {
			problems = append(problems, ErrorDetail{Path: "publishedAt", Msg: "must be RFC 3339 timestamp"})
		} else {
			out.publishedAt = &t
		}
	}

	return problems, out
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
