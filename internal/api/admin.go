package api

import (
	"encoding/json"
	"errors"
	"net/http"
	"strconv"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/lstepnio/NetworkQualityHWCBackend/internal/store"
)

// AdminHandler exposes /admin/* endpoints for the dashboard. The shape of
// these endpoints is internal to this codebase + dashboard pair (no contract
// repo); breaking changes are coordinated via PR.
type AdminHandler struct {
	certs   *store.CertificationsStore
	configs *store.CertConfigStore
}

func NewAdminHandler(certs *store.CertificationsStore, configs *store.CertConfigStore) *AdminHandler {
	return &AdminHandler{certs: certs, configs: configs}
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
		ReceivedAt:         s.ReceivedAt,
	}
}

func (h *AdminHandler) ListCertifications(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	filter := store.ListFilter{
		Tier:          q.Get("tier"),
		DeviceID:      q.Get("deviceId"),
		ConfigVersion: q.Get("configVersion"),
		Limit:         atoiOr(q.Get("limit"), 50),
		Offset:        atoiOr(q.Get("offset"), 0),
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
			ReceivedAt:         c.ReceivedAt,
		}),
		"payloadHash": c.PayloadHash,
		"payload":     payload,
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
	if errors.Is(err, store.ErrNoActiveConfig) {
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
