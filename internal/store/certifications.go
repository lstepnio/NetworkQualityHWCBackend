package store

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

var (
	ErrCertNotFound  = errors.New("store: certification not found")
	ErrHashMismatch  = errors.New("store: certification_id exists with different payload_hash")
)

type CertificationsStore struct {
	pool *pgxpool.Pool
}

func NewCertificationsStore(pool *pgxpool.Pool) *CertificationsStore {
	return &CertificationsStore{pool: pool}
}

// Certification is the row mapped from the certifications table. Strings that
// can be null in the schema use *string so callers can distinguish "absent"
// from "empty".
type Certification struct {
	CertificationID    string
	DeviceID           string
	HSN                *string
	HardwareSerial     *string
	EthernetMac        *string
	SchemaVersion      int
	ConfigVersion      *string
	StartedAt          time.Time
	CompletedAt        time.Time
	AchievedTier       string
	MarginalMetric     *string
	Transport          string
	WidevineLevel      *string
	HDRTypes           []string
	DisplayMaxHeight   *int
	ThermalStatus      *string
	DownloadSteadyMbps *float64
	UploadSteadyMbps   *float64
	LatencyMedianMs    *int
	PublicIP           *string    // Plaintext for rows ingested >= v0.7.11; legacy rows still carry the SHA-256 + pepper string.
	EnqueuedAt         *time.Time // Optional, contract v1.1.0+; nil for older clients.
	SubmittedAt        *time.Time // Optional, contract v1.1.0+; nil for older clients.
	// DNSPreferred denormalizes payload.dnsAssessment.allPreferred so the
	// list view can filter + render without parsing JSONB per row. NULL =
	// no policy in effect (or pre-v2.3.0 client); FALSE = at least one
	// non-preferred actual server; TRUE = all preferred (or vacuously empty).
	DNSPreferred *bool
	Payload      []byte
	PayloadHash  string
	ReceivedAt   time.Time
}

// UpsertResult tells the handler which HTTP status to return: Created for the
// first POST of this certification_id, Duplicate when the same id arrives with
// the exact same payload hash (treat as success), Conflict when the hash
// disagrees (almost always a client bug — server logs and rejects).
type UpsertOutcome int

const (
	UpsertCreated UpsertOutcome = iota
	UpsertDuplicate
	UpsertConflict
)

// Upsert inserts the certification, or returns the stored row's hash when a
// row with this certification_id already exists. The caller decides 200 vs 409
// based on the returned outcome and existing hash.
func (s *CertificationsStore) Upsert(ctx context.Context, c *Certification) (UpsertOutcome, error) {
	const insert = `
		insert into certifications (
			certification_id, device_id, hsn, hardware_serial, ethernet_mac,
			schema_version, config_version, started_at, completed_at,
			achieved_tier, marginal_metric, transport,
			widevine_level, hdr_types, display_max_height, thermal_status,
			download_steady_mbps, upload_steady_mbps, latency_median_ms,
			public_ip, enqueued_at, submitted_at,
			dns_preferred,
			payload, payload_hash
		) values (
			$1, $2, $3, $4, $5,
			$6, $7, $8, $9,
			$10, $11, $12,
			$13, $14, $15, $16,
			$17, $18, $19,
			$20, $21, $22,
			$23,
			$24::jsonb, $25
		)
		on conflict (certification_id) do nothing
		returning certification_id
	`
	var id string
	err := s.pool.QueryRow(ctx, insert,
		c.CertificationID, c.DeviceID, c.HSN, c.HardwareSerial, c.EthernetMac,
		c.SchemaVersion, c.ConfigVersion, c.StartedAt, c.CompletedAt,
		c.AchievedTier, c.MarginalMetric, c.Transport,
		c.WidevineLevel, c.HDRTypes, c.DisplayMaxHeight, c.ThermalStatus,
		c.DownloadSteadyMbps, c.UploadSteadyMbps, c.LatencyMedianMs,
		c.PublicIP, c.EnqueuedAt, c.SubmittedAt,
		c.DNSPreferred,
		string(c.Payload), c.PayloadHash,
	).Scan(&id)
	if err == nil {
		return UpsertCreated, nil
	}
	if !errors.Is(err, pgx.ErrNoRows) {
		return 0, fmt.Errorf("Upsert insert: %w", err)
	}

	// Conflict on certification_id: compare payload hashes.
	const probe = `select payload_hash from certifications where certification_id = $1`
	var existing string
	if err := s.pool.QueryRow(ctx, probe, c.CertificationID).Scan(&existing); err != nil {
		return 0, fmt.Errorf("Upsert probe: %w", err)
	}
	if existing == c.PayloadHash {
		return UpsertDuplicate, nil
	}
	return UpsertConflict, nil
}

// ListFilter narrows /admin/certifications results. Zero values are ignored.
// Limit is capped to 200 server-side; Offset is unbounded.
//
// From/To filter on completed_at (cert run time), not received_at — a
// 3-day-old run that drained from the publish queue 5 min ago belongs in
// its actual chronological slot, not at the top of the feed.
type ListFilter struct {
	Tier          string
	DeviceID      string
	ConfigVersion string
	HSN           string // exact match against the (now plain) hsn column
	PublicIP      string // exact-match against the `public_ip` column (plaintext post the de-hashing policy change; legacy rows still carry SHA-256 strings and are not returned by a plaintext-IP query)
	From          *time.Time
	To            *time.Time
	// QueuedOnly returns only rows whose submitted_at - completed_at is
	// more than 5 minutes. Implies submitted_at is not null, so older-client
	// rows (without submitted_at) never match. Useful for investigating
	// publish-API outages.
	QueuedOnly bool
	// DNSFlagged returns only rows with dns_preferred = false (at least
	// one non-preferred actual DNS server at cert time). Operator-oriented
	// filter; the success state (TRUE) and the no-policy state (NULL) are
	// both excluded.
	DNSFlagged bool
	// SortBy is a whitelisted column key. Empty/unknown → default
	// ordering (completed_at). See sortColumn() for the allowed set.
	SortBy string
	// SortDir is "asc" or "desc". Empty/unknown → "desc". Always
	// applied with `nulls last` so empty cells stay at the bottom.
	SortDir string
	Limit   int
	Offset  int
}

// sortColumn maps the URL-facing sort key to its SQL expression.
// Whitelisted so a malicious caller can't inject. Returns the column
// expression and whether the key was recognized; unknown keys fall
// back to completed_at.
func sortColumn(key string) (string, bool) {
	switch key {
	case "", "completed":
		return "completed_at", key != ""
	case "received":
		return "received_at", true
	case "tier":
		return "achieved_tier", true
	case "download":
		return "download_steady_mbps", true
	case "upload":
		return "upload_steady_mbps", true
	case "latency":
		return "latency_median_ms", true
	case "wifi":
		// Strongest signal sorts to the top in desc (least negative
		// rssi). Casting from text → int because we extract from JSONB.
		return "(payload->'result'->'wifiLink'->>'rssiDbm')::int", true
	case "device":
		return "device_id", true
	case "config":
		return "config_version", true
	case "hsn":
		return "hsn", true
	}
	return "completed_at", false
}

// ListSummary is the row shape returned by List — hot-path columns only,
// not the full JSONB payload. Use Get for the payload.
type ListSummary struct {
	CertificationID    string
	DeviceID           string
	HSN                *string
	ConfigVersion      *string
	StartedAt          time.Time
	CompletedAt        time.Time
	AchievedTier       string
	MarginalMetric     *string
	Transport          string
	WidevineLevel      *string
	HDRTypes           []string
	DisplayMaxHeight   *int
	ThermalStatus      *string
	DownloadSteadyMbps *float64
	UploadSteadyMbps   *float64
	LatencyMedianMs    *int
	// WifiRating is the qualitative bucket the Android client computes
	// from RSSI + linkSpeed (e.g. STRONG, GOOD, MARGINAL, WEAK).
	// Extracted from payload->'result'->'wifiLink' on read; not a
	// dedicated column. Null when the cert ran on Ethernet or when an
	// older client didn't emit the field.
	WifiRating  *string
	WifiRssiDbm *int
	PublicIP    *string // plaintext for rows ingested >= v0.7.11; legacy rows still carry the SHA-256 string
	EnqueuedAt  *time.Time
	SubmittedAt *time.Time
	// DNSPreferred mirrors Certification.DNSPreferred — denormalized
	// payload.dnsAssessment.allPreferred for filter + list-view efficiency.
	DNSPreferred *bool
	ReceivedAt   time.Time
}

func (s *CertificationsStore) List(ctx context.Context, f ListFilter) ([]ListSummary, int, error) {
	if f.Limit <= 0 || f.Limit > 200 {
		f.Limit = 50
	}
	if f.Offset < 0 {
		f.Offset = 0
	}

	conds := []string{"1=1"}
	args := []any{}
	add := func(clause string, val any) {
		args = append(args, val)
		conds = append(conds, fmt.Sprintf(clause, len(args)))
	}
	if f.Tier != "" {
		add("achieved_tier = $%d", f.Tier)
	}
	if f.DeviceID != "" {
		add("device_id = $%d", f.DeviceID)
	}
	if f.ConfigVersion != "" {
		add("config_version = $%d", f.ConfigVersion)
	}
	if f.HSN != "" {
		add("hsn = $%d", f.HSN)
	}
	if f.PublicIP != "" {
		add("public_ip = $%d", f.PublicIP)
	}
	if f.From != nil {
		add("completed_at >= $%d", *f.From)
	}
	if f.To != nil {
		add("completed_at < $%d", *f.To)
	}
	if f.QueuedOnly {
		// >5 minutes between cert running and the row landing means the
		// publish queue actually held it; sub-second drains aren't useful
		// to surface.
		conds = append(conds, "submitted_at is not null and submitted_at - completed_at > interval '5 minutes'")
	}
	if f.DNSFlagged {
		// dns_preferred is a trichotomy (NULL / FALSE / TRUE); NULL =
		// no-policy must NOT match — operators triaging "show me DNS
		// issues" don't want pre-policy rows polluting the result.
		conds = append(conds, "dns_preferred = false")
	}

	sortExpr, _ := sortColumn(f.SortBy)
	dir := "desc"
	if strings.EqualFold(f.SortDir, "asc") {
		dir = "asc"
	}

	args = append(args, f.Limit, f.Offset)
	q := fmt.Sprintf(`
		select
			certification_id, device_id, hsn, config_version,
			started_at, completed_at,
			achieved_tier, marginal_metric, transport,
			widevine_level, hdr_types, display_max_height, thermal_status,
			download_steady_mbps, upload_steady_mbps, latency_median_ms,
			payload->'result'->'wifiLink'->>'rating' as wifi_rating,
			(payload->'result'->'wifiLink'->>'rssiDbm')::int as wifi_rssi_dbm,
			public_ip, enqueued_at, submitted_at,
			dns_preferred,
			received_at,
			count(*) over () as total
		from certifications
		where %s
		order by %s %s nulls last, completed_at desc
		limit $%d offset $%d
	`, strings.Join(conds, " and "), sortExpr, dir, len(args)-1, len(args))

	rows, err := s.pool.Query(ctx, q, args...)
	if err != nil {
		return nil, 0, fmt.Errorf("List query: %w", err)
	}
	defer rows.Close()

	out := make([]ListSummary, 0, f.Limit)
	total := 0
	for rows.Next() {
		var c ListSummary
		if err := rows.Scan(
			&c.CertificationID, &c.DeviceID, &c.HSN, &c.ConfigVersion,
			&c.StartedAt, &c.CompletedAt,
			&c.AchievedTier, &c.MarginalMetric, &c.Transport,
			&c.WidevineLevel, &c.HDRTypes, &c.DisplayMaxHeight, &c.ThermalStatus,
			&c.DownloadSteadyMbps, &c.UploadSteadyMbps, &c.LatencyMedianMs,
			&c.WifiRating, &c.WifiRssiDbm,
			&c.PublicIP, &c.EnqueuedAt, &c.SubmittedAt,
			&c.DNSPreferred,
			&c.ReceivedAt, &total,
		); err != nil {
			return nil, 0, fmt.Errorf("List scan: %w", err)
		}
		out = append(out, c)
	}
	if err := rows.Err(); err != nil {
		return nil, 0, fmt.Errorf("List rows: %w", err)
	}
	return out, total, nil
}

// QueueStatsResult is the aggregate over a recent window of certifications
// where the client supplied a submitted_at. All three percentile values
// are seconds.
type QueueStatsResult struct {
	SampleSize    int
	MedianSeconds *float64
	P95Seconds    *float64
	MaxSeconds    *float64
}

// QueueStats computes the queue-delay distribution (submitted_at - completed_at)
// over rows whose completed_at falls within the trailing window. Only rows
// with a non-null submitted_at are included; otherwise older-client payloads
// would be counted as "zero delay" and skew the percentiles.
func (s *CertificationsStore) QueueStats(ctx context.Context, windowHours int) (QueueStatsResult, error) {
	const q = `
		select
			count(*) as n,
			extract(epoch from percentile_cont(0.5)  within group (order by submitted_at - completed_at)) as median,
			extract(epoch from percentile_cont(0.95) within group (order by submitted_at - completed_at)) as p95,
			extract(epoch from max(submitted_at - completed_at)) as max
		from certifications
		where submitted_at is not null
		  and completed_at >= now() - make_interval(hours => $1)
	`
	var r QueueStatsResult
	err := s.pool.QueryRow(ctx, q, windowHours).Scan(
		&r.SampleSize, &r.MedianSeconds, &r.P95Seconds, &r.MaxSeconds,
	)
	if err != nil {
		return QueueStatsResult{}, fmt.Errorf("QueueStats: %w", err)
	}
	return r, nil
}

func (s *CertificationsStore) Get(ctx context.Context, id string) (*Certification, error) {
	const q = `
		select
			certification_id, device_id, hsn, hardware_serial, ethernet_mac,
			schema_version, config_version, started_at, completed_at,
			achieved_tier, marginal_metric, transport,
			widevine_level, hdr_types, display_max_height, thermal_status,
			download_steady_mbps, upload_steady_mbps, latency_median_ms,
			public_ip, enqueued_at, submitted_at,
			dns_preferred,
			payload::text, payload_hash, received_at
		from certifications
		where certification_id = $1
	`
	var c Certification
	var payloadStr string
	err := s.pool.QueryRow(ctx, q, id).Scan(
		&c.CertificationID, &c.DeviceID, &c.HSN, &c.HardwareSerial, &c.EthernetMac,
		&c.SchemaVersion, &c.ConfigVersion, &c.StartedAt, &c.CompletedAt,
		&c.AchievedTier, &c.MarginalMetric, &c.Transport,
		&c.WidevineLevel, &c.HDRTypes, &c.DisplayMaxHeight, &c.ThermalStatus,
		&c.DownloadSteadyMbps, &c.UploadSteadyMbps, &c.LatencyMedianMs,
		&c.PublicIP, &c.EnqueuedAt, &c.SubmittedAt,
		&c.DNSPreferred,
		&payloadStr, &c.PayloadHash, &c.ReceivedAt,
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrCertNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("Get: %w", err)
	}
	c.Payload = []byte(payloadStr)
	return &c, nil
}
