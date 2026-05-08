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
	PublicIP           *string // Stored as the peppered SHA-256 hash; admin API hashes query inputs to match.
	Payload            []byte
	PayloadHash        string
	ReceivedAt         time.Time
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
			public_ip,
			payload, payload_hash
		) values (
			$1, $2, $3, $4, $5,
			$6, $7, $8, $9,
			$10, $11, $12,
			$13, $14, $15, $16,
			$17, $18, $19,
			$20,
			$21::jsonb, $22
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
		c.PublicIP,
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
type ListFilter struct {
	Tier          string
	DeviceID      string
	ConfigVersion string
	HSN           string // exact match against the (now plain) hsn column
	PublicIPHash  string // exact match against the (hashed) public_ip column — caller hashes
	From          *time.Time
	To            *time.Time
	Limit         int
	Offset        int
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
	PublicIP           *string // hashed
	ReceivedAt         time.Time
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
	if f.PublicIPHash != "" {
		add("public_ip = $%d", f.PublicIPHash)
	}
	if f.From != nil {
		add("received_at >= $%d", *f.From)
	}
	if f.To != nil {
		add("received_at < $%d", *f.To)
	}

	args = append(args, f.Limit, f.Offset)
	q := fmt.Sprintf(`
		select
			certification_id, device_id, hsn, config_version,
			started_at, completed_at,
			achieved_tier, marginal_metric, transport,
			widevine_level, hdr_types, display_max_height, thermal_status,
			download_steady_mbps, upload_steady_mbps, latency_median_ms,
			public_ip, received_at,
			count(*) over () as total
		from certifications
		where %s
		order by received_at desc
		limit $%d offset $%d
	`, strings.Join(conds, " and "), len(args)-1, len(args))

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
			&c.PublicIP, &c.ReceivedAt, &total,
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

func (s *CertificationsStore) Get(ctx context.Context, id string) (*Certification, error) {
	const q = `
		select
			certification_id, device_id, hsn, hardware_serial, ethernet_mac,
			schema_version, config_version, started_at, completed_at,
			achieved_tier, marginal_metric, transport,
			widevine_level, hdr_types, display_max_height, thermal_status,
			download_steady_mbps, upload_steady_mbps, latency_median_ms,
			public_ip,
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
		&c.PublicIP,
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
