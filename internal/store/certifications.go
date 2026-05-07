package store

import (
	"context"
	"errors"
	"fmt"
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
			payload, payload_hash
		) values (
			$1, $2, $3, $4, $5,
			$6, $7, $8, $9,
			$10, $11, $12,
			$13, $14, $15, $16,
			$17, $18, $19,
			$20::jsonb, $21
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

func (s *CertificationsStore) Get(ctx context.Context, id string) (*Certification, error) {
	const q = `
		select
			certification_id, device_id, hsn, hardware_serial, ethernet_mac,
			schema_version, config_version, started_at, completed_at,
			achieved_tier, marginal_metric, transport,
			widevine_level, hdr_types, display_max_height, thermal_status,
			download_steady_mbps, upload_steady_mbps, latency_median_ms,
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
