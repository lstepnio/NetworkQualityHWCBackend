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
	ErrNoActiveConfig = errors.New("store: no active cert_config row")
	ErrConfigNotFound = errors.New("store: cert_config row not found")
)

type CertConfigStore struct {
	pool *pgxpool.Pool
}

func NewCertConfigStore(pool *pgxpool.Pool) *CertConfigStore {
	return &CertConfigStore{pool: pool}
}

type ActiveConfig struct {
	ConfigVersion string
	SchemaVersion int
	Document      []byte
}

// DeviceTarget describes the device making a /v1/cert-config request,
// used by [CertConfigStore.GetActiveForDevice] to resolve the most
// specifically-targeted active row. Empty string in any field means
// "no value sent" — a pre-v2.2.0 client sends none and falls through
// to the all-null default.
type DeviceTarget struct {
	Manufacturer     string
	Model            string
	BuildFingerprint string
}

// GetActiveForDevice resolves the active cert_config row that best
// matches the requesting device per contract SPEC §4.1.1:
//
//   - Tier 1: target_build_fingerprint == request fingerprint
//   - Tier 2: target_model == request model, target_build_fingerprint null
//   - Tier 3: target_manufacturer == request manufacturer, others null
//   - Tier 4: all three selectors null (the default)
//
// Returns [ErrNoActiveConfig] when no row at any tier matches. The
// unique partial index `cert_config_active_per_target` keeps the
// per-tier result unambiguous; the created_at tiebreaker is defensive.
func (s *CertConfigStore) GetActiveForDevice(ctx context.Context, t DeviceTarget) (ActiveConfig, error) {
	const q = `
		select config_version, schema_version, document::text
		from cert_config
		where is_active = true
		  and (target_manufacturer      is null or target_manufacturer      = $1)
		  and (target_model             is null or target_model             = $2)
		  and (target_build_fingerprint is null or target_build_fingerprint = $3)
		order by
		  (target_build_fingerprint is not null) desc,
		  (target_model             is not null) desc,
		  (target_manufacturer      is not null) desc,
		  created_at desc
		limit 1
	`
	var c ActiveConfig
	var doc string
	err := s.pool.QueryRow(ctx, q, t.Manufacturer, t.Model, t.BuildFingerprint).
		Scan(&c.ConfigVersion, &c.SchemaVersion, &doc)
	if errors.Is(err, pgx.ErrNoRows) {
		return ActiveConfig{}, ErrNoActiveConfig
	}
	if err != nil {
		return ActiveConfig{}, fmt.Errorf("GetActiveForDevice: %w", err)
	}
	c.Document = []byte(doc)
	return c, nil
}

// GetActive returns the all-null default active config. Retained for
// the dev-seed bootstrap path (which has no device context) and tests.
// Production reads should go through [GetActiveForDevice].
func (s *CertConfigStore) GetActive(ctx context.Context) (ActiveConfig, error) {
	return s.GetActiveForDevice(ctx, DeviceTarget{})
}

// Insert creates a new cert_config row with the supplied targeting
// selectors. Pass nil for a selector to leave it null ("any").
//
// New rows are created inactive — callers promote them with
// [Activate]. The unique partial index allows multiple inactive rows
// per target group; the constraint only kicks in once a row is
// promoted.
func (s *CertConfigStore) Insert(
	ctx context.Context,
	configVersion string, schemaVersion int, document []byte,
	targetManufacturer, targetModel, targetBuildFingerprint *string,
) error {
	const q = `
		insert into cert_config (
		    config_version, schema_version, document, is_active,
		    target_manufacturer, target_model, target_build_fingerprint
		)
		values ($1, $2, $3::jsonb, false, $4, $5, $6)
	`
	_, err := s.pool.Exec(ctx, q,
		configVersion, schemaVersion, string(document),
		targetManufacturer, targetModel, targetBuildFingerprint,
	)
	if err != nil {
		return fmt.Errorf("Insert: %w", err)
	}
	return nil
}

// ConfigSummary is one row of the cert_config table, as returned by ListAll.
// Document is the full JSONB doc; callers that only want metadata can ignore it.
type ConfigSummary struct {
	ConfigVersion          string
	SchemaVersion          int
	IsActive               bool
	CreatedAt              time.Time
	Document               []byte
	TargetManufacturer     *string
	TargetModel            *string
	TargetBuildFingerprint *string
}

func (s *CertConfigStore) ListAll(ctx context.Context) ([]ConfigSummary, error) {
	const q = `
		select config_version, schema_version, is_active, created_at, document::text,
		       target_manufacturer, target_model, target_build_fingerprint
		from cert_config
		order by created_at desc
	`
	rows, err := s.pool.Query(ctx, q)
	if err != nil {
		return nil, fmt.Errorf("ListAll: %w", err)
	}
	defer rows.Close()

	var out []ConfigSummary
	for rows.Next() {
		var c ConfigSummary
		var doc string
		if err := rows.Scan(&c.ConfigVersion, &c.SchemaVersion, &c.IsActive, &c.CreatedAt, &doc,
			&c.TargetManufacturer, &c.TargetModel, &c.TargetBuildFingerprint); err != nil {
			return nil, fmt.Errorf("ListAll scan: %w", err)
		}
		c.Document = []byte(doc)
		out = append(out, c)
	}
	return out, rows.Err()
}

func (s *CertConfigStore) GetByVersion(ctx context.Context, version string) (*ConfigSummary, error) {
	const q = `
		select config_version, schema_version, is_active, created_at, document::text,
		       target_manufacturer, target_model, target_build_fingerprint
		from cert_config
		where config_version = $1
	`
	var c ConfigSummary
	var doc string
	err := s.pool.QueryRow(ctx, q, version).Scan(&c.ConfigVersion, &c.SchemaVersion, &c.IsActive, &c.CreatedAt, &doc,
		&c.TargetManufacturer, &c.TargetModel, &c.TargetBuildFingerprint)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrConfigNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("GetByVersion: %w", err)
	}
	c.Document = []byte(doc)
	return &c, nil
}

// Activate promotes the named config to active. Scoped to the row's
// target group: the previous active row for the same
// (manufacturer, model, fingerprint) tuple — with NULLs compared
// equal to NULLs — is deactivated, but active rows in other target
// groups are untouched. A request from an SEI device can still
// resolve to the SEI-targeted row after the operator activates a new
// default; a request from a device with no matching targeted row can
// still resolve to the default after the operator activates a new
// SEI row.
func (s *CertConfigStore) Activate(ctx context.Context, configVersion string) error {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("Activate begin: %w", err)
	}
	defer tx.Rollback(ctx)

	const clearSameGroup = `
		update cert_config c
		set is_active = false
		where c.is_active = true
		  and c.config_version <> $1
		  and (
		    select
		      coalesce(target_manufacturer,      '') = coalesce(c.target_manufacturer,      '')
		      and coalesce(target_model,            '') = coalesce(c.target_model,            '')
		      and coalesce(target_build_fingerprint, '') = coalesce(c.target_build_fingerprint, '')
		    from cert_config
		    where config_version = $1
		  )
	`
	if _, err := tx.Exec(ctx, clearSameGroup, configVersion); err != nil {
		return fmt.Errorf("Activate clear-same-group: %w", err)
	}
	tag, err := tx.Exec(ctx, `update cert_config set is_active = true where config_version = $1`, configVersion)
	if err != nil {
		return fmt.Errorf("Activate set: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return ErrConfigNotFound
	}
	return tx.Commit(ctx)
}
