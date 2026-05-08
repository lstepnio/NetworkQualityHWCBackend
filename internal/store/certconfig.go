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

func (s *CertConfigStore) GetActive(ctx context.Context) (ActiveConfig, error) {
	const q = `
		select config_version, schema_version, document::text
		from cert_config
		where is_active = true
	`
	var c ActiveConfig
	var doc string
	err := s.pool.QueryRow(ctx, q).Scan(&c.ConfigVersion, &c.SchemaVersion, &doc)
	if errors.Is(err, pgx.ErrNoRows) {
		return ActiveConfig{}, ErrNoActiveConfig
	}
	if err != nil {
		return ActiveConfig{}, fmt.Errorf("GetActive: %w", err)
	}
	c.Document = []byte(doc)
	return c, nil
}

func (s *CertConfigStore) Insert(ctx context.Context, configVersion string, schemaVersion int, document []byte) error {
	const q = `
		insert into cert_config (config_version, schema_version, document, is_active)
		values ($1, $2, $3::jsonb, false)
	`
	_, err := s.pool.Exec(ctx, q, configVersion, schemaVersion, string(document))
	if err != nil {
		return fmt.Errorf("Insert: %w", err)
	}
	return nil
}

// ConfigSummary is one row of the cert_config table, as returned by ListAll.
// Document is the full JSONB doc; callers that only want metadata can ignore it.
type ConfigSummary struct {
	ConfigVersion string
	SchemaVersion int
	IsActive      bool
	CreatedAt     time.Time
	Document      []byte
}

func (s *CertConfigStore) ListAll(ctx context.Context) ([]ConfigSummary, error) {
	const q = `
		select config_version, schema_version, is_active, created_at, document::text
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
		if err := rows.Scan(&c.ConfigVersion, &c.SchemaVersion, &c.IsActive, &c.CreatedAt, &doc); err != nil {
			return nil, fmt.Errorf("ListAll scan: %w", err)
		}
		c.Document = []byte(doc)
		out = append(out, c)
	}
	return out, rows.Err()
}

func (s *CertConfigStore) GetByVersion(ctx context.Context, version string) (*ConfigSummary, error) {
	const q = `
		select config_version, schema_version, is_active, created_at, document::text
		from cert_config
		where config_version = $1
	`
	var c ConfigSummary
	var doc string
	err := s.pool.QueryRow(ctx, q, version).Scan(&c.ConfigVersion, &c.SchemaVersion, &c.IsActive, &c.CreatedAt, &doc)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrConfigNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("GetByVersion: %w", err)
	}
	c.Document = []byte(doc)
	return &c, nil
}

func (s *CertConfigStore) Activate(ctx context.Context, configVersion string) error {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("Activate begin: %w", err)
	}
	defer tx.Rollback(ctx)

	if _, err := tx.Exec(ctx, `update cert_config set is_active = false where is_active = true`); err != nil {
		return fmt.Errorf("Activate clear: %w", err)
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
