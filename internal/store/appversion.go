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
	ErrNoActiveAppVersion = errors.New("store: no active app_version_manifest row")
	ErrAppVersionNotFound = errors.New("store: app_version_manifest row not found")
)

type AppVersionStore struct {
	pool *pgxpool.Pool
}

func NewAppVersionStore(pool *pgxpool.Pool) *AppVersionStore {
	return &AppVersionStore{pool: pool}
}

// AppVersionSummary is one row of the app_version_manifest table.
type AppVersionSummary struct {
	LatestVersionCode      int
	LatestVersionName      string
	MinRequiredVersionCode int
	PublishedAt            *time.Time
	Document               []byte
	IsActive               bool
	CreatedAt              time.Time
}

func (s *AppVersionStore) GetActive(ctx context.Context) (*AppVersionSummary, error) {
	const q = `
		select latest_version_code, latest_version_name, min_required_version_code,
		       published_at, document::text, is_active, created_at
		from app_version_manifest
		where is_active = true
	`
	var c AppVersionSummary
	var doc string
	err := s.pool.QueryRow(ctx, q).Scan(
		&c.LatestVersionCode, &c.LatestVersionName, &c.MinRequiredVersionCode,
		&c.PublishedAt, &doc, &c.IsActive, &c.CreatedAt,
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrNoActiveAppVersion
	}
	if err != nil {
		return nil, fmt.Errorf("GetActive: %w", err)
	}
	c.Document = []byte(doc)
	return &c, nil
}

func (s *AppVersionStore) GetByVersionCode(ctx context.Context, code int) (*AppVersionSummary, error) {
	const q = `
		select latest_version_code, latest_version_name, min_required_version_code,
		       published_at, document::text, is_active, created_at
		from app_version_manifest
		where latest_version_code = $1
	`
	var c AppVersionSummary
	var doc string
	err := s.pool.QueryRow(ctx, q, code).Scan(
		&c.LatestVersionCode, &c.LatestVersionName, &c.MinRequiredVersionCode,
		&c.PublishedAt, &doc, &c.IsActive, &c.CreatedAt,
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrAppVersionNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("GetByVersionCode: %w", err)
	}
	c.Document = []byte(doc)
	return &c, nil
}

func (s *AppVersionStore) ListAll(ctx context.Context) ([]AppVersionSummary, error) {
	const q = `
		select latest_version_code, latest_version_name, min_required_version_code,
		       published_at, document::text, is_active, created_at
		from app_version_manifest
		order by latest_version_code desc
	`
	rows, err := s.pool.Query(ctx, q)
	if err != nil {
		return nil, fmt.Errorf("ListAll: %w", err)
	}
	defer rows.Close()

	var out []AppVersionSummary
	for rows.Next() {
		var c AppVersionSummary
		var doc string
		if err := rows.Scan(
			&c.LatestVersionCode, &c.LatestVersionName, &c.MinRequiredVersionCode,
			&c.PublishedAt, &doc, &c.IsActive, &c.CreatedAt,
		); err != nil {
			return nil, fmt.Errorf("ListAll scan: %w", err)
		}
		c.Document = []byte(doc)
		out = append(out, c)
	}
	return out, rows.Err()
}

// Insert creates a new (inactive) manifest row. The caller is expected to
// have already validated the document shape; this just persists it. The
// hot-path columns are pulled from the parsed document so the admin list
// view doesn't have to JSON-parse per row.
func (s *AppVersionStore) Insert(
	ctx context.Context,
	versionCode int,
	versionName string,
	minRequiredCode int,
	publishedAt *time.Time,
	document []byte,
) error {
	const q = `
		insert into app_version_manifest (
			latest_version_code, latest_version_name, min_required_version_code,
			published_at, document, is_active
		) values (
			$1, $2, $3, $4, $5::jsonb, false
		)
	`
	_, err := s.pool.Exec(ctx, q, versionCode, versionName, minRequiredCode, publishedAt, string(document))
	if err != nil {
		return fmt.Errorf("Insert: %w", err)
	}
	return nil
}

// Activate flips is_active on the named version inside a single
// transaction. The partial unique index on (true) where is_active enforces
// the "exactly one active row" invariant at the storage layer too.
func (s *AppVersionStore) Activate(ctx context.Context, code int) error {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("Activate begin: %w", err)
	}
	defer tx.Rollback(ctx)

	if _, err := tx.Exec(ctx, `update app_version_manifest set is_active = false where is_active = true`); err != nil {
		return fmt.Errorf("Activate clear: %w", err)
	}
	tag, err := tx.Exec(ctx, `update app_version_manifest set is_active = true where latest_version_code = $1`, code)
	if err != nil {
		return fmt.Errorf("Activate set: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return ErrAppVersionNotFound
	}
	return tx.Commit(ctx)
}
