package store

import (
	"fmt"

	"github.com/golang-migrate/migrate/v4"
	_ "github.com/golang-migrate/migrate/v4/database/postgres"
	_ "github.com/golang-migrate/migrate/v4/source/file"
)

// RunMigrations applies all .up.sql migrations in path against dsn. Idempotent;
// uses a schema_migrations table to track what's been applied. Safe to call on
// every server start.
func RunMigrations(path, dsn string) error {
	m, err := migrate.New("file://"+path, dsn)
	if err != nil {
		return fmt.Errorf("migrate.New: %w", err)
	}
	defer m.Close()

	if err := m.Up(); err != nil && err != migrate.ErrNoChange {
		return fmt.Errorf("migrate.Up: %w", err)
	}
	return nil
}
