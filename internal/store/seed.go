package store

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"os"
)

// SeedIfEmpty inserts and activates the config document at seedPath if there
// is currently no active config row. No-op if an active row already exists.
// Intended for dev/staging via DEV_SEED=1; production sets active configs
// through the (out-of-scope here) admin path.
func SeedIfEmpty(ctx context.Context, s *CertConfigStore, seedPath string, logger *slog.Logger) error {
	if _, err := s.GetActive(ctx); err == nil {
		logger.Info("seed: active config already present, skipping")
		return nil
	} else if !errors.Is(err, ErrNoActiveConfig) {
		return fmt.Errorf("seed precheck: %w", err)
	}

	doc, err := os.ReadFile(seedPath)
	if err != nil {
		return fmt.Errorf("seed read %s: %w", seedPath, err)
	}

	var probe struct {
		ConfigVersion string `json:"configVersion"`
		SchemaVersion int    `json:"schemaVersion"`
	}
	if err := json.Unmarshal(doc, &probe); err != nil {
		return fmt.Errorf("seed parse: %w", err)
	}
	if probe.ConfigVersion == "" || probe.SchemaVersion < 1 {
		return fmt.Errorf("seed missing configVersion or schemaVersion < 1")
	}

	if err := s.Insert(ctx, probe.ConfigVersion, probe.SchemaVersion, doc); err != nil {
		return fmt.Errorf("seed insert: %w", err)
	}
	if err := s.Activate(ctx, probe.ConfigVersion); err != nil {
		return fmt.Errorf("seed activate: %w", err)
	}
	logger.Info("seed: inserted and activated", slog.String("config_version", probe.ConfigVersion))
	return nil
}
