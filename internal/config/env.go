package config

import (
	"fmt"
	"os"
	"strconv"
	"time"
)

type Env struct {
	DatabaseURL      string
	HTTPAddr         string
	PIIPepper        string
	MigrationsPath   string
	DevSeed          bool
	SeedPath         string
	AdminToken       string
	ASNLookupEnabled bool          // when false, the server skips the Cymru DNS lookup and stores null for isp_asn/isp_name. Useful in tests + air-gapped environments.
	ASNLookupTimeout time.Duration // hard per-lookup budget; 500ms by default
}

func Load() (Env, error) {
	dbURL := os.Getenv("DATABASE_URL")
	if dbURL == "" {
		return Env{}, fmt.Errorf("DATABASE_URL is required")
	}
	addr := os.Getenv("HTTP_ADDR")
	if addr == "" {
		addr = ":8080"
	}
	pepper := os.Getenv("PII_PEPPER")
	if pepper == "" {
		pepper = "dev-pepper-change-me"
	}
	mig := os.Getenv("MIGRATIONS_PATH")
	if mig == "" {
		mig = "db/migrations"
	}
	seed := os.Getenv("SEED_PATH")
	if seed == "" {
		seed = "db/seed/cert-config.json"
	}

	// ASN lookup defaults to on with a 500ms budget. Set ASN_LOOKUP_ENABLED=0
	// to disable (tests, air-gapped). Set ASN_LOOKUP_TIMEOUT_MS to tune.
	asnEnabled := os.Getenv("ASN_LOOKUP_ENABLED") != "0"
	asnTimeout := 500 * time.Millisecond
	if v := os.Getenv("ASN_LOOKUP_TIMEOUT_MS"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			asnTimeout = time.Duration(n) * time.Millisecond
		}
	}

	return Env{
		DatabaseURL:      dbURL,
		HTTPAddr:         addr,
		PIIPepper:        pepper,
		MigrationsPath:   mig,
		DevSeed:          os.Getenv("DEV_SEED") == "1",
		SeedPath:         seed,
		AdminToken:       os.Getenv("ADMIN_TOKEN"),
		ASNLookupEnabled: asnEnabled,
		ASNLookupTimeout: asnTimeout,
	}, nil
}
