package config

import (
	"fmt"
	"os"
)

type Env struct {
	DatabaseURL    string
	HTTPAddr       string
	PIIPepper      string
	MigrationsPath string
	DevSeed        bool
	SeedPath       string
	AdminToken     string
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
	return Env{
		DatabaseURL:    dbURL,
		HTTPAddr:       addr,
		PIIPepper:      pepper,
		MigrationsPath: mig,
		DevSeed:        os.Getenv("DEV_SEED") == "1",
		SeedPath:       seed,
		AdminToken:     os.Getenv("ADMIN_TOKEN"),
	}, nil
}
