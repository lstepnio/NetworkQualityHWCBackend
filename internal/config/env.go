package config

import (
	"fmt"
	"os"
)

// Default values for the developer-facing knobs. These exist so a freshly
// cloned repo with `make dev` works without per-developer setup, but they
// are NEVER acceptable in a production deployment — anyone who reads the
// repo knows them. The Load() function refuses to boot if any of them are
// still in effect when APP_ENV is not "dev".
const (
	devAdminTokenDefault = "dev-admin-token-change-me"
	devPIIPepperDefault  = "dev-pepper-change-me"
)

type Env struct {
	AppEnv         string // "dev" | anything-else — gates the dev-default checks
	DatabaseURL    string
	HTTPAddr       string
	PIIPepper      string
	MigrationsPath string
	DevSeed        bool
	SeedPath       string
	AdminToken     string
}

// IsDev reports whether we're running in the developer-mode configuration
// (i.e. dev defaults for AdminToken / PIIPepper are tolerated). Anything
// other than "dev" is treated as production-shaped and triggers the
// fail-fast checks in Load().
func (e Env) IsDev() bool { return e.AppEnv == "dev" }

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
		pepper = devPIIPepperDefault
	}
	mig := os.Getenv("MIGRATIONS_PATH")
	if mig == "" {
		mig = "db/migrations"
	}
	seed := os.Getenv("SEED_PATH")
	if seed == "" {
		seed = "db/seed/cert-config.json"
	}
	// APP_ENV defaults to "dev" so a freshly-cloned repo runs `make dev`
	// without an extra env-var dance. The production deploy ritual MUST
	// set APP_ENV explicitly to something other than "dev" — that's the
	// hard gate against the dev defaults below.
	appEnv := os.Getenv("APP_ENV")
	if appEnv == "" {
		appEnv = "dev"
	}
	env := Env{
		AppEnv:         appEnv,
		DatabaseURL:    dbURL,
		HTTPAddr:       addr,
		PIIPepper:      pepper,
		MigrationsPath: mig,
		DevSeed:        os.Getenv("DEV_SEED") == "1",
		SeedPath:       seed,
		AdminToken:     os.Getenv("ADMIN_TOKEN"),
	}
	if err := env.validateProductionSafety(); err != nil {
		return Env{}, err
	}
	return env, nil
}

// validateProductionSafety refuses to boot when running outside dev mode
// with any dev-only default still in effect. These are values anyone who
// reads the public repo knows; keeping them out of production deploys is
// the cheapest realistic guardrail.
//
// In dev mode this is a no-op — the whole point of the dev defaults is to
// let `make dev` work without per-developer setup.
func (e Env) validateProductionSafety() error {
	if e.IsDev() {
		return nil
	}
	if e.AdminToken == devAdminTokenDefault {
		return fmt.Errorf("refusing to boot: ADMIN_TOKEN is set to the dev default %q while APP_ENV=%q; set a real token", devAdminTokenDefault, e.AppEnv)
	}
	if e.PIIPepper == devPIIPepperDefault {
		return fmt.Errorf("refusing to boot: PII_PEPPER is set to the dev default %q while APP_ENV=%q; set a real pepper", devPIIPepperDefault, e.AppEnv)
	}
	return nil
}
