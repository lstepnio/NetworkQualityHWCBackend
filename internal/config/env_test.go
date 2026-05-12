package config

import (
	"strings"
	"testing"
)

// setenv is a tiny helper because t.Setenv restores on test cleanup but
// we want to set a small batch atomically per test case.
func setenv(t *testing.T, kv map[string]string) {
	t.Helper()
	for k, v := range kv {
		t.Setenv(k, v)
	}
}

func TestLoad_DevModeAcceptsDevDefaults(t *testing.T) {
	setenv(t, map[string]string{
		"DATABASE_URL": "postgres://x/y",
		"APP_ENV":      "dev",
		"ADMIN_TOKEN":  devAdminTokenDefault,
		"PII_PEPPER":   devPIIPepperDefault,
	})
	env, err := Load()
	if err != nil {
		t.Fatalf("dev mode should tolerate dev defaults, got error: %v", err)
	}
	if !env.IsDev() {
		t.Errorf("env.IsDev() = false, want true")
	}
}

func TestLoad_DevModeIsTheDefault(t *testing.T) {
	// No APP_ENV set → default to dev → dev defaults tolerated.
	setenv(t, map[string]string{
		"DATABASE_URL": "postgres://x/y",
		"ADMIN_TOKEN":  devAdminTokenDefault,
	})
	env, err := Load()
	if err != nil {
		t.Fatalf("unset APP_ENV should default to dev, got error: %v", err)
	}
	if env.AppEnv != "dev" {
		t.Errorf("AppEnv = %q, want %q", env.AppEnv, "dev")
	}
}

func TestLoad_ProdRejectsDefaultAdminToken(t *testing.T) {
	setenv(t, map[string]string{
		"DATABASE_URL": "postgres://x/y",
		"APP_ENV":      "prod",
		"ADMIN_TOKEN":  devAdminTokenDefault,
		"PII_PEPPER":   "a-real-pepper",
	})
	_, err := Load()
	if err == nil {
		t.Fatal("expected Load() to refuse boot with dev ADMIN_TOKEN in prod, got nil")
	}
	if !strings.Contains(err.Error(), "ADMIN_TOKEN") {
		t.Errorf("error should mention ADMIN_TOKEN, got: %v", err)
	}
}

func TestLoad_ProdRejectsDefaultPIIPepper(t *testing.T) {
	setenv(t, map[string]string{
		"DATABASE_URL": "postgres://x/y",
		"APP_ENV":      "prod",
		"ADMIN_TOKEN":  "a-real-admin-token",
		// PII_PEPPER unset → falls back to devPIIPepperDefault inside Load()
	})
	_, err := Load()
	if err == nil {
		t.Fatal("expected Load() to refuse boot with default PII_PEPPER in prod, got nil")
	}
	if !strings.Contains(err.Error(), "PII_PEPPER") {
		t.Errorf("error should mention PII_PEPPER, got: %v", err)
	}
}

func TestLoad_ProdAcceptsRealValues(t *testing.T) {
	setenv(t, map[string]string{
		"DATABASE_URL": "postgres://x/y",
		"APP_ENV":      "prod",
		"ADMIN_TOKEN":  "a-real-admin-token",
		"PII_PEPPER":   "a-real-pepper",
	})
	env, err := Load()
	if err != nil {
		t.Fatalf("prod with real values should load cleanly, got: %v", err)
	}
	if env.IsDev() {
		t.Errorf("APP_ENV=prod should give IsDev()=false")
	}
}

func TestLoad_AnyNonDevAppEnvIsTreatedAsProd(t *testing.T) {
	// Defensive: an operator might use APP_ENV=staging, APP_ENV=preview,
	// APP_ENV=production, etc. None of these should tolerate the dev
	// defaults — "dev" is the *only* lax mode.
	for _, label := range []string{"prod", "production", "staging", "preview", "qa"} {
		t.Run(label, func(t *testing.T) {
			setenv(t, map[string]string{
				"DATABASE_URL": "postgres://x/y",
				"APP_ENV":      label,
				"ADMIN_TOKEN":  devAdminTokenDefault,
				"PII_PEPPER":   "a-real-pepper",
			})
			if _, err := Load(); err == nil {
				t.Fatalf("APP_ENV=%q with dev token should fail-fast", label)
			}
		})
	}
}
