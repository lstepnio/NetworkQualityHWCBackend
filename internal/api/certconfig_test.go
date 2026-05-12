package api_test

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/lstepnio/NetworkQualityHWCBackend/internal/api"
	"github.com/lstepnio/NetworkQualityHWCBackend/internal/store"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/testcontainers/testcontainers-go"
	tcpostgres "github.com/testcontainers/testcontainers-go/modules/postgres"
	"github.com/testcontainers/testcontainers-go/wait"
)

// repoRoot returns the absolute path to the repo root, relative to this test file.
// internal/api/certconfig_test.go → ../.. is the root.
func repoRoot(t *testing.T) string {
	t.Helper()
	_, thisFile, _, _ := runtime.Caller(0)
	return filepath.Clean(filepath.Join(filepath.Dir(thisFile), "..", ".."))
}

func startPostgres(t *testing.T) (string, func()) {
	t.Helper()
	ctx := context.Background()
	pgC, err := tcpostgres.Run(ctx,
		"postgres:16-alpine",
		tcpostgres.WithDatabase("certifier"),
		tcpostgres.WithUsername("certifier"),
		tcpostgres.WithPassword("certifier"),
		testcontainers.WithWaitStrategy(
			wait.ForLog("database system is ready to accept connections").
				WithOccurrence(2).
				WithStartupTimeout(60*time.Second),
		),
	)
	if err != nil {
		t.Fatalf("postgres container: %v", err)
	}
	dsn, err := pgC.ConnectionString(ctx, "sslmode=disable")
	if err != nil {
		t.Fatalf("dsn: %v", err)
	}
	return dsn, func() { _ = pgC.Terminate(ctx) }
}

type testEnv struct {
	router http.Handler
	store  *store.CertConfigStore
	pool   *pgxpool.Pool
	dsn    string
}

func newTestEnv(t *testing.T) (*testEnv, func()) {
	t.Helper()
	dsn, stopPG := startPostgres(t)

	root := repoRoot(t)
	if err := store.RunMigrations(filepath.Join(root, "db", "migrations"), dsn); err != nil {
		stopPG()
		t.Fatalf("migrations: %v", err)
	}

	pool, err := store.NewPool(context.Background(), dsn)
	if err != nil {
		stopPG()
		t.Fatalf("pool: %v", err)
	}

	cfgStore := store.NewCertConfigStore(pool)
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	router := api.NewRouter(api.Deps{Logger: logger, CertConfigs: cfgStore})

	return &testEnv{
			router: router,
			store:  cfgStore,
			pool:   pool,
			dsn:    dsn,
		}, func() {
			pool.Close()
			stopPG()
		}
}

func (e *testEnv) seedActive(t *testing.T, configVersion string, schemaVersion int, doc string) {
	t.Helper()
	e.seedActiveWithTarget(t, configVersion, schemaVersion, doc, nil, nil, nil)
}

func (e *testEnv) seedActiveWithTarget(
	t *testing.T, configVersion string, schemaVersion int, doc string,
	manufacturer, model, fingerprint *string,
) {
	t.Helper()
	ctx := context.Background()
	if err := e.store.Insert(ctx, configVersion, schemaVersion, []byte(doc),
		manufacturer, model, fingerprint); err != nil {
		t.Fatalf("insert: %v", err)
	}
	if err := e.store.Activate(ctx, configVersion); err != nil {
		t.Fatalf("activate: %v", err)
	}
}

func strPtr(s string) *string { return &s }

func (e *testEnv) doGet(headers map[string]string) *http.Response {
	r := httptest.NewRequest(http.MethodGet, "/v1/cert-config", nil)
	for k, v := range headers {
		r.Header.Set(k, v)
	}
	w := httptest.NewRecorder()
	e.router.ServeHTTP(w, r)
	return w.Result()
}

func defaultHeaders() map[string]string {
	return map[string]string{
		"X-Device-Id":      "11111111-1111-1111-1111-111111111111",
		"X-App-Version":    "0.1.0",
		"X-Schema-Version": "1",
	}
}

func loadFixture(t *testing.T) string {
	t.Helper()
	root := repoRoot(t)
	b, err := os.ReadFile(filepath.Join(root, "contract", "fixtures", "cert-config.example.json"))
	if err != nil {
		t.Fatalf("fixture: %v", err)
	}
	return string(b)
}

// 1. happy path: 200 + valid CertConfig + ETag
func TestGetCertConfig_HappyPath(t *testing.T) {
	env, cleanup := newTestEnv(t)
	defer cleanup()

	doc := loadFixture(t)
	env.seedActive(t, "2026-05-07.dev.1", 1, doc)

	resp := env.doGet(defaultHeaders())
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		t.Fatalf("status: got %d, want 200", resp.StatusCode)
	}
	if etag := resp.Header.Get("ETag"); etag == "" || !strings.HasPrefix(etag, `"`) {
		t.Errorf("ETag header: got %q, want quoted hex", etag)
	}
	body, _ := io.ReadAll(resp.Body)
	var parsed map[string]any
	if err := json.Unmarshal(body, &parsed); err != nil {
		t.Fatalf("body json: %v", err)
	}
	if parsed["configVersion"] == nil {
		t.Errorf("body missing configVersion")
	}
	if v, ok := parsed["schemaVersion"].(float64); !ok || int(v) != 1 {
		t.Errorf("body schemaVersion: got %v, want 1", parsed["schemaVersion"])
	}
}

// 2. matching If-None-Match → 304 with no body
func TestGetCertConfig_IfNoneMatch_Match(t *testing.T) {
	env, cleanup := newTestEnv(t)
	defer cleanup()

	env.seedActive(t, "2026-05-07.dev.1", 1, loadFixture(t))

	first := env.doGet(defaultHeaders())
	etag := first.Header.Get("ETag")
	first.Body.Close()

	h := defaultHeaders()
	h["If-None-Match"] = etag
	resp := env.doGet(h)
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusNotModified {
		t.Fatalf("status: got %d, want 304", resp.StatusCode)
	}
	body, _ := io.ReadAll(resp.Body)
	if len(body) != 0 {
		t.Errorf("expected empty body on 304, got %d bytes", len(body))
	}
}

// 3. stale If-None-Match → 200 + new ETag
func TestGetCertConfig_IfNoneMatch_Stale(t *testing.T) {
	env, cleanup := newTestEnv(t)
	defer cleanup()

	env.seedActive(t, "2026-05-07.dev.1", 1, loadFixture(t))

	h := defaultHeaders()
	h["If-None-Match"] = `"deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef"`
	resp := env.doGet(h)
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status: got %d, want 200", resp.StatusCode)
	}
	if resp.Header.Get("ETag") == h["If-None-Match"] {
		t.Errorf("ETag header echoed stale value")
	}
}

// 4. malformed X-Schema-Version → 400
func TestGetCertConfig_BadSchemaHeader(t *testing.T) {
	env, cleanup := newTestEnv(t)
	defer cleanup()

	env.seedActive(t, "2026-05-07.dev.1", 1, loadFixture(t))

	for _, bad := range []string{"", "0", "abc", "-1"} {
		h := defaultHeaders()
		h["X-Schema-Version"] = bad
		resp := env.doGet(h)
		resp.Body.Close()
		if resp.StatusCode != http.StatusBadRequest {
			t.Errorf("X-Schema-Version=%q: got %d, want 400", bad, resp.StatusCode)
		}
	}
}

// 5. no active config → 503
func TestGetCertConfig_NoActiveRow(t *testing.T) {
	env, cleanup := newTestEnv(t)
	defer cleanup()

	resp := env.doGet(defaultHeaders())
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("status: got %d, want 503", resp.StatusCode)
	}
}

// 6. permissive auth: missing Authorization is OK
func TestGetCertConfig_NoAuthHeader_Allowed(t *testing.T) {
	env, cleanup := newTestEnv(t)
	defer cleanup()

	env.seedActive(t, "2026-05-07.dev.1", 1, loadFixture(t))

	resp := env.doGet(defaultHeaders())
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status: got %d, want 200 (permissive auth)", resp.StatusCode)
	}
}

// 6b. permissive auth: malformed Authorization (non-Bearer) → 401, so plumbing
// bugs in the client are still visible.
func TestGetCertConfig_NonBearerAuth_Rejected(t *testing.T) {
	env, cleanup := newTestEnv(t)
	defer cleanup()

	env.seedActive(t, "2026-05-07.dev.1", 1, loadFixture(t))

	h := defaultHeaders()
	h["Authorization"] = "Basic dXNlcjpwYXNz"
	resp := env.doGet(h)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("status: got %d, want 401", resp.StatusCode)
	}
}

// 7. Per-device targeting (contract v2.2.0). Seeds a default + a
// manufacturer-targeted row, then asserts each tier resolves correctly.
func TestGetCertConfig_TargetingResolution(t *testing.T) {
	env, cleanup := newTestEnv(t)
	defer cleanup()

	defaultDoc := loadFixture(t)
	// Same shape, different configVersion so we can tell them apart in the response.
	seiDoc := strings.Replace(defaultDoc, `"2026-05-06.1"`, `"2026-05-06.sei-target"`, 1)
	frcDoc := strings.Replace(defaultDoc, `"2026-05-06.1"`, `"2026-05-06.frc-target"`, 1)

	env.seedActive(t, "default-config", 1, defaultDoc)
	env.seedActiveWithTarget(t, "sei-config", 1, seiDoc, strPtr("SEI Robotics"), nil, nil)
	env.seedActiveWithTarget(t, "frc-config", 1, frcDoc, strPtr("SEI Robotics"), strPtr("FRC1-Hotwire"), nil)

	cases := []struct {
		name       string
		mfr, model string
		wantVer    string
	}{
		{"no headers → default", "", "", "2026-05-06.1"},
		{"unknown manufacturer → default", "Acme", "X1", "2026-05-06.1"},
		{"SEI Robotics manufacturer → SEI", "SEI Robotics", "", "2026-05-06.sei-target"},
		{"SEI Robotics + other model → SEI (manufacturer tier wins over default)", "SEI Robotics", "X1", "2026-05-06.sei-target"},
		{"SEI Robotics + FRC1-Hotwire → FRC (model tier wins over manufacturer)", "SEI Robotics", "FRC1-Hotwire", "2026-05-06.frc-target"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			h := defaultHeaders()
			if tc.mfr != "" {
				h["X-Device-Manufacturer"] = tc.mfr
			}
			if tc.model != "" {
				h["X-Device-Model"] = tc.model
			}
			resp := env.doGet(h)
			defer resp.Body.Close()
			if resp.StatusCode != 200 {
				t.Fatalf("status: got %d, want 200", resp.StatusCode)
			}
			body, _ := io.ReadAll(resp.Body)
			var parsed map[string]any
			if err := json.Unmarshal(body, &parsed); err != nil {
				t.Fatalf("body json: %v", err)
			}
			if got := parsed["configVersion"]; got != tc.wantVer {
				t.Errorf("configVersion: got %v, want %s", got, tc.wantVer)
			}
		})
	}
}

// 8. ETag varies per resolved config: an SEI device's ETag must NOT
// match a default device's ETag, even with the same If-None-Match.
func TestGetCertConfig_ETagPerResolvedConfig(t *testing.T) {
	env, cleanup := newTestEnv(t)
	defer cleanup()

	defaultDoc := loadFixture(t)
	seiDoc := strings.Replace(defaultDoc, `"2026-05-06.1"`, `"2026-05-06.sei"`, 1)
	env.seedActive(t, "default-config", 1, defaultDoc)
	env.seedActiveWithTarget(t, "sei-config", 1, seiDoc, strPtr("SEI Robotics"), nil, nil)

	defaultResp := env.doGet(defaultHeaders())
	defer defaultResp.Body.Close()
	defaultETag := defaultResp.Header.Get("ETag")

	h := defaultHeaders()
	h["X-Device-Manufacturer"] = "SEI Robotics"
	seiResp := env.doGet(h)
	defer seiResp.Body.Close()
	seiETag := seiResp.Header.Get("ETag")

	if defaultETag == "" || seiETag == "" {
		t.Fatalf("empty ETag(s): default=%q sei=%q", defaultETag, seiETag)
	}
	if defaultETag == seiETag {
		t.Fatalf("expected different ETags per resolved config; got identical %q", defaultETag)
	}

	// Replay the SEI device's ETag against the default endpoint — must NOT match.
	h2 := defaultHeaders()
	h2["If-None-Match"] = seiETag
	resp := env.doGet(h2)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("spurious 304 across resolved configs: got %d, want 200", resp.StatusCode)
	}
}

// 9. Activation is per-target-group: activating a new SEI config
// deactivates the previous SEI row but leaves the default active.
func TestGetCertConfig_ActivateScopedToTargetGroup(t *testing.T) {
	env, cleanup := newTestEnv(t)
	defer cleanup()

	defaultDoc := loadFixture(t)
	sei1Doc := strings.Replace(defaultDoc, `"2026-05-06.1"`, `"sei-v1"`, 1)
	sei2Doc := strings.Replace(defaultDoc, `"2026-05-06.1"`, `"sei-v2"`, 1)

	env.seedActive(t, "default-config", 1, defaultDoc)
	env.seedActiveWithTarget(t, "sei-v1-config", 1, sei1Doc, strPtr("SEI Robotics"), nil, nil)
	env.seedActiveWithTarget(t, "sei-v2-config", 1, sei2Doc, strPtr("SEI Robotics"), nil, nil)

	// Default device still gets the default — activate sei-v2 did NOT deactivate it.
	resp := env.doGet(defaultHeaders())
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	var p map[string]any
	_ = json.Unmarshal(body, &p)
	if p["configVersion"] != "2026-05-06.1" {
		t.Errorf("default device after SEI re-activation: got %v, want 2026-05-06.1", p["configVersion"])
	}

	// SEI device gets sei-v2 (the most recently activated SEI row).
	h := defaultHeaders()
	h["X-Device-Manufacturer"] = "SEI Robotics"
	resp2 := env.doGet(h)
	defer resp2.Body.Close()
	body2, _ := io.ReadAll(resp2.Body)
	var p2 map[string]any
	_ = json.Unmarshal(body2, &p2)
	if p2["configVersion"] != "sei-v2" {
		t.Errorf("SEI device after sei-v2 activation: got %v, want sei-v2", p2["configVersion"])
	}
}
