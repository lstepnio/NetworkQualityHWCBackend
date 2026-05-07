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
	ctx := context.Background()
	if err := e.store.Insert(ctx, configVersion, schemaVersion, []byte(doc)); err != nil {
		t.Fatalf("insert: %v", err)
	}
	if err := e.store.Activate(ctx, configVersion); err != nil {
		t.Fatalf("activate: %v", err)
	}
}

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
