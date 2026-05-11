package api_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/lstepnio/NetworkQualityHWCBackend/internal/api"
	"github.com/lstepnio/NetworkQualityHWCBackend/internal/pii"
	"github.com/lstepnio/NetworkQualityHWCBackend/internal/store"
)

const (
	pilotPepper    = "test-pepper"
	testAdminToken = "test-admin-token"
	fixtureID      = "550e8400-e29b-41d4-a716-446655440000"
	fixtureDev     = "f47ac10b-58cc-4372-a567-0e02b2c3d479"
)

type certEnv struct {
	router  http.Handler
	configs *store.CertConfigStore
	certs   *store.CertificationsStore
}

func newCertEnv(t *testing.T) (*certEnv, func()) {
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
	certStore := store.NewCertificationsStore(pool)
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))

	// Seed the cert_config row matching the fixture's configVersion so the
	// FK on certifications.config_version is satisfied.
	cfgDoc, err := os.ReadFile(filepath.Join(root, "contract", "fixtures", "cert-config.example.json"))
	if err != nil {
		pool.Close()
		stopPG()
		t.Fatalf("read cert-config fixture: %v", err)
	}
	if err := cfgStore.Insert(context.Background(), "2026-05-06.1", 1, cfgDoc); err != nil {
		pool.Close()
		stopPG()
		t.Fatalf("seed cert_config: %v", err)
	}
	if err := cfgStore.Activate(context.Background(), "2026-05-06.1"); err != nil {
		pool.Close()
		stopPG()
		t.Fatalf("activate cert_config: %v", err)
	}

	router := api.NewRouter(api.Deps{
		Logger:         logger,
		CertConfigs:    cfgStore,
		Certifications: certStore,
		AppVersions:    store.NewAppVersionStore(pool),
		PII:            pii.NewHasher(pilotPepper),
		AdminToken:     testAdminToken,
	})
	return &certEnv{router: router, configs: cfgStore, certs: certStore}, func() {
		pool.Close()
		stopPG()
	}
}

func (e *certEnv) post(body []byte, extraHeaders map[string]string) *http.Response {
	r := httptest.NewRequest(http.MethodPost, "/v1/certifications", bytes.NewReader(body))
	for k, v := range defaultHeaders() {
		r.Header.Set(k, v)
	}
	r.Header.Set("Content-Type", "application/json")
	for k, v := range extraHeaders {
		r.Header.Set(k, v)
	}
	w := httptest.NewRecorder()
	e.router.ServeHTTP(w, r)
	return w.Result()
}

func (e *certEnv) getByID(id string) *http.Response {
	r := httptest.NewRequest(http.MethodGet, "/v1/certifications/"+id, nil)
	for k, v := range defaultHeaders() {
		r.Header.Set(k, v)
	}
	w := httptest.NewRecorder()
	e.router.ServeHTTP(w, r)
	return w.Result()
}

func loadCertFixture(t *testing.T) map[string]any {
	t.Helper()
	path := filepath.Join(repoRoot(t), "contract", "fixtures", "certification.example.json")
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}
	var m map[string]any
	if err := json.Unmarshal(b, &m); err != nil {
		t.Fatalf("fixture parse: %v", err)
	}
	return m
}

func mustMarshal(t *testing.T, v any) []byte {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	return b
}

// SPEC §8 case 3: first POST → 201, row inserted
func TestPostCertification_FirstTime(t *testing.T) {
	env, cleanup := newCertEnv(t)
	defer cleanup()

	body := mustMarshal(t, loadCertFixture(t))
	resp := env.post(body, nil)
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusCreated {
		got, _ := io.ReadAll(resp.Body)
		t.Fatalf("status: got %d (%s), want 201", resp.StatusCode, string(got))
	}
	cert, err := env.certs.Get(context.Background(), fixtureID)
	if err != nil {
		t.Fatalf("expected stored row: %v", err)
	}
	if cert.AchievedTier != "hd" {
		t.Errorf("achieved_tier: got %q, want hd", cert.AchievedTier)
	}
	if cert.Transport != "WIFI" {
		t.Errorf("transport: got %q, want WIFI", cert.Transport)
	}
}

// SPEC §8 case 4: byte-identical re-POST → 200, no second row
func TestPostCertification_ExactDuplicate(t *testing.T) {
	env, cleanup := newCertEnv(t)
	defer cleanup()

	body := mustMarshal(t, loadCertFixture(t))
	first := env.post(body, nil)
	first.Body.Close()
	if first.StatusCode != http.StatusCreated {
		t.Fatalf("first POST: got %d, want 201", first.StatusCode)
	}

	dup := env.post(body, nil)
	defer dup.Body.Close()
	if dup.StatusCode != http.StatusOK {
		got, _ := io.ReadAll(dup.Body)
		t.Fatalf("dup POST: got %d (%s), want 200", dup.StatusCode, string(got))
	}
}

// SPEC §8 case 5: same id, different payload → 409
func TestPostCertification_HashConflict(t *testing.T) {
	env, cleanup := newCertEnv(t)
	defer cleanup()

	original := loadCertFixture(t)
	first := env.post(mustMarshal(t, original), nil)
	first.Body.Close()

	// Mutate a content field whose change is invisible to cross-field
	// validation but flips the payload hash — same certificationId, different
	// body bytes, server should detect via payload_hash mismatch.
	mutated := loadCertFixture(t)
	mutated["metrics"].(map[string]any)["download"].(map[string]any)["steadyMbps"] = 999.9
	resp := env.post(mustMarshal(t, mutated), nil)
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusConflict {
		got, _ := io.ReadAll(resp.Body)
		t.Fatalf("status: got %d (%s), want 409", resp.StatusCode, string(got))
	}
}

// SPEC §8 case 6: wifi == null on Ethernet validates fine
func TestPostCertification_EthernetNullWifi(t *testing.T) {
	env, cleanup := newCertEnv(t)
	defer cleanup()

	fix := loadCertFixture(t)
	fix["certificationId"] = "660e8400-e29b-41d4-a716-446655440000"
	netMap := fix["network"].(map[string]any)
	netMap["transport"] = "ETHERNET"
	fix["wifi"] = nil

	resp := env.post(mustMarshal(t, fix), nil)
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusCreated {
		got, _ := io.ReadAll(resp.Body)
		t.Fatalf("status: got %d (%s), want 201", resp.StatusCode, string(got))
	}
}

// SPEC §8 case 7: payload > 256 KB → 413
func TestPostCertification_TooLarge(t *testing.T) {
	env, cleanup := newCertEnv(t)
	defer cleanup()

	fix := loadCertFixture(t)
	// Pad with a very long ssid string (this field gets PII-hashed but the
	// 413 fires before the body is parsed).
	wifi := fix["wifi"].(map[string]any)
	wifi["ssid"] = strings.Repeat("A", 300_000)

	resp := env.post(mustMarshal(t, fix), nil)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusRequestEntityTooLarge {
		t.Fatalf("status: got %d, want 413", resp.StatusCode)
	}
}

// SPEC §8 case 8: GET by id returns the stored record
func TestGetCertification_ByID(t *testing.T) {
	env, cleanup := newCertEnv(t)
	defer cleanup()

	body := mustMarshal(t, loadCertFixture(t))
	post := env.post(body, nil)
	post.Body.Close()
	if post.StatusCode != http.StatusCreated {
		t.Fatalf("setup POST: got %d", post.StatusCode)
	}

	resp := env.getByID(fixtureID)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status: got %d, want 200", resp.StatusCode)
	}
	got, _ := io.ReadAll(resp.Body)
	var parsed map[string]any
	if err := json.Unmarshal(got, &parsed); err != nil {
		t.Fatalf("body json: %v", err)
	}
	if parsed["certificationId"] != fixtureID {
		t.Errorf("certificationId: got %v, want %s", parsed["certificationId"], fixtureID)
	}
	if parsed["deviceId"] != fixtureDev {
		t.Errorf("deviceId: got %v, want %s", parsed["deviceId"], fixtureDev)
	}
}

// SPEC §8 case 8 negative: unknown id → 404
func TestGetCertification_NotFound(t *testing.T) {
	env, cleanup := newCertEnv(t)
	defer cleanup()
	resp := env.getByID("11111111-2222-3333-4444-555555555555")
	resp.Body.Close()
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("status: got %d, want 404", resp.StatusCode)
	}
}

// PII redaction lands in the stored payload AND the hot-path columns.
// HSN is intentionally exempt — it's the join key to the account system
// per the May 2026 policy update. Everything else stays hashed.
func TestPostCertification_PIIRedacted(t *testing.T) {
	env, cleanup := newCertEnv(t)
	defer cleanup()

	fix := loadCertFixture(t)
	identity := fix["identity"].(map[string]any)
	identity["hsn"] = "RAW_HSN_12345"
	identity["ethernetMac"] = "aa:bb:cc:dd:ee:ff"
	identity["wifiMac"] = "11:22:33:44:55:66"
	netMap := fix["network"].(map[string]any)
	netMap["publicIp"] = "203.0.113.5"
	netMap["gatewayIp"] = "192.168.10.1"
	wifi := fix["wifi"].(map[string]any)
	wifi["ssid"] = "MyHomeNetwork"
	wifi["bssid"] = "AA:BB:CC:11:22:33"

	resp := env.post(mustMarshal(t, fix), nil)
	resp.Body.Close()

	cert, err := env.certs.Get(context.Background(), fixtureID)
	if err != nil {
		t.Fatalf("get: %v", err)
	}

	hasher := pii.NewHasher(pilotPepper)

	// HSN is now PLAIN TEXT in both the column and the JSONB payload.
	if cert.HSN == nil || *cert.HSN != "RAW_HSN_12345" {
		t.Errorf("hsn column: got %v, want plain RAW_HSN_12345", cert.HSN)
	}
	// publicIp on the column is the hashed value (separate hot-path field
	// for searches; admin API hashes the query input before comparison).
	if cert.PublicIP == nil || *cert.PublicIP != hasher.Hash("203.0.113.5") {
		t.Errorf("public_ip column: got %v, want hash of 203.0.113.5", cert.PublicIP)
	}

	var stored map[string]any
	if err := json.Unmarshal(cert.Payload, &stored); err != nil {
		t.Fatalf("stored payload parse: %v", err)
	}
	storedIdentity := stored["identity"].(map[string]any)
	if storedIdentity["hsn"] != "RAW_HSN_12345" {
		t.Errorf("payload.identity.hsn: got %v, want plain RAW_HSN_12345", storedIdentity["hsn"])
	}
	if storedIdentity["ethernetMac"] != hasher.Hash("aa:bb:cc:dd:ee:ff") {
		t.Errorf("payload.identity.ethernetMac not hashed: %v", storedIdentity["ethernetMac"])
	}
	storedNet := stored["network"].(map[string]any)
	if storedNet["publicIp"] != hasher.Hash("203.0.113.5") {
		t.Errorf("payload.network.publicIp not hashed: %v", storedNet["publicIp"])
	}
	if storedNet["gatewayIp"] != hasher.Hash("192.168.10.1") {
		t.Errorf("payload.network.gatewayIp not hashed: %v", storedNet["gatewayIp"])
	}
	storedWifi := stored["wifi"].(map[string]any)
	if storedWifi["ssid"] != hasher.Hash("MyHomeNetwork") {
		t.Errorf("payload.wifi.ssid not hashed: %v", storedWifi["ssid"])
	}
	if storedWifi["bssid"] != hasher.Hash("AA:BB:CC:11:22:33") {
		t.Errorf("payload.wifi.bssid not hashed: %v", storedWifi["bssid"])
	}

	// Sanity: payload_hash on the row equals sha256 of the original body bytes.
	body := mustMarshal(t, fix)
	expected := sha256.Sum256(body)
	if cert.PayloadHash != hex.EncodeToString(expected[:]) {
		t.Errorf("payload_hash mismatch: got %s, want %s", cert.PayloadHash, hex.EncodeToString(expected[:]))
	}
}

// SPEC §8 case 9: malformed Authorization on POST → 401 (permissive mode
// still rejects non-Bearer schemes so client plumbing bugs are visible).
func TestPostCertification_NonBearerAuth_Rejected(t *testing.T) {
	env, cleanup := newCertEnv(t)
	defer cleanup()
	body := mustMarshal(t, loadCertFixture(t))
	resp := env.post(body, map[string]string{"Authorization": "Basic dXNlcjpwYXNz"})
	resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("status: got %d, want 401", resp.StatusCode)
	}
}

// Regression: POST with a configVersion the server has never seen still
// succeeds. Prior to migration 0002 the FK on certifications.config_version
// rejected anything not already in cert_config, so a fresh-from-bundled
// client (configVersion = "local-defaults") would 500 forever.
func TestPostCertification_UnknownConfigVersion(t *testing.T) {
	env, cleanup := newCertEnv(t)
	defer cleanup()

	fix := loadCertFixture(t)
	fix["configVersion"] = "never-seeded-by-server"
	fix["certificationId"] = "770e8400-e29b-41d4-a716-446655440000"

	resp := env.post(mustMarshal(t, fix), nil)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusCreated {
		got, _ := io.ReadAll(resp.Body)
		t.Fatalf("status: got %d (%s), want 201", resp.StatusCode, string(got))
	}

	cert, err := env.certs.Get(context.Background(), "770e8400-e29b-41d4-a716-446655440000")
	if err != nil {
		t.Fatalf("expected stored row: %v", err)
	}
	if cert.ConfigVersion == nil || *cert.ConfigVersion != "never-seeded-by-server" {
		t.Errorf("config_version: got %v, want never-seeded-by-server", cert.ConfigVersion)
	}
}

// Contract v1.1.0 timestamps round-trip when the client supplies them.
func TestPostCertification_QueueTimestamps_RoundTrip(t *testing.T) {
	env, cleanup := newCertEnv(t)
	defer cleanup()

	fix := loadCertFixture(t)
	// completedAt is already in the fixture; submittedAt is 2 seconds later
	// (fresh-publish case — no queue delay).
	completed := "2026-05-06T18:37:46Z"
	fix["completedAt"] = completed
	fix["enqueuedAt"] = "2026-05-06T18:37:46Z"
	fix["submittedAt"] = "2026-05-06T18:37:48Z"
	resp := env.post(mustMarshal(t, fix), nil)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusCreated {
		got, _ := io.ReadAll(resp.Body)
		t.Fatalf("status: got %d (%s), want 201", resp.StatusCode, string(got))
	}

	cert, err := env.certs.Get(context.Background(), fixtureID)
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if cert.EnqueuedAt == nil || cert.SubmittedAt == nil {
		t.Fatalf("expected both queue timestamps populated; got enqueued=%v submitted=%v",
			cert.EnqueuedAt, cert.SubmittedAt)
	}
	delay := int64(cert.SubmittedAt.Sub(cert.CompletedAt).Seconds())
	if delay < 0 || delay > 3 {
		t.Errorf("queue delay: got %ds, want ~2s", delay)
	}
}

// Older clients (no enqueuedAt/submittedAt) ingest cleanly with NULLs.
func TestPostCertification_OlderClient_NoQueueTimestamps(t *testing.T) {
	env, cleanup := newCertEnv(t)
	defer cleanup()

	fix := loadCertFixture(t)
	delete(fix, "enqueuedAt")
	delete(fix, "submittedAt")
	resp := env.post(mustMarshal(t, fix), nil)
	resp.Body.Close()
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("status: got %d, want 201", resp.StatusCode)
	}
	cert, _ := env.certs.Get(context.Background(), fixtureID)
	if cert.EnqueuedAt != nil || cert.SubmittedAt != nil {
		t.Errorf("older-client row should carry null timestamps; got enqueued=%v submitted=%v",
			cert.EnqueuedAt, cert.SubmittedAt)
	}
}

// Each of the four validation rules rejects with the named path.
func TestPostCertification_QueueTimestampValidation(t *testing.T) {
	cases := []struct {
		name string
		mut  func(map[string]any)
		rule string
	}{
		{
			name: "completedAt < startedAt",
			mut: func(m map[string]any) {
				m["startedAt"] = "2026-05-06T18:37:46Z"
				m["completedAt"] = "2026-05-06T18:36:48Z"
			},
			rule: "completedAt_after_startedAt",
		},
		{
			name: "submittedAt too far before completedAt",
			mut: func(m map[string]any) {
				m["completedAt"] = "2026-05-06T18:37:46Z"
				m["submittedAt"] = "2026-05-06T18:00:00Z"
			},
			rule: "submittedAt_near_completedAt",
		},
		{
			name: "enqueuedAt too far before completedAt",
			mut: func(m map[string]any) {
				m["completedAt"] = "2026-05-06T18:37:46Z"
				m["enqueuedAt"] = "2026-05-06T18:00:00Z"
			},
			rule: "enqueuedAt_near_completedAt",
		},
		{
			name: "submittedAt from the future",
			mut: func(m map[string]any) {
				m["submittedAt"] = "2099-01-01T00:00:00Z"
			},
			rule: "submittedAt_before_receivedAt",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			env, cleanup := newCertEnv(t)
			defer cleanup()
			fix := loadCertFixture(t)
			tc.mut(fix)
			resp := env.post(mustMarshal(t, fix), nil)
			defer resp.Body.Close()
			if resp.StatusCode != http.StatusBadRequest {
				got, _ := io.ReadAll(resp.Body)
				t.Fatalf("status: got %d (%s), want 400", resp.StatusCode, string(got))
			}
			body, _ := io.ReadAll(resp.Body)
			if !strings.Contains(string(body), tc.rule) {
				t.Errorf("error body should name rule %q; got: %s", tc.rule, string(body))
			}
		})
	}
}

// Validation error on missing required field → 400 with details.
func TestPostCertification_MissingCertID(t *testing.T) {
	env, cleanup := newCertEnv(t)
	defer cleanup()
	fix := loadCertFixture(t)
	delete(fix, "certificationId")
	resp := env.post(mustMarshal(t, fix), nil)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("status: got %d, want 400", resp.StatusCode)
	}
	got, _ := io.ReadAll(resp.Body)
	if !strings.Contains(string(got), "certificationId") {
		t.Errorf("error body should mention certificationId: %s", string(got))
	}
}
