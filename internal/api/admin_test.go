package api_test

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"

	"github.com/lstepnio/NetworkQualityHWCBackend/internal/api"
	"github.com/lstepnio/NetworkQualityHWCBackend/internal/pii"
	"github.com/lstepnio/NetworkQualityHWCBackend/internal/store"
)

func newAdminEnv(t *testing.T) (*certEnv, func()) {
	t.Helper()
	return newCertEnv(t)
}

func adminGet(t *testing.T, router http.Handler, path, token string) *http.Response {
	t.Helper()
	r := httptest.NewRequest(http.MethodGet, path, nil)
	if token != "" {
		r.Header.Set("Authorization", "Bearer "+token)
	}
	w := httptest.NewRecorder()
	router.ServeHTTP(w, r)
	return w.Result()
}

func TestAdmin_Unauthenticated(t *testing.T) {
	env, cleanup := newAdminEnv(t)
	defer cleanup()
	for _, path := range []string{"/admin/certifications", "/admin/cert-configs", "/admin/certifications/" + fixtureID, "/admin/cert-configs/2026-05-06.1"} {
		resp := adminGet(t, env.router, path, "")
		resp.Body.Close()
		if resp.StatusCode != http.StatusUnauthorized {
			t.Errorf("%s without token: got %d, want 401", path, resp.StatusCode)
		}
	}
}

func TestAdmin_WrongToken(t *testing.T) {
	env, cleanup := newAdminEnv(t)
	defer cleanup()
	resp := adminGet(t, env.router, "/admin/certifications", "wrong-token")
	resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("got %d, want 401", resp.StatusCode)
	}
}

func TestAdmin_DisabledWhenTokenEmpty(t *testing.T) {
	t.Helper()
	dsn, stopPG := startPostgres(t)
	defer stopPG()
	root := repoRoot(t)
	if err := store.RunMigrations(filepath.Join(root, "db", "migrations"), dsn); err != nil {
		t.Fatalf("migrations: %v", err)
	}
	pool, err := store.NewPool(context.Background(), dsn)
	if err != nil {
		t.Fatalf("pool: %v", err)
	}
	defer pool.Close()
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	router := api.NewRouter(api.Deps{
		Logger:         logger,
		CertConfigs:    store.NewCertConfigStore(pool),
		Certifications: store.NewCertificationsStore(pool),
		PII:            pii.NewHasher(pilotPepper),
		AdminToken:     "", // explicit: admin disabled
	})
	resp := adminGet(t, router, "/admin/certifications", "anything")
	resp.Body.Close()
	if resp.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("got %d, want 503 (admin disabled)", resp.StatusCode)
	}
}

func TestAdmin_ListCertifications_Empty(t *testing.T) {
	env, cleanup := newAdminEnv(t)
	defer cleanup()
	resp := adminGet(t, env.router, "/admin/certifications", testAdminToken)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("got %d, want 200", resp.StatusCode)
	}
	var body struct {
		Items  []map[string]any `json:"items"`
		Total  int              `json:"total"`
		Limit  int              `json:"limit"`
		Offset int              `json:"offset"`
	}
	dec(t, resp, &body)
	if body.Total != 0 {
		t.Errorf("total: got %d, want 0", body.Total)
	}
	if body.Items == nil {
		t.Error("items must be [] not null on empty list")
	}
}

func TestAdmin_ListCertifications_Pagination(t *testing.T) {
	env, cleanup := newAdminEnv(t)
	defer cleanup()
	// Seed 3 certs by POSTing variations of the fixture.
	for i := 0; i < 3; i++ {
		fix := loadCertFixture(t)
		fix["certificationId"] = []string{
			"11111111-1111-1111-1111-111111111111",
			"22222222-2222-2222-2222-222222222222",
			"33333333-3333-3333-3333-333333333333",
		}[i]
		body, _ := json.Marshal(fix)
		r := httptest.NewRequest(http.MethodPost, "/v1/certifications", bytes.NewReader(body))
		for k, v := range defaultHeaders() {
			r.Header.Set(k, v)
		}
		r.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		env.router.ServeHTTP(w, r)
		if w.Code != http.StatusCreated {
			t.Fatalf("seed POST %d: got %d", i, w.Code)
		}
	}

	resp := adminGet(t, env.router, "/admin/certifications?limit=2", testAdminToken)
	defer resp.Body.Close()
	var body struct {
		Items  []map[string]any `json:"items"`
		Total  int              `json:"total"`
		Limit  int              `json:"limit"`
		Offset int              `json:"offset"`
	}
	dec(t, resp, &body)
	if body.Total != 3 {
		t.Errorf("total: got %d, want 3", body.Total)
	}
	if len(body.Items) != 2 {
		t.Errorf("items: got %d, want 2 (limit honored)", len(body.Items))
	}
	if body.Limit != 2 {
		t.Errorf("limit echo: got %d, want 2", body.Limit)
	}
}

func TestAdmin_ListCertifications_FilterByTier(t *testing.T) {
	env, cleanup := newAdminEnv(t)
	defer cleanup()
	fix := loadCertFixture(t)
	body, _ := json.Marshal(fix)
	r := httptest.NewRequest(http.MethodPost, "/v1/certifications", bytes.NewReader(body))
	for k, v := range defaultHeaders() {
		r.Header.Set(k, v)
	}
	r.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	env.router.ServeHTTP(w, r)
	if w.Code != http.StatusCreated {
		t.Fatalf("seed POST: got %d", w.Code)
	}

	// Fixture's achieved_tier is "hd" — filter to "hd" returns 1, "uhd" returns 0.
	hd := adminGet(t, env.router, "/admin/certifications?tier=hd", testAdminToken)
	var hdBody struct{ Total int `json:"total"` }
	dec(t, hd, &hdBody)
	if hdBody.Total != 1 {
		t.Errorf("tier=hd: got %d, want 1", hdBody.Total)
	}

	uhd := adminGet(t, env.router, "/admin/certifications?tier=uhd", testAdminToken)
	var uhdBody struct{ Total int `json:"total"` }
	dec(t, uhd, &uhdBody)
	if uhdBody.Total != 0 {
		t.Errorf("tier=uhd: got %d, want 0", uhdBody.Total)
	}
}

func TestAdmin_GetCertification(t *testing.T) {
	env, cleanup := newAdminEnv(t)
	defer cleanup()
	fix := loadCertFixture(t)
	postBody, _ := json.Marshal(fix)
	r := httptest.NewRequest(http.MethodPost, "/v1/certifications", bytes.NewReader(postBody))
	for k, v := range defaultHeaders() {
		r.Header.Set(k, v)
	}
	r.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	env.router.ServeHTTP(w, r)

	resp := adminGet(t, env.router, "/admin/certifications/"+fixtureID, testAdminToken)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("got %d, want 200", resp.StatusCode)
	}
	var parsed struct {
		Summary     map[string]any `json:"summary"`
		PayloadHash string         `json:"payloadHash"`
		Payload     map[string]any `json:"payload"`
	}
	dec(t, resp, &parsed)
	if parsed.Summary["certificationId"] != fixtureID {
		t.Errorf("summary.certificationId: got %v", parsed.Summary["certificationId"])
	}
	if parsed.PayloadHash == "" {
		t.Error("payloadHash should be present")
	}
	if parsed.Payload["certificationId"] != fixtureID {
		t.Error("payload should round-trip the full record")
	}
}

func TestAdmin_GetCertification_NotFound(t *testing.T) {
	env, cleanup := newAdminEnv(t)
	defer cleanup()
	resp := adminGet(t, env.router, "/admin/certifications/00000000-0000-0000-0000-000000000000", testAdminToken)
	resp.Body.Close()
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("got %d, want 404", resp.StatusCode)
	}
}

func TestAdmin_ListCertConfigs(t *testing.T) {
	env, cleanup := newAdminEnv(t)
	defer cleanup()
	resp := adminGet(t, env.router, "/admin/cert-configs", testAdminToken)
	defer resp.Body.Close()
	var body struct {
		Items []map[string]any `json:"items"`
		Total int              `json:"total"`
	}
	dec(t, resp, &body)
	if body.Total < 1 {
		t.Errorf("expected at least the seeded config, got %d", body.Total)
	}
	if body.Items[0]["isActive"] != true {
		t.Errorf("first row should be active: %v", body.Items[0])
	}
	if _, ok := body.Items[0]["document"]; ok {
		t.Error("document should be omitted when includeDocument=true is not set")
	}
}

func TestAdmin_ListCertConfigs_IncludeDocument(t *testing.T) {
	env, cleanup := newAdminEnv(t)
	defer cleanup()
	resp := adminGet(t, env.router, "/admin/cert-configs?includeDocument=true", testAdminToken)
	defer resp.Body.Close()
	var body struct {
		Items []map[string]any `json:"items"`
	}
	dec(t, resp, &body)
	if len(body.Items) == 0 {
		t.Fatal("expected at least one config")
	}
	if _, ok := body.Items[0]["document"]; !ok {
		t.Error("document should be included with includeDocument=true")
	}
}

func TestAdmin_GetCertConfig(t *testing.T) {
	env, cleanup := newAdminEnv(t)
	defer cleanup()
	resp := adminGet(t, env.router, "/admin/cert-configs/2026-05-06.1", testAdminToken)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("got %d, want 200", resp.StatusCode)
	}
	var body map[string]any
	dec(t, resp, &body)
	if body["configVersion"] != "2026-05-06.1" {
		t.Errorf("configVersion: got %v", body["configVersion"])
	}
	if body["document"] == nil {
		t.Error("document should always be included for single fetch")
	}
}

func TestAdmin_GetCertConfig_NotFound(t *testing.T) {
	env, cleanup := newAdminEnv(t)
	defer cleanup()
	resp := adminGet(t, env.router, "/admin/cert-configs/never-existed", testAdminToken)
	resp.Body.Close()
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("got %d, want 404", resp.StatusCode)
	}
}

func adminPost(t *testing.T, router http.Handler, path, token string, body []byte) *http.Response {
	t.Helper()
	r := httptest.NewRequest(http.MethodPost, path, bytes.NewReader(body))
	if token != "" {
		r.Header.Set("Authorization", "Bearer "+token)
	}
	r.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	router.ServeHTTP(w, r)
	return w.Result()
}

func sampleConfigDoc(version string) []byte {
	doc := map[string]any{
		"schemaVersion": 1,
		"configVersion": version,
		"servers": []map[string]any{
			{"id": "dfw", "name": "Dallas", "host": "speedtestdfw.gethotwired.com", "port": 8080, "secure": true, "weight": 1.0},
		},
		"tests": map[string]any{
			"download": map[string]any{"durationSec": 10, "parallel": 4, "perRequestBytes": 100000000, "warmupFraction": 0.33},
			"upload":   map[string]any{"durationSec": 5, "parallel": 2, "perRequestBytes": 50000000, "warmupFraction": 0.33},
			"latency":  map[string]any{"samples": 10, "timeoutMs": 2000},
			"playback": map[string]any{"manifestUrl": "https://example.test/m.mpd", "durationSec": 20},
		},
		"tiers": []map[string]any{
			{"id": "sd", "displayName": "SD", "minDownloadMbps": 5, "minUploadMbps": 1, "maxLatencyMs": 200, "maxJitterMs": 50, "minPlaybackHeight": 480, "minPlaybackBitrateKbps": 1500},
		},
		"uploadResults": map[string]any{"enabled": true, "endpoint": "http://example.test/v1/certifications"},
	}
	b, _ := json.Marshal(doc)
	return b
}

func TestAdmin_CreateCertConfig_OK(t *testing.T) {
	env, cleanup := newAdminEnv(t)
	defer cleanup()

	body := sampleConfigDoc("2030-01-01.test.1")
	resp := adminPost(t, env.router, "/admin/cert-configs", testAdminToken, body)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusCreated {
		got, _ := io.ReadAll(resp.Body)
		t.Fatalf("status: got %d (%s), want 201", resp.StatusCode, string(got))
	}

	var parsed map[string]any
	dec(t, resp, &parsed)
	if parsed["configVersion"] != "2030-01-01.test.1" {
		t.Errorf("configVersion: got %v", parsed["configVersion"])
	}
	if parsed["isActive"] != false {
		t.Errorf("isActive: got %v, want false (must not auto-activate)", parsed["isActive"])
	}
}

func TestAdmin_CreateCertConfig_Conflict(t *testing.T) {
	env, cleanup := newAdminEnv(t)
	defer cleanup()
	body := sampleConfigDoc("2026-05-06.1") // collides with the seeded version
	resp := adminPost(t, env.router, "/admin/cert-configs", testAdminToken, body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusConflict {
		t.Fatalf("status: got %d, want 409", resp.StatusCode)
	}
}

func TestAdmin_CreateCertConfig_Validation(t *testing.T) {
	env, cleanup := newAdminEnv(t)
	defer cleanup()

	cases := []struct {
		name string
		mut  func(map[string]any)
	}{
		{"missing configVersion", func(m map[string]any) { delete(m, "configVersion") }},
		{"empty configVersion", func(m map[string]any) { m["configVersion"] = "" }},
		{"missing schemaVersion", func(m map[string]any) { delete(m, "schemaVersion") }},
		{"zero schemaVersion", func(m map[string]any) { m["schemaVersion"] = 0 }},
		{"empty servers", func(m map[string]any) { m["servers"] = []map[string]any{} }},
		{"empty tiers", func(m map[string]any) { m["tiers"] = []map[string]any{} }},
		{"missing tests", func(m map[string]any) { delete(m, "tests") }},
		{"missing uploadResults", func(m map[string]any) { delete(m, "uploadResults") }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var doc map[string]any
			_ = json.Unmarshal(sampleConfigDoc("2030-validation."+tc.name), &doc)
			tc.mut(doc)
			b, _ := json.Marshal(doc)
			resp := adminPost(t, env.router, "/admin/cert-configs", testAdminToken, b)
			resp.Body.Close()
			if resp.StatusCode != http.StatusBadRequest {
				t.Errorf("status: got %d, want 400", resp.StatusCode)
			}
		})
	}
}

func TestAdmin_CreateCertConfig_Unauthorized(t *testing.T) {
	env, cleanup := newAdminEnv(t)
	defer cleanup()
	resp := adminPost(t, env.router, "/admin/cert-configs", "", sampleConfigDoc("never.created"))
	resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("status: got %d, want 401", resp.StatusCode)
	}
}

func TestAdmin_ActivateCertConfig(t *testing.T) {
	env, cleanup := newAdminEnv(t)
	defer cleanup()

	// Create a draft
	body := sampleConfigDoc("2030-01-01.activate-test")
	resp := adminPost(t, env.router, "/admin/cert-configs", testAdminToken, body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("create draft: got %d", resp.StatusCode)
	}

	// Activate it
	act := adminPost(t, env.router, "/admin/cert-configs/2030-01-01.activate-test/activate", testAdminToken, nil)
	defer act.Body.Close()
	if act.StatusCode != http.StatusOK {
		got, _ := io.ReadAll(act.Body)
		t.Fatalf("activate: got %d (%s)", act.StatusCode, string(got))
	}
	var parsed map[string]any
	dec(t, act, &parsed)
	if parsed["isActive"] != true {
		t.Errorf("isActive: got %v, want true", parsed["isActive"])
	}

	// Confirm the seeded one is no longer active (exactly one active row at a time)
	listResp := adminGet(t, env.router, "/admin/cert-configs", testAdminToken)
	defer listResp.Body.Close()
	var list struct {
		Items []map[string]any `json:"items"`
	}
	dec(t, listResp, &list)
	activeCount := 0
	for _, c := range list.Items {
		if c["isActive"] == true {
			activeCount++
		}
	}
	if activeCount != 1 {
		t.Errorf("active count: got %d, want 1 (after activate)", activeCount)
	}
}

func TestAdmin_ActivateCertConfig_NotFound(t *testing.T) {
	env, cleanup := newAdminEnv(t)
	defer cleanup()
	resp := adminPost(t, env.router, "/admin/cert-configs/never-existed/activate", testAdminToken, nil)
	resp.Body.Close()
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("status: got %d, want 404", resp.StatusCode)
	}
}

func dec(t *testing.T, resp *http.Response, v any) {
	t.Helper()
	body, _ := io.ReadAll(resp.Body)
	if err := json.Unmarshal(body, v); err != nil {
		t.Fatalf("decode: %v (body: %s)", err, string(body))
	}
}

