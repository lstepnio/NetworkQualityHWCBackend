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
	"time"

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
		AppVersions:    store.NewAppVersionStore(pool),
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

func TestAdmin_ListCertifications_FilterByHSN(t *testing.T) {
	env, cleanup := newAdminEnv(t)
	defer cleanup()

	// Two POSTs with distinct HSNs.
	for i, hsn := range []string{"E44AW3251919440", "E44AW9999999999"} {
		fix := loadCertFixture(t)
		fix["certificationId"] = []string{
			"a0000001-0000-0000-0000-000000000001",
			"a0000002-0000-0000-0000-000000000002",
		}[i]
		fix["identity"].(map[string]any)["hsn"] = hsn
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

	resp := adminGet(t, env.router, "/admin/certifications?hsn=E44AW3251919440", testAdminToken)
	defer resp.Body.Close()
	var body struct {
		Items []map[string]any `json:"items"`
		Total int              `json:"total"`
	}
	dec(t, resp, &body)
	if body.Total != 1 {
		t.Errorf("total: got %d, want 1 (HSN filter)", body.Total)
	}
	if len(body.Items) > 0 && body.Items[0]["hsn"] != "E44AW3251919440" {
		t.Errorf("hsn echoed: got %v, want plain E44AW3251919440", body.Items[0]["hsn"])
	}
}

func TestAdmin_ListCertifications_WifiFieldsAndSort(t *testing.T) {
	env, cleanup := newAdminEnv(t)
	defer cleanup()

	// Two POSTs with different RSSI values so we can prove the sort
	// expression resolves and orders correctly.
	rssis := []int{-60, -80}
	for i, rssi := range rssis {
		fix := loadCertFixture(t)
		fix["certificationId"] = []string{
			"c0000001-0000-0000-0000-000000000001",
			"c0000002-0000-0000-0000-000000000002",
		}[i]
		result := fix["result"].(map[string]any)
		wifiLink := result["wifiLink"].(map[string]any)
		wifiLink["rssiDbm"] = rssi
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

	// Default (desc): strongest RSSI first (least negative).
	resp := adminGet(t, env.router, "/admin/certifications?sort=wifi", testAdminToken)
	defer resp.Body.Close()
	var body struct {
		Items []map[string]any `json:"items"`
	}
	dec(t, resp, &body)
	if len(body.Items) != 2 {
		t.Fatalf("items: got %d, want 2", len(body.Items))
	}
	if body.Items[0]["wifiRating"] != "STRONG" {
		t.Errorf("wifiRating: got %v, want STRONG (extracted from payload->result->wifiLink)", body.Items[0]["wifiRating"])
	}
	// json.Number-ish: float64 from generic map decoder.
	if got, want := body.Items[0]["wifiRssiDbm"].(float64), float64(-60); got != want {
		t.Errorf("desc sort: first rssi got %v, want %v", got, want)
	}
	if got, want := body.Items[1]["wifiRssiDbm"].(float64), float64(-80); got != want {
		t.Errorf("desc sort: second rssi got %v, want %v", got, want)
	}

	// asc: weakest RSSI first.
	resp2 := adminGet(t, env.router, "/admin/certifications?sort=wifi&dir=asc", testAdminToken)
	defer resp2.Body.Close()
	var body2 struct {
		Items []map[string]any `json:"items"`
	}
	dec(t, resp2, &body2)
	if got, want := body2.Items[0]["wifiRssiDbm"].(float64), float64(-80); got != want {
		t.Errorf("asc sort: first rssi got %v, want %v", got, want)
	}

	// Unknown sort key falls back to default ordering — must not 500
	// or expose a SQL error.
	resp3 := adminGet(t, env.router, "/admin/certifications?sort=DROP+TABLE", testAdminToken)
	defer resp3.Body.Close()
	if resp3.StatusCode != http.StatusOK {
		t.Errorf("unknown sort key: got %d, want 200 (defensive fallback)", resp3.StatusCode)
	}
}

func TestAdmin_ListCertifications_FilterByPublicIP(t *testing.T) {
	env, cleanup := newAdminEnv(t)
	defer cleanup()

	// Two POSTs with distinct public IPs. The publicIp filter takes the
	// raw IP and the server hashes it before comparing — exact match works.
	for i, ip := range []string{"203.0.113.5", "198.51.100.42"} {
		fix := loadCertFixture(t)
		fix["certificationId"] = []string{
			"b0000001-0000-0000-0000-000000000001",
			"b0000002-0000-0000-0000-000000000002",
		}[i]
		fix["network"].(map[string]any)["publicIp"] = ip
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

	resp := adminGet(t, env.router, "/admin/certifications?publicIp=203.0.113.5", testAdminToken)
	defer resp.Body.Close()
	var body struct {
		Items []map[string]any `json:"items"`
		Total int              `json:"total"`
	}
	dec(t, resp, &body)
	if body.Total != 1 {
		t.Errorf("total: got %d, want 1 (publicIp filter)", body.Total)
	}
	// The response carries the plaintext publicIp (de-hashed in the
	// PII-policy update — see internal/pii/hash.go::piiPaths).
	if len(body.Items) > 0 {
		if _, hasLegacyHash := body.Items[0]["publicIpHash"]; hasLegacyHash {
			t.Error("response carries legacy publicIpHash field; should have been renamed to publicIp")
		}
		if ip, ok := body.Items[0]["publicIp"].(string); !ok || ip != "203.0.113.5" {
			t.Errorf("publicIp: got %v, want plain 203.0.113.5", body.Items[0]["publicIp"])
		}
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

func TestAdmin_QueueDelay_DerivedField(t *testing.T) {
	env, cleanup := newAdminEnv(t)
	defer cleanup()

	// Seed two rows: one fresh (small delay), one queue-drained (3 days later).
	for i, sub := range []string{"2026-05-06T18:37:48Z", "2026-05-09T18:37:48Z"} {
		fix := loadCertFixture(t)
		fix["certificationId"] = []string{
			"c0000001-0000-0000-0000-000000000001",
			"c0000002-0000-0000-0000-000000000002",
		}[i]
		fix["completedAt"] = "2026-05-06T18:37:46Z"
		fix["enqueuedAt"] = "2026-05-06T18:37:46Z"
		fix["submittedAt"] = sub
		body, _ := json.Marshal(fix)
		r := httptest.NewRequest(http.MethodPost, "/v1/certifications", bytes.NewReader(body))
		for k, v := range defaultHeaders() {
			r.Header.Set(k, v)
		}
		r.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		env.router.ServeHTTP(w, r)
		if w.Code != http.StatusCreated {
			t.Fatalf("seed %d: got %d", i, w.Code)
		}
	}

	resp := adminGet(t, env.router, "/admin/certifications", testAdminToken)
	defer resp.Body.Close()
	var body struct {
		Items []map[string]any `json:"items"`
	}
	dec(t, resp, &body)

	// Find both rows and check their queueDelaySeconds.
	delays := map[string]float64{}
	for _, it := range body.Items {
		id, _ := it["certificationId"].(string)
		if d, ok := it["queueDelaySeconds"].(float64); ok {
			delays[id] = d
		}
	}
	if d := delays["c0000001-0000-0000-0000-000000000001"]; d > 5 {
		t.Errorf("fresh row delay: got %v, want <= 5", d)
	}
	if d := delays["c0000002-0000-0000-0000-000000000002"]; d < 3*24*3600-60 {
		t.Errorf("queue-drained row delay: got %v, want ~3 days", d)
	}
}

func TestAdmin_QueueDelay_NullForOlderClient(t *testing.T) {
	env, cleanup := newAdminEnv(t)
	defer cleanup()

	fix := loadCertFixture(t)
	delete(fix, "enqueuedAt")
	delete(fix, "submittedAt")
	body, _ := json.Marshal(fix)
	r := httptest.NewRequest(http.MethodPost, "/v1/certifications", bytes.NewReader(body))
	for k, v := range defaultHeaders() {
		r.Header.Set(k, v)
	}
	r.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	env.router.ServeHTTP(w, r)

	resp := adminGet(t, env.router, "/admin/certifications/"+fixtureID, testAdminToken)
	defer resp.Body.Close()
	var detail struct {
		Summary map[string]any `json:"summary"`
	}
	dec(t, resp, &detail)
	if _, ok := detail.Summary["queueDelaySeconds"]; ok {
		t.Errorf("queueDelaySeconds should be omitted for older-client row; got: %v",
			detail.Summary["queueDelaySeconds"])
	}
}

func TestAdmin_ListCertifications_QueuedOnly(t *testing.T) {
	env, cleanup := newAdminEnv(t)
	defer cleanup()

	// One fresh row, one delayed by 1 hour, one delayed by 3 days.
	cases := []struct {
		id  string
		sub string
	}{
		{"d0000001-0000-0000-0000-000000000001", "2026-05-06T18:37:48Z"}, // fresh
		{"d0000002-0000-0000-0000-000000000002", "2026-05-06T19:37:46Z"}, // 1h delay
		{"d0000003-0000-0000-0000-000000000003", "2026-05-09T18:37:46Z"}, // 3d delay
	}
	for _, c := range cases {
		fix := loadCertFixture(t)
		fix["certificationId"] = c.id
		fix["completedAt"] = "2026-05-06T18:37:46Z"
		fix["enqueuedAt"] = "2026-05-06T18:37:46Z"
		fix["submittedAt"] = c.sub
		body, _ := json.Marshal(fix)
		r := httptest.NewRequest(http.MethodPost, "/v1/certifications", bytes.NewReader(body))
		for k, v := range defaultHeaders() {
			r.Header.Set(k, v)
		}
		r.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		env.router.ServeHTTP(w, r)
	}

	resp := adminGet(t, env.router, "/admin/certifications?queuedOnly=true", testAdminToken)
	defer resp.Body.Close()
	var body struct {
		Total int `json:"total"`
	}
	dec(t, resp, &body)
	if body.Total != 2 {
		t.Errorf("queuedOnly total: got %d, want 2 (the 1h and 3d delays)", body.Total)
	}
}

func TestAdmin_QueueStats(t *testing.T) {
	env, cleanup := newAdminEnv(t)
	defer cleanup()

	// Seed three rows with known delays in seconds: 10, 100, 1000.
	now := time.Now().UTC()
	for i, delaySec := range []int{10, 100, 1000} {
		fix := loadCertFixture(t)
		fix["certificationId"] = []string{
			"e0000001-0000-0000-0000-000000000001",
			"e0000002-0000-0000-0000-000000000002",
			"e0000003-0000-0000-0000-000000000003",
		}[i]
		// completedAt within the 24h window so the stats query picks it up.
		completed := now.Add(-1 * time.Hour)
		submitted := completed.Add(time.Duration(delaySec) * time.Second)
		fix["startedAt"] = completed.Add(-30 * time.Second).Format(time.RFC3339)
		fix["completedAt"] = completed.Format(time.RFC3339)
		fix["enqueuedAt"] = completed.Format(time.RFC3339)
		fix["submittedAt"] = submitted.Format(time.RFC3339)
		body, _ := json.Marshal(fix)
		r := httptest.NewRequest(http.MethodPost, "/v1/certifications", bytes.NewReader(body))
		for k, v := range defaultHeaders() {
			r.Header.Set(k, v)
		}
		r.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		env.router.ServeHTTP(w, r)
		if w.Code != http.StatusCreated {
			t.Fatalf("seed %d: got %d", i, w.Code)
		}
	}

	resp := adminGet(t, env.router, "/admin/queue-stats?windowHours=24", testAdminToken)
	defer resp.Body.Close()
	var body map[string]any
	dec(t, resp, &body)
	if int(body["sampleSize"].(float64)) != 3 {
		t.Errorf("sampleSize: got %v, want 3", body["sampleSize"])
	}
	if body["medianSeconds"].(float64) != 100 {
		t.Errorf("median: got %v, want 100", body["medianSeconds"])
	}
	if body["maxSeconds"].(float64) != 1000 {
		t.Errorf("max: got %v, want 1000", body["maxSeconds"])
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

// sampleConfigDoc returns a minimal v1.4.0-shape cert-config — no
// `servers`, no `tests.latency`, no per-phase `durationSec`/
// `perRequestBytes`/`warmupFraction` keys.
func sampleConfigDoc(version string) []byte {
	doc := map[string]any{
		"schemaVersion": 1,
		"configVersion": version,
		"tests": map[string]any{
			"download": map[string]any{"parallel": 4},
			"upload":   map[string]any{"parallel": 2},
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

func TestAdmin_CreateCertConfig_WithKillswitch_OK(t *testing.T) {
	env, cleanup := newAdminEnv(t)
	defer cleanup()

	for _, tc := range []struct {
		name string
		ks   map[string]any
	}{
		{"enabled with reason", map[string]any{"enabled": true, "reason": "Maintenance"}},
		{"enabled without reason", map[string]any{"enabled": true}},
		{"explicitly disabled", map[string]any{"enabled": false}},
		{"reason explicitly null", map[string]any{"enabled": true, "reason": nil}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var doc map[string]any
			_ = json.Unmarshal(sampleConfigDoc("2030-killswitch."+tc.name), &doc)
			doc["killswitch"] = tc.ks
			b, _ := json.Marshal(doc)
			resp := adminPost(t, env.router, "/admin/cert-configs", testAdminToken, b)
			defer resp.Body.Close()
			if resp.StatusCode != http.StatusCreated {
				got, _ := io.ReadAll(resp.Body)
				t.Fatalf("status: got %d (%s), want 201", resp.StatusCode, string(got))
			}
		})
	}
}

func TestAdmin_CreateCertConfig_WithTunables_OK(t *testing.T) {
	env, cleanup := newAdminEnv(t)
	defer cleanup()

	var doc map[string]any
	_ = json.Unmarshal(sampleConfigDoc("2030-tunables.ok"), &doc)
	doc["wifiLinkQuality"] = map[string]any{
		"excellentRssiMin":                -50,
		"strongRssiMin":                   -60,
		"goodRssiMin":                     -70,
		"rateAdaptationDegradedThreshold": 0.6,
	}
	doc["healthAssessment"] = map[string]any{
		"excellentMin":             90,
		"strongMin":                65,
		"goodMin":                  40,
		"topTierStretchUpFactor":   1.3,
		"topTierStretchDownFactor": 0.75,
	}
	b, _ := json.Marshal(doc)
	resp := adminPost(t, env.router, "/admin/cert-configs", testAdminToken, b)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusCreated {
		got, _ := io.ReadAll(resp.Body)
		t.Fatalf("status: got %d (%s), want 201", resp.StatusCode, string(got))
	}
}

// TestAdmin_CreateCertConfig_WithDnsPolicy_OK covers the v2.3.0 optional
// `dnsPolicy.preferredServers` envelope: the server should validate it,
// store it inside the opaque JSONB document, and round-trip it intact on
// GET. The companion negative cases live in
// TestAdmin_CreateCertConfig_DnsPolicy_Validation. Omission is asserted as
// a regression check at the bottom so a future refactor can't make the
// field implicitly required.
func TestAdmin_CreateCertConfig_WithDnsPolicy_OK(t *testing.T) {
	env, cleanup := newAdminEnv(t)
	defer cleanup()

	var doc map[string]any
	_ = json.Unmarshal(sampleConfigDoc("2030-dns.ok"), &doc)
	doc["dnsPolicy"] = map[string]any{
		"preferredServers": []string{"1.1.1.1", "8.8.8.8"},
	}
	b, _ := json.Marshal(doc)
	resp := adminPost(t, env.router, "/admin/cert-configs", testAdminToken, b)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusCreated {
		got, _ := io.ReadAll(resp.Body)
		t.Fatalf("status: got %d (%s), want 201", resp.StatusCode, string(got))
	}

	// GET round-trip: the stored document must still carry the policy.
	getResp := adminGet(t, env.router, "/admin/cert-configs/2030-dns.ok", testAdminToken)
	defer getResp.Body.Close()
	var body map[string]any
	dec(t, getResp, &body)
	gotDoc, ok := body["document"].(map[string]any)
	if !ok {
		t.Fatalf("document not present on GET: %v", body)
	}
	gotPolicy, ok := gotDoc["dnsPolicy"].(map[string]any)
	if !ok {
		t.Fatalf("dnsPolicy missing or wrong shape after round-trip: %v", gotDoc["dnsPolicy"])
	}
	servers, ok := gotPolicy["preferredServers"].([]any)
	if !ok || len(servers) != 2 || servers[0] != "1.1.1.1" || servers[1] != "8.8.8.8" {
		t.Errorf("preferredServers round-trip mismatch: got %v", gotPolicy["preferredServers"])
	}

	// Regression: omitting dnsPolicy entirely is still a 201 and the
	// stored document must not synthesize the key.
	noDoc := sampleConfigDoc("2030-dns.absent")
	noResp := adminPost(t, env.router, "/admin/cert-configs", testAdminToken, noDoc)
	defer noResp.Body.Close()
	if noResp.StatusCode != http.StatusCreated {
		got, _ := io.ReadAll(noResp.Body)
		t.Fatalf("omit-dnsPolicy status: got %d (%s), want 201", noResp.StatusCode, string(got))
	}
	noGet := adminGet(t, env.router, "/admin/cert-configs/2030-dns.absent", testAdminToken)
	defer noGet.Body.Close()
	var noBody map[string]any
	dec(t, noGet, &noBody)
	if storedDoc, ok := noBody["document"].(map[string]any); ok {
		if _, present := storedDoc["dnsPolicy"]; present {
			t.Errorf("dnsPolicy should not be present when caller omitted it: %v", storedDoc["dnsPolicy"])
		}
	}
}

// TestAdmin_CreateCertConfig_DnsPolicy_Validation asserts both the 400
// status AND the specific error path returned for each shape we reject —
// the dashboard surfaces these paths field-by-field in the inspector.
func TestAdmin_CreateCertConfig_DnsPolicy_Validation(t *testing.T) {
	env, cleanup := newAdminEnv(t)
	defer cleanup()

	cases := []struct {
		name     string
		policy   any
		wantPath string
	}{
		{
			name:     "empty preferredServers",
			policy:   map[string]any{"preferredServers": []any{}},
			wantPath: "dnsPolicy.preferredServers",
		},
		{
			name:     "dnsPolicy is a string",
			policy:   "garbage",
			wantPath: "dnsPolicy",
		},
		{
			name:     "non-string entry",
			policy:   map[string]any{"preferredServers": []any{123}},
			wantPath: "dnsPolicy.preferredServers[0]",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var doc map[string]any
			_ = json.Unmarshal(sampleConfigDoc("2030-dns.bad."+tc.name), &doc)
			doc["dnsPolicy"] = tc.policy
			b, _ := json.Marshal(doc)
			resp := adminPost(t, env.router, "/admin/cert-configs", testAdminToken, b)
			defer resp.Body.Close()
			if resp.StatusCode != http.StatusBadRequest {
				t.Fatalf("status: got %d, want 400", resp.StatusCode)
			}
			var body struct {
				Error   string `json:"error"`
				Details []struct {
					Path string `json:"path"`
					Msg  string `json:"msg"`
				} `json:"details"`
			}
			dec(t, resp, &body)
			found := false
			for _, d := range body.Details {
				if d.Path == tc.wantPath {
					found = true
					break
				}
			}
			if !found {
				t.Errorf("expected details to include path %q, got %+v", tc.wantPath, body.Details)
			}
		})
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
		{"empty tiers", func(m map[string]any) { m["tiers"] = []map[string]any{} }},
		{"missing tests", func(m map[string]any) { delete(m, "tests") }},
		{"missing uploadResults", func(m map[string]any) { delete(m, "uploadResults") }},
		{"playback.durationSec below floor (real-world regression: dev.7/dev.8 shipped with 1)", func(m map[string]any) {
			m["tests"].(map[string]any)["playback"].(map[string]any)["durationSec"] = 1
		}},
		{"playback.durationSec above ceiling", func(m map[string]any) {
			m["tests"].(map[string]any)["playback"].(map[string]any)["durationSec"] = 121
		}},
		{"playback missing manifestUrl", func(m map[string]any) {
			delete(m["tests"].(map[string]any)["playback"].(map[string]any), "manifestUrl")
		}},
		{"download.parallel zero", func(m map[string]any) {
			m["tests"].(map[string]any)["download"].(map[string]any)["parallel"] = 0
		}},
		{"download.parallel above ceiling", func(m map[string]any) {
			m["tests"].(map[string]any)["download"].(map[string]any)["parallel"] = 17
		}},
		{"upload.parallel above ceiling (dashboard slider lets users pick >16)", func(m map[string]any) {
			m["tests"].(map[string]any)["upload"].(map[string]any)["parallel"] = 32
		}},
		// ─── killswitch (optional but strict when present) ───
		{"killswitch missing enabled", func(m map[string]any) {
			m["killswitch"] = map[string]any{"reason": "Maintenance"}
		}},
		{"killswitch enabled as string (must be boolean, not 'yes'/'true')", func(m map[string]any) {
			m["killswitch"] = map[string]any{"enabled": "true"}
		}},
		{"killswitch enabled as number (must be boolean)", func(m map[string]any) {
			m["killswitch"] = map[string]any{"enabled": 1}
		}},
		{"killswitch reason as number (must be string or null)", func(m map[string]any) {
			m["killswitch"] = map[string]any{"enabled": true, "reason": 42}
		}},
		// ─── wifiLinkQuality (optional but validated when present) ───
		{"wifiLinkQuality.excellentRssiMin out of range", func(m map[string]any) {
			m["wifiLinkQuality"] = map[string]any{
				"excellentRssiMin": -200, "strongRssiMin": -65, "goodRssiMin": -75,
				"rateAdaptationDegradedThreshold": 0.5,
			}
		}},
		{"wifiLinkQuality ordering invariant violated", func(m map[string]any) {
			m["wifiLinkQuality"] = map[string]any{
				"excellentRssiMin": -75, "strongRssiMin": -65, "goodRssiMin": -55,
				"rateAdaptationDegradedThreshold": 0.5,
			}
		}},
		{"wifiLinkQuality rateAdaptationDegradedThreshold above ceiling", func(m map[string]any) {
			m["wifiLinkQuality"] = map[string]any{
				"excellentRssiMin": -55, "strongRssiMin": -65, "goodRssiMin": -75,
				"rateAdaptationDegradedThreshold": 1.5,
			}
		}},
		// ─── healthAssessment (optional but validated when present) ──
		{"healthAssessment.excellentMin above 100", func(m map[string]any) {
			m["healthAssessment"] = map[string]any{
				"excellentMin": 150, "strongMin": 55, "goodMin": 30,
				"topTierStretchUpFactor": 1.5, "topTierStretchDownFactor": 0.66,
			}
		}},
		{"healthAssessment ordering invariant violated", func(m map[string]any) {
			m["healthAssessment"] = map[string]any{
				"excellentMin": 30, "strongMin": 55, "goodMin": 80,
				"topTierStretchUpFactor": 1.5, "topTierStretchDownFactor": 0.66,
			}
		}},
		{"healthAssessment.topTierStretchUpFactor not strictly > 1.0", func(m map[string]any) {
			m["healthAssessment"] = map[string]any{
				"excellentMin": 80, "strongMin": 55, "goodMin": 30,
				"topTierStretchUpFactor": 1.0, "topTierStretchDownFactor": 0.66,
			}
		}},
		{"healthAssessment.topTierStretchDownFactor above 1.0", func(m map[string]any) {
			m["healthAssessment"] = map[string]any{
				"excellentMin": 80, "strongMin": 55, "goodMin": 30,
				"topTierStretchUpFactor": 1.5, "topTierStretchDownFactor": 1.5,
			}
		}},
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

