package api_test

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
)

// sampleAppVersionDoc builds a valid AppVersionManifest body for tests.
// The SHA-256 hex strings are obviously placeholder but match the
// contract's `^[0-9a-f]{64}$` pattern so validation passes.
func sampleAppVersionDoc(versionCode int, versionName string) []byte {
	doc := map[string]any{
		"schemaVersion":          1,
		"latestVersionName":      versionName,
		"latestVersionCode":      versionCode,
		"minRequiredVersionCode": versionCode,
		"apkUrl":                 "https://certifier-api.gethotwired.com/v1/app/download/" + versionName + ".apk",
		"apkSizeBytes":           12345678,
		"apkSha256":              "ab12cd34ef560000000000000000000000000000000000000000000000000000",
		"signingCertSha256":      "ff009911000000000000000000000000000000000000000000000000000000ff",
		"releaseNotes":           "test build",
		"publishedAt":            "2026-05-11T18:00:00Z",
	}
	b, _ := json.Marshal(doc)
	return b
}

func appVersionHeaders(versionCode int) map[string]string {
	h := defaultHeaders()
	h["X-App-Version-Code"] = strconv.Itoa(versionCode)
	return h
}

func TestAppVersion_NoActive_503(t *testing.T) {
	env, cleanup := newCertEnv(t)
	defer cleanup()

	r := httptest.NewRequest(http.MethodGet, "/v1/app/version", nil)
	for k, v := range appVersionHeaders(50) {
		r.Header.Set(k, v)
	}
	w := httptest.NewRecorder()
	env.router.ServeHTTP(w, r)
	resp := w.Result()
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("status: got %d, want 503 (no manifest yet)", resp.StatusCode)
	}
}

func TestAppVersion_BadVersionCodeHeader(t *testing.T) {
	env, cleanup := newCertEnv(t)
	defer cleanup()

	for _, bad := range []string{"", "0", "abc", "-1"} {
		r := httptest.NewRequest(http.MethodGet, "/v1/app/version", nil)
		for k, v := range defaultHeaders() {
			r.Header.Set(k, v)
		}
		if bad != "" {
			r.Header.Set("X-App-Version-Code", bad)
		}
		w := httptest.NewRecorder()
		env.router.ServeHTTP(w, r)
		if w.Code != http.StatusBadRequest {
			t.Errorf("X-App-Version-Code=%q: got %d, want 400", bad, w.Code)
		}
	}
}

func TestAppVersion_HappyPath(t *testing.T) {
	env, cleanup := newCertEnv(t)
	defer cleanup()

	// Seed via the admin write API (the device-facing path is GET-only).
	createResp := adminPost(t, env.router, "/admin/app-versions", testAdminToken, sampleAppVersionDoc(70, "0.7.0"))
	if createResp.StatusCode != http.StatusCreated {
		got, _ := io.ReadAll(createResp.Body)
		t.Fatalf("create: got %d (%s)", createResp.StatusCode, string(got))
	}
	createResp.Body.Close()

	actResp := adminPost(t, env.router, "/admin/app-versions/70/activate", testAdminToken, nil)
	if actResp.StatusCode != http.StatusOK {
		t.Fatalf("activate: got %d", actResp.StatusCode)
	}
	actResp.Body.Close()

	// GET /v1/app/version
	r := httptest.NewRequest(http.MethodGet, "/v1/app/version", nil)
	for k, v := range appVersionHeaders(50) {
		r.Header.Set(k, v)
	}
	w := httptest.NewRecorder()
	env.router.ServeHTTP(w, r)
	resp := w.Result()
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status: got %d, want 200", resp.StatusCode)
	}
	etag := resp.Header.Get("ETag")
	if etag == "" || !strings.HasPrefix(etag, `"`) {
		t.Errorf("ETag: got %q, want quoted hex", etag)
	}
	var body map[string]any
	dec(t, resp, &body)
	if body["latestVersionCode"].(float64) != 70 {
		t.Errorf("latestVersionCode: got %v", body["latestVersionCode"])
	}
	if body["latestVersionName"] != "0.7.0" {
		t.Errorf("latestVersionName: got %v", body["latestVersionName"])
	}

	// If-None-Match echoing the ETag → 304
	r2 := httptest.NewRequest(http.MethodGet, "/v1/app/version", nil)
	for k, v := range appVersionHeaders(50) {
		r2.Header.Set(k, v)
	}
	r2.Header.Set("If-None-Match", etag)
	w2 := httptest.NewRecorder()
	env.router.ServeHTTP(w2, r2)
	if w2.Code != http.StatusNotModified {
		t.Errorf("If-None-Match match: got %d, want 304", w2.Code)
	}
}

func TestAdmin_CreateAppVersion_Conflict(t *testing.T) {
	env, cleanup := newCertEnv(t)
	defer cleanup()

	body := sampleAppVersionDoc(70, "0.7.0")
	r1 := adminPost(t, env.router, "/admin/app-versions", testAdminToken, body)
	r1.Body.Close()
	if r1.StatusCode != http.StatusCreated {
		t.Fatalf("first create: got %d", r1.StatusCode)
	}
	r2 := adminPost(t, env.router, "/admin/app-versions", testAdminToken, body)
	r2.Body.Close()
	if r2.StatusCode != http.StatusConflict {
		t.Fatalf("duplicate: got %d, want 409", r2.StatusCode)
	}
}

func TestAdmin_CreateAppVersion_Validation(t *testing.T) {
	env, cleanup := newCertEnv(t)
	defer cleanup()

	cases := []struct {
		name string
		mut  func(map[string]any)
	}{
		{"missing latestVersionName", func(m map[string]any) { delete(m, "latestVersionName") }},
		{"min > latest", func(m map[string]any) {
			m["minRequiredVersionCode"] = 999
		}},
		{"bad apkSha256", func(m map[string]any) { m["apkSha256"] = "not-hex" }},
		{"uppercase apkSha256", func(m map[string]any) {
			m["apkSha256"] = "AB12CD34EF560000000000000000000000000000000000000000000000000000"
		}},
		{"bad signingCertSha256", func(m map[string]any) { m["signingCertSha256"] = "short" }},
		{"non-http apkUrl", func(m map[string]any) { m["apkUrl"] = "ftp://example/x.apk" }},
		{"missing apkSizeBytes", func(m map[string]any) { delete(m, "apkSizeBytes") }},
		{"zero apkSizeBytes", func(m map[string]any) { m["apkSizeBytes"] = 0 }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var doc map[string]any
			_ = json.Unmarshal(sampleAppVersionDoc(80, "0.8.0"), &doc)
			tc.mut(doc)
			b, _ := json.Marshal(doc)
			resp := adminPost(t, env.router, "/admin/app-versions", testAdminToken, b)
			resp.Body.Close()
			if resp.StatusCode != http.StatusBadRequest {
				t.Errorf("got %d, want 400", resp.StatusCode)
			}
		})
	}
}

func TestAdmin_ActivateAppVersion(t *testing.T) {
	env, cleanup := newCertEnv(t)
	defer cleanup()

	// Create two; activate the second; verify exactly one active.
	for _, v := range []int{60, 70} {
		resp := adminPost(t, env.router, "/admin/app-versions", testAdminToken, sampleAppVersionDoc(v, "0."+strconv.Itoa(v)))
		resp.Body.Close()
		if resp.StatusCode != http.StatusCreated {
			t.Fatalf("create %d: got %d", v, resp.StatusCode)
		}
	}
	// Activate 60 first
	resp1 := adminPost(t, env.router, "/admin/app-versions/60/activate", testAdminToken, nil)
	resp1.Body.Close()
	// Then activate 70 — should flip 60 to inactive
	resp2 := adminPost(t, env.router, "/admin/app-versions/70/activate", testAdminToken, nil)
	resp2.Body.Close()
	if resp2.StatusCode != http.StatusOK {
		t.Fatalf("activate 70: got %d", resp2.StatusCode)
	}
	listResp := adminGet(t, env.router, "/admin/app-versions", testAdminToken)
	defer listResp.Body.Close()
	var list struct {
		Items []map[string]any `json:"items"`
	}
	dec(t, listResp, &list)
	active := 0
	var activeCode int
	for _, it := range list.Items {
		if it["isActive"] == true {
			active++
			activeCode = int(it["latestVersionCode"].(float64))
		}
	}
	if active != 1 {
		t.Errorf("active count: got %d, want 1", active)
	}
	if activeCode != 70 {
		t.Errorf("active code: got %d, want 70", activeCode)
	}
}

func TestAdmin_ActivateAppVersion_NotFound(t *testing.T) {
	env, cleanup := newCertEnv(t)
	defer cleanup()
	resp := adminPost(t, env.router, "/admin/app-versions/999/activate", testAdminToken, nil)
	resp.Body.Close()
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("got %d, want 404", resp.StatusCode)
	}
}
