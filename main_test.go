package trusteddevices

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"go.uber.org/zap"
)

// okHandler is a next-handler that records whether it was reached.
type okHandler struct{ called bool }

func (h *okHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) error {
	h.called = true
	w.WriteHeader(http.StatusOK)
	return nil
}

// newReq builds a request whose Caddy-resolved client IP is clientIP, with the
// given raw headers. clientIP simulates what Caddy's trusted_proxies logic would
// produce; raw headers simulate what an attacker can set.
func newReq(clientIP string, headers map[string]string) *http.Request {
	r := httptest.NewRequest(http.MethodGet, "http://example.com/", nil)
	r.RemoteAddr = "203.0.113.7:54321" // untrusted source address
	for k, v := range headers {
		r.Header.Set(k, v)
	}
	ctx := context.WithValue(r.Context(), caddyhttp.VarsCtxKey, map[string]any{
		caddyhttp.ClientIPVarKey: clientIP,
	})
	return r.WithContext(ctx)
}

func newMiddleware(t *testing.T) *Middleware {
	t.Helper()
	return &Middleware{
		TrustedTokensFile: filepath.Join(t.TempDir(), "tokens.json"),
		CookieName:        "trusted_device",
		maxAge:            8760 * time.Hour,
		trustedIPs:        map[string]bool{"192.168.1.100": true},
		tokens:            map[string]time.Time{},
		logger:            zap.NewNop(),
	}
}

func serve(t *testing.T, m *Middleware, r *http.Request) (*httptest.ResponseRecorder, bool) {
	t.Helper()
	rec := httptest.NewRecorder()
	next := &okHandler{}
	if err := m.ServeHTTP(rec, r, caddyhttp.HandlerFunc(next.ServeHTTP)); err != nil {
		t.Fatalf("ServeHTTP returned error: %v", err)
	}
	return rec, next.called
}

// The core regression test: forging X-Forwarded-For / X-Real-IP to a trusted IP
// must NOT grant access, because we rely on Caddy's resolved client IP.
func TestSpoofedForwardingHeadersDenied(t *testing.T) {
	cases := []map[string]string{
		{"X-Forwarded-For": "192.168.1.100"},
		{"X-Forwarded-For": "192.168.1.100, 10.0.0.1"},
		{"X-Real-IP": "192.168.1.100"},
		{"X-Forwarded-For": "192.168.1.100", "X-Real-IP": "192.168.1.100"},
	}
	for _, headers := range cases {
		m := newMiddleware(t)
		// Caddy resolved the real (untrusted) client IP; headers are attacker-set.
		r := newReq("203.0.113.7", headers)
		rec, called := serve(t, m, r)
		if called {
			t.Fatalf("access granted via spoofed headers %v", headers)
		}
		if rec.Code != http.StatusForbidden {
			t.Fatalf("expected 403 for spoofed headers %v, got %d", headers, rec.Code)
		}
		if len(rec.Result().Cookies()) != 0 {
			t.Fatalf("cookie issued to spoofed request %v", headers)
		}
	}
}

func TestTrustedIPGrantsAccessAndIssuesCookie(t *testing.T) {
	m := newMiddleware(t)
	r := newReq("192.168.1.100", nil)
	rec, called := serve(t, m, r)
	if !called {
		t.Fatal("trusted IP was denied")
	}
	cookies := rec.Result().Cookies()
	if len(cookies) != 1 {
		t.Fatalf("expected 1 cookie, got %d", len(cookies))
	}
	c := cookies[0]
	if !c.HttpOnly {
		t.Error("cookie should be HttpOnly")
	}
	if c.SameSite != http.SameSiteLaxMode {
		t.Error("cookie should be SameSite=Lax")
	}
	// Token must be persisted and valid.
	if _, ok := m.tokens[c.Value]; !ok {
		t.Error("token not stored in memory")
	}
}

func TestValidCookieGrantsAccessFromUntrustedIP(t *testing.T) {
	m := newMiddleware(t)
	token := "valid-token-123"
	m.tokens[token] = time.Now().Add(time.Hour)

	r := newReq("203.0.113.7", nil) // untrusted IP
	r.AddCookie(&http.Cookie{Name: m.CookieName, Value: token})
	_, called := serve(t, m, r)
	if !called {
		t.Fatal("valid cookie from untrusted IP was denied")
	}
}

func TestExpiredCookieDenied(t *testing.T) {
	m := newMiddleware(t)
	token := "expired-token"
	m.tokens[token] = time.Now().Add(-time.Hour)

	r := newReq("203.0.113.7", nil)
	r.AddCookie(&http.Cookie{Name: m.CookieName, Value: token})
	rec, called := serve(t, m, r)
	if called {
		t.Fatal("expired cookie granted access")
	}
	if rec.Code != http.StatusForbidden {
		t.Fatalf("expected 403, got %d", rec.Code)
	}
}

func TestUnknownCookieDenied(t *testing.T) {
	m := newMiddleware(t)
	r := newReq("203.0.113.7", nil)
	r.AddCookie(&http.Cookie{Name: m.CookieName, Value: "made-up-token"})
	_, called := serve(t, m, r)
	if called {
		t.Fatal("unknown token granted access")
	}
}

func TestUserAgentNoLongerGrantsAccess(t *testing.T) {
	m := newMiddleware(t)
	r := newReq("203.0.113.7", map[string]string{"User-Agent": "MyApp/1.0"})
	_, called := serve(t, m, r)
	if called {
		t.Fatal("User-Agent should no longer grant access")
	}
}

func TestEmptyTrustedIPsFailsClosed(t *testing.T) {
	m := newMiddleware(t)
	m.trustedIPs = map[string]bool{} // no trusted IPs loaded
	r := newReq("192.168.1.100", nil)
	_, called := serve(t, m, r)
	if called {
		t.Fatal("access granted with empty trusted IP set")
	}
}

func TestSaveTokensPermissionsAndAtomicity(t *testing.T) {
	m := newMiddleware(t)
	m.tokens["tok"] = time.Now().Add(time.Hour)
	if err := m.saveTokens(); err != nil {
		t.Fatalf("saveTokens failed: %v", err)
	}
	info, err := os.Stat(m.TrustedTokensFile)
	if err != nil {
		t.Fatalf("tokens file missing: %v", err)
	}
	if perm := info.Mode().Perm(); perm != 0600 {
		t.Fatalf("tokens file perms = %o, want 0600", perm)
	}
	// File must be valid JSON containing the token.
	data, _ := os.ReadFile(m.TrustedTokensFile)
	var got map[string]time.Time
	if err := json.Unmarshal(data, &got); err != nil {
		t.Fatalf("tokens file not valid JSON: %v", err)
	}
	if _, ok := got["tok"]; !ok {
		t.Fatal("token not persisted")
	}
	// No leftover temp files in the directory.
	entries, _ := os.ReadDir(filepath.Dir(m.TrustedTokensFile))
	for _, e := range entries {
		if filepath.Ext(e.Name()) == ".tmp" {
			t.Fatalf("leftover temp file: %s", e.Name())
		}
	}
}

func TestConcurrentSaveTokens(t *testing.T) {
	m := newMiddleware(t)
	var wg sync.WaitGroup
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func(n int) {
			defer wg.Done()
			m.mu.Lock()
			m.tokens[time.Now().Format(time.RFC3339Nano)+string(rune(n))] = time.Now().Add(time.Hour)
			m.mu.Unlock()
			if err := m.saveTokens(); err != nil {
				t.Errorf("concurrent saveTokens failed: %v", err)
			}
		}(i)
	}
	wg.Wait()
	data, err := os.ReadFile(m.TrustedTokensFile)
	if err != nil {
		t.Fatalf("reading tokens file: %v", err)
	}
	var got map[string]time.Time
	if err := json.Unmarshal(data, &got); err != nil {
		t.Fatalf("tokens file corrupted after concurrent writes: %v", err)
	}
}

func TestPruneExpired(t *testing.T) {
	m := newMiddleware(t)
	m.tokens["live"] = time.Now().Add(time.Hour)
	m.tokens["dead"] = time.Now().Add(-time.Hour)
	m.pruneExpired()
	if _, ok := m.tokens["dead"]; ok {
		t.Error("expired token not pruned")
	}
	if _, ok := m.tokens["live"]; !ok {
		t.Error("live token incorrectly pruned")
	}
}

func TestGetClientIPIgnoresHeaders(t *testing.T) {
	r := newReq("198.51.100.5", map[string]string{
		"X-Forwarded-For": "192.168.1.100",
		"X-Real-IP":       "10.0.0.1",
	})
	if ip := getClientIP(r); ip != "198.51.100.5" {
		t.Fatalf("getClientIP = %q, want resolved client_ip 198.51.100.5", ip)
	}
}

func TestGetClientIPFallbackToRemoteAddr(t *testing.T) {
	// No Caddy vars in context: must fall back to RemoteAddr, never headers.
	r := httptest.NewRequest(http.MethodGet, "http://example.com/", nil)
	r.RemoteAddr = "203.0.113.9:1234"
	r.Header.Set("X-Forwarded-For", "192.168.1.100")
	if ip := getClientIP(r); ip != "203.0.113.9" {
		t.Fatalf("getClientIP fallback = %q, want 203.0.113.9", ip)
	}
}
