package trusteddevices

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"regexp"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
)

const (
	home  = "192.168.1.100"
	away  = "203.0.113.50"
	admin = "/.trusted-devices"
)

func newPairingMiddleware(t *testing.T) *Middleware {
	t.Helper()
	m := newMiddleware(t)
	m.Pairing = true
	m.PairingPath = admin
	return m
}

// pairingReq builds a request as a browser would send it; token is the device's cookie, if it has one.
func pairingReq(ip, method, path, token string, form url.Values) *http.Request {
	var r *http.Request
	if form != nil {
		r = httptest.NewRequest(method, "https://example.com"+path, strings.NewReader(form.Encode()))
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		r.Header.Set("Sec-Fetch-Site", "same-origin")
	} else {
		r = httptest.NewRequest(method, "https://example.com"+path, nil)
	}
	r.Header.Set("Sec-Fetch-Mode", "navigate")
	r.Header.Set("User-Agent", "Mozilla/5.0 (iPhone; CPU iPhone OS 19_0 like Mac OS X)")
	if token != "" {
		r.AddCookie(&http.Cookie{Name: "trusted_device", Value: token})
	}
	ctx := context.WithValue(r.Context(), caddyhttp.VarsCtxKey, map[string]any{caddyhttp.ClientIPVarKey: ip})
	return r.WithContext(ctx)
}

func cookieOf(t *testing.T, rec *httptest.ResponseRecorder) string {
	t.Helper()
	for _, c := range rec.Result().Cookies() {
		if c.Name == "trusted_device" {
			return c.Value
		}
	}
	t.Fatal("no cookie set")
	return ""
}

var codePattern = regexp.MustCompile(`class="code">([A-Z0-9]{6})<`)

func codeIn(t *testing.T, rec *httptest.ResponseRecorder) string {
	t.Helper()
	match := codePattern.FindStringSubmatch(rec.Body.String())
	if match == nil {
		t.Fatalf("no pairing code in page:\n%s", rec.Body.String())
	}
	return match[1]
}

// pairFirstDevice approves the first device, which happens by itself, and returns its token.
func pairFirstDevice(t *testing.T, m *Middleware) string {
	t.Helper()
	rec, called := serve(t, m, pairingReq(home, http.MethodGet, "/", "", nil))
	if !called {
		t.Fatal("first device was not let through")
	}
	return cookieOf(t, rec)
}

// startPairing has a new device at home ask to pair, and returns its token and code.
func startPairing(t *testing.T, m *Middleware) (string, string) {
	t.Helper()
	rec, called := serve(t, m, pairingReq(home, http.MethodGet, "/", "", nil))
	if called {
		t.Fatal("a new device was let through before approval")
	}
	if rec.Code != http.StatusForbidden {
		t.Fatalf("waiting page status = %d", rec.Code)
	}
	return cookieOf(t, rec), codeIn(t, rec)
}

func TestFirstDeviceIsApprovedByItself(t *testing.T) {
	m := newPairingMiddleware(t)
	token := pairFirstDevice(t, m)
	if _, called := serve(t, m, pairingReq(away, http.MethodGet, "/", token, nil)); !called {
		t.Fatal("first device denied away from home")
	}
}

func TestNewDeviceWaitsUntilApproved(t *testing.T) {
	m := newPairingMiddleware(t)
	adminToken := pairFirstDevice(t, m)
	token, code := startPairing(t, m)

	// Reloading while waiting shows the same code, also when the device has left the trusted network.
	rec, called := serve(t, m, pairingReq(away, http.MethodGet, "/", token, nil))
	if called || codeIn(t, rec) != code {
		t.Fatal("waiting device didn't get its waiting page")
	}

	rec, _ = serve(t, m, pairingReq(home, http.MethodPost, admin+"/approve", adminToken, url.Values{"code": {strings.ToLower(code)}, "name": {"Sam's phone"}}))
	if rec.Code != http.StatusSeeOther {
		t.Fatalf("approve status = %d", rec.Code)
	}
	if _, called := serve(t, m, pairingReq(away, http.MethodGet, "/", token, nil)); !called {
		t.Fatal("approved device denied")
	}
	if names := deviceNames(m); !names["Sam's phone"] {
		t.Fatalf("approved device not listed by name: %v", names)
	}
}

func deviceNames(m *Middleware) map[string]bool {
	names := map[string]bool{}
	for _, d := range m.tokens.devices("") {
		names[d.Name] = true
	}
	return names
}

func TestUnknownDeviceAwayFromHomeCantPair(t *testing.T) {
	m := newPairingMiddleware(t)
	pairFirstDevice(t, m)
	rec, called := serve(t, m, pairingReq(away, http.MethodGet, "/", "", nil))
	if called || rec.Code != http.StatusForbidden || len(rec.Result().Cookies()) != 0 {
		t.Fatal("unknown device away from home got further than a 403")
	}
	if len(m.tokens.pendingList()) != 0 {
		t.Fatal("pairing started from an untrusted IP")
	}
}

func TestTrustedIPAloneIsNotEnough(t *testing.T) {
	m := newPairingMiddleware(t)
	pairFirstDevice(t, m)
	r := pairingReq(home, http.MethodGet, "/api/data", "", nil)
	r.Header.Set("Sec-Fetch-Mode", "cors")
	if _, called := serve(t, m, r); called {
		t.Fatal("request without approved token passed on a trusted IP")
	}
}

func TestAdminPageOnlyOnTrustedNetwork(t *testing.T) {
	m := newPairingMiddleware(t)
	adminToken := pairFirstDevice(t, m)
	_, code := startPairing(t, m)

	rec, called := serve(t, m, pairingReq(away, http.MethodGet, admin, adminToken, nil))
	if called || rec.Code != http.StatusForbidden || strings.Contains(rec.Body.String(), code) {
		t.Fatal("admin page shown away from home")
	}
	rec, _ = serve(t, m, pairingReq(away, http.MethodPost, admin+"/approve", adminToken, url.Values{"code": {code}}))
	if rec.Code != http.StatusForbidden || len(m.tokens.pendingList()) != 1 {
		t.Fatal("device approved from away from home")
	}

	rec, called = serve(t, m, pairingReq(home, http.MethodGet, admin, adminToken, nil))
	if called || rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), code) {
		t.Fatalf("admin page at home doesn't show the waiting code (status %d)", rec.Code)
	}
}

func TestWaitingDeviceCantApprove(t *testing.T) {
	m := newPairingMiddleware(t)
	pairFirstDevice(t, m)
	token, code := startPairing(t, m)
	serve(t, m, pairingReq(home, http.MethodPost, admin+"/approve", token, url.Values{"code": {code}}))
	if _, called := serve(t, m, pairingReq(home, http.MethodGet, "/", token, nil)); called {
		t.Fatal("a waiting device approved itself")
	}
}

func TestCrossSitePostRefused(t *testing.T) {
	m := newPairingMiddleware(t)
	adminToken := pairFirstDevice(t, m)
	_, code := startPairing(t, m)
	for _, site := range []string{"cross-site", "same-site", "none"} {
		r := pairingReq(home, http.MethodPost, admin+"/approve", adminToken, url.Values{"code": {code}})
		r.Header.Set("Sec-Fetch-Site", site)
		if rec, _ := serve(t, m, r); rec.Code != http.StatusForbidden {
			t.Fatalf("%s post: status %d", site, rec.Code)
		}
	}
	r := pairingReq(home, http.MethodPost, admin+"/approve", adminToken, url.Values{"code": {code}})
	r.Header.Del("Sec-Fetch-Site")
	r.Header.Set("Origin", "https://evil.example")
	if rec, _ := serve(t, m, r); rec.Code != http.StatusForbidden {
		t.Fatalf("post from another origin: status %d", rec.Code)
	}
	if len(m.tokens.pendingList()) != 1 {
		t.Fatal("cross-site post approved the device")
	}
}

func TestRejectAndRevoke(t *testing.T) {
	m := newPairingMiddleware(t)
	adminToken := pairFirstDevice(t, m)

	token, code := startPairing(t, m)
	serve(t, m, pairingReq(home, http.MethodPost, admin+"/reject", adminToken, url.Values{"code": {code}}))
	if rec, called := serve(t, m, pairingReq(away, http.MethodGet, "/", token, nil)); called || strings.Contains(rec.Body.String(), code) {
		t.Fatal("rejected device still waiting or let through")
	}

	token, code = startPairing(t, m)
	serve(t, m, pairingReq(home, http.MethodPost, admin+"/approve", adminToken, url.Values{"code": {code}, "name": {"Old tablet"}}))
	serve(t, m, pairingReq(home, http.MethodPost, admin+"/revoke", adminToken, url.Values{"id": {deviceID(token)}}))
	if _, called := serve(t, m, pairingReq(away, http.MethodGet, "/", token, nil)); called {
		t.Fatal("revoked device let through")
	}
	if _, called := serve(t, m, pairingReq(away, http.MethodGet, "/", adminToken, nil)); !called {
		t.Fatal("revoking one device revoked another")
	}
}

func TestAdminPageEscapesDeviceDetails(t *testing.T) {
	m := newPairingMiddleware(t)
	adminToken := pairFirstDevice(t, m)
	r := pairingReq(home, http.MethodGet, "/", "", nil)
	r.Header.Set("User-Agent", `<img src=x onerror=alert(1)>`)
	serve(t, m, r)
	rec, _ := serve(t, m, pairingReq(home, http.MethodGet, admin, adminToken, nil))
	if strings.Contains(rec.Body.String(), "<img") {
		t.Fatal("user agent not escaped on the admin page")
	}
}

func TestAdminPageDoesNotRevealTokens(t *testing.T) {
	m := newPairingMiddleware(t)
	adminToken := pairFirstDevice(t, m)
	token, _ := startPairing(t, m)
	rec, _ := serve(t, m, pairingReq(home, http.MethodGet, admin, adminToken, nil))
	if body := rec.Body.String(); strings.Contains(body, adminToken) || strings.Contains(body, token) {
		t.Fatal("admin page contains a token")
	}
}

func TestPendingIsCapped(t *testing.T) {
	m := newPairingMiddleware(t)
	pairFirstDevice(t, m)
	for i := 0; i < maxPending; i++ {
		startPairing(t, m)
	}
	if rec, _ := serve(t, m, pairingReq(home, http.MethodGet, "/", "", nil)); rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503", rec.Code)
	}
}

func TestPendingExpires(t *testing.T) {
	m := newPairingMiddleware(t)
	pairFirstDevice(t, m)
	token, _ := startPairing(t, m)
	m.tokens.mu.Lock()
	p := m.tokens.pending[token]
	p.Created = time.Now().Add(-pendingTTL - time.Minute)
	m.tokens.pending[token] = p
	m.tokens.mu.Unlock()
	if _, ok := m.tokens.pendingFor(token); ok {
		t.Fatal("expired pairing still waiting")
	}
}

func TestTokensFileKeepsOldFormatAndReadsNew(t *testing.T) {
	s := newLoadedStore(t)
	named, _ := s.addFirstDevice("Kitchen tablet", time.Hour)
	plain := s.issue(time.Hour)

	data, err := os.ReadFile(s.path)
	if err != nil {
		t.Fatal(err)
	}
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(data, &raw); err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(string(raw[plain]), `"`) {
		t.Fatalf("token without a name not written as a plain timestamp: %s", raw[plain])
	}
	if !strings.Contains(string(raw[named]), `"name": "Kitchen tablet"`) {
		t.Fatalf("named token missing its name: %s", raw[named])
	}

	reloaded := newTokenStore(s.path, s.logger)
	reloaded.load()
	if !reloaded.isValid(plain) || !reloaded.isValid(named) || reloaded.tokens[named].Name != "Kitchen tablet" {
		t.Fatal("tokens file didn't read back")
	}
}

func TestCaddyfilePairingOptions(t *testing.T) {
	var m Middleware
	d := caddyfile.NewTestDispenser(`trusted_devices {
		pairing
		pairing_path /.devices
	}`)
	if err := m.UnmarshalCaddyfile(d); err != nil {
		t.Fatal(err)
	}
	if !m.Pairing || m.PairingPath != "/.devices" {
		t.Fatalf("pairing = %v, path = %q", m.Pairing, m.PairingPath)
	}
	if err := m.UnmarshalCaddyfile(caddyfile.NewTestDispenser("trusted_devices {\n pairing yes\n}")); err == nil {
		t.Fatal("pairing with an argument accepted")
	}
}

// A tokens file that can't be read at startup holds paired devices the store just can't see; nobody may become the
// first device then.
func TestUnreadableTokensFileDoesNotApproveByItself(t *testing.T) {
	m := newPairingMiddleware(t)
	if err := os.WriteFile(m.tokens.path, []byte(`{"half-edited": `), 0600); err != nil {
		t.Fatal(err)
	}
	m.tokens.load()
	rec, called := serve(t, m, pairingReq(home, http.MethodGet, "/", "", nil))
	if called {
		t.Fatal("a new device was approved by itself while the tokens file couldn't be parsed")
	}
	codeIn(t, rec)
}

func TestDeletedTokensFileDoesNotApproveByItself(t *testing.T) {
	m := newPairingMiddleware(t)
	admin := pairFirstDevice(t, m)
	if err := os.Remove(m.tokens.path); err != nil {
		t.Fatal(err)
	}
	m.tokens.lastCheck.Store(0)
	if _, called := serve(t, m, pairingReq(home, http.MethodGet, "/", "", nil)); called {
		t.Fatal("a new device was approved by itself after the tokens file was deleted")
	}
	if _, called := serve(t, m, pairingReq(away, http.MethodGet, "/", admin, nil)); !called {
		t.Fatal("deleting the tokens file locked out an approved device")
	}
}

func TestOnlyOneFirstDevice(t *testing.T) {
	m := newPairingMiddleware(t)
	var through atomic.Int32
	var wg sync.WaitGroup
	errs := make(chan error, 20)
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			next := &okHandler{}
			err := m.ServeHTTP(httptest.NewRecorder(), pairingReq(home, http.MethodGet, "/", "", nil), caddyhttp.HandlerFunc(next.ServeHTTP))
			if err != nil {
				errs <- err
			}
			if next.called {
				through.Add(1)
			}
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Fatal(err)
	}
	if n := through.Load(); n != 1 {
		t.Fatalf("%d devices approved by themselves, want 1", n)
	}
}

// ageToken makes token look last used long ago, with expiry close.
func ageToken(m *Middleware, token string) {
	m.tokens.mu.Lock()
	info := m.tokens.tokens[token]
	info.LastSeen, info.Expires = time.Now().Add(-2*lastSeenResolution), time.Now().Add(time.Minute)
	m.tokens.tokens[token] = info
	m.tokens.mu.Unlock()
}

func TestUseExtendsTokenAndCookie(t *testing.T) {
	m := newPairingMiddleware(t)
	token := pairFirstDevice(t, m)
	ageToken(m, token)

	rec, called := serve(t, m, pairingReq(away, http.MethodGet, "/", token, nil))
	if !called {
		t.Fatal("device denied")
	}
	if expires := readTokensFile(t, m.tokens.path)[token].Expires; time.Until(expires) < m.maxAge-time.Minute {
		t.Fatalf("expiry not extended on use: %v", expires)
	}
	if cookieOf(t, rec) != token || rec.Result().Cookies()[0].MaxAge != int(m.maxAge.Seconds()) {
		t.Fatal("cookie not renewed along with the token")
	}
}

func TestUseWithinAnHourWritesNothing(t *testing.T) {
	m := newPairingMiddleware(t)
	token := pairFirstDevice(t, m)
	past := time.Now().Add(-time.Hour).Truncate(time.Second)
	if err := os.Chtimes(m.tokens.path, past, past); err != nil {
		t.Fatal(err)
	}
	m.tokens.lastCheck.Store(0)
	rec, _ := serve(t, m, pairingReq(away, http.MethodGet, "/", token, nil))
	if info, _ := os.Stat(m.tokens.path); !info.ModTime().Equal(past) {
		t.Fatal("tokens file written on a use within the hour")
	}
	if len(rec.Result().Cookies()) != 0 {
		t.Fatal("cookie renewed on a use within the hour")
	}
}

// A site without pairing that shares the tokens file hands out tokens to anything on a trusted IP; those must not
// get past a site with pairing.
func TestUnpairedTokenNotAcceptedWithPairing(t *testing.T) {
	plain := newMiddleware(t)
	paired := newPairingMiddleware(t)
	paired.tokens = plain.tokens
	pairFirstDevice(t, paired)

	rec, _ := serve(t, plain, pairingReq(home, http.MethodGet, "/", "", nil))
	guest := cookieOf(t, rec)
	if _, called := serve(t, paired, pairingReq(away, http.MethodGet, "/", guest, nil)); called {
		t.Fatal("token from a site without pairing got past pairing")
	}
	if _, called := serve(t, paired, pairingReq(home, http.MethodGet, admin, guest, nil)); called {
		t.Fatal("token from a site without pairing reached the admin page")
	}
}

// Turning pairing on for an existing tokens file: the old tokens stay as they are, and the first device to pair
// becomes the first approved one.
func TestTurningPairingOnKeepsOldTokensUntouched(t *testing.T) {
	m := newPairingMiddleware(t)
	m.tokens.load()
	old := m.tokens.issue(time.Hour)

	if _, called := serve(t, m, pairingReq(away, http.MethodGet, "/", old, nil)); called {
		t.Fatal("token from before pairing let through with pairing on")
	}
	first := pairFirstDevice(t, m)
	ageToken(m, first)
	serve(t, m, pairingReq(away, http.MethodGet, "/", first, nil))

	data, _ := os.ReadFile(m.tokens.path)
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(data, &raw); err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(string(raw[old]), `"`) {
		t.Fatalf("token from before pairing rewritten: %s", raw[old])
	}
	if strings.Contains(string(data), "0001-01-01") {
		t.Fatal("zero times written to the tokens file")
	}
}
