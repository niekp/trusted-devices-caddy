package trusteddevices

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"slices"
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
	r.Header.Set("Sec-Fetch-Dest", "document")
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

func TestAdminPageShowsSiteOfDevices(t *testing.T) {
	m := newPairingMiddleware(t)
	adminToken := pairFirstDevice(t, m)
	r := pairingReq(home, http.MethodGet, "/", "", nil)
	r.Host = "other.example.com"
	rec, _ := serve(t, m, r)
	code := codeIn(t, rec)

	rec, _ = serve(t, m, pairingReq(home, http.MethodGet, admin, adminToken, nil))
	if !strings.Contains(rec.Body.String(), "on other.example.com") {
		t.Fatal("waiting device listed without its site")
	}
	serve(t, m, pairingReq(home, http.MethodPost, admin+"/approve", adminToken, url.Values{"code": {code}, "name": {"Acc tablet"}}))
	sites := map[string]string{}
	for _, d := range m.tokens.devices("") {
		sites[d.Name] = d.Site
	}
	if sites["Acc tablet"] != "other.example.com" || sites["iPhone"] != "example.com" {
		t.Fatalf("devices not stored with the site they paired on: %v", sites)
	}
	rec, _ = serve(t, m, pairingReq(home, http.MethodGet, admin, adminToken, nil))
	body := rec.Body.String()
	here, other := strings.Index(body, "<h3>example.com</h3>"), strings.Index(body, "<h3>other.example.com</h3>")
	if here < 0 || other < here || !strings.Contains(body[other:], "Acc tablet") {
		t.Fatalf("approved devices not grouped by site, this site first:\n%s", body)
	}
	if !strings.Contains(body, `Revoke<span class="sr-only"> Acc tablet on other.example.com</span>`) {
		t.Fatal("revoke button doesn't name the device and site it revokes")
	}
}

func TestBySiteOrdersCurrentThenNameThenUnknown(t *testing.T) {
	devices := []device{{Name: "a", Site: ""}, {Name: "b", Site: "z.example"}, {Name: "c", Site: "here"},
		{Name: "d", Site: "a.example"}, {Name: "e", Site: "z.example"}}
	var got []string
	for _, g := range bySite(devices, "here") {
		names := ""
		for _, d := range g.Devices {
			names += d.Name
		}
		got = append(got, g.Site+":"+names)
	}
	if want := []string{"here:c", "a.example:d", "z.example:be", ":a"}; !slices.Equal(got, want) {
		t.Fatalf("groups = %v, want %v", got, want)
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
	named, _ := s.addFirstDevice("Kitchen tablet", "example.com", time.Hour, false)
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
	if !strings.Contains(string(raw[named]), `"site": "example.com"`) {
		t.Fatalf("named token missing its site: %s", raw[named])
	}

	reloaded := newTokenStore(s.path, s.logger)
	reloaded.load()
	if !reloaded.isValid(plain) || !reloaded.isValid(named) || reloaded.tokens[named].Name != "Kitchen tablet" ||
		reloaded.tokens[named].Site != "example.com" {
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

func TestTokensFileThatCantBeReadDoesNotApproveByItself(t *testing.T) {
	m := newPairingMiddleware(t)
	admin := pairFirstDevice(t, m)
	before, err := os.ReadFile(m.tokens.path)
	if err != nil {
		t.Fatal(err)
	}
	m.tokens = newTokenStore(m.tokens.path, m.tokens.logger)
	if err := os.Chmod(m.tokens.path, 0); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(m.tokens.path, 0600) })
	m.tokens.load()

	if _, called := serve(t, m, pairingReq(home, http.MethodGet, "/", "", nil)); called {
		t.Fatal("a new device was approved by itself while the tokens file couldn't be read")
	}
	if err := os.Chmod(m.tokens.path, 0600); err != nil {
		t.Fatal(err)
	}
	after, err := os.ReadFile(m.tokens.path)
	if err != nil {
		t.Fatal(err)
	}
	if string(after) != string(before) {
		t.Fatal("the tokens file was overwritten while it couldn't be read")
	}
	m.tokens.lastCheck.Store(0)
	if _, called := serve(t, m, pairingReq(away, http.MethodGet, "/", admin, nil)); !called {
		t.Fatal("approved device denied once the tokens file was readable again")
	}
}

func TestFirstDeviceNotApprovedWhenItCantBeSaved(t *testing.T) {
	m := newPairingMiddleware(t)
	m.tokens = newTokenStore(filepath.Join(t.TempDir(), "missing", "tokens.json"), m.tokens.logger)
	m.tokens.load()
	if _, called := serve(t, m, pairingReq(home, http.MethodGet, "/", "", nil)); called {
		t.Fatal("first device approved although its token couldn't be saved")
	}
	if len(m.tokens.tokens) != 0 {
		t.Fatal("unsaved first device kept in memory")
	}
}

func TestApproveThatCantBeSavedKeepsWaiting(t *testing.T) {
	m := newPairingMiddleware(t)
	adminToken := pairFirstDevice(t, m)
	token, code := startPairing(t, m)
	editTokensFile(t, m.tokens, `{"half-edited": `)

	rec, _ := serve(t, m, pairingReq(home, http.MethodPost, admin+"/approve", adminToken, url.Values{"code": {code}}))
	if rec.Code != http.StatusConflict {
		t.Fatalf("approve status = %d, want 409", rec.Code)
	}
	if _, ok := m.tokens.pendingFor(token); !ok {
		t.Fatal("device no longer waiting after an approval that couldn't be saved")
	}
	if m.tokens.isPaired(token) {
		t.Fatal("device approved in memory only")
	}
}

func TestDeviceCantRevokeItself(t *testing.T) {
	m := newPairingMiddleware(t)
	adminToken := pairFirstDevice(t, m)
	rec, _ := serve(t, m, pairingReq(home, http.MethodGet, admin, adminToken, nil))
	if strings.Contains(rec.Body.String(), "/revoke") {
		t.Fatal("admin page offers to revoke the current device")
	}
	rec, _ = serve(t, m, pairingReq(home, http.MethodPost, admin+"/revoke", adminToken, url.Values{"id": {deviceID(adminToken)}}))
	if rec.Code != http.StatusConflict {
		t.Fatalf("revoke status = %d, want 409", rec.Code)
	}
	if !m.tokens.isPaired(adminToken) {
		t.Fatal("the current device revoked itself")
	}
}

func TestScriptOnTheSiteCantUseTheAdminPage(t *testing.T) {
	m := newPairingMiddleware(t)
	adminToken := pairFirstDevice(t, m)
	_, code := startPairing(t, m)

	r := pairingReq(home, http.MethodGet, admin, adminToken, nil)
	r.Header.Set("Sec-Fetch-Mode", "cors")
	r.Header.Set("Sec-Fetch-Dest", "empty")
	if rec, _ := serve(t, m, r); rec.Code != http.StatusForbidden || strings.Contains(rec.Body.String(), code) {
		t.Fatalf("fetch read the admin page: status %d", rec.Code)
	}

	r = pairingReq(home, http.MethodPost, admin+"/approve", adminToken, url.Values{"code": {code}})
	r.Header.Set("Sec-Fetch-Mode", "cors")
	r.Header.Set("Sec-Fetch-Dest", "empty")
	if rec, _ := serve(t, m, r); rec.Code != http.StatusForbidden {
		t.Fatalf("fetch post: status %d", rec.Code)
	}
	if len(m.tokens.pendingList()) != 1 {
		t.Fatal("a fetch from the site approved the device")
	}
}

func TestCodesUseOnlyTheAlphabet(t *testing.T) {
	for i := 0; i < 1000; i++ {
		code := newCode()
		if len(code) != codeLength || strings.Trim(code, codeAlphabet) != "" {
			t.Fatalf("bad code %q", code)
		}
	}
}

func newAdminsMiddleware(t *testing.T) *Middleware {
	t.Helper()
	m := newPairingMiddleware(t)
	m.Admins = true
	return m
}

// approveDevice pairs a new device at home with adminToken, and returns its token.
func approveDevice(t *testing.T, m *Middleware, adminToken string) string {
	t.Helper()
	token, code := startPairing(t, m)
	serve(t, m, pairingReq(home, http.MethodPost, admin+"/approve", adminToken, url.Values{"code": {code}, "name": {"Dad's phone"}}))
	if !m.tokens.isPaired(token) {
		t.Fatal("device not approved")
	}
	return token
}

func TestFirstDeviceIsAdmin(t *testing.T) {
	m := newAdminsMiddleware(t)
	first := pairFirstDevice(t, m)
	other := approveDevice(t, m, first)
	if !m.tokens.isAdmin(first) || m.tokens.isAdmin(other) {
		t.Fatalf("admin: first = %v, other = %v", m.tokens.isAdmin(first), m.tokens.isAdmin(other))
	}
	if raw := readTokensFile(t, m.tokens.path); !raw[first].Admin || raw[other].Admin {
		t.Fatal("admin flag not written to the tokens file")
	}
}

func TestWithAdminsOnlyAnAdminManagesDevices(t *testing.T) {
	m := newAdminsMiddleware(t)
	first := pairFirstDevice(t, m)
	other := approveDevice(t, m, first)

	// The device gets in, also from home, but not to the admin page.
	if _, called := serve(t, m, pairingReq(home, http.MethodGet, "/", other, nil)); !called {
		t.Fatal("approved device denied")
	}
	rec, called := serve(t, m, pairingReq(home, http.MethodGet, admin, other, nil))
	if called || rec.Code != http.StatusForbidden || strings.Contains(rec.Body.String(), "Trusted devices") {
		t.Fatalf("admin page shown to a device that isn't admin (status %d)", rec.Code)
	}

	_, code := startPairing(t, m)
	for _, post := range []struct {
		path string
		form url.Values
	}{
		{"/approve", url.Values{"code": {code}}},
		{"/reject", url.Values{"code": {code}}},
		{"/revoke", url.Values{"id": {deviceID(first)}}},
		{"/make-admin", url.Values{"id": {deviceID(other)}}},
	} {
		rec, _ := serve(t, m, pairingReq(home, http.MethodPost, admin+post.path, other, post.form))
		if rec.Code != http.StatusForbidden {
			t.Fatalf("%s by a device that isn't admin: status %d", post.path, rec.Code)
		}
	}
	if len(m.tokens.pendingList()) != 1 || !m.tokens.isPaired(first) || m.tokens.isAdmin(other) {
		t.Fatal("a device that isn't admin changed something")
	}

	rec, _ = serve(t, m, pairingReq(home, http.MethodGet, admin, first, nil))
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), code) {
		t.Fatalf("admin can't see the waiting code (status %d)", rec.Code)
	}
}

func TestAdminMakesAnotherAdmin(t *testing.T) {
	m := newAdminsMiddleware(t)
	first := pairFirstDevice(t, m)
	other := approveDevice(t, m, first)

	rec, _ := serve(t, m, pairingReq(home, http.MethodGet, admin, first, nil))
	if !strings.Contains(rec.Body.String(), "/make-admin") {
		t.Fatal("admin page doesn't offer to make a device admin")
	}
	rec, _ = serve(t, m, pairingReq(home, http.MethodPost, admin+"/make-admin", first, url.Values{"id": {deviceID(other)}}))
	if rec.Code != http.StatusSeeOther || !m.tokens.isAdmin(other) {
		t.Fatalf("make admin: status %d, admin %v", rec.Code, m.tokens.isAdmin(other))
	}
	if rec, _ := serve(t, m, pairingReq(home, http.MethodGet, admin, other, nil)); rec.Code != http.StatusOK {
		t.Fatalf("new admin can't open the admin page (status %d)", rec.Code)
	}
	rec, _ = serve(t, m, pairingReq(home, http.MethodPost, admin+"/make-admin", first, url.Values{"id": {deviceID(other)}}))
	if rec.Code != http.StatusConflict {
		t.Fatalf("making an admin admin again: status %d, want 409", rec.Code)
	}
}

func TestAdminByHandInTokensFile(t *testing.T) {
	m := newAdminsMiddleware(t)
	first := pairFirstDevice(t, m)
	other := approveDevice(t, m, first)

	raw := readTokensFile(t, m.tokens.path)
	info := raw[other]
	info.Admin = true
	raw[other] = info
	data, err := json.Marshal(raw)
	if err != nil {
		t.Fatal(err)
	}
	editTokensFile(t, m.tokens, string(data))

	if rec, _ := serve(t, m, pairingReq(home, http.MethodGet, admin, other, nil)); rec.Code != http.StatusOK {
		t.Fatalf("device made admin by hand can't open the admin page (status %d)", rec.Code)
	}
}

func TestAdminStillOnlyOnTrustedNetwork(t *testing.T) {
	m := newAdminsMiddleware(t)
	first := pairFirstDevice(t, m)
	if rec, called := serve(t, m, pairingReq(away, http.MethodGet, admin, first, nil)); called || rec.Code != http.StatusForbidden {
		t.Fatalf("admin page shown to an admin away from home (status %d)", rec.Code)
	}
}

func TestWithoutAdminsEveryDeviceManages(t *testing.T) {
	m := newPairingMiddleware(t)
	first := pairFirstDevice(t, m)
	other := approveDevice(t, m, first)

	rec, _ := serve(t, m, pairingReq(home, http.MethodGet, admin, other, nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("without admins a device that isn't admin can't open the admin page (status %d)", rec.Code)
	}
	if strings.Contains(rec.Body.String(), "/make-admin") || strings.Contains(rec.Body.String(), "· admin") {
		t.Fatal("admin page shows admins while the option is off")
	}
	rec, _ = serve(t, m, pairingReq(home, http.MethodPost, admin+"/make-admin", first, url.Values{"id": {deviceID(other)}}))
	if rec.Code != http.StatusNotFound || m.tokens.isAdmin(other) {
		t.Fatalf("make admin while the option is off: status %d", rec.Code)
	}
}

func TestCaddyfileAdminsOption(t *testing.T) {
	var m Middleware
	if err := m.UnmarshalCaddyfile(caddyfile.NewTestDispenser("trusted_devices {\n pairing\n admins\n}")); err != nil {
		t.Fatal(err)
	}
	if !m.Admins {
		t.Fatal("admins not set")
	}
	if err := (&Middleware{}).UnmarshalCaddyfile(caddyfile.NewTestDispenser("trusted_devices {\n admins yes\n}")); err == nil {
		t.Fatal("admins with an argument accepted")
	}

	without := newMiddleware(t)
	without.Admins = true
	if err := without.Validate(); err == nil {
		t.Fatal("admins without pairing accepted")
	}
}

// A site without admins that shares the tokens file mustn't make anyone admin where the option is on.
func TestFirstDeviceOnASiteWithoutAdminsIsNotAdmin(t *testing.T) {
	without := newPairingMiddleware(t)
	with := newAdminsMiddleware(t)
	with.TrustedTokensFile, with.tokens = without.TrustedTokensFile, without.tokens

	first := pairFirstDevice(t, without)
	if without.tokens.isAdmin(first) {
		t.Fatal("first device on a site without admins became admin")
	}
	if rec, _ := serve(t, without, pairingReq(home, http.MethodGet, admin, first, nil)); rec.Code != http.StatusOK {
		t.Fatalf("without admins the first device can't manage devices (status %d)", rec.Code)
	}
	if rec, _ := serve(t, with, pairingReq(home, http.MethodGet, admin, first, nil)); rec.Code != http.StatusForbidden {
		t.Fatalf("first device from a site without admins manages a site with admins (status %d)", rec.Code)
	}
}

func TestWithAdminsPagesSayAnAdminIsNeeded(t *testing.T) {
	m := newAdminsMiddleware(t)
	first := pairFirstDevice(t, m)
	other := approveDevice(t, m, first)

	rec, _ := serve(t, m, pairingReq(home, http.MethodGet, admin, other, nil))
	if !strings.Contains(rec.Body.String(), "only an admin device") {
		t.Fatalf("403 for a device that isn't admin doesn't say why: %q", rec.Body.String())
	}
	rec, _ = serve(t, m, pairingReq(away, http.MethodGet, admin, other, nil))
	if strings.Contains(rec.Body.String(), "admin") {
		t.Fatalf("403 away from home mentions admins: %q", rec.Body.String())
	}

	rec, _ = serve(t, m, pairingReq(home, http.MethodGet, "/", "", nil))
	if !strings.Contains(rec.Body.String(), "On an admin device") {
		t.Fatal("waiting page doesn't say to approve on an admin device")
	}
	plain := newPairingMiddleware(t)
	pairFirstDevice(t, plain)
	rec, _ = serve(t, plain, pairingReq(home, http.MethodGet, "/", "", nil))
	if !strings.Contains(rec.Body.String(), "already approved") {
		t.Fatal("waiting page without admins changed")
	}
}

func TestExpiredDeviceCantBeMadeAdmin(t *testing.T) {
	m := newAdminsMiddleware(t)
	first := pairFirstDevice(t, m)
	other := approveDevice(t, m, first)

	m.tokens.mu.Lock()
	info := m.tokens.tokens[other]
	info.Expires = time.Now().Add(-time.Minute)
	m.tokens.tokens[other] = info
	m.tokens.mu.Unlock()

	rec, _ := serve(t, m, pairingReq(home, http.MethodPost, admin+"/make-admin", first, url.Values{"id": {deviceID(other)}}))
	if rec.Code != http.StatusConflict || m.tokens.tokens[other].Admin {
		t.Fatalf("expired device made admin (status %d)", rec.Code)
	}
}
