package trusteddevices

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"go.uber.org/zap"
)

// editTokensFile replaces the tokens file by hand, as an admin would, and lets the next request look at it.
func editTokensFile(t *testing.T, s *tokenStore, content string) {
	t.Helper()
	if err := os.WriteFile(s.path, []byte(content), 0600); err != nil {
		t.Fatal(err)
	}
	// Make sure the change is visible even on a file system with coarse timestamps.
	later := time.Now().Add(time.Minute)
	if err := os.Chtimes(s.path, later, later); err != nil {
		t.Fatal(err)
	}
	s.mu.Lock()
	s.lastCheck.Store(0)
	s.mu.Unlock()
}

func readTokensFile(t *testing.T, path string) map[string]tokenInfo {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var tokens map[string]tokenInfo
	if err := json.Unmarshal(data, &tokens); err != nil {
		t.Fatalf("tokens file not valid JSON: %v", err)
	}
	return tokens
}

func newLoadedStore(t *testing.T) *tokenStore {
	t.Helper()
	s := newTokenStore(filepath.Join(t.TempDir(), "tokens.json"), zap.NewNop())
	s.load()
	return s
}

func TestEmptyingTokensFileRevokesWithoutRestart(t *testing.T) {
	s := newLoadedStore(t)
	token := s.issue(time.Hour)
	if !s.isValid(token) {
		t.Fatal("new token is not valid")
	}
	editTokensFile(t, s, "{}")
	if s.isValid(token) {
		t.Fatal("token still valid after emptying the tokens file")
	}
}

func TestRemovingOneTokenKeepsTheOthers(t *testing.T) {
	s := newLoadedStore(t)
	lost := s.issue(time.Hour)
	kept := s.issue(time.Hour)
	tokens := readTokensFile(t, s.path)
	delete(tokens, lost)
	data, _ := json.Marshal(tokens)
	editTokensFile(t, s, string(data))
	if s.isValid(lost) {
		t.Fatal("removed token is still valid")
	}
	if !s.isValid(kept) {
		t.Fatal("token left in the file was revoked too")
	}
}

// An editor that saves by moving the old file aside leaves a moment without one; that must not revoke anything, nor
// may a save in that moment write the old set back.
func TestMissingTokensFileKeepsTokensAndIsNotRecreated(t *testing.T) {
	s := newLoadedStore(t)
	token := s.issue(time.Hour)
	if err := os.Remove(s.path); err != nil {
		t.Fatal(err)
	}
	s.lastCheck.Store(0)
	if !s.isValid(token) {
		t.Fatal("token revoked while the tokens file was briefly missing")
	}
	s.issue(time.Hour)
	if _, err := os.Stat(s.path); !os.IsNotExist(err) {
		t.Fatal("a save recreated the tokens file while it was missing")
	}

	editTokensFile(t, s, "{}")
	if s.isValid(token) {
		t.Fatal("token still valid after the file came back empty")
	}
}

func TestNextIssueKeepsHandEdits(t *testing.T) {
	s := newLoadedStore(t)
	revoked := s.issue(time.Hour)
	editTokensFile(t, s, "{}")
	// No request came in between: issuing must still read the edit first instead of writing the old set back.
	fresh := s.issue(time.Hour)
	tokens := readTokensFile(t, s.path)
	if _, ok := tokens[revoked]; ok {
		t.Fatal("next save wrote the revoked token back")
	}
	if _, ok := tokens[fresh]; !ok {
		t.Fatal("new token missing from the tokens file")
	}
}

// An editor that empties the file before writing it leaves a moment where it can't be parsed; tokens must survive
// that, and nothing may be written over the file until it's whole again.
func TestUnparsableTokensFileKeepsTokensAndIsNotOverwritten(t *testing.T) {
	s := newLoadedStore(t)
	token := s.issue(time.Hour)
	for _, content := range []string{"", `{"half-edited": `} {
		editTokensFile(t, s, content)
		if !s.isValid(token) {
			t.Fatalf("token revoked while the tokens file read %q", content)
		}
		s.issue(time.Hour)
		if data, _ := os.ReadFile(s.path); string(data) != content {
			t.Fatalf("tokens file was overwritten: %s", data)
		}
	}

	editTokensFile(t, s, "{}")
	if s.isValid(token) {
		t.Fatal("token still valid after the file was fixed without it")
	}
	fresh := s.issue(time.Hour)
	if _, ok := readTokensFile(t, s.path)[fresh]; !ok {
		t.Fatal("saving didn't resume after the file was fixed")
	}
}

func TestEditDuringAnotherSaveIsKept(t *testing.T) {
	s := newLoadedStore(t)
	revoked := s.issue(time.Hour)
	// The file changes between a request reading it and a new token being written.
	s.update(func() bool {
		later := time.Now().Add(time.Minute)
		os.WriteFile(s.path, []byte("{}"), 0600)
		os.Chtimes(s.path, later, later)
		return false
	})
	s.issue(time.Hour)
	if _, ok := readTokensFile(t, s.path)[revoked]; ok {
		t.Fatal("a save wrote a revoked token back")
	}
}

func TestOwnSaveIsNotReadBackAsAnEdit(t *testing.T) {
	s := newLoadedStore(t)
	token := s.issue(time.Hour)
	s.mu.Lock()
	s.tokens["only-in-memory"] = tokenInfo{Expires: time.Now().Add(time.Hour)}
	s.lastCheck.Store(0)
	s.mu.Unlock()
	if !s.isValid("only-in-memory") || !s.isValid(token) {
		t.Fatal("an unchanged tokens file replaced the tokens in memory")
	}
}
