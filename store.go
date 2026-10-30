package trusteddevices

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/caddyserver/caddy/v2"
	"github.com/google/uuid"
	"go.uber.org/zap"
)

const cleanupInterval = time.Hour

// reloadCheckInterval limits how often a request checks the tokens file for changes made by hand.
const reloadCheckInterval = time.Second

// tokenStores shares one store per tokens file across all handler instances and config reloads.
var tokenStores = caddy.NewUsagePool()

// tokenStore holds the tokens of one tokens file; every handler using that file shares it.
type tokenStore struct {
	path        string
	tokens      map[string]time.Time
	mu          sync.RWMutex
	saveMu      sync.Mutex // serializes writes to the tokens file
	stopCleanup chan struct{}
	logger      *zap.Logger

	// What the tokens file looked like when it was last read or written, so a change made by hand (removing a
	// token, emptying or deleting the file) is picked up without a restart and not overwritten by the next save.
	fileSeen  bool
	fileMod   time.Time
	fileSize  int64
	lastCheck time.Time
	// broken is set while the tokens file can't be parsed: no token is valid, and saving won't overwrite the file.
	broken bool
}

// acquireTokenStore returns the shared store for path, loading it from disk on first use.
func acquireTokenStore(path string, logger *zap.Logger) (*tokenStore, error) {
	value, _, err := tokenStores.LoadOrNew(path, func() (caddy.Destructor, error) {
		store := newTokenStore(path, logger)
		store.load()
		go store.cleanupLoop(cleanupInterval)
		return store, nil
	})
	if err != nil {
		return nil, err
	}
	return value.(*tokenStore), nil
}

// releaseTokenStore drops one reference; the last release stops the store.
func releaseTokenStore(path string) {
	_, _ = tokenStores.Delete(path)
}

func newTokenStore(path string, logger *zap.Logger) *tokenStore {
	return &tokenStore{
		path:        path,
		tokens:      make(map[string]time.Time),
		stopCleanup: make(chan struct{}),
		logger:      logger,
	}
}

// Destruct stops the background cleanup goroutine.
func (s *tokenStore) Destruct() error {
	close(s.stopCleanup)
	return nil
}

// load reads the tokens file, dropping expired tokens.
func (s *tokenStore) load() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.lastCheck = time.Now()
	if _, err := os.Stat(s.path); os.IsNotExist(err) {
		s.logger.Info("tokens file does not exist yet, will be created on first use", zap.String("file", s.path))
		return
	}
	s.syncLocked()
}

// refresh picks up changes to the tokens file, at most once per reloadCheckInterval.
func (s *tokenStore) refresh() {
	s.mu.Lock()
	defer s.mu.Unlock()
	if now := time.Now(); now.Sub(s.lastCheck) >= reloadCheckInterval {
		s.lastCheck = now
		s.syncLocked()
	}
}

// syncLocked replaces the tokens in memory with the file's when the file changed since it was last read or
// written. A deleted file revokes every token; a file that can't be parsed makes every token invalid until it's
// fixed. The caller holds s.mu.
func (s *tokenStore) syncLocked() {
	info, err := os.Stat(s.path)
	if os.IsNotExist(err) {
		if s.fileSeen {
			s.logger.Info("tokens file removed, revoking all tokens", zap.String("file", s.path))
			s.tokens = make(map[string]time.Time)
			s.fileSeen = false
			s.broken = false
		}
		return
	}
	if err != nil {
		s.logger.Warn("could not check tokens file", zap.String("file", s.path), zap.Error(err))
		return
	}
	if s.fileSeen && info.ModTime().Equal(s.fileMod) && info.Size() == s.fileSize {
		return
	}
	s.fileSeen, s.fileMod, s.fileSize = true, info.ModTime(), info.Size()

	data, err := os.ReadFile(s.path)
	if err != nil {
		s.logger.Warn("could not load tokens file", zap.String("file", s.path), zap.Error(err))
		return
	}
	tokens := make(map[string]time.Time)
	if err := json.Unmarshal(data, &tokens); err != nil {
		s.logger.Error("failed to parse tokens file, denying all tokens until it is fixed", zap.String("file", s.path), zap.Error(err))
		s.tokens = make(map[string]time.Time)
		s.broken = true
		return
	}
	s.tokens = tokens
	s.broken = false
	s.removeExpired(time.Now())
	s.logger.Info("loaded trusted tokens", zap.Int("count", len(s.tokens)), zap.String("file", s.path))
}

// isValid reports whether token exists and has not expired.
func (s *tokenStore) isValid(token string) bool {
	s.refresh()
	s.mu.RLock()
	expiry, exists := s.tokens[token]
	s.mu.RUnlock()
	return exists && time.Now().Before(expiry)
}

// issue creates and persists a new token valid for maxAge.
func (s *tokenStore) issue(maxAge time.Duration) string {
	token := uuid.New().String()

	s.mu.Lock()
	s.syncLocked()
	s.tokens[token] = time.Now().Add(maxAge)
	s.mu.Unlock()

	if err := s.save(); err != nil {
		s.logger.Error("failed to save token", zap.Error(err))
	}
	return token
}

// cleanupLoop periodically removes expired tokens until the store is destructed.
func (s *tokenStore) cleanupLoop(interval time.Duration) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-s.stopCleanup:
			return
		case <-ticker.C:
			s.pruneExpired()
		}
	}
}

// pruneExpired removes expired tokens from memory and persists the result.
func (s *tokenStore) pruneExpired() {
	s.mu.Lock()
	s.syncLocked()
	changed := s.removeExpired(time.Now())
	s.mu.Unlock()

	if changed {
		if err := s.save(); err != nil {
			s.logger.Error("failed to save tokens after prune", zap.Error(err))
		}
	}
}

// removeExpired deletes tokens expired at now; the caller holds the lock if needed.
func (s *tokenStore) removeExpired(now time.Time) bool {
	changed := false
	for token, expiry := range s.tokens {
		if now.After(expiry) {
			delete(s.tokens, token)
			changed = true
		}
	}
	return changed
}

// save atomically persists the tokens to file with 0600 permissions.
func (s *tokenStore) save() error {
	s.saveMu.Lock()
	defer s.saveMu.Unlock()

	s.mu.RLock()
	broken := s.broken
	data, err := json.MarshalIndent(s.tokens, "", "  ")
	count := len(s.tokens)
	s.mu.RUnlock()
	if broken {
		return fmt.Errorf("tokens file %s can't be parsed, not overwriting it", s.path)
	}
	if err != nil {
		return fmt.Errorf("marshaling tokens: %w", err)
	}

	dir := filepath.Dir(s.path)
	tmp, err := os.CreateTemp(dir, ".trusted_tokens-*.tmp")
	if err != nil {
		return fmt.Errorf("creating temp tokens file: %w", err)
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName) // no-op if the rename succeeded

	if err := tmp.Chmod(0600); err != nil {
		tmp.Close()
		return fmt.Errorf("chmod temp tokens file: %w", err)
	}
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return fmt.Errorf("writing temp tokens file: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("closing temp tokens file: %w", err)
	}
	if err := os.Rename(tmpName, s.path); err != nil {
		return fmt.Errorf("renaming tokens file: %w", err)
	}
	if info, err := os.Stat(s.path); err == nil {
		s.mu.Lock()
		s.fileSeen, s.fileMod, s.fileSize = true, info.ModTime(), info.Size()
		s.mu.Unlock()
	}

	s.logger.Debug("saved tokens to file", zap.String("file", s.path), zap.Int("count", count))
	return nil
}
