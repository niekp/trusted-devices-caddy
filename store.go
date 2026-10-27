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
	data, err := os.ReadFile(s.path)
	if os.IsNotExist(err) {
		s.logger.Info("tokens file does not exist yet, will be created on first use", zap.String("file", s.path))
		return
	}
	if err != nil {
		s.logger.Warn("could not load tokens file", zap.String("file", s.path), zap.Error(err))
		return
	}
	if err := json.Unmarshal(data, &s.tokens); err != nil {
		s.logger.Error("failed to parse tokens file", zap.String("file", s.path), zap.Error(err))
		return
	}
	s.removeExpired(time.Now())
	s.logger.Info("loaded trusted tokens", zap.Int("count", len(s.tokens)), zap.String("file", s.path))
}

// isValid reports whether token exists and has not expired.
func (s *tokenStore) isValid(token string) bool {
	s.mu.RLock()
	expiry, exists := s.tokens[token]
	s.mu.RUnlock()
	return exists && time.Now().Before(expiry)
}

// issue creates and persists a new token valid for maxAge.
func (s *tokenStore) issue(maxAge time.Duration) string {
	token := uuid.New().String()

	s.mu.Lock()
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
	data, err := json.MarshalIndent(s.tokens, "", "  ")
	count := len(s.tokens)
	s.mu.RUnlock()
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

	s.logger.Debug("saved tokens to file", zap.String("file", s.path), zap.Int("count", count))
	return nil
}
