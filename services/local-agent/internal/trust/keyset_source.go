package trust

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"time"

	"enclout/services/local-agent/internal/api"
)

const DefaultKeysetCacheTTL = 5 * time.Minute

type SigningKeysetFetcher interface {
	GetSigningKeyset(ctx context.Context) (api.SigningKeyset, error)
}

type KeysetSource struct {
	fetcher SigningKeysetFetcher
	ttl     time.Duration
	now     func() time.Time

	mu        sync.RWMutex
	trusted   map[string]string
	expiresAt time.Time
}

func NewKeysetSource(fetcher SigningKeysetFetcher, bootstrap map[string]string, ttl time.Duration) *KeysetSource {
	return newKeysetSource(fetcher, bootstrap, ttl, time.Now)
}

func newKeysetSource(fetcher SigningKeysetFetcher, bootstrap map[string]string, ttl time.Duration, now func() time.Time) *KeysetSource {
	if ttl <= 0 {
		ttl = DefaultKeysetCacheTTL
	}
	if now == nil {
		now = time.Now
	}

	source := &KeysetSource{
		fetcher: fetcher,
		ttl:     ttl,
		now:     now,
	}

	if cached := copyTrustedKeyMap(bootstrap); len(cached) > 0 {
		source.trusted = cached
		source.expiresAt = now().UTC().Add(ttl)
	}

	return source
}

func (s *KeysetSource) TrustedKeys(ctx context.Context) (map[string]string, error) {
	now := s.now().UTC()
	if cached, ok := s.cachedIfFresh(now); ok {
		return cached, nil
	}

	if s.fetcher == nil {
		return nil, fmt.Errorf("refresh signing keyset: no fetcher configured")
	}

	keyset, err := s.fetcher.GetSigningKeyset(ctx)
	if err != nil {
		return nil, fmt.Errorf("refresh signing keyset: %w", err)
	}

	trusted, err := trustedMapFromKeyset(keyset)
	if err != nil {
		return nil, fmt.Errorf("refresh signing keyset: %w", err)
	}

	s.mu.Lock()
	s.trusted = trusted
	s.expiresAt = now.Add(s.ttl)
	s.mu.Unlock()

	return copyTrustedKeyMap(trusted), nil
}

func (s *KeysetSource) cachedIfFresh(now time.Time) (map[string]string, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	if len(s.trusted) == 0 || !now.Before(s.expiresAt) {
		return nil, false
	}
	return copyTrustedKeyMap(s.trusted), true
}

func trustedMapFromKeyset(keyset api.SigningKeyset) (map[string]string, error) {
	if len(keyset.Keys) == 0 {
		return nil, fmt.Errorf("keyset is empty")
	}

	out := make(map[string]string, len(keyset.Keys))
	for _, key := range keyset.Keys {
		kid := strings.TrimSpace(key.KID)
		alg := strings.TrimSpace(key.Alg)
		pub := strings.TrimSpace(key.PublicKeyB64)

		if kid == "" || pub == "" {
			return nil, fmt.Errorf("keyset contains empty kid or public key")
		}
		if alg != "ed25519" {
			return nil, fmt.Errorf("unsupported signing key algorithm %q", alg)
		}
		out[kid] = pub
	}

	active := strings.TrimSpace(keyset.ActiveKID)
	if active != "" {
		if _, ok := out[active]; !ok {
			return nil, fmt.Errorf("active kid %q missing from keyset", active)
		}
	}
	return out, nil
}

func copyTrustedKeyMap(in map[string]string) map[string]string {
	if len(in) == 0 {
		return nil
	}
	out := make(map[string]string, len(in))
	for kid, key := range in {
		kid = strings.TrimSpace(kid)
		key = strings.TrimSpace(key)
		if kid == "" || key == "" {
			continue
		}
		out[kid] = key
	}
	if len(out) == 0 {
		return nil
	}
	return out
}
