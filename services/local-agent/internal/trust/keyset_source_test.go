package trust

import (
	"context"
	"errors"
	"testing"
	"time"

	"enclout/services/local-agent/internal/api"
)

type fetchResult struct {
	keyset api.SigningKeyset
	err    error
}

type fakeKeysetFetcher struct {
	results []fetchResult
	calls   int
}

func (f *fakeKeysetFetcher) GetSigningKeyset(_ context.Context) (api.SigningKeyset, error) {
	i := f.calls
	f.calls++
	if i >= len(f.results) {
		return api.SigningKeyset{}, errors.New("unexpected fetch")
	}
	return f.results[i].keyset, f.results[i].err
}

func TestTrustedKeysUsesBootstrapCacheBeforeTTL(t *testing.T) {
	now := time.Date(2026, time.February, 25, 10, 0, 0, 0, time.UTC)
	clock := func() time.Time { return now }
	fetcher := &fakeKeysetFetcher{
		results: []fetchResult{
			{
				keyset: api.SigningKeyset{
					ActiveKID: "v2",
					Keys: []api.SigningKeyInfo{
						{KID: "v2", Alg: "ed25519", PublicKeyB64: "BBBB"},
					},
				},
			},
		},
	}

	source := newKeysetSource(fetcher, map[string]string{"v1": "AAAA"}, 5*time.Minute, clock)
	got, err := source.TrustedKeys(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if fetcher.calls != 0 {
		t.Fatalf("expected zero fetches while bootstrap cache is fresh, got %d", fetcher.calls)
	}
	if got["v1"] != "AAAA" {
		t.Fatalf("unexpected bootstrap keyset: %#v", got)
	}
}

func TestTrustedKeysFetchesAndCachesRemoteKeyset(t *testing.T) {
	now := time.Date(2026, time.February, 25, 10, 0, 0, 0, time.UTC)
	clock := func() time.Time { return now }
	fetcher := &fakeKeysetFetcher{
		results: []fetchResult{
			{
				keyset: api.SigningKeyset{
					ActiveKID: "v2",
					Keys: []api.SigningKeyInfo{
						{KID: "v1", Alg: "ed25519", PublicKeyB64: "AAAA"},
						{KID: "v2", Alg: "ed25519", PublicKeyB64: "BBBB"},
					},
				},
			},
		},
	}

	source := newKeysetSource(fetcher, nil, 5*time.Minute, clock)

	first, err := source.TrustedKeys(context.Background())
	if err != nil {
		t.Fatalf("unexpected error from first fetch: %v", err)
	}
	if fetcher.calls != 1 {
		t.Fatalf("expected one fetch call, got %d", fetcher.calls)
	}
	if len(first) != 2 || first["v1"] != "AAAA" || first["v2"] != "BBBB" {
		t.Fatalf("unexpected fetched keyset: %#v", first)
	}

	now = now.Add(2 * time.Minute)
	second, err := source.TrustedKeys(context.Background())
	if err != nil {
		t.Fatalf("unexpected error from cache read: %v", err)
	}
	if fetcher.calls != 1 {
		t.Fatalf("expected cached read without extra fetch, got %d calls", fetcher.calls)
	}
	if len(second) != 2 || second["v1"] != "AAAA" || second["v2"] != "BBBB" {
		t.Fatalf("unexpected cached keyset: %#v", second)
	}
}

func TestTrustedKeysFailClosedAfterCacheExpiryIfRefreshFails(t *testing.T) {
	now := time.Date(2026, time.February, 25, 10, 0, 0, 0, time.UTC)
	clock := func() time.Time { return now }
	fetcher := &fakeKeysetFetcher{
		results: []fetchResult{
			{err: errors.New("control-plane unavailable")},
		},
	}

	source := newKeysetSource(fetcher, map[string]string{"v1": "AAAA"}, 5*time.Minute, clock)

	_, err := source.TrustedKeys(context.Background())
	if err != nil {
		t.Fatalf("unexpected error while bootstrap cache is fresh: %v", err)
	}
	if fetcher.calls != 0 {
		t.Fatalf("expected no remote call while cache is fresh, got %d", fetcher.calls)
	}

	now = now.Add(6 * time.Minute)
	_, err = source.TrustedKeys(context.Background())
	if err == nil {
		t.Fatalf("expected error after cache expiry and refresh failure")
	}
	if fetcher.calls != 1 {
		t.Fatalf("expected one refresh attempt after expiry, got %d", fetcher.calls)
	}
}
