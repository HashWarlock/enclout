package config

import "testing"

func TestLoadConfigRequired(t *testing.T) {
	t.Setenv("BIND_ADDR", "127.0.0.1:8080")
	t.Setenv("SIGNING_KEY_B64", "")
	t.Setenv("API_AUTH_TOKEN", "tok")

	_, err := Load()
	if err == nil {
		t.Fatal("expected error for missing SIGNING_KEY_B64")
	}

	if err.Error() != "missing SIGNING_KEY_B64" {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestLoadConfigDefaultsBindAddress(t *testing.T) {
	t.Setenv("BIND_ADDR", "")
	t.Setenv("SIGNING_KEY_B64", "ZmFrZS1zaWduaW5nLWtleS0xMjM0NTY3ODkwMTIzNDU2Nzg5MDE=")
	t.Setenv("API_AUTH_TOKEN", "tok")

	cfg, err := Load()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if cfg.BindAddr != defaultBindAddr {
		t.Fatalf("expected default bind addr %q, got %q", defaultBindAddr, cfg.BindAddr)
	}
	if cfg.StorePath != defaultStorePath {
		t.Fatalf("expected default store path %q, got %q", defaultStorePath, cfg.StorePath)
	}
}

func TestLoadConfigRequiresAPIToken(t *testing.T) {
	t.Setenv("BIND_ADDR", "127.0.0.1:8080")
	t.Setenv("SIGNING_KEY_B64", "ZmFrZS1zaWduaW5nLWtleS0xMjM0NTY3ODkwMTIzNDU2Nzg5MDE=")
	t.Setenv("API_AUTH_TOKEN", "")

	_, err := Load()
	if err == nil {
		t.Fatal("expected error for missing API_AUTH_TOKEN")
	}
	if err.Error() != "missing API_AUTH_TOKEN" {
		t.Fatalf("unexpected error: %v", err)
	}
}
