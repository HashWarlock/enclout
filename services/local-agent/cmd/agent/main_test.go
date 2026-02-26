package main

import (
	"testing"
	"time"
)

func TestLoadTrustedControlPlaneSigningKeysFromEnvIsOptional(t *testing.T) {
	t.Setenv("CONTROL_PLANE_SIGNING_KEYS_JSON", "")
	t.Setenv("CONTROL_PLANE_SIGNING_PUBKEY_B64", "")
	t.Setenv("CONTROL_PLANE_SIGNING_KID", "")

	keys, err := loadTrustedControlPlaneSigningKeysFromEnv()
	if err != nil {
		t.Fatalf("expected no error when signing key bootstrap is unset, got: %v", err)
	}
	if len(keys) != 0 {
		t.Fatalf("expected no bootstrap keys, got: %#v", keys)
	}
}

func TestLoadTrustedControlPlaneSigningKeysFromEnvSingleKeyFallback(t *testing.T) {
	t.Setenv("CONTROL_PLANE_SIGNING_KEYS_JSON", "")
	t.Setenv("CONTROL_PLANE_SIGNING_PUBKEY_B64", "AAAA")
	t.Setenv("CONTROL_PLANE_SIGNING_KID", "v9")

	keys, err := loadTrustedControlPlaneSigningKeysFromEnv()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(keys) != 1 || keys["v9"] != "AAAA" {
		t.Fatalf("unexpected keys map: %#v", keys)
	}
}

func TestParseDurationOrDefaultHandlesDurationAndSeconds(t *testing.T) {
	if got := parseDurationOrDefault("10m", 5*time.Minute); got != 10*time.Minute {
		t.Fatalf("expected 10m, got %s", got)
	}
	if got := parseDurationOrDefault("45", 5*time.Minute); got != 45*time.Second {
		t.Fatalf("expected 45s, got %s", got)
	}
	if got := parseDurationOrDefault("bad", 5*time.Minute); got != 5*time.Minute {
		t.Fatalf("expected fallback duration, got %s", got)
	}
}
