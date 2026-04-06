package identity

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
)

// fakeDstackHandler simulates the dstack TEE runtime HTTP API as expected by
// the official dstack Go SDK (github.com/Dstack-TEE/dstack/sdk/go/dstack).
func fakeDstackHandler(t *testing.T) http.HandlerFunc {
	t.Helper()

	// A deterministic 32-byte seed for testing.
	seed := bytes.Repeat([]byte{0x42}, ed25519.SeedSize)
	seedHex := hex.EncodeToString(seed)

	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}

		body, _ := io.ReadAll(r.Body)
		defer r.Body.Close()
		_ = body

		w.Header().Set("Content-Type", "application/json")

		switch r.URL.Path {
		case "/Version":
			// Required by the SDK before any non-secp256k1 algorithm (e.g. ed25519).
			json.NewEncoder(w).Encode(map[string]any{
				"version": "0.5.7",
				"rev":     "test",
			})

		case "/GetKey":
			json.NewEncoder(w).Encode(map[string]any{
				"key":             seedHex,
				"signature_chain": []string{},
			})

		case "/GetQuote":
			json.NewEncoder(w).Encode(map[string]any{
				"quote":       "deadbeef",
				"event_log":   "[]",
				"report_data": "",
				"vm_config":   "",
			})

		case "/Info":
			json.NewEncoder(w).Encode(map[string]any{
				"app_id":      "test-app-id",
				"instance_id": "test-instance-id",
				"app_name":    "test-app",
				"tcb_info":    `{"mrtd":"abc","rtmr0":"","rtmr1":"","rtmr2":"","rtmr3":""}`,
			})

		default:
			http.Error(w, "not found: "+r.URL.Path, http.StatusNotFound)
		}
	}
}

// startFakeDstack starts a fake dstack server, sets DSTACK_SIMULATOR_ENDPOINT,
// and returns a cleanup function.
func startFakeDstack(t *testing.T) {
	t.Helper()
	srv := httptest.NewServer(fakeDstackHandler(t))
	t.Cleanup(srv.Close)
	t.Setenv("DSTACK_SIMULATOR_ENDPOINT", srv.URL)
}

func TestDstackDeriver_DeriveIdentity(t *testing.T) {
	startFakeDstack(t)

	deriver := NewDstackDeriver()
	id, att, err := deriver.DeriveIdentity(context.Background(), "test-connector")
	if err != nil {
		t.Fatalf("DeriveIdentity failed: %v", err)
	}

	if id.ConnectorID != "test-connector" {
		t.Errorf("expected connector_id 'test-connector', got %q", id.ConnectorID)
	}

	if !strings.HasPrefix(id.SSHPublicKey, "ssh-ed25519 ") {
		t.Errorf("expected ssh-ed25519 prefix, got %q", id.SSHPublicKey)
	}

	if id.PublicKeyHex == "" {
		t.Error("expected non-empty PublicKeyHex")
	}

	if len(id.FingerprintSHA256) != 64 {
		t.Errorf("expected 64-char fingerprint, got %d chars", len(id.FingerprintSHA256))
	}

	if att.QuoteHex != "deadbeef" {
		t.Errorf("expected quote 'deadbeef', got %q", att.QuoteHex)
	}

	if att.MRTD != "abc" {
		t.Errorf("expected MRTD 'abc', got %q", att.MRTD)
	}

	// ReportDataExpectedSHA256 must be the SHA256 of the SSH public key (hex).
	if len(att.ReportDataExpectedSHA256) != 64 {
		t.Errorf("expected 64-char report data hash, got %d", len(att.ReportDataExpectedSHA256))
	}
}

func TestDstackDeriver_EmptyConnectorID(t *testing.T) {
	startFakeDstack(t)

	deriver := NewDstackDeriver()
	_, _, err := deriver.DeriveIdentity(context.Background(), "")
	if err == nil {
		t.Error("expected error for empty connectorID")
	}
}

func TestEnvDeriver_DeriveIdentity(t *testing.T) {
	seed := bytes.Repeat([]byte{0x42}, ed25519.SeedSize)
	seedB64 := "QkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkI=" // base64 of 32 x 0x42

	t.Setenv("TEE_SEED_B64", seedB64)
	t.Setenv("TEE_QUOTE_HEX", "cafebabe")
	t.Setenv("TEE_MRTD", "test-mrtd")
	t.Setenv("TEE_POLICY_VERSION", "v1")

	deriver := &EnvDeriver{}
	id, att, err := deriver.DeriveIdentity(context.Background(), "env-connector")
	if err != nil {
		t.Fatalf("DeriveIdentity failed: %v", err)
	}

	if id.ConnectorID != "env-connector" {
		t.Errorf("expected connector_id 'env-connector', got %q", id.ConnectorID)
	}

	pub, _, _ := DeriveEd25519(seed)
	expectedSSH, _ := SSHPublicKeyString(pub)
	if id.SSHPublicKey != expectedSSH {
		t.Errorf("SSH key mismatch:\n  got:    %s\n  expect: %s", id.SSHPublicKey, expectedSSH)
	}

	if att.QuoteHex != "cafebabe" {
		t.Errorf("expected quote 'cafebabe', got %q", att.QuoteHex)
	}
	if att.MRTD != "test-mrtd" {
		t.Errorf("expected MRTD 'test-mrtd', got %q", att.MRTD)
	}
	if att.PolicyVersion != "v1" {
		t.Errorf("expected PolicyVersion 'v1', got %q", att.PolicyVersion)
	}
}

func TestEnvDeriver_MissingSeed(t *testing.T) {
	os.Unsetenv("TEE_SEED_B64")

	deriver := &EnvDeriver{}
	_, _, err := deriver.DeriveIdentity(context.Background(), "test")
	if err == nil {
		t.Error("expected error for missing TEE_SEED_B64")
	}
}

func TestEnvDeriver_EmptyConnectorID(t *testing.T) {
	t.Setenv("TEE_SEED_B64", "QkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkI=")

	deriver := &EnvDeriver{}
	_, _, err := deriver.DeriveIdentity(context.Background(), "")
	if err == nil {
		t.Error("expected error for empty connectorID")
	}
}
