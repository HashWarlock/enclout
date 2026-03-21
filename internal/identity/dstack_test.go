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

// fakeDstackHandler simulates the dstack TEE runtime HTTP API.
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

		body, err := io.ReadAll(r.Body)
		if err != nil {
			http.Error(w, "read body", http.StatusInternalServerError)
			return
		}
		defer r.Body.Close()

		w.Header().Set("Content-Type", "application/json")

		switch r.URL.Path {
		case "/GetKey":
			var req struct {
				Path    string `json:"path"`
				Purpose string `json:"purpose"`
			}
			if err := json.Unmarshal(body, &req); err != nil {
				http.Error(w, "bad json", http.StatusBadRequest)
				return
			}
			resp := map[string]any{
				"key":             seedHex,
				"signature_chain": []string{},
			}
			json.NewEncoder(w).Encode(resp)

		case "/GetQuote":
			var req struct {
				ReportData string `json:"report_data"`
			}
			if err := json.Unmarshal(body, &req); err != nil {
				http.Error(w, "bad json", http.StatusBadRequest)
				return
			}
			resp := map[string]any{
				"quote":     "deadbeef",
				"event_log": "[]",
			}
			json.NewEncoder(w).Encode(resp)

		case "/Info":
			resp := map[string]any{
				"app_id":      "test-app-id",
				"instance_id": "test-instance-id",
				"app_name":    "test-app",
				"tcb_info":    `{"mrtd":"abc"}`,
			}
			json.NewEncoder(w).Encode(resp)

		default:
			http.Error(w, "not found: "+r.URL.Path, http.StatusNotFound)
		}
	}
}

func TestDstackClient_GetKey(t *testing.T) {
	srv := httptest.NewServer(fakeDstackHandler(t))
	defer srv.Close()

	client := NewDstackClient(srv.URL)
	key, err := client.GetKey(context.Background(), "ssh/connector/v1", "ed25519")
	if err != nil {
		t.Fatalf("GetKey failed: %v", err)
	}

	expected := bytes.Repeat([]byte{0x42}, 32)
	if !bytes.Equal(key, expected) {
		t.Errorf("expected key %x, got %x", expected, key)
	}
}

func TestDstackClient_GetQuote(t *testing.T) {
	srv := httptest.NewServer(fakeDstackHandler(t))
	defer srv.Close()

	client := NewDstackClient(srv.URL)
	quote, eventLog, err := client.GetQuote(context.Background(), "test-data")
	if err != nil {
		t.Fatalf("GetQuote failed: %v", err)
	}

	if quote != "deadbeef" {
		t.Errorf("expected quote 'deadbeef', got %q", quote)
	}
	if eventLog != "[]" {
		t.Errorf("expected event_log '[]', got %q", eventLog)
	}
}

func TestDstackClient_Info(t *testing.T) {
	srv := httptest.NewServer(fakeDstackHandler(t))
	defer srv.Close()

	client := NewDstackClient(srv.URL)
	info, err := client.Info(context.Background())
	if err != nil {
		t.Fatalf("Info failed: %v", err)
	}

	if info.AppID != "test-app-id" {
		t.Errorf("expected app_id 'test-app-id', got %q", info.AppID)
	}
	if info.InstanceID != "test-instance-id" {
		t.Errorf("expected instance_id 'test-instance-id', got %q", info.InstanceID)
	}
	if info.AppName != "test-app" {
		t.Errorf("expected app_name 'test-app', got %q", info.AppName)
	}
}

func TestDstackDeriver_DeriveIdentity(t *testing.T) {
	srv := httptest.NewServer(fakeDstackHandler(t))
	defer srv.Close()

	client := NewDstackClient(srv.URL)
	deriver := NewDstackDeriver(client)

	identity, attestation, err := deriver.DeriveIdentity(context.Background(), "test-connector")
	if err != nil {
		t.Fatalf("DeriveIdentity failed: %v", err)
	}

	if identity.ConnectorID != "test-connector" {
		t.Errorf("expected connector_id 'test-connector', got %q", identity.ConnectorID)
	}

	if !strings.HasPrefix(identity.SSHPublicKey, "ssh-ed25519 ") {
		t.Errorf("expected ssh-ed25519 prefix, got %q", identity.SSHPublicKey)
	}

	if identity.PublicKeyHex == "" {
		t.Error("expected non-empty PublicKeyHex")
	}

	if len(identity.FingerprintSHA256) != 64 {
		t.Errorf("expected 64-char fingerprint, got %d chars", len(identity.FingerprintSHA256))
	}

	if attestation.QuoteHex != "deadbeef" {
		t.Errorf("expected quote 'deadbeef', got %q", attestation.QuoteHex)
	}
}

func TestDstackDeriver_EmptyConnectorID(t *testing.T) {
	srv := httptest.NewServer(fakeDstackHandler(t))
	defer srv.Close()

	client := NewDstackClient(srv.URL)
	deriver := NewDstackDeriver(client)

	_, _, err := deriver.DeriveIdentity(context.Background(), "")
	if err == nil {
		t.Error("expected error for empty connectorID")
	}
}

func TestEnvDeriver_DeriveIdentity(t *testing.T) {
	// Set up environment for the test.
	seed := bytes.Repeat([]byte{0x42}, ed25519.SeedSize)
	seedB64 := "QkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkI=" // base64 of 32 x 0x42

	t.Setenv("TEE_SEED_B64", seedB64)
	t.Setenv("TEE_QUOTE_HEX", "cafebabe")
	t.Setenv("TEE_MRTD", "test-mrtd")
	t.Setenv("TEE_POLICY_VERSION", "v1")

	deriver := &EnvDeriver{}
	identity, attestation, err := deriver.DeriveIdentity(context.Background(), "env-connector")
	if err != nil {
		t.Fatalf("DeriveIdentity failed: %v", err)
	}

	if identity.ConnectorID != "env-connector" {
		t.Errorf("expected connector_id 'env-connector', got %q", identity.ConnectorID)
	}

	// Verify the key matches what we expect from this seed.
	pub, _, _ := DeriveEd25519(seed)
	expectedSSH, _ := SSHPublicKeyString(pub)
	if identity.SSHPublicKey != expectedSSH {
		t.Errorf("SSH key mismatch:\n  got:    %s\n  expect: %s", identity.SSHPublicKey, expectedSSH)
	}

	if attestation.QuoteHex != "cafebabe" {
		t.Errorf("expected quote 'cafebabe', got %q", attestation.QuoteHex)
	}
	if attestation.MRTD != "test-mrtd" {
		t.Errorf("expected MRTD 'test-mrtd', got %q", attestation.MRTD)
	}
	if attestation.PolicyVersion != "v1" {
		t.Errorf("expected PolicyVersion 'v1', got %q", attestation.PolicyVersion)
	}
}

func TestEnvDeriver_MissingSeed(t *testing.T) {
	// Ensure TEE_SEED_B64 is not set.
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
