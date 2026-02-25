package integration

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

type bundleFixture struct {
	Payload struct {
		RequestID                string `json:"request_id"`
		ConnectorID              string `json:"connector_id"`
		SSHPublicKey             string `json:"ssh_public_key"`
		QuoteHex                 string `json:"quote_hex"`
		MRTD                     string `json:"mrtd"`
		RTMR0                    string `json:"rtmr0"`
		RTMR1                    string `json:"rtmr1"`
		RTMR2                    string `json:"rtmr2"`
		RTMR3                    string `json:"rtmr3"`
		ReportDataExpectedSHA256 string `json:"report_data_expected_sha256"`
	} `json:"payload"`
	Signature string `json:"signature"`
}

func TestStrictFlowSuccessFixture(t *testing.T) {
	bundle := readBundleFixture(t, "valid_bundle.json")
	if bundle.Payload.SSHPublicKey == "" {
		t.Fatalf("expected ssh_public_key in valid fixture")
	}
	if bundle.Payload.QuoteHex == "" {
		t.Fatalf("expected quote_hex in valid fixture")
	}
	if bundle.Signature == "" {
		t.Fatalf("expected signature in valid fixture")
	}
}

func TestStrictFlowMismatchFixture(t *testing.T) {
	bundle := readBundleFixture(t, "mismatched_report_data_bundle.json")
	if bundle.Payload.ReportDataExpectedSHA256 == "ec7ef73f196ba6f9fd696d4d1f4a15f16ec14ce53b0ff32117f5e98a6ce3b542" {
		t.Fatalf("expected mismatched fixture to carry different report_data hash")
	}
}

func readBundleFixture(t *testing.T, name string) bundleFixture {
	t.Helper()
	path := filepath.Join("testdata", name)
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read fixture %s: %v", path, err)
	}
	var out bundleFixture
	if err := json.Unmarshal(raw, &out); err != nil {
		t.Fatalf("unmarshal fixture %s: %v", path, err)
	}
	return out
}
