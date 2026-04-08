package config_test

import (
	"path/filepath"
	"testing"

	"enclout/internal/config"
)

func TestParseAllowList_EmptyInput(t *testing.T) {
	got := config.ParseAllowList("")
	if len(got) != 0 {
		t.Fatalf("expected empty result, got %#v", got)
	}
}

func TestParseAllowList_SingleValue(t *testing.T) {
	got := config.ParseAllowList("mrtd-123")
	want := []string{"mrtd-123"}
	if len(got) != len(want) || got[0] != want[0] {
		t.Fatalf("expected %#v, got %#v", want, got)
	}
}

func TestParseAllowList_MultipleValues(t *testing.T) {
	got := config.ParseAllowList("mrtd-123,rtmr3-456,abc-789")
	want := []string{"mrtd-123", "rtmr3-456", "abc-789"}
	if len(got) != len(want) {
		t.Fatalf("expected %#v, got %#v", want, got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("expected %#v, got %#v", want, got)
		}
	}
}

func TestParseAllowList_WhitespaceTrimming(t *testing.T) {
	got := config.ParseAllowList("  mrtd-123 , ,  rtmr3-456  ,   abc-789   ")
	want := []string{"mrtd-123", "rtmr3-456", "abc-789"}
	if len(got) != len(want) {
		t.Fatalf("expected %#v, got %#v", want, got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("expected %#v, got %#v", want, got)
		}
	}
}

func TestParseAllowList_IgnoresEmptySegments(t *testing.T) {
	got := config.ParseAllowList(",")
	if len(got) != 0 {
		t.Fatalf("expected empty result, got %#v", got)
	}
}

func TestServeConfig_Validate_MissingAuthToken(t *testing.T) {
	c := config.DefaultServeConfig()
	c.SigningKeyB64 = "some-key"
	// AuthToken is empty
	if err := c.Validate(); err == nil {
		t.Fatal("expected error for missing auth token")
	}
}

func TestServeConfig_Validate_MissingSigningKey(t *testing.T) {
	c := config.DefaultServeConfig()
	c.AuthToken = "some-token"
	// Both signing keys empty
	if err := c.Validate(); err == nil {
		t.Fatal("expected error for missing signing key")
	}
}

func TestServeConfig_Validate_Valid(t *testing.T) {
	c := config.DefaultServeConfig()
	c.AuthToken = "some-token"
	c.SigningKeyB64 = "some-key"
	if err := c.Validate(); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestAgentConfig_Validate_MissingServer(t *testing.T) {
	c := config.DefaultAgentConfig()
	c.DeviceID = "dev-1"
	c.Username = "deploy"
	c.DCAPUrl = "http://dcap"
	if err := c.Validate(); err == nil {
		t.Fatal("expected error for missing server")
	}
}

func TestAgentConfig_Validate_MissingDeviceID(t *testing.T) {
	c := config.DefaultAgentConfig()
	c.Server = "http://server"
	c.Username = "deploy"
	c.DCAPUrl = "http://dcap"
	if err := c.Validate(); err == nil {
		t.Fatal("expected error for missing device ID")
	}
}

func TestAgentConfig_Validate_Valid(t *testing.T) {
	c := config.DefaultAgentConfig()
	c.Server = "http://server"
	c.DeviceID = "dev-1"
	c.Username = "deploy"
	c.DCAPUrl = "http://dcap"
	if err := c.Validate(); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestDefaultAgentConfig_SetsAuditDir(t *testing.T) {
	t.Setenv("HOME", "/home/tester")

	c := config.DefaultAgentConfig()
	want := filepath.Join("/home/tester", ".enclout", "audit")
	if c.AuditDir != want {
		t.Fatalf("expected audit dir %q, got %q", want, c.AuditDir)
	}
}
