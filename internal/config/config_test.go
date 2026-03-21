package config_test

import (
	"testing"

	"enclout/internal/config"
)

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
