package config

import (
	"fmt"
	"strings"
	"time"
)

type ServeConfig struct {
	Bind             string
	DB               string
	ConnectorID      string
	AuthToken        string
	SigningKeyB64    string
	SigningKeysJSON  string
	SigningActiveKID string
	LogFormat        string
}

func (c ServeConfig) Validate() error {
	if c.AuthToken == "" {
		return fmt.Errorf("auth token is required")
	}
	if c.SigningKeyB64 == "" && c.SigningKeysJSON == "" {
		return fmt.Errorf("at least one signing key is required (--signing-key or --signing-keys-json)")
	}
	return nil
}

type AgentConfig struct {
	Server           string
	DeviceID         string
	Username         string
	Token            string
	PollInterval     time.Duration
	KeysDir          string
	DCAPUrl          string
	DCAPToken        string
	DCAPTimeout      time.Duration
	AllowMRTD        []string
	AllowRTMR3       []string
	SigningKeysJSON  string
	SigningPubkeyB64 string
	SigningCacheTTL  time.Duration
	LogFormat        string
}

func (c AgentConfig) Validate() error {
	if c.Server == "" {
		return fmt.Errorf("server URL is required")
	}
	if c.DeviceID == "" {
		return fmt.Errorf("device ID is required")
	}
	if c.Username == "" {
		return fmt.Errorf("username is required")
	}
	if c.DCAPUrl == "" {
		return fmt.Errorf("DCAP verifier URL is required")
	}
	return nil
}

// DefaultAgentConfig returns an AgentConfig with sensible defaults filled in.
func DefaultAgentConfig() AgentConfig {
	return AgentConfig{
		PollInterval:    5 * time.Second,
		KeysDir:         "~/.enclout/keys",
		DCAPTimeout:     10 * time.Second,
		SigningCacheTTL: 5 * time.Minute,
		LogFormat:       "text",
	}
}

// DefaultServeConfig returns a ServeConfig with sensible defaults filled in.
func DefaultServeConfig() ServeConfig {
	return ServeConfig{
		Bind:      "127.0.0.1:8080",
		DB:        "./enclout.db",
		LogFormat: "text",
	}
}

// ParseAllowList splits a comma-separated allowlist string into trimmed values.
// Empty segments are ignored. A blank input returns nil, nil.
// If the input is non-empty but yields no entries, the input is malformed.
func ParseAllowList(raw string) ([]string, error) {
	if strings.TrimSpace(raw) == "" {
		return nil, nil
	}

	parts := strings.Split(raw, ",")
	out := make([]string, 0, len(parts))
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		out = append(out, part)
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("allowlist must contain at least one value")
	}
	return out, nil
}
