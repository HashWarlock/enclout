package config

import (
	"encoding/json"
	"fmt"
	"os"
)

const (
	defaultBindAddr  = "127.0.0.1:8080"
	defaultStorePath = "./var/control-plane-requests.json"
)

type Config struct {
	BindAddr         string
	SigningKeyB64    string
	SigningKeys      map[string]string
	SigningActiveKID string
	APIToken         string
	StorePath        string
}

func Load() (Config, error) {
	cfg := Config{
		BindAddr:         os.Getenv("BIND_ADDR"),
		SigningKeyB64:    os.Getenv("SIGNING_KEY_B64"),
		SigningActiveKID: os.Getenv("SIGNING_ACTIVE_KID"),
		APIToken:         os.Getenv("API_AUTH_TOKEN"),
		StorePath:        os.Getenv("STORE_PATH"),
	}

	if cfg.BindAddr == "" {
		cfg.BindAddr = defaultBindAddr
	}

	if cfg.SigningKeyB64 == "" {
		if err := loadSigningKeysFromEnv(&cfg); err != nil {
			return Config{}, err
		}
	} else {
		if cfg.SigningActiveKID == "" {
			cfg.SigningActiveKID = "v1"
		}
		cfg.SigningKeys = map[string]string{
			cfg.SigningActiveKID: cfg.SigningKeyB64,
		}
	}
	if cfg.APIToken == "" {
		return Config{}, fmt.Errorf("missing API_AUTH_TOKEN")
	}
	if cfg.StorePath == "" {
		cfg.StorePath = defaultStorePath
	}

	return cfg, nil
}

func loadSigningKeysFromEnv(cfg *Config) error {
	raw := os.Getenv("SIGNING_KEYS_JSON")
	if raw == "" {
		return fmt.Errorf("missing SIGNING_KEY_B64")
	}

	var keys map[string]string
	if err := json.Unmarshal([]byte(raw), &keys); err != nil {
		return fmt.Errorf("invalid SIGNING_KEYS_JSON: %w", err)
	}
	if len(keys) == 0 {
		return fmt.Errorf("SIGNING_KEYS_JSON must include at least one key")
	}
	if cfg.SigningActiveKID == "" {
		return fmt.Errorf("missing SIGNING_ACTIVE_KID")
	}
	if _, ok := keys[cfg.SigningActiveKID]; !ok {
		return fmt.Errorf("SIGNING_ACTIVE_KID %q not found in SIGNING_KEYS_JSON", cfg.SigningActiveKID)
	}

	cfg.SigningKeys = keys
	return nil
}
