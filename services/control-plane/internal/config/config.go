package config

import (
	"fmt"
	"os"
)

const (
	defaultBindAddr  = "127.0.0.1:8080"
	defaultStorePath = "./var/control-plane-requests.json"
)

type Config struct {
	BindAddr      string
	SigningKeyB64 string
	APIToken      string
	StorePath     string
}

func Load() (Config, error) {
	cfg := Config{
		BindAddr:      os.Getenv("BIND_ADDR"),
		SigningKeyB64: os.Getenv("SIGNING_KEY_B64"),
		APIToken:      os.Getenv("API_AUTH_TOKEN"),
		StorePath:     os.Getenv("STORE_PATH"),
	}

	if cfg.BindAddr == "" {
		cfg.BindAddr = defaultBindAddr
	}

	if cfg.SigningKeyB64 == "" {
		return Config{}, fmt.Errorf("missing SIGNING_KEY_B64")
	}
	if cfg.APIToken == "" {
		return Config{}, fmt.Errorf("missing API_AUTH_TOKEN")
	}
	if cfg.StorePath == "" {
		cfg.StorePath = defaultStorePath
	}

	return cfg, nil
}
