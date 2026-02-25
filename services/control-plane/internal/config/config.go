package config

import (
	"fmt"
	"os"
)

const (
	defaultBindAddr = "127.0.0.1:8080"
)

type Config struct {
	BindAddr      string
	SigningKeyB64 string
}

func Load() (Config, error) {
	cfg := Config{
		BindAddr:      os.Getenv("BIND_ADDR"),
		SigningKeyB64: os.Getenv("SIGNING_KEY_B64"),
	}

	if cfg.BindAddr == "" {
		cfg.BindAddr = defaultBindAddr
	}

	if cfg.SigningKeyB64 == "" {
		return Config{}, fmt.Errorf("missing SIGNING_KEY_B64")
	}

	return cfg, nil
}
