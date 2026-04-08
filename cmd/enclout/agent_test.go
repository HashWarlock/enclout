package main

import (
	"testing"

	"enclout/internal/config"
)

func TestAgentCmd_RegistersAllowListFlags(t *testing.T) {
	cmd := agentCmd()

	if cmd.Flags().Lookup("allow-mrtd") == nil {
		t.Fatal("expected allow-mrtd flag to be registered")
	}
	if cmd.Flags().Lookup("allow-rtmr3") == nil {
		t.Fatal("expected allow-rtmr3 flag to be registered")
	}
}

func TestLoadAgentConfig_AppliesEnvAndParsesAllowLists(t *testing.T) {
	t.Setenv("ENCLOUT_SERVER", "https://control.example")
	t.Setenv("ENCLOUT_DEVICE_ID", "device-1")
	t.Setenv("ENCLOUT_USERNAME", "deploy")
	t.Setenv("ENCLOUT_DCAP_URL", "https://dcap.example")
	t.Setenv("ENCLOUT_ALLOW_MRTD", " mrtd-a , , mrtd-b ")
	t.Setenv("ENCLOUT_ALLOW_RTMR3", " rtmr3-a,rtmr3-b ")

	cmd := agentCmd()
	bindEnvDefaults(cmd, map[string]string{
		"server":      "ENCLOUT_SERVER",
		"device-id":   "ENCLOUT_DEVICE_ID",
		"username":    "ENCLOUT_USERNAME",
		"dcap-url":    "ENCLOUT_DCAP_URL",
		"allow-mrtd":  "ENCLOUT_ALLOW_MRTD",
		"allow-rtmr3": "ENCLOUT_ALLOW_RTMR3",
		"log-format":  "ENCLOUT_LOG_FORMAT",
	})

	var cfg config.AgentConfig
	if err := loadAgentConfig(cmd, &cfg); err != nil {
		t.Fatalf("unexpected error loading config: %v", err)
	}

	if cfg.Server != "https://control.example" {
		t.Fatalf("expected server from env, got %q", cfg.Server)
	}
	if cfg.DeviceID != "device-1" {
		t.Fatalf("expected device ID from env, got %q", cfg.DeviceID)
	}
	if cfg.Username != "deploy" {
		t.Fatalf("expected username from env, got %q", cfg.Username)
	}
	if cfg.DCAPUrl != "https://dcap.example" {
		t.Fatalf("expected DCAP URL from env, got %q", cfg.DCAPUrl)
	}

	wantMRTD := []string{"mrtd-a", "mrtd-b"}
	if len(cfg.AllowMRTD) != len(wantMRTD) {
		t.Fatalf("expected MRTD allowlist %#v, got %#v", wantMRTD, cfg.AllowMRTD)
	}
	for i := range wantMRTD {
		if cfg.AllowMRTD[i] != wantMRTD[i] {
			t.Fatalf("expected MRTD allowlist %#v, got %#v", wantMRTD, cfg.AllowMRTD)
		}
	}

	wantRTMR3 := []string{"rtmr3-a", "rtmr3-b"}
	if len(cfg.AllowRTMR3) != len(wantRTMR3) {
		t.Fatalf("expected RTMR3 allowlist %#v, got %#v", wantRTMR3, cfg.AllowRTMR3)
	}
	for i := range wantRTMR3 {
		if cfg.AllowRTMR3[i] != wantRTMR3[i] {
			t.Fatalf("expected RTMR3 allowlist %#v, got %#v", wantRTMR3, cfg.AllowRTMR3)
		}
	}
}

func TestLoadAgentConfig_RejectsMalformedAllowListEnv(t *testing.T) {
	t.Setenv("ENCLOUT_SERVER", "https://control.example")
	t.Setenv("ENCLOUT_DEVICE_ID", "device-1")
	t.Setenv("ENCLOUT_USERNAME", "deploy")
	t.Setenv("ENCLOUT_DCAP_URL", "https://dcap.example")
	t.Setenv("ENCLOUT_ALLOW_MRTD", ",")

	cmd := agentCmd()
	bindEnvDefaults(cmd, map[string]string{
		"server":     "ENCLOUT_SERVER",
		"device-id":  "ENCLOUT_DEVICE_ID",
		"username":   "ENCLOUT_USERNAME",
		"dcap-url":   "ENCLOUT_DCAP_URL",
		"allow-mrtd": "ENCLOUT_ALLOW_MRTD",
	})

	var cfg config.AgentConfig
	if err := loadAgentConfig(cmd, &cfg); err == nil {
		t.Fatal("expected malformed allowlist env to fail")
	}
}
