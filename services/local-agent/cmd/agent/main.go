package main

import (
	"context"
	"log"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"

	"enclout/services/local-agent/internal/api"
	"enclout/services/local-agent/internal/approval"
	"enclout/services/local-agent/internal/flow"
	"enclout/services/local-agent/internal/sshkeys"
	"enclout/services/local-agent/internal/verify"
)

func main() {
	controlPlaneURL := mustEnv("CONTROL_PLANE_URL")
	deviceID := mustEnv("DEVICE_ID")
	localUser := mustEnv("LOCAL_USERNAME")
	token := os.Getenv("AGENT_TOKEN")
	keysDir := os.Getenv("MANAGED_KEYS_DIR")
	if keysDir == "" {
		keysDir = "/var/lib/connector-agent/keys"
	}

	apiClient := api.NewClient(controlPlaneURL, token)
	prompter := approval.NewPrompter(approval.NewNativePrompter(), approval.NewCLIPrompter(os.Stdin, os.Stdout))
	policy := verify.NewStaticPolicy(splitCSV(os.Getenv("ALLOW_MRTD")), splitCSV(os.Getenv("ALLOW_RTMR3")))
	dcapVerifier, err := verify.NewHTTPDCAPVerifier(
		mustEnv("DCAP_VERIFIER_URL"),
		os.Getenv("DCAP_VERIFIER_TOKEN"),
		parseDurationOrDefault(os.Getenv("DCAP_VERIFIER_TIMEOUT"), 10*time.Second),
	)
	if err != nil {
		log.Fatalf("create dcap verifier: %v", err)
	}
	verifier := verify.NewStrictVerifier(dcapVerifier, policy)
	keyManager := sshkeys.NewManager(keysDir)
	runner := flow.NewRunner(apiClient, prompter, verifier, keyManager)

	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()

	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()

	log.Printf("local-agent started for device %s", deviceID)
	for {
		select {
		case <-ctx.Done():
			log.Printf("local-agent shutting down")
			return
		case <-ticker.C:
			pending, err := apiClient.PollPending(ctx, deviceID)
			if err != nil {
				log.Printf("poll pending requests failed: %v", err)
				continue
			}
			for _, req := range pending {
				err := runner.Process(ctx, flow.Request{
					ID:          req.ID,
					ConnectorID: req.ConnectorID,
					LocalUser:   localUser,
				})
				if err != nil {
					log.Printf("request %s failed: %v", req.ID, err)
				}
			}
		}
	}
}

func mustEnv(name string) string {
	v := os.Getenv(name)
	if v == "" {
		log.Fatalf("missing required env var %s", name)
	}
	return v
}

func splitCSV(v string) []string {
	if strings.TrimSpace(v) == "" {
		return nil
	}
	parts := strings.Split(v, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p != "" {
			out = append(out, p)
		}
	}
	return out
}

func parseDurationOrDefault(raw string, fallback time.Duration) time.Duration {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return fallback
	}
	if seconds, err := strconv.Atoi(raw); err == nil && seconds > 0 {
		return time.Duration(seconds) * time.Second
	}
	dur, err := time.ParseDuration(raw)
	if err != nil || dur <= 0 {
		return fallback
	}
	return dur
}
