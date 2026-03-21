package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"enclout/internal/agent"
	"enclout/internal/attestation"
	"enclout/internal/client"
	"enclout/internal/config"

	"github.com/spf13/cobra"
)

// jsonUnmarshal is a thin wrapper for json.Unmarshal used by the client adapter.
func jsonUnmarshal(data []byte, v any) error {
	return json.Unmarshal(data, v)
}

func agentCmd() *cobra.Command {
	cfg := config.DefaultAgentConfig()

	cmd := &cobra.Command{
		Use:   "agent",
		Short: "Start the local agent daemon",
		RunE: func(cmd *cobra.Command, args []string) error {
			// Apply env var fallbacks.
			bindEnvDefaults(cmd, map[string]string{
				"server":        "ENCLOUT_SERVER",
				"device-id":     "ENCLOUT_DEVICE_ID",
				"username":      "ENCLOUT_USERNAME",
				"token":         "ENCLOUT_TOKEN",
				"poll-interval": "ENCLOUT_POLL_INTERVAL",
				"keys-dir":      "ENCLOUT_KEYS_DIR",
				"dcap-url":      "ENCLOUT_DCAP_URL",
				"dcap-token":    "ENCLOUT_DCAP_TOKEN",
				"dcap-timeout":  "ENCLOUT_DCAP_TIMEOUT",
				"log-format":    "ENCLOUT_LOG_FORMAT",
			})

			// Re-read flag values after env fallback.
			cfg.Server, _ = cmd.Flags().GetString("server")
			cfg.DeviceID, _ = cmd.Flags().GetString("device-id")
			cfg.Username, _ = cmd.Flags().GetString("username")
			cfg.Token, _ = cmd.Flags().GetString("token")
			cfg.PollInterval, _ = cmd.Flags().GetDuration("poll-interval")
			cfg.KeysDir, _ = cmd.Flags().GetString("keys-dir")
			cfg.DCAPUrl, _ = cmd.Flags().GetString("dcap-url")
			cfg.DCAPToken, _ = cmd.Flags().GetString("dcap-token")
			cfg.DCAPTimeout, _ = cmd.Flags().GetDuration("dcap-timeout")
			cfg.LogFormat, _ = cmd.Flags().GetString("log-format")

			if err := cfg.Validate(); err != nil {
				return fmt.Errorf("invalid configuration: %w", err)
			}

			// Set up logger.
			logger := newLogger(cfg.LogFormat)

			// Create HTTP client.
			apiClient := client.New(cfg.Server, cfg.Token)

			// Create adapter that bridges client.Client to the agent interfaces.
			adapter := &clientAdapter{client: apiClient}

			// Create prompter (CLI-only for now; no native desktop prompt).
			cliPrompt := agent.NewCLIPrompter(os.Stdin, os.Stdout)
			prompter := agent.NewPrompter(nil, cliPrompt)

			// Create DCAP verifier.
			dcapVerifier, err := attestation.NewHTTPDCAPVerifier(cfg.DCAPUrl, cfg.DCAPToken, cfg.DCAPTimeout)
			if err != nil {
				return fmt.Errorf("create DCAP verifier: %w", err)
			}

			// Build measurement policy from allowlists.
			policy := attestation.NewStaticPolicy(cfg.AllowMRTD, cfg.AllowRTMR3)

			// Create strict verifier combining DCAP + policy.
			verifier := attestation.NewStrictVerifier(dcapVerifier, policy)

			// Create SSH key installer.
			keyManager := agent.NewSSHKeyManager(cfg.KeysDir)

			// Create keyset source for trusted signing key verification.
			keysetSource := agent.NewKeysetSource(apiClient, nil, cfg.SigningCacheTTL)

			// Create runner with all dependencies.
			runner := agent.NewRunner(adapter, prompter, verifier, keyManager, keysetSource, logger)

			// Create daemon.
			daemon := agent.NewDaemon(adapter, runner, cfg.DeviceID, cfg.PollInterval, logger)

			// Set up graceful shutdown context.
			ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
			defer stop()

			// Run daemon (blocks until context is cancelled).
			return daemon.Run(ctx)
		},
	}

	cmd.Flags().StringVar(&cfg.Server, "server", cfg.Server, "Control plane URL (required)")
	cmd.Flags().StringVar(&cfg.DeviceID, "device-id", cfg.DeviceID, "Local device identifier (required)")
	cmd.Flags().StringVar(&cfg.Username, "username", cfg.Username, "SSH username (required)")
	cmd.Flags().StringVar(&cfg.Token, "token", cfg.Token, "Bearer auth token")
	cmd.Flags().DurationVar(&cfg.PollInterval, "poll-interval", cfg.PollInterval, "Poll interval")
	cmd.Flags().StringVar(&cfg.KeysDir, "keys-dir", cfg.KeysDir, "SSH keys directory")
	cmd.Flags().StringVar(&cfg.DCAPUrl, "dcap-url", cfg.DCAPUrl, "DCAP verifier URL (required)")
	cmd.Flags().StringVar(&cfg.DCAPToken, "dcap-token", cfg.DCAPToken, "DCAP verifier token")
	cmd.Flags().DurationVar(&cfg.DCAPTimeout, "dcap-timeout", cfg.DCAPTimeout, "DCAP timeout")
	cmd.Flags().StringVar(&cfg.LogFormat, "log-format", cfg.LogFormat, "Log format (text|json)")

	return cmd
}

// clientAdapter bridges client.Client to the agent.PendingPoller and
// agent.RequestClient interfaces.
type clientAdapter struct {
	client *client.Client
}

// ListPending adapts client.Client.ListPending ([]RequestResponse) to
// agent.PendingPoller ([]PendingRequest).
func (a *clientAdapter) ListPending(ctx context.Context, deviceID string) ([]agent.PendingRequest, error) {
	responses, err := a.client.ListPending(ctx, deviceID)
	if err != nil {
		return nil, err
	}
	out := make([]agent.PendingRequest, len(responses))
	for i, r := range responses {
		out[i] = agent.PendingRequest{
			ID:          r.ID,
			ConnectorID: r.ConnectorID,
			LocalUser:   r.DeviceID, // best available mapping
		}
	}
	return out, nil
}

// PostDecision delegates to client.Client.PostDecision.
func (a *clientAdapter) PostDecision(ctx context.Context, requestID string, approved bool) error {
	return a.client.PostDecision(ctx, requestID, approved)
}

// GetBundle adapts client.Client.GetBundle (json.RawMessage) to
// agent.SignedBundle.
func (a *clientAdapter) GetBundle(ctx context.Context, requestID string) (agent.SignedBundle, error) {
	raw, err := a.client.GetBundle(ctx, requestID)
	if err != nil {
		return agent.SignedBundle{}, err
	}

	var envelope struct {
		Payload   map[string]any `json:"payload"`
		Signature string         `json:"signature"`
		Alg       string         `json:"alg"`
		KID       string         `json:"kid"`
	}
	if err := jsonUnmarshal(raw, &envelope); err != nil {
		return agent.SignedBundle{}, fmt.Errorf("parse signed bundle: %w", err)
	}

	// Extract the raw payload bytes for signature verification.
	var rawPayload struct {
		Payload json.RawMessage `json:"payload"`
	}
	if err := jsonUnmarshal(raw, &rawPayload); err != nil {
		return agent.SignedBundle{}, fmt.Errorf("extract raw payload: %w", err)
	}

	return agent.SignedBundle{
		Payload:    envelope.Payload,
		PayloadRaw: []byte(rawPayload.Payload),
		Signature:  envelope.Signature,
		Alg:        envelope.Alg,
		KID:        envelope.KID,
	}, nil
}

// PostResult delegates to client.Client.PostResult.
func (a *clientAdapter) PostResult(ctx context.Context, requestID string, status string, reasonCode string) error {
	return a.client.PostResult(ctx, requestID, status, reasonCode)
}
