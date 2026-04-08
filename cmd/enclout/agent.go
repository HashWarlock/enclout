package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"path/filepath"
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
				"audit-dir":     "ENCLOUT_AUDIT_DIR",
				"dcap-url":      "ENCLOUT_DCAP_URL",
				"dcap-token":    "ENCLOUT_DCAP_TOKEN",
				"dcap-timeout":  "ENCLOUT_DCAP_TIMEOUT",
				"allow-mrtd":    "ENCLOUT_ALLOW_MRTD",
				"allow-rtmr3":   "ENCLOUT_ALLOW_RTMR3",
				"log-format":    "ENCLOUT_LOG_FORMAT",
			})

			if err := loadAgentConfig(cmd, &cfg); err != nil {
				return fmt.Errorf("invalid configuration: %w", err)
			}

			cfg.AuditDir = expandHomeDir(cfg.AuditDir)

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
			auditSink := filesystemAuditSink{dir: cfg.AuditDir}
			runner := newAgentRunner(adapter, prompter, verifier, keyManager, keysetSource, cfg.Username, logger, auditSink)

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
	cmd.Flags().StringVar(&cfg.AuditDir, "audit-dir", cfg.AuditDir, "Audit sink directory")
	cmd.Flags().StringVar(&cfg.DCAPUrl, "dcap-url", cfg.DCAPUrl, "DCAP verifier URL (required)")
	cmd.Flags().StringVar(&cfg.DCAPToken, "dcap-token", cfg.DCAPToken, "DCAP verifier token")
	cmd.Flags().DurationVar(&cfg.DCAPTimeout, "dcap-timeout", cfg.DCAPTimeout, "DCAP timeout")
	cmd.Flags().String("allow-mrtd", "", "Comma-separated MRTD allowlist")
	cmd.Flags().String("allow-rtmr3", "", "Comma-separated RTMR3 allowlist")
	cmd.Flags().StringVar(&cfg.LogFormat, "log-format", cfg.LogFormat, "Log format (text|json)")

	return cmd
}

type filesystemAuditSink struct {
	dir string
}

func (s filesystemAuditSink) Ready(_ context.Context) error {
	if err := os.MkdirAll(s.dir, 0o700); err != nil {
		return fmt.Errorf("prepare audit sink dir: %w", err)
	}
	f, err := os.CreateTemp(s.dir, ".audit-ready-*")
	if err != nil {
		return fmt.Errorf("create audit sink temp file: %w", err)
	}
	name := f.Name()
	if closeErr := f.Close(); closeErr != nil {
		_ = os.Remove(name)
		return fmt.Errorf("close audit sink temp file: %w", closeErr)
	}
	if err := os.Remove(name); err != nil {
		return fmt.Errorf("remove audit sink temp file: %w", err)
	}
	return nil
}

func newAgentRunner(
	client agent.RequestClient,
	prompter agent.DecisionSource,
	verifier agent.BundleVerifier,
	keyInstaller agent.KeyInstaller,
	trustedKeys agent.TrustedKeySource,
	username string,
	logger *slog.Logger,
	auditSink agent.AuditSink,
) *agent.Runner {
	return agent.NewRunnerWithUsernameAndAuditSink(client, prompter, verifier, keyInstaller, trustedKeys, username, auditSink, logger)
}

func loadAgentConfig(cmd *cobra.Command, cfg *config.AgentConfig) error {
	var err error
	cfg.Server, err = cmd.Flags().GetString("server")
	if err != nil {
		return err
	}
	cfg.DeviceID, err = cmd.Flags().GetString("device-id")
	if err != nil {
		return err
	}
	cfg.Username, err = cmd.Flags().GetString("username")
	if err != nil {
		return err
	}
	cfg.Token, err = cmd.Flags().GetString("token")
	if err != nil {
		return err
	}
	cfg.PollInterval, err = cmd.Flags().GetDuration("poll-interval")
	if err != nil {
		return err
	}
	cfg.KeysDir, err = cmd.Flags().GetString("keys-dir")
	if err != nil {
		return err
	}
	cfg.AuditDir, err = cmd.Flags().GetString("audit-dir")
	if err != nil {
		return err
	}
	cfg.DCAPUrl, err = cmd.Flags().GetString("dcap-url")
	if err != nil {
		return err
	}
	cfg.DCAPToken, err = cmd.Flags().GetString("dcap-token")
	if err != nil {
		return err
	}
	cfg.DCAPTimeout, err = cmd.Flags().GetDuration("dcap-timeout")
	if err != nil {
		return err
	}

	cfg.AllowMRTD = config.ParseAllowList(mustGetString(cmd, "allow-mrtd"))
	cfg.AllowRTMR3 = config.ParseAllowList(mustGetString(cmd, "allow-rtmr3"))

	cfg.LogFormat, err = cmd.Flags().GetString("log-format")
	return err
}

func mustGetString(cmd *cobra.Command, flagName string) string {
	v, _ := cmd.Flags().GetString(flagName)
	return v
}

func expandHomeDir(path string) string {
	if len(path) < 2 || path[:2] != "~/" {
		return path
	}

	home, err := os.UserHomeDir()
	if err != nil || home == "" {
		return path
	}

	return filepath.Join(home, path[2:])
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
			LocalUser:   "",
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
