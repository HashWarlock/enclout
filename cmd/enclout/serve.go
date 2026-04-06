package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"enclout/internal/config"
	"enclout/internal/identity"
	"enclout/internal/server"
	"enclout/internal/signing"
	"enclout/internal/store"
	"enclout/migrations"

	"github.com/spf13/cobra"
)

func serveCmd() *cobra.Command {
	cfg := config.DefaultServeConfig()

	cmd := &cobra.Command{
		Use:   "serve",
		Short: "Start the control plane HTTP server",
		RunE: func(cmd *cobra.Command, args []string) error {
			// Apply env var fallbacks for flags not explicitly set.
			bindEnvDefaults(cmd, map[string]string{
				"bind":              "ENCLOUT_BIND",
				"db":                "ENCLOUT_DB",
				"connector-id":     "ENCLOUT_CONNECTOR_ID",
				"auth-token":       "ENCLOUT_AUTH_TOKEN",
				"signing-key":      "ENCLOUT_SIGNING_KEY_B64",
				"signing-keys-json": "ENCLOUT_SIGNING_KEYS_JSON",
				"signing-active-kid": "ENCLOUT_SIGNING_ACTIVE_KID",
				"log-format":       "ENCLOUT_LOG_FORMAT",
			})

			// Re-read flag values after env fallback.
			cfg.Bind, _ = cmd.Flags().GetString("bind")
			cfg.DB, _ = cmd.Flags().GetString("db")
			cfg.ConnectorID, _ = cmd.Flags().GetString("connector-id")
			cfg.AuthToken, _ = cmd.Flags().GetString("auth-token")
			cfg.SigningKeyB64, _ = cmd.Flags().GetString("signing-key")
			cfg.SigningKeysJSON, _ = cmd.Flags().GetString("signing-keys-json")
			cfg.SigningActiveKID, _ = cmd.Flags().GetString("signing-active-kid")
			cfg.LogFormat, _ = cmd.Flags().GetString("log-format")

			if err := cfg.Validate(); err != nil {
				return fmt.Errorf("invalid configuration: %w", err)
			}

			// Set up logger.
			logger := newLogger(cfg.LogFormat)

			// Open SQLite database with migrations.
			db, err := store.Open(cfg.DB, migrations.FS)
			if err != nil {
				return fmt.Errorf("open database: %w", err)
			}
			defer db.Close()

			// Build signing key(s).
			signer, err := buildSigner(cfg)
			if err != nil {
				return fmt.Errorf("configure signing: %w", err)
			}

			// Build dependencies.
			deps := server.Deps{
				DB:       db,
				Requests: store.NewRequestRepository(db),
				Sessions: store.NewSessionRepository(db),
				Bundles:  store.NewBundleRepository(db),
				Audit:    store.NewAuditLogger(db),
				Signer:   signer,
			}

			// Set up graceful shutdown context.
			ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
			defer stop()

			// Auto-register connector bundle if connector-id is set.
			if cfg.ConnectorID != "" {
				if err := registerConnectorBundle(ctx, cfg.ConnectorID, deps.Bundles, logger); err != nil {
					logger.Warn("connector auto-registration failed", "error", err)
				}
			}

			// Create server.
			srv := server.New(server.Config{
				Bind:      cfg.Bind,
				AuthToken: cfg.AuthToken,
				Logger:    logger,
			}, deps)

			// Start expiration goroutine.
			srv.StartExpiration(ctx)

			// Start server in a goroutine.
			errCh := make(chan error, 1)
			go func() {
				logger.Info("server starting", "bind", cfg.Bind)
				if err := srv.Start(); err != nil && !errors.Is(err, http.ErrServerClosed) {
					errCh <- err
				}
				close(errCh)
			}()

			// Wait for shutdown signal or server error.
			select {
			case <-ctx.Done():
				logger.Info("shutting down server")
				shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
				defer cancel()
				if err := srv.Shutdown(shutdownCtx); err != nil {
					return fmt.Errorf("shutdown: %w", err)
				}
				logger.Info("server stopped")
				return nil
			case err := <-errCh:
				if err != nil {
					return fmt.Errorf("server: %w", err)
				}
				return nil
			}
		},
	}

	cmd.Flags().StringVar(&cfg.Bind, "bind", cfg.Bind, "Listen address")
	cmd.Flags().StringVar(&cfg.DB, "db", cfg.DB, "SQLite database path")
	cmd.Flags().StringVar(&cfg.ConnectorID, "connector-id", cfg.ConnectorID, "Connector ID for TEE mode")
	cmd.Flags().StringVar(&cfg.AuthToken, "auth-token", cfg.AuthToken, "Bearer auth token (required)")
	cmd.Flags().StringVar(&cfg.SigningKeyB64, "signing-key", cfg.SigningKeyB64, "Base64-encoded Ed25519 signing seed")
	cmd.Flags().StringVar(&cfg.SigningKeysJSON, "signing-keys-json", cfg.SigningKeysJSON, "JSON map of KID -> base64 seed")
	cmd.Flags().StringVar(&cfg.SigningActiveKID, "signing-active-kid", "v1", "Active signing key ID")
	cmd.Flags().StringVar(&cfg.LogFormat, "log-format", cfg.LogFormat, "Log format (text|json)")

	return cmd
}

// buildSigner creates a BundleSigner from the serve config: either a single
// Ed25519 key or a keyset with an active KID.
func buildSigner(cfg config.ServeConfig) (signing.BundleSigner, error) {
	if cfg.SigningKeysJSON != "" {
		var seedMap map[string]string
		if err := json.Unmarshal([]byte(cfg.SigningKeysJSON), &seedMap); err != nil {
			return nil, fmt.Errorf("parse signing-keys-json: %w", err)
		}
		return signing.NewSignerSetFromSeedMap(seedMap, cfg.SigningActiveKID)
	}
	return signing.NewEd25519SignerFromSeedB64(cfg.SigningKeyB64)
}

// newLogger creates an slog.Logger based on the log format string.
func newLogger(format string) *slog.Logger {
	var handler slog.Handler
	switch format {
	case "json":
		handler = slog.NewJSONHandler(os.Stderr, nil)
	default:
		handler = slog.NewTextHandler(os.Stderr, nil)
	}
	return slog.New(handler)
}

// registerConnectorBundle derives a TEE identity and registers the connector
// bundle in the local database on startup. The dstack SDK reads
// DSTACK_SIMULATOR_ENDPOINT automatically; in a CVM it falls back to
// /var/run/dstack.sock.
func registerConnectorBundle(ctx context.Context, connectorID string, bundles *store.BundleRepository, logger *slog.Logger) error {
	deriver := identity.NewDstackDeriver()

	logger.Info("deriving TEE identity", "connector_id", connectorID)

	id, att, err := deriver.DeriveIdentity(ctx, connectorID)
	if err != nil {
		return fmt.Errorf("derive identity: %w", err)
	}

	bundle := store.ConnectorBundle{
		ConnectorID:   id.ConnectorID,
		SSHPublicKey:  id.SSHPublicKey,
		QuoteHex:      att.QuoteHex,
		EventLog:      att.EventLog,
		MRTD:          att.MRTD,
		RTMR0:         att.RTMR0,
		RTMR1:         att.RTMR1,
		RTMR2:         att.RTMR2,
		RTMR3:         att.RTMR3,
		PolicyVersion: att.PolicyVersion,
	}

	if err := bundles.Register(ctx, bundle); err != nil {
		return fmt.Errorf("register bundle: %w", err)
	}

	logger.Info("connector registered",
		"connector_id", connectorID,
		"fingerprint", id.FingerprintSHA256,
		"ssh_public_key", id.SSHPublicKey,
	)
	return nil
}

// bindEnvDefaults checks each flag; if it was not explicitly set on the command
// line and the corresponding environment variable is set, it applies the env
// value as the flag default.
func bindEnvDefaults(cmd *cobra.Command, flagEnv map[string]string) {
	for flagName, envVar := range flagEnv {
		if cmd.Flags().Changed(flagName) {
			continue
		}
		if v, ok := os.LookupEnv(envVar); ok {
			_ = cmd.Flags().Set(flagName, v)
		}
	}
}
