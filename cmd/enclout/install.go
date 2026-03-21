package main

import (
	"context"
	"fmt"

	"enclout/internal/access"
	"enclout/internal/client"

	"github.com/spf13/cobra"
)

func installCmd() *cobra.Command {
	var serverURL, installToken, token string

	cmd := &cobra.Command{
		Use:   "install",
		Short: "Redeem install token and configure agent service",
		RunE: func(cmd *cobra.Command, args []string) error {
			// Apply env var fallbacks for flags not explicitly set.
			bindEnvDefaults(cmd, map[string]string{
				"server":        "ENCLOUT_SERVER",
				"install-token": "ENCLOUT_INSTALL_TOKEN",
				"token":         "ENCLOUT_TOKEN",
			})

			// Re-read flag values after env fallback.
			serverURL, _ = cmd.Flags().GetString("server")
			installToken, _ = cmd.Flags().GetString("install-token")
			token, _ = cmd.Flags().GetString("token")

			// Create client.
			c := client.New(serverURL, token)
			ctx := context.Background()

			// Hash the raw install token and redeem it.
			tokenDigest := access.DigestToken(installToken)
			session, err := c.RedeemToken(ctx, tokenDigest)
			if err != nil {
				return fmt.Errorf("redeem token: %w", err)
			}

			// Generate a new device ID.
			deviceID := access.RandomID()

			// Use the session's connector ID if available, otherwise generate one.
			connectorID := session.ConnectorID
			if connectorID == "" {
				connectorID = access.RandomID()
			}

			// Register identity on the session.
			if err := c.RegisterIdentity(ctx, session.ID, connectorID, deviceID); err != nil {
				return fmt.Errorf("register identity: %w", err)
			}

			// Print device ID and instructions.
			fmt.Printf("Session:      %s\n", session.ID)
			fmt.Printf("Device ID:    %s\n", deviceID)
			fmt.Printf("Connector ID: %s\n", connectorID)
			fmt.Println()
			fmt.Println("Device registered successfully.")
			fmt.Println("Start the agent with:")
			fmt.Printf("  enclout agent --server %s --device-id %s\n", serverURL, deviceID)

			// Mark session as installed.
			if err := c.SessionResult(ctx, session.ID, "installed", ""); err != nil {
				return fmt.Errorf("set session result: %w", err)
			}

			return nil
		},
	}

	cmd.Flags().StringVar(&serverURL, "server", "", "Control plane URL (required)")
	cmd.Flags().StringVar(&installToken, "install-token", "", "Install token from the invite URL (required)")
	cmd.Flags().StringVar(&token, "token", "", "Bearer auth token")
	_ = cmd.MarkFlagRequired("server")
	_ = cmd.MarkFlagRequired("install-token")

	return cmd
}
