package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"time"

	"enclout/internal/access"
	"enclout/internal/client"

	"github.com/spf13/cobra"
)

func connectCmd() *cobra.Command {
	var serverURL, deviceID, connectorID, requesterID, token, source string
	var wait, jsonOutput bool

	cmd := &cobra.Command{
		Use:   "connect",
		Short: "Create a connection request",
		RunE: func(cmd *cobra.Command, args []string) error {
			// Apply env var fallbacks for flags not explicitly set.
			bindEnvDefaults(cmd, map[string]string{
				"server":       "ENCLOUT_SERVER",
				"device-id":    "ENCLOUT_DEVICE_ID",
				"connector-id": "ENCLOUT_CONNECTOR_ID",
				"requester":    "ENCLOUT_REQUESTER",
				"token":        "ENCLOUT_TOKEN",
			})

			// Re-read flag values after env fallback.
			serverURL, _ = cmd.Flags().GetString("server")
			deviceID, _ = cmd.Flags().GetString("device-id")
			connectorID, _ = cmd.Flags().GetString("connector-id")
			requesterID, _ = cmd.Flags().GetString("requester")
			token, _ = cmd.Flags().GetString("token")
			source, _ = cmd.Flags().GetString("source")

			// Create client.
			c := client.New(serverURL, token)

			// Create connection request.
			ctx := context.Background()
			req, err := c.CreateRequest(ctx, requesterID, deviceID, connectorID, source, 5*time.Minute)
			if err != nil {
				return fmt.Errorf("create request: %w", err)
			}

			// If --wait: poll GetRequest every 2s until terminal state.
			if wait {
				req, err = pollUntilTerminal(ctx, c, req.ID)
				if err != nil {
					return fmt.Errorf("poll request: %w", err)
				}
			}

			// Output result.
			if jsonOutput {
				enc := json.NewEncoder(os.Stdout)
				enc.SetIndent("", "  ")
				if err := enc.Encode(req); err != nil {
					return fmt.Errorf("encode json: %w", err)
				}
			} else {
				fmt.Printf("Request ID:  %s\n", req.ID)
				fmt.Printf("Status:      %s\n", req.Status)
				fmt.Printf("Device:      %s\n", req.DeviceID)
				fmt.Printf("Connector:   %s\n", req.ConnectorID)
				fmt.Printf("Created:     %s\n", req.CreatedAt.Format(time.RFC3339))
				fmt.Printf("Expires:     %s\n", req.ExpiresAt.Format(time.RFC3339))
				if req.ReasonCode != "" {
					fmt.Printf("Reason:      %s\n", req.ReasonCode)
				}
			}

			// Exit codes: 0=connected, 1=denied/failed, 2=expired.
			switch access.Status(req.Status) {
			case access.StatusConnected:
				return nil
			case access.StatusExpired:
				os.Exit(2)
			case access.StatusDeniedLocal, access.StatusVerificationFailed:
				os.Exit(1)
			}
			return nil
		},
	}

	cmd.Flags().StringVar(&serverURL, "server", "", "Control plane URL (required)")
	cmd.Flags().StringVar(&deviceID, "device-id", "", "Target device ID (required)")
	cmd.Flags().StringVar(&connectorID, "connector-id", "", "Connector ID (required)")
	cmd.Flags().StringVar(&requesterID, "requester", "", "Requester identity")
	cmd.Flags().StringVar(&token, "token", "", "Bearer auth token")
	cmd.Flags().StringVar(&source, "source", "cli", "Request source")
	cmd.Flags().BoolVar(&wait, "wait", false, "Wait for terminal status")
	cmd.Flags().BoolVar(&jsonOutput, "json", false, "Output JSON")
	_ = cmd.MarkFlagRequired("server")
	_ = cmd.MarkFlagRequired("device-id")
	_ = cmd.MarkFlagRequired("connector-id")

	return cmd
}

// pollUntilTerminal polls GetRequest every 2s until the request reaches a
// terminal state (connected, denied, expired, or verification_failed).
func pollUntilTerminal(ctx context.Context, c *client.Client, requestID string) (client.RequestResponse, error) {
	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return client.RequestResponse{}, ctx.Err()
		case <-ticker.C:
			req, err := c.GetRequest(ctx, requestID)
			if err != nil {
				return client.RequestResponse{}, err
			}
			switch access.Status(req.Status) {
			case access.StatusConnected,
				access.StatusDeniedLocal,
				access.StatusExpired,
				access.StatusVerificationFailed:
				return req, nil
			}
			// Still pending or approved — keep polling.
		}
	}
}
