package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"time"

	"enclout/internal/client"

	"github.com/spf13/cobra"
)

func statusCmd() *cobra.Command {
	var serverURL, requestID, deviceID, token string
	var jsonOutput bool

	cmd := &cobra.Command{
		Use:   "status",
		Short: "Check request or device status",
		RunE: func(cmd *cobra.Command, args []string) error {
			// Apply env var fallbacks for flags not explicitly set.
			bindEnvDefaults(cmd, map[string]string{
				"server":     "ENCLOUT_SERVER",
				"request-id": "ENCLOUT_REQUEST_ID",
				"device-id":  "ENCLOUT_DEVICE_ID",
				"token":      "ENCLOUT_TOKEN",
			})

			// Re-read flag values after env fallback.
			serverURL, _ = cmd.Flags().GetString("server")
			requestID, _ = cmd.Flags().GetString("request-id")
			deviceID, _ = cmd.Flags().GetString("device-id")
			token, _ = cmd.Flags().GetString("token")

			if requestID == "" && deviceID == "" {
				return fmt.Errorf("one of --request-id or --device-id is required")
			}

			// Create client.
			c := client.New(serverURL, token)
			ctx := cmd.Context()

			// If --request-id: fetch and display a single request.
			if requestID != "" {
				return showRequest(ctx, c, requestID, jsonOutput)
			}

			// If --device-id: list all pending requests for the device.
			return listPending(ctx, c, deviceID, jsonOutput)
		},
	}

	cmd.Flags().StringVar(&serverURL, "server", "", "Control plane URL (required)")
	cmd.Flags().StringVar(&requestID, "request-id", "", "Request ID to check")
	cmd.Flags().StringVar(&deviceID, "device-id", "", "Device ID to list pending")
	cmd.Flags().StringVar(&token, "token", "", "Bearer auth token")
	cmd.Flags().BoolVar(&jsonOutput, "json", false, "Output JSON")
	_ = cmd.MarkFlagRequired("server")

	return cmd
}

func showRequest(ctx context.Context, c *client.Client, requestID string, jsonOut bool) error {
	req, err := c.GetRequest(ctx, requestID)
	if err != nil {
		return fmt.Errorf("get request: %w", err)
	}

	if jsonOut {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		return enc.Encode(req)
	}

	fmt.Printf("Request ID:  %s\n", req.ID)
	fmt.Printf("Status:      %s\n", req.Status)
	fmt.Printf("Requester:   %s\n", req.RequesterID)
	fmt.Printf("Device:      %s\n", req.DeviceID)
	fmt.Printf("Connector:   %s\n", req.ConnectorID)
	fmt.Printf("Source:      %s\n", req.Source)
	fmt.Printf("Created:     %s\n", req.CreatedAt.Format(time.RFC3339))
	fmt.Printf("Expires:     %s\n", req.ExpiresAt.Format(time.RFC3339))
	if req.ReasonCode != "" {
		fmt.Printf("Reason:      %s\n", req.ReasonCode)
	}
	return nil
}

func listPending(ctx context.Context, c *client.Client, deviceID string, jsonOut bool) error {
	reqs, err := c.ListPending(ctx, deviceID)
	if err != nil {
		return fmt.Errorf("list pending: %w", err)
	}

	if jsonOut {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		return enc.Encode(reqs)
	}

	if len(reqs) == 0 {
		fmt.Println("No pending requests.")
		return nil
	}

	for i, req := range reqs {
		if i > 0 {
			fmt.Println("---")
		}
		fmt.Printf("Request ID:  %s\n", req.ID)
		fmt.Printf("Status:      %s\n", req.Status)
		fmt.Printf("Requester:   %s\n", req.RequesterID)
		fmt.Printf("Connector:   %s\n", req.ConnectorID)
		fmt.Printf("Created:     %s\n", req.CreatedAt.Format(time.RFC3339))
		fmt.Printf("Expires:     %s\n", req.ExpiresAt.Format(time.RFC3339))
	}
	return nil
}
