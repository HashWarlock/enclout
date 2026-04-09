package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"time"

	"enclout/internal/agent"
	"enclout/internal/client"

	"github.com/spf13/cobra"
)

func statusCmd() *cobra.Command {
	var serverURL, requestID, deviceID, token, keysDir, username string
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
				"keys-dir":   "ENCLOUT_KEYS_DIR",
				"username":   "ENCLOUT_USERNAME",
			})

			// Re-read flag values after env fallback.
			serverURL, _ = cmd.Flags().GetString("server")
			requestID, _ = cmd.Flags().GetString("request-id")
			deviceID, _ = cmd.Flags().GetString("device-id")
			token, _ = cmd.Flags().GetString("token")
			keysDir, _ = cmd.Flags().GetString("keys-dir")
			username, _ = cmd.Flags().GetString("username")

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
			return listPending(ctx, c, deviceID, jsonOutput, keysDir, username)
		},
	}

	cmd.Flags().StringVar(&serverURL, "server", "", "Control plane URL (required)")
	cmd.Flags().StringVar(&requestID, "request-id", "", "Request ID to check")
	cmd.Flags().StringVar(&deviceID, "device-id", "", "Device ID to list pending")
	cmd.Flags().StringVar(&token, "token", "", "Bearer auth token")
	cmd.Flags().StringVar(&keysDir, "keys-dir", "~/.enclout/keys", "Managed SSH key directory")
	cmd.Flags().StringVar(&username, "username", "", "Local SSH username for managed key inventory")
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

type managedKeyStatus struct {
	ConnectorID string    `json:"connector_id"`
	InstalledAt time.Time `json:"installed_at"`
	Status      string    `json:"status"`
}

type keyInventoryReport struct {
	Enabled bool               `json:"enabled"`
	Managed int                `json:"managed"`
	Stale   int                `json:"stale"`
	Keys    []managedKeyStatus `json:"keys"`
}

func listPending(ctx context.Context, c *client.Client, deviceID string, jsonOut bool, keysDir, username string) error {
	reqs, err := c.ListPending(ctx, deviceID)
	if err != nil {
		return fmt.Errorf("list pending: %w", err)
	}
	inv, err := buildKeyInventory(ctx, c, keysDir, username)
	if err != nil {
		return fmt.Errorf("key inventory: %w", err)
	}

	if jsonOut {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		return enc.Encode(map[string]any{
			"pending_requests": reqs,
			"key_inventory":    inv,
		})
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

	if inv.Enabled {
		if len(reqs) > 0 {
			fmt.Println("---")
		}
		fmt.Printf("Managed keys: %d\n", inv.Managed)
		fmt.Printf("Stale keys:   %d\n", inv.Stale)
		for _, k := range inv.Keys {
			fmt.Printf("Connector:    %s\n", k.ConnectorID)
			if !k.InstalledAt.IsZero() {
				fmt.Printf("Installed:    %s\n", k.InstalledAt.Format(time.RFC3339))
			}
			fmt.Printf("State:        %s\n", k.Status)
			fmt.Println("---")
		}
	}
	return nil
}

func buildKeyInventory(ctx context.Context, c *client.Client, keysDir, username string) (keyInventoryReport, error) {
	if username == "" {
		return keyInventoryReport{Enabled: false}, nil
	}
	manager := agent.NewSSHKeyManager(keysDir)
	local, err := manager.ListManaged(username)
	if err != nil {
		return keyInventoryReport{}, err
	}

	remote, err := c.ListConnectors(ctx)
	if err != nil {
		return keyInventoryReport{}, err
	}
	remoteIDs := make(map[string]struct{}, len(remote))
	for _, r := range remote {
		remoteIDs[r.ConnectorID] = struct{}{}
	}

	out := keyInventoryReport{
		Enabled: true,
		Managed: len(local),
		Keys:    make([]managedKeyStatus, 0, len(local)),
	}
	for _, k := range local {
		state := "active"
		if _, ok := remoteIDs[k.ConnectorID]; !ok {
			state = "stale"
			out.Stale++
		}
		out.Keys = append(out.Keys, managedKeyStatus{
			ConnectorID: k.ConnectorID,
			InstalledAt: k.InstalledAt,
			Status:      state,
		})
	}
	return out, nil
}
