package main

import (
	"github.com/mark3labs/mcp-go/server"
	"github.com/spf13/cobra"

	"enclout/internal/client"
	"enclout/internal/mcpserver"
)

func mcpCmd() *cobra.Command {
	var serverURL, token string
	cmd := &cobra.Command{
		Use:   "mcp",
		Short: "Start MCP tool server (stdio)",
		RunE: func(cmd *cobra.Command, args []string) error {
			// Apply env var fallbacks.
			bindEnvDefaults(cmd, map[string]string{
				"server": "ENCLOUT_SERVER",
				"token":  "ENCLOUT_TOKEN",
			})

			// Re-read flag values after env fallback.
			serverURL, _ = cmd.Flags().GetString("server")
			token, _ = cmd.Flags().GetString("token")

			c := client.New(serverURL, token)
			mcpSrv := mcpserver.New(c, serverURL)

			// Create a new MCP server and register tools.
			srv := server.NewMCPServer("enclout", version)
			mcpSrv.Register(srv)

			// Serve over stdio.
			return server.ServeStdio(srv)
		},
	}
	cmd.Flags().StringVar(&serverURL, "server", "", "Control plane URL (required)")
	cmd.Flags().StringVar(&token, "token", "", "Bearer auth token")
	_ = cmd.MarkFlagRequired("server")

	// Hide from bash completion stderr output (MCP stdio servers must not
	// write anything unexpected to stdout/stderr).
	cmd.SilenceUsage = true
	cmd.SilenceErrors = true

	return cmd
}
