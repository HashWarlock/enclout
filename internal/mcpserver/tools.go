package mcpserver

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/mark3labs/mcp-go/mcp"
	mcpserver "github.com/mark3labs/mcp-go/server"

	"enclout/internal/client"
)

// Server wraps a typed HTTP client to expose enclout operations as MCP tools.
type Server struct {
	client    *client.Client
	serverURL string
}

// New creates a new MCP tool server backed by the given HTTP client.
// serverURL is used to generate install commands (e.g. curl snippets).
func New(c *client.Client, serverURL string) *Server {
	return &Server{client: c, serverURL: serverURL}
}

// Register adds all enclout tools to the given MCP server.
func (s *Server) Register(srv *mcpserver.MCPServer) {
	srv.AddTool(connectTool(), s.handleConnect)
	srv.AddTool(installStartTool(), s.handleInstallStart)
	srv.AddTool(installApproveTool(), s.handleInstallApprove)
	srv.AddTool(installStatusTool(), s.handleInstallStatus)
	srv.AddTool(requestStatusTool(), s.handleRequestStatus)
	srv.AddTool(listPendingTool(), s.handleListPending)
}

// --- Tool definitions ---

func connectTool() mcp.Tool {
	return mcp.NewTool("enclout_connect",
		mcp.WithDescription("Create a connection request to an enclout connector"),
		mcp.WithString("requester_id", mcp.Required(), mcp.Description("ID of the user requesting access")),
		mcp.WithString("device_id", mcp.Required(), mcp.Description("Target device identifier")),
		mcp.WithString("connector_id", mcp.Required(), mcp.Description("Target connector identifier")),
		mcp.WithString("source", mcp.Description("Source channel (e.g. telegram, slack)")),
	)
}

func installStartTool() mcp.Tool {
	return mcp.NewTool("enclout_install_start",
		mcp.WithDescription("Start a new connector install session"),
		mcp.WithString("requester_id", mcp.Required(), mcp.Description("ID of the user initiating the install")),
		mcp.WithString("source", mcp.Description("Source channel (e.g. web, cli)")),
	)
}

func installApproveTool() mcp.Tool {
	return mcp.NewTool("enclout_install_approve",
		mcp.WithDescription("Approve an install session"),
		mcp.WithString("session_id", mcp.Required(), mcp.Description("Install session ID to approve")),
	)
}

func installStatusTool() mcp.Tool {
	return mcp.NewTool("enclout_install_status",
		mcp.WithDescription("Check the status of an install session"),
		mcp.WithString("session_id", mcp.Required(), mcp.Description("Install session ID to check")),
	)
}

func requestStatusTool() mcp.Tool {
	return mcp.NewTool("enclout_request_status",
		mcp.WithDescription("Check the status of a connection request"),
		mcp.WithString("request_id", mcp.Required(), mcp.Description("Connection request ID to check")),
	)
}

func listPendingTool() mcp.Tool {
	return mcp.NewTool("enclout_list_pending",
		mcp.WithDescription("List pending connection requests for a device"),
		mcp.WithString("device_id", mcp.Required(), mcp.Description("Device ID to list pending requests for")),
	)
}

// --- Handlers ---

func (s *Server) handleConnect(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	args := request.GetArguments()

	requesterID, _ := args["requester_id"].(string)
	deviceID, _ := args["device_id"].(string)
	connectorID, _ := args["connector_id"].(string)
	source, _ := args["source"].(string)

	if requesterID == "" || deviceID == "" || connectorID == "" {
		return mcp.NewToolResultError("requester_id, device_id, and connector_id are required"), nil
	}

	resp, err := s.client.CreateRequest(ctx, requesterID, deviceID, connectorID, source, 5*time.Minute)
	if err != nil {
		return mcp.NewToolResultError(fmt.Sprintf("failed to create request: %v", err)), nil
	}

	return jsonResult(resp)
}

func (s *Server) handleInstallStart(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	args := request.GetArguments()

	requesterID, _ := args["requester_id"].(string)
	source, _ := args["source"].(string)

	if requesterID == "" {
		return mcp.NewToolResultError("requester_id is required"), nil
	}

	resp, err := s.client.CreateSession(ctx, requesterID, source, 10*time.Minute)
	if err != nil {
		return mcp.NewToolResultError(fmt.Sprintf("failed to create install session: %v", err)), nil
	}

	// Build the result with install commands
	type installResult struct {
		Session         client.SessionResponse `json:"session"`
		InstallToken    string                 `json:"install_token"`
		InstallURL      string                 `json:"install_url"`
		InstallCommands map[string]string      `json:"install_commands"`
	}

	installURL := resp.InstallURL
	if installURL == "" {
		installURL = fmt.Sprintf("%s/install?token=%s", s.serverURL, resp.InstallToken)
	}

	result := installResult{
		Session:      resp.Session,
		InstallToken: resp.InstallToken,
		InstallURL:   installURL,
		InstallCommands: map[string]string{
			"linux_macos": fmt.Sprintf("curl -fsSL %s | bash", installURL),
		},
	}

	return jsonResult(result)
}

func (s *Server) handleInstallApprove(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	args := request.GetArguments()

	sessionID, _ := args["session_id"].(string)
	if sessionID == "" {
		return mcp.NewToolResultError("session_id is required"), nil
	}

	if err := s.client.ApproveSession(ctx, sessionID); err != nil {
		return mcp.NewToolResultError(fmt.Sprintf("failed to approve session: %v", err)), nil
	}

	return mcp.NewToolResultText(fmt.Sprintf("session %s approved successfully", sessionID)), nil
}

func (s *Server) handleInstallStatus(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	args := request.GetArguments()

	sessionID, _ := args["session_id"].(string)
	if sessionID == "" {
		return mcp.NewToolResultError("session_id is required"), nil
	}

	resp, err := s.client.GetSession(ctx, sessionID)
	if err != nil {
		return mcp.NewToolResultError(fmt.Sprintf("failed to get session: %v", err)), nil
	}

	return jsonResult(resp)
}

func (s *Server) handleRequestStatus(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	args := request.GetArguments()

	requestID, _ := args["request_id"].(string)
	if requestID == "" {
		return mcp.NewToolResultError("request_id is required"), nil
	}

	resp, err := s.client.GetRequest(ctx, requestID)
	if err != nil {
		return mcp.NewToolResultError(fmt.Sprintf("failed to get request: %v", err)), nil
	}

	return jsonResult(resp)
}

func (s *Server) handleListPending(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	args := request.GetArguments()

	deviceID, _ := args["device_id"].(string)
	if deviceID == "" {
		return mcp.NewToolResultError("device_id is required"), nil
	}

	resp, err := s.client.ListPending(ctx, deviceID)
	if err != nil {
		return mcp.NewToolResultError(fmt.Sprintf("failed to list pending requests: %v", err)), nil
	}

	return jsonResult(resp)
}

// jsonResult marshals v to JSON and returns it as a text tool result.
func jsonResult(v any) (*mcp.CallToolResult, error) {
	data, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("marshal result: %w", err)
	}
	return mcp.NewToolResultText(string(data)), nil
}
