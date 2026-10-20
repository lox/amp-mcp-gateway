// Package sandbox defines the request and result exchanged with a disposable MCP runner.
package sandbox

import (
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

const (
	// ExecutionTimeout includes cloning, installation, initialization and one MCP request.
	ExecutionTimeout = 3 * time.Minute
	// MachineLifetime bounds orphaned Machines after loss of the gateway or API response.
	MachineLifetime = 5 * time.Minute
	// ResultLimit bounds serialized MCP results crossing back into the gateway.
	ResultLimit = 4 << 20
	RequestPath = "/run/mcp-request.json"
	ResultPath  = "/run/mcp-result.json"
)

// Server describes public source code to install and run using MCP over stdio.
type Server struct {
	Repository string
	Revision   string `json:",omitempty"`
	InstallCmd string `json:",omitempty"`
	RunCmd     string
}

// Request lists tools when Tool is empty, otherwise invokes exactly that tool once.
type Request struct {
	Server    Server
	Tool      string         `json:",omitempty"`
	Arguments map[string]any `json:",omitempty"`
}

// Response carries MCP data or a fixed, credential-free runner error.
type Response struct {
	Tools  []*mcp.Tool         `json:",omitempty"`
	Result *mcp.CallToolResult `json:",omitempty"`
	Error  string              `json:",omitempty"`
}
