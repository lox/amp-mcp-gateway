// Package sandbox defines the requests exchanged with an idle-expiring MCP runner.
package sandbox

import (
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

const (
	// ExecutionTimeout bounds one MCP request, including installation on first use.
	ExecutionTimeout = 3 * time.Minute
	// IdleTimeout bounds unused Machines, including after loss of the gateway.
	IdleTimeout = 10 * time.Minute
	// RequestLimit leaves room for base64 encoding within Fly exec's command arguments.
	RequestLimit = 64 << 10
	// ResultLimit bounds serialized MCP results crossing back into the gateway.
	ResultLimit = 4 << 20
	Directory   = "/run/mcp-sandbox"
	ConfigPath  = Directory + "/server.json"
	RequestPath = Directory + "/request.json"
	ResultPath  = Directory + "/result.json"
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
	ID        string
	Tool      string         `json:",omitempty"`
	Arguments map[string]any `json:",omitempty"`
}

// Response carries MCP data or a fixed, credential-free runner error.
type Response struct {
	ID     string
	Tools  []*mcp.Tool         `json:",omitempty"`
	Result *mcp.CallToolResult `json:",omitempty"`
	Error  string              `json:",omitempty"`
}
