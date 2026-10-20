// mcp-sandbox supervises an idle-expiring stdio MCP process as root.
package main

import (
	"context"
	"os"

	"ampcode.com/lox/amp-mcp-gateway/internal/sandbox"
)

func main() {
	// Exiting PID 1 tears down even descendants that escaped the process group.
	sandbox.Run(context.Background(), sandbox.Directory, sandbox.IdleTimeout)
	os.Exit(0)
}
