// mcp-sandbox supervises a single disposable MCP execution as root.
package main

import (
	"context"
	"os"
	"time"

	"ampcode.com/lox/amp-mcp-gateway/internal/sandbox"
)

func main() {
	// This watchdog is independent of subprocess shutdown and SDK cleanup. PID 1
	// exiting tears down the Machine even if an untrusted descendant escaped its
	// process group. Never exit early: the gateway needs time to collect the file.
	go sandbox.Run(context.Background())
	<-time.After(sandbox.MachineLifetime)
	os.Exit(0)
}
