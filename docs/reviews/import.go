//go:build reviewimport

// One-off offline migration; see docs/reviews.md. Not part of the gateway binary.
package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"ampcode.com/lox/amp-mcp-gateway/internal/reviews"
)

func main() {
	database := flag.String("database", "", "existing account database (gateway must be stopped)")
	app := flag.String("app", "", "paused Reviews integration ID")
	flag.Usage = func() {
		fmt.Fprintln(os.Stderr, "Offline amp-reviewbot import. Read JSONL from stdin; read this database's encryption key from GATEWAY_ENCRYPTION_KEY.")
		flag.PrintDefaults()
	}
	flag.Parse()
	key := os.Getenv("GATEWAY_ENCRYPTION_KEY")
	if *database == "" || *app == "" || key == "" || flag.NArg() != 0 {
		flag.Usage()
		os.Exit(2)
	}
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	count, err := reviews.ImportLegacy(ctx, *database, key, *app, os.Stdin)
	fmt.Printf("Imported %d historical reviews. No reviews were queued.\n", count)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		fmt.Fprintln(os.Stderr, "Fix the error and rerun the same export; existing deliveries are skipped.")
		os.Exit(1)
	}
}
