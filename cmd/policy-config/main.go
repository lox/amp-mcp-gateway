// Command policy-config writes a candidate configuration for owner review.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"

	"ampcode.com/lox/amp-mcp-gateway/internal/gateway"
	"ampcode.com/lox/amp-mcp-gateway/internal/policy"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func run() error {
	input := flag.String("config", "gateway.json", "input configuration; classify only tools without explicit or configured inherited policies")
	output := flag.String("out", "", "new candidate config file (required; never overwrites an existing file)")
	flag.Parse()
	if *output == "" || flag.NArg() != 0 {
		return errors.New("use -config INPUT -out NEW-CANDIDATE; review the candidate before activating it")
	}
	f, err := os.Open(*input)
	if err != nil {
		return err
	}
	defer f.Close()
	var cfg gateway.Config
	d := json.NewDecoder(f)
	d.DisallowUnknownFields()
	if err := d.Decode(&cfg); err != nil {
		return errors.New("invalid configuration JSON")
	}
	if err := d.Decode(new(any)); err != io.EOF {
		return errors.New("configuration must contain one JSON object")
	}
	// Validate all tools before sending metadata or creating the candidate.
	if _, err := gateway.New(cfg, nil, nil); err != nil {
		return err
	}
	out, err := os.OpenFile(*output, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return err
	}
	complete := false
	defer func() {
		out.Close()
		if !complete {
			os.Remove(*output)
		}
	}()
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	client := policy.Client{Key: os.Getenv("TYPESAFE_API_KEY")}
	if client.Key == "" {
		fmt.Fprintln(os.Stderr, "TYPESAFE_API_KEY is not set; skipping classification. Unconfigured policies will require approval; explicit and inherited policies are preserved.")
	} else {
		fmt.Fprintln(os.Stderr, "Sending unset-policy tool names, descriptions and schemas to TypeSafe. No call arguments or connection credentials are sent.")
	}
	for i, tool := range cfg.Tools {
		if err := ctx.Err(); err != nil {
			return err
		}
		inherited := cfg.ToolDefaults[tool.Connection] != ""
		for _, integration := range cfg.Integrations {
			if integration.ID == tool.Connection {
				inherited = true
			}
		}
		if tool.Policy == "" && inherited {
			fmt.Fprintf(os.Stderr, "%q: inherited policy preserved\n", tool.ID)
			continue
		}
		s := client.Suggest(ctx, tool)
		cfg.Tools[i].Policy = s.Policy
		fmt.Fprintf(os.Stderr, "%q: %s (%s; model=%q)\n", tool.ID, s.Policy, s.Reason, s.Model)
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	enc := json.NewEncoder(out)
	enc.SetIndent("", "  ")
	if err := enc.Encode(cfg); err != nil {
		return err
	}
	if err := out.Close(); err != nil {
		return err
	}
	complete = true
	fmt.Fprintln(os.Stderr, "Candidate saved. Review every Policy before using this file with mcp-gateway -config for a new installation. Existing database policies take precedence; apply reviewed changes through the dashboard. The running gateway is unchanged.")
	return nil
}
