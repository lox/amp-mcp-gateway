package main

import (
	"encoding/json"
	"flag"
	"os"
	"path/filepath"
	"testing"

	"ampcode.com/lox/amp-mcp-gateway/internal/gateway"
)

func invoke(t *testing.T, args ...string) error {
	t.Helper()
	oldFlags, oldArgs := flag.CommandLine, os.Args
	defer func() { flag.CommandLine, os.Args = oldFlags, oldArgs }()
	flag.CommandLine = flag.NewFlagSet("policy-config", flag.ContinueOnError)
	os.Args = append([]string{"policy-config"}, args...)
	return run()
}

func TestCandidatePreservesConfigAndRefusesOverwrite(t *testing.T) {
	t.Setenv("TYPESAFE_API_KEY", "unused-for-explicit-policies")
	input, err := os.ReadFile("../../gateway.example.json")
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	src, dst := filepath.Join(dir, "input.json"), filepath.Join(dir, "candidate.json")
	if err := os.WriteFile(src, input, 0600); err != nil {
		t.Fatal(err)
	}
	if err := invoke(t, "-config", src, "-out", dst); err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(dst)
	if err != nil {
		t.Fatal(err)
	}
	var cfg gateway.Config
	if err := json.Unmarshal(b, &cfg); err != nil {
		t.Fatal(err)
	}
	if cfg.Tools[0].Policy != "allow" || cfg.Tools[1].Policy != "require_approval" || cfg.Connections[1].OAuth.ClientSecretEnv != "NOTES_CLIENT_SECRET" {
		t.Fatal("candidate lost explicit policies or connection config")
	}
	info, err := os.Stat(dst)
	if err != nil || info.Mode().Perm() != 0600 {
		t.Fatal("candidate must be private")
	}
	if err := invoke(t, "-config", src, "-out", src); err == nil {
		t.Fatal("overwrote source")
	}
	after, _ := os.ReadFile(src)
	if string(after) != string(input) {
		t.Fatal("source changed")
	}
}

func TestInvalidInputDoesNotCreateCandidate(t *testing.T) {
	t.Setenv("TYPESAFE_API_KEY", "unused")
	for _, input := range []string{`{"unexpected":true}`, `{} {}`, `{"Tools":[{"ID":"bad"}]}`} {
		dir := t.TempDir()
		src, dst := filepath.Join(dir, "input.json"), filepath.Join(dir, "candidate.json")
		if err := os.WriteFile(src, []byte(input), 0600); err != nil {
			t.Fatal(err)
		}
		if err := invoke(t, "-config", src, "-out", dst); err == nil {
			t.Fatal("accepted invalid input")
		}
		if _, err := os.Stat(dst); !os.IsNotExist(err) {
			t.Fatal("created candidate for invalid input")
		}
	}
}

func TestMissingKeyWritesConservativeCandidate(t *testing.T) {
	t.Setenv("TYPESAFE_API_KEY", "")
	input := `{"Connections":[{"ID":"test"},{"ID":"restricted"}],"ToolDefaults":{"restricted":"deny"},"Tools":[
		{"ID":"unset","Connection":"test","Name":"read","InputSchema":{"type":"object"}},
		{"ID":"allowed","Connection":"test","Name":"read","Policy":"allow","InputSchema":{"type":"object"}},
		{"ID":"denied","Connection":"test","Name":"delete","Policy":"deny","InputSchema":{"type":"object"}},
		{"ID":"approval","Connection":"test","Name":"write","Policy":"require_approval","InputSchema":{"type":"object"}},
		{"ID":"inherited","Connection":"restricted","Name":"read","InputSchema":{"type":"object"}}
	]}`
	dir := t.TempDir()
	src, dst := filepath.Join(dir, "input.json"), filepath.Join(dir, "candidate.json")
	if err := os.WriteFile(src, []byte(input), 0600); err != nil {
		t.Fatal(err)
	}
	if err := invoke(t, "-config", src, "-out", dst); err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(dst)
	if err != nil {
		t.Fatal(err)
	}
	var cfg gateway.Config
	if err := json.Unmarshal(b, &cfg); err != nil {
		t.Fatal(err)
	}
	if cfg.ToolDefaults["restricted"] != "deny" {
		t.Fatal("changed inherited restriction")
	}
	for i, want := range []string{"require_approval", "allow", "deny", "require_approval", ""} {
		if cfg.Tools[i].Policy != want {
			t.Fatalf("tool %d: got %s, want %s", i, cfg.Tools[i].Policy, want)
		}
	}
}
