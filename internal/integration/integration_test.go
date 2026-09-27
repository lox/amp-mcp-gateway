package integration

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

func fixtureManager(t *testing.T) *Manager {
	t.Helper()
	m, err := New(t.Context(), []Config{{
		Manifest: filepath.Join("testdata", "fixture", "manifest.json"),
		Account:  "fixture account",
		Policy:   "require_approval",
	}}, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := m.Close(context.Background()); err != nil {
			t.Error(err)
		}
	})
	return m
}

func TestJavaScriptPluginCall(t *testing.T) {
	m := fixtureManager(t)
	definitions := m.Definitions()
	if len(definitions) != 1 || definitions[0].ID != "fixture" || len(definitions[0].Tools) != 3 {
		t.Fatalf("unexpected definitions: %#v", definitions)
	}
	binding := m.Binding("fixture")
	if len(binding) != 64 {
		t.Fatalf("unexpected binding %q", binding)
	}
	manifestBytes, err := os.ReadFile(filepath.Join("testdata", "fixture", "manifest.json"))
	if err != nil {
		t.Fatal(err)
	}
	wasmBytes, err := os.ReadFile(filepath.Join("testdata", "fixture", "fixture.wasm"))
	if err != nil {
		t.Fatal(err)
	}
	expectedHash := sha256.New()
	expectedHash.Write(manifestBytes)
	expectedHash.Write(wasmBytes)
	if binding != hex.EncodeToString(expectedHash.Sum(nil)) {
		t.Fatal("binding does not cover the exact manifest and wasm bytes")
	}
	result, err := m.Call(t.Context(), "fixture", "echo", binding, map[string]any{"text": "hello"})
	if err != nil {
		t.Fatal(err)
	}
	text, ok := result.Content[0].(*mcp.TextContent)
	if !ok || text.Text != "plugin:hello" {
		t.Fatalf("unexpected plugin output: %#v", result)
	}
	if _, err := m.Call(t.Context(), "fixture", "echo", "stale", map[string]any{"text": "hello"}); err == nil {
		t.Fatal("stale plugin binding accepted")
	}
}

func TestJavaScriptPluginSandbox(t *testing.T) {
	m := fixtureManager(t)
	binding := m.Binding("fixture")
	if _, err := m.Call(t.Context(), "fixture", "network", binding, map[string]any{}); err == nil || !strings.Contains(err.Error(), "not allowed") {
		t.Fatalf("network access was not denied: %v", err)
	}
	ctx, cancel := context.WithTimeout(t.Context(), 50*time.Millisecond)
	defer cancel()
	if _, err := m.Call(ctx, "fixture", "spin", binding, map[string]any{}); err == nil || !strings.Contains(err.Error(), "deadline exceeded") {
		t.Fatalf("runaway plugin was not stopped: %v", err)
	}
	if _, err := m.Call(t.Context(), "fixture", "echo", binding, map[string]any{"text": "after timeout"}); err != nil {
		t.Fatalf("fresh instance failed after timeout: %v", err)
	}
}

func TestManifestValidation(t *testing.T) {
	tests := []struct {
		name     string
		manifest manifest
	}{
		{"path traversal", manifest{ID: "test", Name: "Test", Version: "1", Wasm: "../plugin.wasm", Tools: []Tool{{Name: "run", Description: "Run", InputSchema: map[string]any{"type": "object"}}}}},
		{"duplicate tools", manifest{ID: "test", Name: "Test", Version: "1", Wasm: "plugin.wasm", Tools: []Tool{{Name: "run", Description: "Run", InputSchema: map[string]any{"type": "object"}}, {Name: "run", Description: "Again", InputSchema: map[string]any{"type": "object"}}}}},
		{"missing schema", manifest{ID: "test", Name: "Test", Version: "1", Wasm: "plugin.wasm", Tools: []Tool{{Name: "run", Description: "Run"}}}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if err := validateManifest(test.manifest); err == nil {
				t.Fatal("invalid manifest accepted")
			}
		})
	}
}

func TestWASIOutputCannotBeEnabled(t *testing.T) {
	t.Setenv("EXTISM_ENABLE_WASI_OUTPUT", "1")
	if _, err := New(t.Context(), []Config{{Manifest: "unused.json"}}, nil); err == nil {
		t.Fatal("ambient WASI output override accepted")
	}
}
