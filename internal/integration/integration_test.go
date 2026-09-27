package integration

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(request *http.Request) (*http.Response, error) {
	return f(request)
}

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
	requests := 0
	originalTransport := http.DefaultTransport
	http.DefaultTransport = roundTripFunc(func(*http.Request) (*http.Response, error) {
		requests++
		return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(strings.NewReader("unexpected")), Header: http.Header{}}, nil
	})
	t.Cleanup(func() { http.DefaultTransport = originalTransport })
	result, err := m.Call(t.Context(), "fixture", "network", binding, map[string]any{})
	if err != nil || !result.IsError || requests != 0 {
		t.Fatalf("network access was not denied: result=%#v err=%v requests=%d", result, err, requests)
	}
	ctx, cancel := context.WithTimeout(t.Context(), 50*time.Millisecond)
	defer cancel()
	result, err = m.Call(ctx, "fixture", "spin", binding, map[string]any{})
	if err != nil || !result.IsError {
		t.Fatalf("runaway plugin was not stopped: result=%#v err=%v", result, err)
	}
	if _, err := m.Call(t.Context(), "fixture", "echo", binding, map[string]any{"text": "after timeout"}); err != nil {
		t.Fatalf("fresh instance failed after timeout: %v", err)
	}
}

func TestManifestToolsMustBeExported(t *testing.T) {
	directory := t.TempDir()
	wasm, err := os.ReadFile(filepath.Join("testdata", "fixture", "fixture.wasm"))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(directory, "fixture.wasm"), wasm, 0600); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(filepath.Join("testdata", "fixture", "manifest.json"))
	if err != nil {
		t.Fatal(err)
	}
	var manifest manifest
	if err := json.Unmarshal(raw, &manifest); err != nil {
		t.Fatal(err)
	}
	manifest.Tools = append(manifest.Tools, Tool{Name: "missing", Description: "Missing export", InputSchema: map[string]any{"type": "object"}})
	raw, err = json.Marshal(manifest)
	if err != nil {
		t.Fatal(err)
	}
	manifestPath := filepath.Join(directory, "manifest.json")
	if err := os.WriteFile(manifestPath, raw, 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := New(t.Context(), []Config{{Manifest: manifestPath}}, nil); err == nil || !strings.Contains(err.Error(), "not exported") {
		t.Fatalf("missing export accepted: %v", err)
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
