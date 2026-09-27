// Package integration runs operator-installed integration plugins in WebAssembly.
package integration

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"slices"

	extism "github.com/extism/go-sdk"
	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/tetratelabs/wazero"
)

const (
	maxManifestBytes = 1 << 20
	maxInputBytes    = 1 << 20
	maxWasmBytes     = 32 << 20
	maxOutputBytes   = 1 << 20
	maxMemoryPages   = 1024 // 64 MiB
)

var identifier = regexp.MustCompile(`^[a-zA-Z0-9_-]{1,60}$`)

// Config installs one plugin from a reviewed local manifest.
type Config struct {
	Manifest, Account, Policy string
}

// Tool is a tool declared by a plugin manifest.
type Tool struct {
	Name, Description string
	InputSchema       map[string]any `json:"input_schema"`
}

type manifest struct {
	ID, Name, Version, Wasm string
	Tools                   []Tool
}

// Definition is the validated, loaded description used to publish plugin tools.
type Definition struct {
	ID, Name, Version, Account, Policy, Digest string
	Tools                                      []Tool
}

// Backend is the transport used for non-plugin connections.
type Backend interface {
	Call(context.Context, string, string, string, map[string]any) (*mcp.CallToolResult, error)
	Binding(string) string
}

type loaded struct {
	definition Definition
	compiled   *extism.CompiledPlugin
}

// Manager routes plugin calls and delegates all other connections.
type Manager struct {
	next    Backend
	plugins map[string]loaded
}

// New loads and compiles the configured plugins. Plugins get WASI for the
// JavaScript runtime, but no mounted filesystem, environment, output stream or
// allowed HTTP hosts.
func New(ctx context.Context, configs []Config, next Backend) (*Manager, error) {
	if len(configs) > 0 {
		if _, enabled := os.LookupEnv("EXTISM_ENABLE_WASI_OUTPUT"); enabled {
			return nil, errors.New("EXTISM_ENABLE_WASI_OUTPUT must be unset for integration plugins")
		}
	}
	m := &Manager{next: next, plugins: make(map[string]loaded, len(configs))}
	for _, cfg := range configs {
		plugin, err := load(ctx, cfg)
		if err != nil {
			m.Close(context.Background())
			return nil, fmt.Errorf("load integration plugin %q: %w", cfg.Manifest, err)
		}
		if _, exists := m.plugins[plugin.definition.ID]; exists {
			plugin.compiled.Close(context.Background())
			m.Close(context.Background())
			return nil, fmt.Errorf("duplicate integration plugin ID %q", plugin.definition.ID)
		}
		m.plugins[plugin.definition.ID] = plugin
	}
	return m, nil
}

func load(ctx context.Context, cfg Config) (loaded, error) {
	if cfg.Manifest == "" {
		return loaded{}, errors.New("manifest path is required")
	}
	rawManifest, err := readBounded(cfg.Manifest, maxManifestBytes)
	if err != nil {
		return loaded{}, err
	}
	var manifest manifest
	decoder := json.NewDecoder(bytes.NewReader(rawManifest))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&manifest); err != nil {
		return loaded{}, fmt.Errorf("decode manifest: %w", err)
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		if err == nil {
			err = errors.New("multiple JSON values")
		}
		return loaded{}, fmt.Errorf("decode manifest: %w", err)
	}
	if err := validateManifest(manifest); err != nil {
		return loaded{}, err
	}
	if !validPolicy(cfg.Policy) {
		return loaded{}, errors.New("policy must be allow, require_approval or deny")
	}
	wasmPath := filepath.Join(filepath.Dir(cfg.Manifest), manifest.Wasm)
	wasm, err := readBounded(wasmPath, maxWasmBytes)
	if err != nil {
		return loaded{}, err
	}
	hash := sha256.New()
	hash.Write(rawManifest)
	hash.Write(wasm)
	digest := hex.EncodeToString(hash.Sum(nil))
	compiled, err := extism.NewCompiledPlugin(ctx, extism.Manifest{
		Wasm:         []extism.Wasm{extism.WasmData{Data: wasm, Hash: digestBytes(wasm)}},
		Memory:       &extism.ManifestMemory{MaxPages: maxMemoryPages, MaxHttpResponseBytes: 0, MaxVarBytes: 0},
		AllowedHosts: []string{},
		AllowedPaths: map[string]string{},
	}, extism.PluginConfig{
		EnableWasi: true,
		RuntimeConfig: wazero.NewRuntimeConfig().
			WithMemoryLimitPages(maxMemoryPages).
			WithCloseOnContextDone(true),
	}, nil)
	if err != nil {
		return loaded{}, fmt.Errorf("compile wasm: %w", err)
	}
	return loaded{
		definition: Definition{ID: manifest.ID, Name: manifest.Name, Version: manifest.Version, Account: cfg.Account, Policy: cfg.Policy, Digest: digest, Tools: slices.Clone(manifest.Tools)},
		compiled:   compiled,
	}, nil
}

func validateManifest(m manifest) error {
	if !identifier.MatchString(m.ID) {
		return errors.New("manifest ID must contain 1-60 letters, numbers, dashes or underscores")
	}
	if m.Name == "" || len(m.Name) > 100 || m.Version == "" || len(m.Version) > 100 {
		return errors.New("manifest name and version are required and limited to 100 characters")
	}
	if filepath.Base(m.Wasm) != m.Wasm || filepath.IsAbs(m.Wasm) || filepath.Ext(m.Wasm) != ".wasm" {
		return errors.New("manifest wasm must name a sibling .wasm file")
	}
	if len(m.Tools) == 0 || len(m.Tools) > 500 {
		return errors.New("manifest must declare 1-500 tools")
	}
	seen := make(map[string]bool, len(m.Tools))
	for _, tool := range m.Tools {
		if !identifier.MatchString(tool.Name) || tool.Description == "" || len(tool.Description) > 1000 || tool.InputSchema == nil {
			return errors.New("each tool needs a valid name, description and input schema")
		}
		if seen[tool.Name] {
			return fmt.Errorf("duplicate tool %q", tool.Name)
		}
		seen[tool.Name] = true
	}
	return nil
}

func validPolicy(policy string) bool {
	return policy == "" || policy == "allow" || policy == "require_approval" || policy == "deny"
}

func readBounded(path string, limit int64) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() || info.Size() > limit {
		return nil, errors.New("plugin file is not a regular file within the size limit")
	}
	data, err := io.ReadAll(io.LimitReader(f, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > limit {
		return nil, errors.New("plugin file exceeds the size limit")
	}
	return data, nil
}

func digestBytes(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

// Definitions returns the immutable catalogue loaded at startup.
func (m *Manager) Definitions() []Definition {
	definitions := make([]Definition, 0, len(m.plugins))
	for _, plugin := range m.plugins {
		definition := plugin.definition
		definition.Tools = slices.Clone(definition.Tools)
		definitions = append(definitions, definition)
	}
	slices.SortFunc(definitions, func(a, b Definition) int { return bytes.Compare([]byte(a.ID), []byte(b.ID)) })
	return definitions
}

// Binding returns the loaded artifact digest for plugin connections.
func (m *Manager) Binding(connection string) string {
	if plugin, ok := m.plugins[connection]; ok {
		return plugin.definition.Digest
	}
	if m.next == nil {
		return ""
	}
	return m.next.Binding(connection)
}

// Call invokes one fresh plugin instance so memory and mutable globals are not
// shared between operations.
func (m *Manager) Call(ctx context.Context, connection, tool, expectedBinding string, args map[string]any) (*mcp.CallToolResult, error) {
	plugin, ok := m.plugins[connection]
	if !ok {
		if m.next == nil {
			return nil, errors.New("unknown integration plugin")
		}
		return m.next.Call(ctx, connection, tool, expectedBinding, args)
	}
	if expectedBinding == "" || expectedBinding != plugin.definition.Digest {
		return nil, errors.New("integration plugin changed before dispatch")
	}
	input, err := json.Marshal(args)
	if err != nil {
		return nil, err
	}
	if len(input) > maxInputBytes {
		return nil, errors.New("integration plugin input exceeds limit")
	}
	instance, err := plugin.compiled.Instance(ctx, extism.PluginInstanceConfig{ModuleConfig: wazero.NewModuleConfig()})
	if err != nil {
		return nil, fmt.Errorf("instantiate integration plugin: %w", err)
	}
	defer instance.Close(context.Background())
	exit, output, err := instance.CallWithContext(ctx, tool, input)
	if err != nil {
		return nil, fmt.Errorf("call integration plugin: %w", err)
	}
	if exit != 0 {
		return nil, fmt.Errorf("integration plugin exited with status %d", exit)
	}
	if len(output) > maxOutputBytes {
		return nil, errors.New("integration plugin output exceeds limit")
	}
	var result mcp.CallToolResult
	if err := json.Unmarshal(output, &result); err != nil {
		return nil, errors.New("integration plugin returned an invalid MCP tool result")
	}
	return &result, nil
}

// Close releases compiled plugin runtimes.
func (m *Manager) Close(ctx context.Context) error {
	var errs []error
	for _, plugin := range m.plugins {
		errs = append(errs, plugin.compiled.Close(ctx))
	}
	return errors.Join(errs...)
}
