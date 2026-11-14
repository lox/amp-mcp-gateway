// Package jsintegration defines immutable, operator-installed JavaScript API tools.
package jsintegration

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/url"
	"os"
	"path"
	"regexp"
	"strings"

	"ampcode.com/lox/amp-mcp-gateway/internal/jsruntime"
	"github.com/santhosh-tekuri/jsonschema/v6"
)

// Definition is a static source bundle and its HTTP authority. Origin is not an MCP URL.
// SourceFile is read only during startup; retained Source bytes are used thereafter.
type Definition struct {
	Origin     string
	SourceFile string `json:",omitempty"`
	Source     string `json:",omitempty"`
	// Generation is assigned by the owner ledger at startup, never by JavaScript.
	Generation string `json:",omitempty"`
	Tools      []Tool
}

// Tool declares a handler and its exact HTTP method/path capabilities. Policy is gateway-owned.
type Tool struct {
	Name, Handler, Description string
	InputSchema, OutputSchema  map[string]any
	HTTP                       []Grant
}

// Grant authorizes an exact method/path pair, without query parameters.
type Grant struct{ Method, Path string }

var name = regexp.MustCompile(`^[A-Za-z_$][A-Za-z0-9_$]*$`)

// Load reads a bounded bundle once. Runtime execution never reads SourceFile.
func (d *Definition) Load() error {
	if d.SourceFile != "" {
		f, err := os.Open(d.SourceFile)
		if err != nil {
			return err
		}
		defer f.Close()
		b, err := io.ReadAll(io.LimitReader(f, jsruntime.MaxSource+1))
		if err != nil {
			return err
		}
		d.Source = string(b)
	}
	return d.Validate()
}

// Validate checks metadata without evaluating integration code.
func (d *Definition) Validate() error {
	encoded, err := json.Marshal(d)
	if err != nil || len(encoded) > 1<<20 {
		return errors.New("JavaScript manifest and source exceed 1 MiB")
	}
	u, err := url.Parse(d.Origin)
	if err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || u.Path != "" || u.RawQuery != "" || u.Fragment != "" || u.Opaque != "" || (u.Port() != "" && u.Port() != "443") {
		return errors.New("JavaScript origin must be an HTTPS origin on port 443")
	}
	if len(d.Source) == 0 || len(d.Source) > jsruntime.MaxSource || len(d.Tools) == 0 || len(d.Tools) > 100 {
		return errors.New("invalid JavaScript bundle size or tool count")
	}
	names := map[string]bool{}
	for _, t := range d.Tools {
		if !name.MatchString(t.Name) || !name.MatchString(t.Handler) || names[t.Name] || len(t.Description) > 4096 || len(t.HTTP) > 10 {
			return errors.New("invalid JavaScript tool definition")
		}
		names[t.Name] = true
		for _, s := range []map[string]any{t.InputSchema, t.OutputSchema} {
			if _, err := CompileSchema(s); err != nil {
				return err
			}
		}
		for _, grant := range t.HTTP {
			switch grant.Method {
			case "GET", "POST", "PUT", "PATCH", "DELETE", "HEAD":
			default:
				return errors.New("invalid HTTP grant method")
			}
			if !ValidPath(grant.Path) {
				return errors.New("invalid exact HTTP grant path")
			}
		}
	}
	return nil
}

// ValidPath deliberately excludes percent encodings and all ambiguous path spellings.
func ValidPath(p string) bool {
	if p == "" || p[0] != '/' || strings.HasPrefix(p, "//") || strings.ContainsAny(p, "%\\?#\r\n\x00") || path.Clean(p) != p {
		return false
	}
	for _, c := range p {
		if c < 0x21 || c > 0x7e {
			return false
		}
	}
	return true
}

// CompileSchema allows only document-local references, never network loading.
func CompileSchema(s map[string]any) (*jsonschema.Schema, error) {
	b, err := json.Marshal(s)
	if err != nil || s == nil || len(b) > 64<<10 {
		return nil, errors.New("invalid JavaScript schema")
	}
	c := jsonschema.NewCompiler()
	c.UseLoader(jsonschema.SchemeURLLoader{})
	if err := c.AddResource("schema.json", s); err != nil {
		return nil, err
	}
	return c.Compile("schema.json")
}

// Binding includes the complete artifact, runtime ABI and credential generation.
// The digest is authority metadata, not a credential supplied to JavaScript.
func (d *Definition) Binding(token string) string {
	b, _ := json.Marshal([]any{jsruntime.ABI, d, token})
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:])
}
