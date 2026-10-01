package gateway

import (
	"bytes"
	"encoding/json"
	"html"
	"net/http/httptest"
	"strings"
	"testing"

	"ampcode.com/lox/amp-mcp-gateway/internal/store"
	"ampcode.com/lox/amp-mcp-gateway/internal/upstream"
)

func TestPrettyJSONExpansion(t *testing.T) {
	for _, raw := range []string{
		strings.Repeat("[", 1000) + "9007199254740993" + strings.Repeat("]", 1000),
		strings.Repeat(`{"x":`, 1000) + `{"id":1,"id":2}` + strings.Repeat("}", 1000),
		strings.Repeat("[", 1000) + "invalid",
	} {
		got := prettyJSON([]byte(raw))
		if len(got) > 3*len(raw)+4096 {
			t.Fatalf("formatting expanded %d bytes to %d", len(raw), len(got))
		}
		var compact bytes.Buffer
		if json.Valid([]byte(raw)) {
			if err := json.Compact(&compact, []byte(got)); err != nil || compact.String() != raw {
				t.Fatal("formatting changed JSON tokens")
			}
		} else if got != raw {
			t.Fatal("formatting changed plain text")
		}
	}
}

func TestDeepJSONPresentation(t *testing.T) {
	nested := strings.Repeat("[", 1000) + "123" + strings.Repeat("]", 1000)
	g, s, _ := fixture(t)
	args := map[string]any{"payload": json.RawMessage(nested)}
	text, err := json.Marshal(nested)
	if err != nil {
		t.Fatal(err)
	}
	for i, result := range []string{
		`{"structuredContent":` + nested + `}`,
		`{"content":[{"type":"text","text":` + string(text) + `}]}`,
		`{"content":[{"type":"custom","value":` + nested + `}]}`,
		`{"legacy":` + nested + `}`,
	} {
		o := store.Operation{ID: string(rune('a' + i)), Tool: "notes.write", Connection: "notes", Status: "pending", Arguments: args, Result: json.RawMessage(result)}
		if _, err := s.Submit(t.Context(), o); err != nil {
			t.Fatal(err)
		}
		r := httptest.NewRequest("GET", "/operations/"+o.ID, nil)
		r.SetPathValue("id", o.ID)
		w := httptest.NewRecorder()
		g.operation(w, r)
		body := html.UnescapeString(w.Body.String())
		if len(body) > 100<<10 || !strings.Contains(body, nested) || !strings.Contains(body, "Approve once") {
			t.Fatalf("operation presentation expanded or lost full content: %d bytes", len(body))
		}
		stored, err := s.Get(t.Context(), o.ID)
		if err != nil || !bytes.Equal(stored.Result, o.Result) {
			t.Fatal("presentation changed stored result")
		}
	}
	tool := g.cfg.Tools[0]
	tool.InputSchema = map[string]any{"type": "object", "x-extra": json.RawMessage(nested)}
	m, err := upstream.New(g.cfg.BaseURL, g.cfg.Connections, s)
	if err != nil {
		t.Fatal(err)
	}
	w := httptest.NewRecorder()
	g.toolsPage(w, httptest.NewRequest("GET", "/connections/notes/tools", nil), m, "notes", []Tool{tool}, "fixture", "", false)
	if w.Body.Len() > 100<<10 || !strings.Contains(html.UnescapeString(w.Body.String()), nested) {
		t.Fatalf("schema presentation expanded or lost content: %d bytes", w.Body.Len())
	}
}

func FuzzPrettyJSONPreservesTokens(f *testing.F) {
	for _, seed := range []string{`{"x":"[]{}\\\"","id":9007199254740993,"id":2}`, `[]`, `[[{},[],[1,2,3]]]`, strings.Repeat("[", 1000) + "0" + strings.Repeat("]", 1000), "plain text"} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, raw string) {
		if len(raw) > 1<<20 {
			t.Skip()
		}
		got := prettyJSON([]byte(raw))
		var before, after bytes.Buffer
		if json.Compact(&before, []byte(raw)) != nil {
			if got != raw {
				t.Fatal("changed non-JSON text")
			}
			return
		}
		if len(got) > 3*before.Len()+4096 {
			t.Fatal("exceeded formatting budget")
		}
		if json.Compact(&after, []byte(got)) != nil || !bytes.Equal(before.Bytes(), after.Bytes()) {
			t.Fatal("changed JSON tokens")
		}
	})
}
