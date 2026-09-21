package upstream

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

func TestDiscoveryCursorBudget(t *testing.T) {
	for _, jsonResponse := range []bool{true, false} {
		for _, tc := range []struct {
			name      string
			cursors   []string
			wantError bool
			wantPages int
		}{
			{"cumulative", []string{strings.Repeat("a", 1<<20), strings.Repeat("b", 1<<20), ""}, true, 2},
			{"oversized", []string{strings.Repeat("a", (2<<20)+1), ""}, true, 1},
			{"large allowed", []string{strings.Repeat("a", 1<<20), ""}, false, 2},
			{"opaque", []string{"雪\"\\\n", " next opaque cursor ", ""}, false, 3},
			{"cycle", []string{"a", "b", "a"}, true, 3},
		} {
			t.Run(fmt.Sprintf("%s/json=%t", tc.name, jsonResponse), func(t *testing.T) {
				var pages atomic.Int32
				server := mcp.NewServer(&mcp.Implementation{Name: "pagination-fixture", Version: "1"}, nil)
				server.AddReceivingMiddleware(func(next mcp.MethodHandler) mcp.MethodHandler {
					return func(ctx context.Context, method string, req mcp.Request) (mcp.Result, error) {
						if method != "tools/list" {
							return next(ctx, method, req)
						}
						i := int(pages.Add(1)) - 1
						if i >= len(tc.cursors) {
							return nil, fmt.Errorf("unexpected extra page")
						}
						want := ""
						if i > 0 {
							want = tc.cursors[i-1]
						}
						if req.GetParams().(*mcp.ListToolsParams).Cursor != want {
							t.Error("opaque cursor changed in transit")
						}
						return &mcp.ListToolsResult{NextCursor: tc.cursors[i], Tools: []*mcp.Tool{}}, nil
					}
				})
				fixture := httptest.NewServer(mcp.NewStreamableHTTPHandler(func(*http.Request) *mcp.Server { return server }, &mcp.StreamableHTTPOptions{Stateless: true, JSONResponse: jsonResponse}))
				defer fixture.Close()
				m := newTestManager(t, fixture.URL, Connection{ID: "one", URL: fixture.URL, NoAuth: true})
				_, err := m.ListTools(t.Context(), "one")
				if (err != nil) != tc.wantError || int(pages.Load()) != tc.wantPages {
					t.Fatalf("pages=%d error=%v", pages.Load(), err)
				}
				if tc.wantError {
					var diagnostic *Failure
					if !errors.As(err, &diagnostic) || diagnostic.Stage != "request" {
						t.Fatalf("missing request diagnostic: %v", err)
					}
					if tc.name != "cycle" && (diagnostic.Unwrap() == nil || !strings.Contains(diagnostic.Unwrap().Error(), "catalogue exceeds")) {
						t.Fatalf("wrong rejection cause: %v", diagnostic.Unwrap())
					}
				}
			})
		}
	}
}
