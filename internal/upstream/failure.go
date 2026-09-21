package upstream

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"mime"
	"net"
	"net/http"
	"strings"
	"sync"

	"github.com/modelcontextprotocol/go-sdk/jsonrpc"
	"golang.org/x/oauth2"
)

// Failure contains locally chosen labels, numeric codes and a restricted provider
// request ID. It excludes arbitrary upstream text, bodies, URLs and arguments.
// A failure does not establish whether a tool had effects and must not be retried
// automatically.
type Failure struct {
	Stage      string          `json:"stage"`
	Kind       string          `json:"kind"`
	HTTPStatus int             `json:"http_status,omitempty"`
	RPCCode    *int64          `json:"rpc_code,omitempty"`
	HTTP       *HTTPDiagnostic `json:"http,omitempty"`
	cause      error
}

// HTTPDiagnostic is safe to persist in an operation and return to its caller.
// Hints are local guidance, not proof of the upstream cause or execution outcome.
type HTTPDiagnostic struct {
	Reason    string `json:"reason,omitempty"`
	Hint      string `json:"hint,omitempty"`
	RequestID string `json:"request_id,omitempty"`
}

func (f *Failure) Error() string { return "upstream " + f.Stage + ": " + f.Kind }
func (f *Failure) Unwrap() error { return f.cause }

func failure(stage string, err error, status int) *Failure {
	f := &Failure{Stage: stage, Kind: "other", HTTPStatus: status, cause: err}
	var tokenErr *oauth2.RetrieveError
	var rpcErr *jsonrpc.Error
	var networkErr net.Error
	switch {
	case errors.Is(err, context.DeadlineExceeded):
		f.Kind = "timeout"
	case errors.Is(err, context.Canceled):
		f.Kind = "cancelled"
	case errors.As(err, &tokenErr):
		f.Kind = "oauth_token"
		if tokenErr.Response != nil {
			f.HTTPStatus = tokenErr.Response.StatusCode
		}
	case errors.As(err, &rpcErr):
		f.Kind, f.RPCCode = "jsonrpc", new(rpcErr.Code)
	case status != 0:
		f.Kind = "http"
	case errors.As(err, &networkErr):
		f.Kind = "network"
		if networkErr.Timeout() {
			f.Kind = "timeout"
		}
	}
	return f
}

// Each session owns its recorder; SDK HTTP requests may run concurrently. Read
// only a bounded error prefix and replay it unchanged for the SDK. Never capture
// OAuth exchanges (these happen inside the wrapped authentication transport).
type statusTransport struct {
	base   http.RoundTripper
	mu     sync.Mutex
	status int
	detail *HTTPDiagnostic
}

func (t *statusTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	res, err := t.base.RoundTrip(r)
	if res != nil && res.StatusCode >= 300 {
		detail := &HTTPDiagnostic{}
		// Dropbox supplies a 32-character hexadecimal support correlation ID.
		// Do not copy generic headers, arbitrary IDs, or values from other hosts.
		id := res.Header.Get("X-Dropbox-Request-Id")
		if r.URL.Hostname() == "mcp.dropbox.com" && len(id) == 32 && strings.Trim(id, "0123456789abcdef") == "" {
			detail.RequestID = id
		}
		contentType, _, _ := mime.ParseMediaType(res.Header.Get("Content-Type"))
		if err == nil && res.Body != nil && (res.StatusCode == 400 || res.StatusCode == 401 || res.StatusCode == 403) && (contentType == "text/plain" || contentType == "application/json") {
			body, readErr := io.ReadAll(io.LimitReader(res.Body, 4097))
			res.Body = &diagnosticBody{prefix: bytes.NewReader(body), original: res.Body, readErr: readErr}
			if readErr == nil && len(body) <= 4096 {
				detail.Reason, detail.Hint = knownHTTPError(body, contentType)
			}
		}
		t.mu.Lock()
		t.status, t.detail = res.StatusCode, detail
		t.mu.Unlock()
	}
	return res, err
}

func (t *statusTransport) reset() {
	t.mu.Lock()
	t.status, t.detail = 0, nil
	t.mu.Unlock()
}

func (t *statusTransport) failure(stage string, err error) *Failure {
	t.mu.Lock()
	defer t.mu.Unlock()
	f := failure(stage, err, t.status)
	if f.Kind == "http" && t.detail != nil && *t.detail != (HTTPDiagnostic{}) {
		f.HTTP = t.detail
	}
	return f
}

func knownHTTPError(body []byte, contentType string) (string, string) {
	if contentType == "text/plain" && strings.TrimSpace(string(body)) == "invalid request: authentication provider rejected request" {
		return "authentication_rejected", "The upstream authentication provider rejected the request. Check the app's required permissions, then reconnect OAuth; changing app permissions does not update an existing grant."
	}
	if contentType == "application/json" {
		var response struct {
			Error string `json:"error"`
		}
		if json.Unmarshal(body, &response) == nil {
			switch response.Error {
			case "invalid_token":
				return "invalid_token", "The provider rejected the access token. Check credentials and reconnect OAuth if needed."
			case "insufficient_scope":
				return "insufficient_scope", "The provider reports missing permissions. Check the app's required scopes and reconnect OAuth to grant them."
			}
		}
	}
	return "", ""
}

// Preserve the bytes and any read failure already observed while inspecting the
// prefix. Close must still reach the original response body.
type diagnosticBody struct {
	prefix   *bytes.Reader
	original io.ReadCloser
	readErr  error
}

func (b *diagnosticBody) Read(p []byte) (int, error) {
	if b.prefix.Len() > 0 {
		return b.prefix.Read(p)
	}
	if b.readErr != nil {
		return 0, b.readErr
	}
	return b.original.Read(p)
}

func (b *diagnosticBody) Close() error { return b.original.Close() }
