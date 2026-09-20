package upstream

import (
	"context"
	"errors"
	"net"
	"net/http"
	"sync/atomic"

	"github.com/modelcontextprotocol/go-sdk/jsonrpc"
	"golang.org/x/oauth2"
)

// Failure contains only locally chosen labels and numeric protocol codes. It
// deliberately excludes upstream messages, bodies, URLs, headers and arguments.
// A failure does not establish whether a tool had effects and must not be retried
// automatically.
type Failure struct {
	Stage      string `json:"stage"`
	Kind       string `json:"kind"`
	HTTPStatus int    `json:"http_status,omitempty"`
	RPCCode    *int64 `json:"rpc_code,omitempty"`
	cause      error
}

func (f *Failure) Error() string { return "upstream " + f.Stage + ": " + f.Kind }
func (f *Failure) Unwrap() error { return f.cause }

func failure(stage string, err error, status int) error {
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

// Observe status without consuming responses or changing transport behavior.
// Each session owns its recorder; SDK HTTP requests may run concurrently.
type statusTransport struct {
	base   http.RoundTripper
	status atomic.Int64
}

func (t *statusTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	res, err := t.base.RoundTrip(r)
	if res != nil && res.StatusCode >= 300 {
		t.status.Store(int64(res.StatusCode))
	}
	return res, err
}
