package policy

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"
)

type transport func(*http.Request) (*http.Response, error)

func (f transport) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func TestSuggest(t *testing.T) {
	for _, tc := range []struct {
		name, key string
		value     any
		want      string
	}{
		{"public read at threshold", "safe", 0.95, "allow"},
		{"below threshold", "safe", 0.949, "require_approval"},
		{"write at threshold", "writes", 0.05, "allow"},
		{"write above threshold", "writes", 0.051, "require_approval"},
		{"communication", "communicates", 0.8, "require_approval"},
		{"spending", "spends", 0.6, "require_approval"},
		{"permissions", "permissions", 0.3, "require_approval"},
		{"sensitive reads", "sensitive", 0.7, "require_approval"},
		{"arbitrary execution", "execution", 0.9, "require_approval"},
		{"null risk", "writes", nil, "require_approval"},
		{"out of range", "safe", 2, "require_approval"},
		{"wrong type", "safe", "yes", "require_approval"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			answers := map[string]any{"safe": map[string]any{"type": "noul", "noul": 1}}
			for _, key := range []string{"writes", "communicates", "spends", "permissions", "sensitive", "execution"} {
				answers[key] = map[string]any{"type": "noul", "noul": 0}
			}
			answers[tc.key] = map[string]any{"type": "noul", "noul": tc.value}
			body, err := json.Marshal(map[string]any{"model": "jev-test", "answers": answers})
			if err != nil {
				t.Fatal(err)
			}
			c := Client{Key: "test-secret", HTTP: &http.Client{Transport: transport(func(r *http.Request) (*http.Response, error) {
				b, _ := io.ReadAll(r.Body)
				if strings.Contains(string(b), "private-connection") || strings.Contains(string(b), "test-secret") {
					t.Fatal("sent connection or credential in body")
				}
				if r.Header.Get("Authorization") != "Bearer test-secret" {
					t.Fatal("missing authentication")
				}
				return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader(string(body)))}, nil
			})}}
			got := c.Suggest(context.Background(), Tool{Name: "lookup", InputSchema: map[string]any{"type": "object"}})
			if got.Policy != tc.want {
				t.Fatalf("got %s, want %s", got.Policy, tc.want)
			}
		})
	}
}

func TestMissingKeyNeverCallsProvider(t *testing.T) {
	c := Client{HTTP: &http.Client{Transport: transport(func(*http.Request) (*http.Response, error) {
		t.Fatal("missing key must not make a network request")
		return nil, errors.New("unexpected request")
	})}}
	if got := c.Suggest(t.Context(), Tool{}); got.Policy != "require_approval" {
		t.Fatalf("missing key: %+v", got)
	}
}

func TestProviderFailureIsSanitized(t *testing.T) {
	c := Client{Key: "secret", HTTP: &http.Client{Transport: transport(func(*http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: 401, Body: io.NopCloser(strings.NewReader("secret provider detail"))}, nil
	})}}
	got := c.Suggest(t.Context(), Tool{})
	if got.Policy != "require_approval" || strings.Contains(got.Reason, "secret") {
		t.Fatalf("%+v", got)
	}
}

func TestInvalidResponsesFailClosed(t *testing.T) {
	for _, body := range []string{
		`not json`,
		`{"model":"jev-test","answers":{"safe":{"type":"noul","noul":1}}}`,
		`{"model":"jev-test","answers":null}`,
		strings.Repeat(" ", 64*1024+1),
	} {
		c := Client{Key: "test", HTTP: &http.Client{Transport: transport(func(*http.Request) (*http.Response, error) {
			return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader(body))}, nil
		})}}
		if got := c.Suggest(t.Context(), Tool{}); got.Policy != "require_approval" {
			t.Fatalf("invalid response allowed: %+v", got)
		}
	}
}

func TestTransportFailureAndCancellation(t *testing.T) {
	c := Client{Key: "test", HTTP: &http.Client{Transport: transport(func(r *http.Request) (*http.Response, error) {
		if _, ok := r.Context().Deadline(); !ok {
			t.Fatal("request has no deadline")
		}
		return nil, errors.New("private transport details")
	})}}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	for _, ctx := range []context.Context{t.Context(), ctx} {
		got := c.Suggest(ctx, Tool{})
		if got.Policy != "require_approval" || strings.Contains(got.Reason, "private") {
			t.Fatalf("%+v", got)
		}
	}
}
