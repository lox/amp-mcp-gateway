package upstream

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/oauth2"
)

func refreshFixture(t *testing.T, handler http.HandlerFunc, expiry time.Time) (*Manager, *managedConnection, *memoryStore) {
	t.Helper()
	server := httptest.NewServer(handler)
	t.Cleanup(server.Close)
	c := Connection{ID: "oauth", URL: server.URL + "/mcp", OAuth: &OAuthConfig{ClientID: "fixture-client", AuthURL: server.URL + "/authorize", TokenURL: server.URL + "/token", Resource: server.URL + "/mcp"}}
	s := &memoryStore{data: map[string][]byte{}}
	raw, err := json.Marshal(&credentials{Token: oauth2.Token{AccessToken: "old-canary", RefreshToken: "refresh-canary", Expiry: expiry}})
	if err != nil {
		t.Fatal(err)
	}
	s.data[tokenKey(c)] = raw
	m, err := New("http://localhost", []Connection{c}, s)
	if err != nil {
		t.Fatal(err)
	}
	return m, m.conns[c.ID], s
}

func TestProactiveRefreshDueAndRestart(t *testing.T) {
	for _, tc := range []struct {
		name   string
		expiry time.Time
		want   int32
	}{
		{"soon", time.Now().Add(80 * time.Second), 1},
		{"later", time.Now().Add(4 * time.Minute), 0},
		{"no expiry", time.Time{}, 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var calls atomic.Int32
			var m *Manager
			var c *managedConnection
			var s *memoryStore
			m, c, s = refreshFixture(t, func(w http.ResponseWriter, r *http.Request) {
				calls.Add(1)
				stored, err := m.loadToken(r.Context(), c)
				if err != nil || stored.RefreshState != "refreshing" {
					t.Error("refresh dispatched before durable claim")
				}
				r.ParseForm()
				if r.Form.Get("resource") != c.config.URL || r.Form.Get("refresh_token") != "refresh-canary" || r.Form.Get("grant_type") != "refresh_token" || r.Form.Get("client_id") != "fixture-client" {
					t.Error("incorrect refresh request")
				}
				w.Header().Set("Content-Type", "application/json")
				fmt.Fprint(w, `{"access_token":"new-canary","refresh_token":"rotated-canary","expires_in":3600}`)
			}, tc.expiry)
			m.refreshDue(t.Context())
			m.refreshDue(t.Context())
			if calls.Load() != tc.want {
				t.Fatalf("refresh calls = %d, want %d", calls.Load(), tc.want)
			}
			if tc.want == 0 {
				return
			}
			restarted, err := New("http://localhost", []Connection{c.config}, s)
			if err != nil {
				t.Fatal(err)
			}
			token, err := restarted.refresh(t.Context(), restarted.conns[c.config.ID], false)
			if err != nil || token.AccessToken != "new-canary" || token.RefreshToken != "rotated-canary" || calls.Load() != 1 {
				t.Fatal("restart did not reuse durably rotated credentials", err)
			}
			h := restarted.Health(t.Context(), c.config.ID)
			if h.RefreshedAt.IsZero() || h.Status != "Not tested" {
				t.Fatal("refresh must not claim MCP access was tested")
			}
		})
	}
}

func TestRefreshFailureDoesNotReplay(t *testing.T) {
	for _, tc := range []struct {
		name, body, state, status string
		code                      int
	}{
		{"revoked", `{"error":"invalid_grant","error_description":"private-canary"}`, "reconnect", "Reconnect required", 400},
		{"client rejected", `{"error":"invalid_client"}`, "configuration", "Refresh blocked", 401},
		{"malformed success", `{"access_token":`, "unknown", "Refresh uncertain", 200},
		{"contradictory success", `{"error":"server_error"}`, "unknown", "Refresh uncertain", 200},
		{"unstructured outage", `private-canary`, "unknown", "Refresh uncertain", 503},
		{"lost response", "", "unknown", "Refresh uncertain", 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var calls atomic.Int32
			m, c, s := refreshFixture(t, func(w http.ResponseWriter, r *http.Request) {
				calls.Add(1)
				if tc.code == 0 {
					conn, _, err := w.(http.Hijacker).Hijack()
					if err != nil {
						t.Error(err)
						return
					}
					conn.Close()
					return
				}
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(tc.code)
				fmt.Fprint(w, tc.body)
			}, time.Now().Add(-time.Minute))
			if _, err := m.refresh(t.Context(), c, false); err == nil || strings.Contains(err.Error(), "private-canary") {
				t.Fatal("refresh failure missing or leaked provider response")
			}
			token, _ := m.loadToken(t.Context(), c)
			if token.RefreshState != tc.state {
				t.Fatalf("state = %q", token.RefreshState)
			}
			restarted, err := New("http://localhost", []Connection{c.config}, s)
			if err != nil {
				t.Fatal(err)
			}
			restarted.refreshDue(t.Context())
			_, _ = restarted.refresh(t.Context(), restarted.conns[c.config.ID], false)
			_ = restarted.TestConnection(t.Context(), c.config.ID)
			if calls.Load() != 1 || restarted.Health(t.Context(), c.config.ID).Status != tc.status {
				t.Fatal("failed refresh replayed or health incorrect")
			}
		})
	}
}

func TestTemporaryRefreshFailuresHaveBoundedPersistentBackoff(t *testing.T) {
	var calls atomic.Int32
	m, c, s := refreshFixture(t, func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(503)
		fmt.Fprint(w, `{"error":"temporarily_unavailable"}`)
	}, time.Now().Add(-time.Minute))
	for attempt := 1; attempt <= 3; attempt++ {
		_, _ = m.refresh(t.Context(), c, false)
		token, _ := m.loadToken(t.Context(), c)
		if calls.Load() != int32(attempt) || token.Attempts != attempt {
			t.Fatal("incorrect attempt count")
		}
		if attempt < 3 {
			if token.RefreshState != "retry" || time.Until(token.RetryAt) < time.Duration(attempt)*time.Minute-5*time.Second {
				t.Fatal("missing backoff")
			}
			m.refreshDue(t.Context())
			if calls.Load() != int32(attempt) {
				t.Fatal("retried before deadline")
			}
			token.RetryAt = time.Now().Add(-time.Second)
			if err := m.saveCredentials(t.Context(), c, token); err != nil {
				t.Fatal(err)
			}
			var err error
			m, err = New("http://localhost", []Connection{c.config}, s)
			if err != nil {
				t.Fatal(err)
			}
			c = m.conns[c.config.ID]
		}
	}
	m.refreshDue(t.Context())
	if calls.Load() != 3 || m.Health(t.Context(), c.config.ID).Status != "Refresh paused" {
		t.Fatal("unbounded refresh retries")
	}
	_ = m.TestConnection(t.Context(), c.config.ID)
	if calls.Load() != 4 || m.Health(t.Context(), c.config.ID).Status != "Refresh delayed" {
		t.Fatal("manual test did not resume safe retries")
	}
}

type failingTokenStore struct {
	*memoryStore
	failAt, writes int
}

func (s *failingTokenStore) SaveToken(ctx context.Context, key string, raw []byte) error {
	s.writes++
	if s.writes == s.failAt {
		return errors.New("disk unavailable")
	}
	return s.memoryStore.SaveToken(ctx, key, raw)
}

func TestRefreshPersistenceFailures(t *testing.T) {
	for _, failAt := range []int{1, 2} {
		t.Run(fmt.Sprint(failAt), func(t *testing.T) {
			var calls atomic.Int32
			m, c, s := refreshFixture(t, func(w http.ResponseWriter, r *http.Request) {
				calls.Add(1)
				w.Header().Set("Content-Type", "application/json")
				fmt.Fprint(w, `{"access_token":"new","refresh_token":"rotated","expires_in":3600}`)
			}, time.Now().Add(-time.Minute))
			m.store = &failingTokenStore{memoryStore: s, failAt: failAt}
			if token, err := m.refresh(t.Context(), c, false); err == nil || token != nil {
				t.Fatal("unpersisted token exposed")
			}
			if calls.Load() != int32(failAt-1) {
				t.Fatal("dispatch without claim")
			}
			if failAt == 2 {
				restarted, err := New("http://localhost", []Connection{c.config}, s)
				if err != nil {
					t.Fatal(err)
				}
				restarted.refreshDue(t.Context())
				if calls.Load() != 1 || restarted.Health(t.Context(), c.config.ID).Status != "Refresh uncertain" {
					t.Fatal("lost rotation replayed after restart")
				}
			}
		})
	}
}

func TestRefreshWorkerStops(t *testing.T) {
	m, err := New("http://localhost", nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if err := m.RunRefresh(ctx); err != nil {
		t.Fatal(err)
	}
}

func TestRefreshConnectionFailureCanRetry(t *testing.T) {
	closed := httptest.NewServer(http.NotFoundHandler())
	closed.Close()
	m, c, _ := refreshFixture(t, func(w http.ResponseWriter, r *http.Request) { t.Error("wrong token endpoint") }, time.Now().Add(-time.Minute))
	token, err := m.loadToken(t.Context(), c)
	if err != nil {
		t.Fatal(err)
	}
	c.config.OAuth.TokenURL = closed.URL
	if err := m.saveCredentials(t.Context(), c, token); err != nil {
		t.Fatal(err)
	}
	if _, err := m.refresh(t.Context(), c, false); err == nil {
		t.Fatal("connection refusal succeeded")
	}
	if h := m.Health(t.Context(), c.config.ID); h.Status != "Refresh delayed" || h.RetryAt.IsZero() {
		t.Fatalf("safe retry not scheduled: %+v", h)
	}
}

func TestRefreshRetainsTokenWhenProviderDoesNotRotate(t *testing.T) {
	m, c, _ := refreshFixture(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"access_token":"fresh","expires_in":3600}`)
	}, time.Now().Add(-time.Minute))
	token, err := m.refresh(t.Context(), c, false)
	if err != nil || token.RefreshToken != "refresh-canary" {
		t.Fatal("refresh token lost when omitted by provider", err)
	}
}

func TestLegacyClientAuthChangesOnlyAfterDefiniteRejection(t *testing.T) {
	var calls atomic.Int32
	m, c, _ := refreshFixture(t, func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		w.Header().Set("Content-Type", "application/json")
		if _, _, basic := r.BasicAuth(); basic {
			w.WriteHeader(401)
			fmt.Fprint(w, `{"error":"invalid_client"}`)
			return
		}
		r.ParseForm()
		if r.Form.Get("client_secret") != "fixture-secret" {
			t.Error("missing client authentication")
		}
		fmt.Fprint(w, `{"access_token":"fresh","expires_in":3600}`)
	}, time.Now().Add(-time.Minute))
	token, _ := m.loadToken(t.Context(), c)
	c.config.OAuth.ClientSecret = "fixture-secret"
	if err := m.saveCredentials(t.Context(), c, token); err != nil {
		t.Fatal(err)
	}
	_, _ = m.refresh(t.Context(), c, false)
	if calls.Load() != 1 {
		t.Fatal("auth method automatically replayed")
	}
	token, _ = m.loadToken(t.Context(), c)
	if token.AuthStyle != oauth2.AuthStyleInParams || token.RefreshState != "retry" {
		t.Fatal("safe auth fallback not persisted")
	}
	token.RetryAt = time.Now().Add(-time.Second)
	if err := m.saveCredentials(t.Context(), c, token); err != nil {
		t.Fatal(err)
	}
	if _, err := m.refresh(t.Context(), c, false); err != nil {
		t.Fatal(err)
	}
	if calls.Load() != 2 {
		t.Fatal("wrong fallback attempt count")
	}
}
