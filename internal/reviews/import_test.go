//go:build reviewimport

package reviews

import (
	"encoding/json"
	"strings"
	"testing"

	"ampcode.com/lox/amp-mcp-gateway/internal/store"
	"golang.org/x/sync/semaphore"
)

func TestLegacyOfflineImport(t *testing.T) {
	_, gh := newGitHub(t)
	s, st, path, key := fixtureService(t, "user", &fakeAmp{}, gh, semaphore.NewWeighted(4))
	a := fixtureApp(t, "lox")
	a.Enabled = false
	if err := s.Save(t.Context(), a); err != nil {
		t.Fatal(err)
	}
	if err := st.SaveToken(t.Context(), "account-identity", []byte("user")); err != nil {
		t.Fatal(err)
	}
	p := fixturePull("lox/repo", 44)
	entry := map[string]any{
		"job":     map[string]any{"id": 17, "source_delivery_id": "old-delivery", "event_type": "pull_request.opened", "installation_id": 11, "repository_id": 44, "repository_full_name": "Lox/Repo", "pull_number": 7, "base_sha": p.Base.SHA, "head_sha": p.Head.SHA, "amp_project": "old/project", "pull_request_title": p.Title, "pull_request_body": p.Body, "base_ref": "main", "head_ref": "feature", "check_run_id": 101, "status": "succeeded", "created_at": "2026-10-01T01:02:03Z", "completed_at": "2026-10-01T01:03:03Z"},
		"threads": []any{map[string]any{"thread_id": testThread, "amp_usage_usd": 0.25, "estimated_provider_cost_at_list_price_usd": 1.5, "usage_details": map[string]any{"inputTokens": 123, "outputTokens": 45, "requests": 6}, "archived_at": "2026-10-01T01:03:04Z"}},
		"result":  map[string]any{"conclusion": "success", "fail_on": "high", "prompt_identifier": "legacy-prompt", "summary": "No issues", "findings": []any{}, "omitted_findings": 0},
	}
	raw, _ := json.Marshal(entry)
	if _, err := ImportLegacy(t.Context(), path, key, a.ID, strings.NewReader(string(raw))); err == nil || !strings.Contains(err.Error(), "already in use") {
		t.Fatalf("import must refuse a running gateway: %v", err)
	}
	if err := st.Close(); err != nil {
		t.Fatal(err)
	}
	// A partial import can be resumed without replacing the committed history.
	if count, err := ImportLegacy(t.Context(), path, key, a.ID, strings.NewReader(string(raw)+"\nnot-json")); count != 1 || err == nil {
		t.Fatalf("partial import: %d %v", count, err)
	}
	if count, err := ImportLegacy(t.Context(), path, key, a.ID, strings.NewReader(string(raw))); count != 0 || err != nil {
		t.Fatalf("reimport: %d %v", count, err)
	}
	entry["job"].(map[string]any)["installation_id"] = 22
	foreign, _ := json.Marshal(entry)
	if count, err := ImportLegacy(t.Context(), path, key, a.ID, strings.NewReader(string(foreign))); count != 0 || err == nil {
		t.Fatal("accepted a foreign installation")
	}
	st, err := store.Open(path, key)
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	s, err = New(t.Context(), "user", st, &fakeAmp{}, gh, semaphore.NewWeighted(4))
	if err != nil {
		t.Fatal(err)
	}
	jobs := history(t, s)
	if len(jobs) != 1 {
		t.Fatalf("history count: %d", len(jobs))
	}
	j := jobs[0]
	if j.OwnerID != "user" || j.Repository != "lox/repo" || j.Project != "old/project" || j.Context != p.job("lox/repo", 44).Context || j.CheckID != 101 || j.BaseSHA != p.Base.SHA || j.HeadSHA != p.Head.SHA || j.Result == nil || j.Result.Summary != "No issues" || len(j.Threads) != 1 || !j.Threads[0].Archived || j.Threads[0].Usage.InputTokens != 123 || *j.Threads[0].Usage.ProviderEstimateUSD != 1.5 {
		t.Fatal("historical data lost")
	}
	if err := s.Step(t.Context()); err != nil || history(t, s)[0].Status != "succeeded" {
		t.Fatal("import queued work")
	}
	a.Enabled = true
	if err := s.Save(t.Context(), a); err != nil {
		t.Fatal(err)
	}
	if err := st.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := ImportLegacy(t.Context(), path, key, a.ID, strings.NewReader(string(raw))); err == nil || !strings.Contains(err.Error(), "pause") {
		t.Fatalf("import accepted for enabled App: %v", err)
	}
}
