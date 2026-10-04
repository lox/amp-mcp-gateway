package browserauth

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"golang.org/x/oauth2"
)

func TestProjectNames(t *testing.T) {
	requests := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests++
		if r.URL.Path != "/api/v2/workspace/projects" || r.Header.Get("Authorization") != "Bearer fixture" || r.URL.Query().Get("limit") != "100" {
			t.Error("incorrect project request")
		}
		w.Header().Set("Content-Type", "application/json")
		if r.URL.Query().Get("cursor") == "" {
			_, _ = w.Write([]byte(`{"nextCursor":"page&two","projects":[{"id":"p1","namespace":"team","name":"First","owner":{"type":"workspace","id":"workspace","name":"Our workspace"}},{"id":"foreign","namespace":"other","name":"Private","owner":{"type":"workspace","id":"other","name":"Other workspace"}}]}`))
			return
		}
		if r.URL.Query().Get("cursor") != "page&two" {
			t.Error("cursor not encoded")
		}
		_, _ = w.Write([]byte(`{"projects":[{"id":"p2","namespace":"team","name":"Second","owner":{"type":"workspace","id":"workspace","name":"Our workspace"}}]}`))
	}))
	defer server.Close()
	a := &Auth{actorURL: server.URL + "/api/v2/actor", workspaceID: "workspace", client: server.Client()}
	names, err := a.ProjectNames(t.Context(), &oauth2.Token{AccessToken: "fixture"})
	if err != nil || requests != 2 || names.Project("workspace", "p2") != "team/Second" || names.Workspace("workspace") != "Our workspace" {
		t.Fatalf("names = %#v, requests = %d, err = %v", names, requests, err)
	}
	if names.Project("other", "p1") != "" || names.Project("workspace", "foreign") != "" || names.Workspace("other") != "" {
		t.Fatal("names crossed workspace identity boundary")
	}
}

func TestProjectNamesFailureDiscardsPartialResults(t *testing.T) {
	for _, failure := range []string{"forbidden", "malformed", "repeated cursor"} {
		t.Run(failure, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Query().Get("cursor") != "" {
					switch failure {
					case "forbidden":
						http.Error(w, "sensitive provider error", 403)
						return
					case "malformed":
						_, _ = w.Write([]byte(`{"projects":`))
						return
					}
				}
				_ = json.NewEncoder(w).Encode(map[string]any{"nextCursor": "same", "projects": []any{map[string]any{"id": "p1", "namespace": "team", "name": "First", "owner": map[string]string{"type": "workspace", "id": "workspace", "name": "Workspace"}}}})
			}))
			defer server.Close()
			a := &Auth{actorURL: server.URL + "/api/v2/actor", workspaceID: "workspace", client: server.Client()}
			names, err := a.ProjectNames(t.Context(), &oauth2.Token{AccessToken: "fixture"})
			if err == nil || names.Project("workspace", "p1") != "" {
				t.Fatal("failed lookup retained partial names")
			}
		})
	}
}
