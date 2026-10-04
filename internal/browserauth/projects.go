package browserauth

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"strings"

	"golang.org/x/oauth2"
)

// ProjectNames contains display-only metadata. IDs remain the authority.
type ProjectNames struct {
	WorkspaceID, WorkspaceName string
	Projects                   map[string]string
}

// Project returns a name only for the exact workspace/project pair.
func (n ProjectNames) Project(workspace, project string) string {
	if workspace == "" || workspace != n.WorkspaceID {
		return ""
	}
	return n.Projects[project]
}

// Workspace returns a name only for the exact workspace ID.
func (n ProjectNames) Workspace(workspace string) string {
	if workspace == "" || workspace != n.WorkspaceID {
		return ""
	}
	return n.WorkspaceName
}

// ProjectNames lists the configured workspace's projects with a delegated token.
// It never reads threads: that API currently requires broader M2M credentials.
func (a *Auth) ProjectNames(ctx context.Context, token *oauth2.Token) (ProjectNames, error) {
	names := ProjectNames{WorkspaceID: a.workspaceID, Projects: map[string]string{}}
	cursor := ""
	seen := map[string]bool{}
	for range 100 { // Bound both work and retained names to 10,000 projects.
		query := url.Values{"limit": {"100"}}
		if cursor != "" {
			query.Set("cursor", cursor)
		}
		endpoint := strings.TrimSuffix(a.actorURL, "/actor") + "/workspace/projects?" + query.Encode()
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
		if err != nil {
			return ProjectNames{}, errors.New("invalid projects endpoint")
		}
		token.SetAuthHeader(req)
		req.Header.Set("Accept", "application/json")
		res, err := a.client.Do(req)
		if err != nil {
			return ProjectNames{}, errors.New("projects unavailable")
		}
		body, err := io.ReadAll(io.LimitReader(res.Body, (1<<20)+1))
		res.Body.Close()
		var page struct {
			NextCursor string
			Projects   []struct {
				ID, Namespace, Name string
				Owner               struct{ ID, Name, Type string }
			}
		}
		if err != nil || len(body) > 1<<20 || res.StatusCode != http.StatusOK || json.Unmarshal(body, &page) != nil || len(page.Projects) > 100 {
			return ProjectNames{}, errors.New("projects unavailable")
		}
		for _, p := range page.Projects {
			if p.Owner.Type != "workspace" || p.Owner.ID != a.workspaceID || p.ID == "" || p.Name == "" || p.Namespace == "" {
				continue
			}
			names.Projects[p.ID] = p.Namespace + "/" + p.Name
			names.WorkspaceName = p.Owner.Name
		}
		if page.NextCursor == "" {
			return names, nil
		}
		if seen[page.NextCursor] || len(page.NextCursor) > 4096 {
			break
		}
		cursor = page.NextCursor
		seen[cursor] = true
	}
	return ProjectNames{}, errors.New("project pagination limit reached")
}

// RefreshToken performs one refresh attempt. The caller must serialize and
// durably retire the old refresh token first, then persist the returned token.
func (a *Auth) RefreshToken(ctx context.Context, token *oauth2.Token) (*oauth2.Token, error) {
	config := a.oauth
	// Amp advertises client_secret_post. Explicit auth avoids the library's
	// discovery retry on an ambiguous token endpoint failure.
	config.Endpoint.AuthStyle = oauth2.AuthStyleInParams
	ctx = context.WithValue(ctx, oauth2.HTTPClient, a.client)
	updated, err := config.TokenSource(ctx, token).Token()
	if err != nil {
		return nil, errors.New("Amp token refresh failed; sign in again")
	}
	return updated, nil
}
