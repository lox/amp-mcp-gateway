package reviews

import (
	"bytes"
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"
)

// GitHub speaks only GitHub's App REST API. BaseURL is overridden by local tests.
type GitHub struct {
	Client  *http.Client
	BaseURL string
}

var errGitHubRejected = errors.New("GitHub rejected request")

type githubSession struct {
	api         *GitHub
	token, repo string
	app         App
	issued      time.Time
	mu          sync.Mutex
}

func privateKey(raw string) (*rsa.PrivateKey, error) {
	block, _ := pem.Decode([]byte(strings.ReplaceAll(raw, `\n`, "\n")))
	if block == nil {
		return nil, errors.New("supply a PEM RSA GitHub App private key")
	}
	key, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		value, e := x509.ParsePKCS8PrivateKey(block.Bytes)
		if e == nil {
			key, _ = value.(*rsa.PrivateKey)
		}
	}
	if key == nil || key.N.BitLen() < 2048 {
		return nil, errors.New("GitHub App key must be RSA with at least 2048 bits")
	}
	return key, nil
}

func appJWT(a App) (string, error) {
	key, err := privateKey(a.PrivateKey)
	if err != nil {
		return "", err
	}
	header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"RS256","typ":"JWT"}`))
	claims, _ := json.Marshal(map[string]any{"iat": time.Now().Add(-time.Minute).Unix(), "exp": time.Now().Add(9 * time.Minute).Unix(), "iss": strconv.FormatInt(a.AppID, 10)})
	unsigned := header + "." + base64.RawURLEncoding.EncodeToString(claims)
	digest := sha256.Sum256([]byte(unsigned))
	sig, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, digest[:])
	if err != nil {
		return "", err
	}
	return unsigned + "." + base64.RawURLEncoding.EncodeToString(sig), nil
}

func (g *GitHub) request(ctx context.Context, token, method, path string, input, output any) error {
	base := g.BaseURL
	if base == "" {
		base = "https://api.github.com"
	}
	var body []byte
	if input != nil {
		var err error
		body, err = json.Marshal(input)
		if err != nil {
			return err
		}
	}
	client := http.Client{Timeout: 30 * time.Second}
	if g.Client != nil {
		client = *g.Client
	}
	client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	for attempt := 0; attempt < 3; attempt++ {
		req, err := http.NewRequestWithContext(ctx, method, base+path, bytes.NewReader(body))
		if err != nil {
			return errors.New("invalid GitHub request")
		}
		req.Header.Set("Authorization", "Bearer "+token)
		req.Header.Set("Accept", "application/vnd.github+json")
		req.Header.Set("X-GitHub-Api-Version", "2022-11-28")
		req.Header.Set("Content-Type", "application/json")
		res, err := client.Do(req)
		if err != nil {
			if method == "GET" && attempt < 2 && sleep(ctx, time.Duration(attempt+1)*time.Second) == nil {
				continue
			}
			return errors.New("GitHub request outcome unavailable")
		}
		raw, readErr := io.ReadAll(io.LimitReader(res.Body, (8<<20)+1))
		res.Body.Close()
		if method == "GET" && (res.StatusCode == 429 || res.StatusCode >= 500) && attempt < 2 {
			if err := sleep(ctx, time.Duration(attempt+1)*time.Second); err != nil {
				return err
			}
			continue
		}
		if readErr != nil || len(raw) > 8<<20 {
			return errors.New("GitHub response unavailable or too large")
		}
		if res.StatusCode < 200 || res.StatusCode >= 300 {
			// Authentication/validation/rate-limit rejections are definite. A
			// timeout or server/proxy error can follow a successful write.
			if res.StatusCode >= 400 && res.StatusCode < 500 && res.StatusCode != 408 {
				return fmt.Errorf("%w: HTTP %d", errGitHubRejected, res.StatusCode)
			}
			return fmt.Errorf("GitHub returned HTTP %d", res.StatusCode)
		}
		if output != nil && json.Unmarshal(raw, output) != nil {
			return errors.New("invalid GitHub response")
		}
		return nil
	}
	return errors.New("GitHub read retries exhausted")
}

func (g *GitHub) verifyInstallation(ctx context.Context, a App) (int64, error) {
	jwt, err := appJWT(a)
	if err != nil {
		return 0, err
	}
	installationPath := fmt.Sprintf("/app/installations/%d", a.InstallationID)
	var installation struct {
		ID      int64
		AppID   int64 `json:"app_id"`
		Account struct {
			Login string
			ID    int64
		}
		SuspendedAt *string `json:"suspended_at"`
	}
	if err := g.request(ctx, jwt, "GET", installationPath, nil, &installation); err != nil {
		return 0, err
	}
	if installation.ID != a.InstallationID || installation.AppID != a.AppID || installation.Account.ID <= 0 || a.GitHubOwnerID != 0 && installation.Account.ID != a.GitHubOwnerID || !strings.EqualFold(installation.Account.Login, a.Owner) || installation.SuspendedAt != nil {
		return 0, errors.New("GitHub installation does not match approved App owner")
	}
	return installation.Account.ID, nil
}

func (g *GitHub) session(ctx context.Context, a App, repo string) (*githubSession, error) {
	if !a.allows(repo) {
		return nil, errors.New("repository not approved")
	}
	if _, err := g.verifyInstallation(ctx, a); err != nil {
		return nil, err
	}
	jwt, err := appJWT(a)
	if err != nil {
		return nil, err
	}
	installationPath := fmt.Sprintf("/app/installations/%d", a.InstallationID)
	_, name, _ := strings.Cut(repo, "/")
	var token struct{ Token string }
	// Restrict the installation token to this one approved repository.
	err = g.request(ctx, jwt, "POST", installationPath+"/access_tokens", map[string]any{"repositories": []string{name}, "permissions": map[string]string{"checks": "write", "contents": "read", "pull_requests": "read"}}, &token)
	if err != nil {
		return nil, err
	}
	if token.Token == "" {
		return nil, errors.New("GitHub issued no installation token")
	}
	return &githubSession{api: g, token: token.Token, repo: repo, app: a, issued: time.Now()}, nil
}

func (g *githubSession) request(ctx context.Context, method, suffix string, input, output any) error {
	g.mu.Lock()
	if time.Since(g.issued) > 50*time.Minute {
		fresh, err := g.api.session(ctx, g.app, g.repo)
		if err != nil {
			g.mu.Unlock()
			return err
		}
		g.token, g.issued = fresh.token, fresh.issued
	}
	token := g.token
	g.mu.Unlock()
	return g.api.request(ctx, token, method, "/repos/"+g.repo+suffix, input, output)
}

func (g *githubSession) current(ctx context.Context, j Job) (bool, error) {
	var p pull
	if err := g.request(ctx, "GET", fmt.Sprintf("/pulls/%d", j.Number), nil, &p); err != nil {
		return false, err
	}
	return p.State == "open" && !p.Draft && p.Head.SHA == j.HeadSHA && p.Base.Repo.ID == j.RepositoryID && strings.EqualFold(p.Base.Repo.FullName, j.Repository), nil
}

func (g *githubSession) createCheck(ctx context.Context, j Job) (int64, error) {
	var check struct{ ID int64 }
	err := g.request(ctx, "POST", "/check-runs", map[string]any{"name": "Amp Review", "head_sha": j.HeadSHA, "status": "in_progress", "external_id": j.ID, "started_at": time.Now().UTC().Format(time.RFC3339)}, &check)
	if err == nil && check.ID <= 0 {
		err = errors.New("GitHub returned no check ID")
	}
	return check.ID, err
}

func (g *githubSession) changed(ctx context.Context, j Job) (map[string]map[int]bool, error) {
	var comparison struct {
		Files []struct{ Filename, Patch string }
	}
	// Unlike pulls/files this is frozen to the stored base/head pair, even if
	// the PR base moves between the state check and annotation publication.
	err := g.request(ctx, "GET", "/compare/"+j.BaseSHA+"..."+j.HeadSHA+"?per_page=1", nil, &comparison)
	if err != nil {
		return nil, err
	}
	if len(comparison.Files) >= 300 {
		return nil, errors.New("comparison reaches GitHub's 300-file limit; review cannot safely annotate it")
	}
	lines := map[string]map[int]bool{}
	for _, file := range comparison.Files {
		lines[file.Filename] = ChangedLines(file.Patch)
	}
	return lines, nil
}

func (g *githubSession) finish(ctx context.Context, j Job, conclusion, message string) error {
	output := map[string]any{"title": "Review " + conclusion, "summary": message}
	if j.Result != nil && (conclusion == "success" || conclusion == "neutral" || conclusion == "failure") {
		annotations := []map[string]any{}
		blocking := 0
		for _, f := range j.Result.Findings {
			level := "notice"
			if f.Severity == "medium" {
				level = "warning"
			}
			if severityRank(f.Severity) >= 2 {
				level = "failure"
			}
			if severityRank(f.Severity) >= severityRank(j.FailOn) {
				blocking++
			}
			annotations = append(annotations, map[string]any{"path": f.Path, "start_line": f.StartLine, "end_line": f.EndLine, "annotation_level": level, "title": f.Title, "message": f.Message + "\n\nSuggested fix: " + f.Suggestion})
		}
		output = map[string]any{"title": fmt.Sprintf("%d blocking, %d advisory issues", blocking, len(annotations)-blocking), "summary": j.Result.Summary, "annotations": annotations}
	}
	body := map[string]any{"status": "completed", "conclusion": conclusion, "completed_at": time.Now().UTC().Format(time.RFC3339), "output": output}
	if len(j.Threads) > 0 {
		body["details_url"] = "https://ampcode.com/threads/" + j.Threads[len(j.Threads)-1].ID
	}
	return g.request(ctx, "PATCH", fmt.Sprintf("/check-runs/%d", j.CheckID), body, nil)
}

func (g *githubSession) link(ctx context.Context, j Job, id string) error {
	return g.request(ctx, "PATCH", fmt.Sprintf("/check-runs/%d", j.CheckID), map[string]any{"details_url": "https://ampcode.com/threads/" + id}, nil)
}

func (g *githubSession) openPulls(ctx context.Context) ([]pull, error) {
	var pulls []pull
	for page := 1; page <= 10; page++ {
		var batch []pull
		if err := g.request(ctx, "GET", fmt.Sprintf("/pulls?state=open&sort=updated&direction=desc&per_page=100&page=%d", page), nil, &batch); err != nil {
			return nil, err
		}
		pulls = append(pulls, batch...)
		if len(batch) < 100 {
			break
		}
	}
	return pulls, nil
}
