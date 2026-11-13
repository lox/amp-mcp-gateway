package reviews

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"slices"
	"strings"
)

// Configuration is the sole persisted source of review policy and credentials.
// It belongs to one gateway user, even when an execution key is workspace-owned.
type Configuration struct {
	Version      int
	Integrations map[string]Integration
	Credentials  map[string]string
}

type Settings struct {
	FailOn, Visibility string
	TimeoutMinutes     int
}

// Integration represents one GitHub App, not one installation of that App.
type Integration struct {
	ID                        string
	AppID                     int64
	PrivateKey, WebhookSecret string
	Enabled                   bool
	Settings
	Installations []Installation
}

type Installation struct {
	ID                  int64
	OwnerID             int64
	Owner               string
	ExecutionCredential string
	Repositories        []Repository
}

type Repository struct {
	ID            int64
	Name, Project string
	Enabled       bool
	Settings
}

func emptyConfiguration() Configuration {
	return Configuration{Version: 2, Integrations: map[string]Integration{}, Credentials: map[string]string{}}
}

// resolve produces an ephemeral execution binding; it is never stored as config.
func (c Configuration) resolve(id string, installation int64, repo string) (App, bool) {
	in, ok := c.Integrations[id]
	if !ok {
		return App{}, false
	}
	for _, i := range in.Installations {
		if i.ID != installation {
			continue
		}
		for _, r := range i.Repositories {
			if r.Name != strings.ToLower(repo) {
				continue
			}
			settings := in.Settings
			if r.FailOn != "" {
				settings.FailOn = r.FailOn
			}
			if r.Visibility != "" {
				settings.Visibility = r.Visibility
			}
			if r.TimeoutMinutes != 0 {
				settings.TimeoutMinutes = r.TimeoutMinutes
			}
			return App{ID: in.ID, AppID: in.AppID, InstallationID: i.ID, Owner: i.Owner, GitHubOwnerID: i.OwnerID,
				RepositoryID: r.ID, ExecutionCredential: i.ExecutionCredential, PrivateKey: in.PrivateKey, WebhookSecret: in.WebhookSecret,
				AmpKey: c.Credentials[i.ExecutionCredential], Projects: map[string]string{r.Name: r.Project},
				Enabled: in.Enabled && r.Enabled && i.OwnerID > 0 && r.ID > 0,
				FailOn:  settings.FailOn, Visibility: settings.Visibility, TimeoutMinutes: settings.TimeoutMinutes}, true
		}
	}
	return App{}, false
}

func (c Configuration) apps() []App {
	var apps []App
	for id, in := range c.Integrations {
		for _, i := range in.Installations {
			for _, r := range i.Repositories {
				a, _ := c.resolve(id, i.ID, r.Name)
				apps = append(apps, a)
			}
		}
	}
	return apps
}

// Configuration returns a detached, presentation-safe copy. Keys are never read back.
func (s *Service) Configuration() Configuration {
	s.mu.Lock()
	defer s.mu.Unlock()
	b, _ := json.Marshal(s.config)
	var c Configuration
	_ = json.Unmarshal(b, &c)
	for id, in := range c.Integrations {
		in.PrivateKey, in.WebhookSecret = "", ""
		c.Integrations[id] = in
	}
	for id := range c.Credentials {
		c.Credentials[id] = ""
	}
	return c
}

// SaveIntegration verifies GitHub identities before committing configuration.
// Blank credentials retain saved values; credentials are shared by explicit name.
func (s *Service) SaveIntegration(ctx context.Context, in Integration, credentials map[string]string) error {
	return s.saveIntegration(ctx, in, credentials, true)
}

// SaveDraft supports the credential-free demo. Unverified drafts cannot execute.
func (s *Service) SaveDraft(ctx context.Context, in Integration, credentials map[string]string) error {
	if in.Enabled {
		return errors.New("unverified drafts cannot enable reviews")
	}
	return s.saveIntegration(ctx, in, credentials, false)
}

func validSettings(v Settings, optional bool) bool {
	return (optional && v.FailOn == "" || severityRank(v.FailOn) >= 0) &&
		(optional && v.Visibility == "" || v.Visibility == "private" || v.Visibility == "workspace") &&
		(optional && v.TimeoutMinutes == 0 || v.TimeoutMinutes >= 5 && v.TimeoutMinutes <= 120)
}

func (s *Service) saveIntegration(ctx context.Context, in Integration, credentials map[string]string, verify bool) error {
	// Detach caller-owned slices before normalization and retaining the config.
	raw, err := json.Marshal(in)
	if err != nil {
		return err
	}
	if err := json.Unmarshal(raw, &in); err != nil {
		return err
	}
	s.mu.Lock()
	previous := s.config // Published configurations are immutable.
	base := hash(previous)
	s.mu.Unlock()
	old, exists := previous.Integrations[in.ID]
	if exists && old.AppID != in.AppID {
		return errors.New("create a new integration for a different GitHub App")
	}
	if !exists && len(previous.Integrations) >= 10 {
		return errors.New("at most ten review Apps per account")
	}
	if !namePattern.MatchString(in.ID) || in.AppID <= 0 {
		return errors.New("invalid App identity")
	}
	for id, other := range previous.Integrations {
		if id != in.ID && other.AppID == in.AppID {
			return errors.New("add installations to the existing integration for this GitHub App")
		}
	}
	if in.PrivateKey == "" {
		in.PrivateKey = old.PrivateKey
	}
	if in.WebhookSecret == "" {
		in.WebhookSecret = old.WebhookSecret
	}
	if _, err := privateKey(in.PrivateKey); err != nil {
		return err
	}
	if len(in.WebhookSecret) < 16 || len(in.WebhookSecret) > 1024 {
		return errors.New("supply a webhook secret (16–1024 bytes)")
	}
	if !validSettings(in.Settings, false) {
		return errors.New("choose a severity, private/workspace visibility, and a 5–120 minute timeout")
	}
	next := Configuration{Version: 2, Integrations: maps.Clone(previous.Integrations), Credentials: maps.Clone(previous.Credentials)}
	for id, key := range credentials {
		if !namePattern.MatchString(id) || len(key) > 4096 {
			return errors.New("invalid execution credential name or key")
		}
		if key != "" {
			next.Credentials[id] = key
		}
		if next.Credentials[id] == "" {
			return errors.New("supply an Amp service account API key for each new execution credential")
		}
	}
	if len(next.Credentials) > 20 {
		return errors.New("at most twenty execution credentials per account")
	}
	if len(in.Installations) > 20 {
		return errors.New("at most twenty approved installations per App")
	}
	seenInstallations, seenRepositories := map[int64]bool{}, map[string]bool{}
	for n := range in.Installations {
		i := &in.Installations[n]
		i.Owner = strings.ToLower(strings.TrimSpace(i.Owner))
		if i.ID <= 0 || !namePattern.MatchString(i.Owner) || seenInstallations[i.ID] {
			return errors.New("supply distinct installation IDs and GitHub owners")
		}
		seenInstallations[i.ID] = true
		if next.Credentials[i.ExecutionCredential] == "" {
			return errors.New("select a saved execution credential for each installation")
		}
		if len(i.Repositories) > 100 {
			return errors.New("at most one hundred repositories per installation")
		}
		// Never trust an owner ID supplied by the browser. Retain only the stored
		// identity, then verify it with GitHub before approving a new installation.
		i.OwnerID = 0
		for _, previous := range old.Installations {
			if previous.ID == i.ID {
				if previous.Owner != i.Owner {
					return errors.New("an approved installation cannot be reassigned to another owner")
				}
				i.OwnerID = previous.OwnerID
			}
		}
		a := App{AppID: in.AppID, PrivateKey: in.PrivateKey, InstallationID: i.ID, Owner: i.Owner, GitHubOwnerID: i.OwnerID}
		if verify && (i.OwnerID == 0 || in.PrivateKey != old.PrivateKey) {
			ownerID, err := s.github.verifyInstallation(ctx, a)
			if err != nil {
				return fmt.Errorf("verify installation %d: %w", i.ID, err)
			}
			i.OwnerID, a.GitHubOwnerID = ownerID, ownerID
		} else if !verify {
			i.OwnerID = 0
		}
		for k := range i.Repositories {
			r := &i.Repositories[k]
			r.Name, r.Project = strings.ToLower(strings.TrimSpace(r.Name)), strings.TrimSpace(r.Project)
			if !validRepository(r.Name) || !strings.HasPrefix(r.Name, i.Owner+"/") || !validRepository(r.Project) || seenRepositories[r.Name] || !validSettings(r.Settings, true) {
				return errors.New("configure distinct owner/repo names, exact Amp namespace/project mappings and valid overrides")
			}
			seenRepositories[r.Name] = true
			r.ID = 0
			for _, previous := range old.Installations {
				if previous.ID == i.ID {
					for _, repository := range previous.Repositories {
						if repository.Name == r.Name {
							r.ID = repository.ID
						}
					}
				}
			}
			if verify && (r.ID == 0 || in.PrivateKey != old.PrivateKey) {
				a.Projects = map[string]string{r.Name: r.Project}
				gh, err := s.github.session(ctx, a, r.Name)
				if err != nil {
					return fmt.Errorf("verify repository %s: %w", r.Name, err)
				}
				var repository struct {
					ID       int64
					FullName string `json:"full_name"`
				}
				if err := gh.request(ctx, "GET", "", nil, &repository); err != nil {
					return fmt.Errorf("verify repository %s: %w", r.Name, err)
				}
				if repository.ID <= 0 || !strings.EqualFold(repository.FullName, r.Name) || r.ID != 0 && r.ID != repository.ID {
					return errors.New("repository identity changed; remove and explicitly approve it again")
				}
				r.ID = repository.ID
			} else if !verify {
				r.ID = 0
			}
		}
	}
	next.Integrations[in.ID] = in
	// GitHub verification must not hold the worker/revocation mutex. A concurrent
	// save invalidates this candidate rather than overwriting the newer policy.
	s.mu.Lock()
	defer s.mu.Unlock()
	if hash(s.config) != base {
		return errors.New("review configuration changed during verification; reload and save again")
	}
	// Evaluate revocation before the commit; disconnecting the browser after a
	// successful save must not prevent cancellation. Shared key edits affect all Apps.
	cancelActive := false
	if s.activeCancel != nil {
		j, err := s.get(ctx, s.activeID)
		if err != nil {
			return err
		}
		a, ok := next.resolve(j.App, j.InstallationID, j.Repository)
		cancelActive = !ok || !a.Enabled || a.binding() != j.Binding
	}
	b, err := json.Marshal(next)
	if err != nil {
		return err
	}
	if err := s.store.SaveToken(ctx, configKey, b); err != nil {
		return err
	}
	s.config = next
	if cancelActive {
		s.activeCancel()
	}
	return nil
}

// Legacy configuration is retained as paused drafts. Identity verification is
// required before re-enabling; history and cleanup credentials keep their IDs.
func readConfiguration(raw []byte) (Configuration, error) {
	c := emptyConfiguration()
	if len(raw) == 0 {
		return c, nil
	}
	var marker struct{ Version int }
	if err := json.Unmarshal(raw, &marker); err != nil {
		return c, err
	}
	if marker.Version != 0 {
		if marker.Version != 2 {
			return c, errors.New("unsupported review configuration version")
		}
		if err := json.Unmarshal(raw, &c); err != nil {
			return c, err
		}
		if c.Integrations == nil || c.Credentials == nil {
			return c, errors.New("invalid review configuration")
		}
		return c, nil
	}
	var legacy map[string]struct {
		App
		Repositories  []string
		OwnerApproved bool
	}
	if err := json.Unmarshal(raw, &legacy); err != nil {
		return c, err
	}
	c = emptyConfiguration()
	for id, old := range legacy {
		if old.ID != id || old.AppID <= 0 {
			return c, errors.New("invalid legacy reviews configuration")
		}
		c.Credentials[id] = old.AmpKey
		i := Installation{ID: old.InstallationID, Owner: old.Owner, ExecutionCredential: id}
		for repo, project := range old.Projects {
			if old.OwnerApproved || slices.Contains(old.Repositories, repo) {
				i.Repositories = append(i.Repositories, Repository{Name: repo, Project: project, Enabled: true})
			}
		}
		slices.SortFunc(i.Repositories, func(a, b Repository) int { return strings.Compare(a.Name, b.Name) })
		c.Integrations[id] = Integration{ID: id, AppID: old.AppID, PrivateKey: old.PrivateKey, WebhookSecret: old.WebhookSecret,
			Settings: Settings{FailOn: old.FailOn, Visibility: old.Visibility, TimeoutMinutes: old.TimeoutMinutes}, Installations: []Installation{i}}
	}
	return c, nil
}
