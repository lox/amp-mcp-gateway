package main

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"ampcode.com/lox/amp-mcp-gateway/internal/gateway"
	"ampcode.com/lox/amp-mcp-gateway/internal/store"
)

const (
	legacyRegistryKey     = "amp-accounts/v1"
	legacyProvisioningKey = "amp-account-provisioning/v1"
	legacyIdentityKey     = "gateway-account-identity/v1"
)

type legacyDeploymentConfig struct {
	deploymentConfig
	OwnerSubject string
	Issuer       string
	ClientID     string
	HostedDomain string
}

// migrateAccounts performs the intentionally offline, lossy schema migration.
// It retains only account catalogues and credentials; operation history is not copied.
func migrateAccounts(ctx context.Context, sourceConfigPath, destinationDir, encryptionKey string) (err error) {
	raw, err := os.ReadFile(sourceConfigPath)
	if err != nil {
		return fmt.Errorf("read source configuration: %w", err)
	}
	var source legacyDeploymentConfig
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if err := d.Decode(&source); err != nil {
		return fmt.Errorf("decode source configuration: %w", err)
	}
	if source.Database == "" || source.AmpUserID == "" || source.OwnerSubject == "" {
		return errors.New("source is not a supported linked-account deployment")
	}
	migrateFlyPolicies(source.Integrations, source.Tools)
	destinationDir, err = filepath.Abs(destinationDir)
	if err != nil {
		return fmt.Errorf("resolve destination: %w", err)
	}
	if _, err := os.Stat(destinationDir); !errors.Is(err, os.ErrNotExist) {
		if err != nil {
			return fmt.Errorf("inspect destination: %w", err)
		}
		return errors.New("migration destination already exists")
	}

	reader := store.NewLegacySnapshotReader()
	defer func() { err = errors.Join(err, reader.Close()) }()
	root, err := reader.Read(ctx, source.Database, encryptionKey)
	if err != nil {
		return fmt.Errorf("read primary account: %w", err)
	}
	if len(root.Tokens[legacyProvisioningKey]) != 0 {
		return errors.New("source has pending account provisioning")
	}
	var links map[string]string
	if data := root.Tokens[legacyRegistryKey]; len(data) == 0 || json.Unmarshal(data, &links) != nil || links == nil {
		return errors.New("source has an invalid or missing account registry")
	}
	if links[source.OwnerSubject] != source.AmpUserID {
		return errors.New("source primary identity does not match its registry")
	}

	type account struct {
		id       string
		snapshot store.Snapshot
	}
	accounts := make([]account, 0, len(links))
	seenIDs, expectedFiles := map[string]bool{}, map[string]bool{}
	for subject, id := range links {
		if subject == "" || id == "" || strings.TrimSpace(id) != id || seenIDs[id] {
			return errors.New("source contains empty or duplicate account identities")
		}
		seenIDs[id] = true
		identity, _ := json.Marshal([]string{source.Issuer, subject, id})
		var snapshot store.Snapshot
		if subject == source.OwnerSubject {
			snapshot = root
		} else {
			hash := sha256.Sum256(identity)
			name := hex.EncodeToString(hash[:]) + ".db"
			expectedFiles[name] = true
			key, keyErr := legacyAccountKey(encryptionKey, "storage", identity)
			if keyErr != nil {
				return keyErr
			}
			snapshot, err = reader.Read(ctx, filepath.Join(source.Database+".accounts", name), key)
			if err != nil {
				return fmt.Errorf("read account %q: %w", id, err)
			}
		}
		wantIdentity, _ := json.Marshal([]string{source.Issuer, subject, id})
		if !bytes.Equal(snapshot.Tokens[legacyIdentityKey], wantIdentity) {
			return fmt.Errorf("account %q has a mismatched identity", id)
		}
		snapshot.Catalogue, err = migrateCatalogue(snapshot.Catalogue)
		if err != nil {
			return fmt.Errorf("account %q has an invalid catalogue", id)
		}
		accounts = append(accounts, account{id, snapshot})
	}
	entries, err := os.ReadDir(source.Database + ".accounts")
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	for _, entry := range entries {
		if strings.HasSuffix(entry.Name(), ".db") && !expectedFiles[entry.Name()] {
			return errors.New("source contains an orphan account database")
		}
	}
	slices.SortFunc(accounts, func(a, b account) int { return strings.Compare(a.id, b.id) })

	parent := filepath.Dir(destinationDir)
	if err := os.MkdirAll(parent, 0700); err != nil {
		return err
	}
	stage, err := os.MkdirTemp(parent, ".gateway-migration-")
	if err != nil {
		return err
	}
	defer func() {
		if err != nil {
			_ = os.RemoveAll(stage)
		}
	}()
	if err = os.Chmod(stage, 0700); err != nil {
		return err
	}
	ids := make([]string, 0, len(accounts))
	for _, a := range accounts {
		ids = append(ids, a.id)
	}
	for _, a := range accounts {
		path, key := filepath.Join(stage, "gateway.db"), encryptionKey
		if a.id != source.AmpUserID {
			hash := sha256.Sum256([]byte(a.id))
			path = filepath.Join(stage, "gateway.db.accounts", hex.EncodeToString(hash[:])+".db")
			key, err = accountKey(encryptionKey, "storage", []byte(a.id))
			if err != nil {
				return err
			}
		}
		clean := cleanLegacyTokens(a.snapshot.Tokens)
		clean[identityKey] = []byte(a.id)
		if a.id == source.AmpUserID {
			clean[registryKey], _ = json.Marshal(ids)
		}
		if err = importSnapshot(ctx, path, key, a.snapshot.Catalogue, clean, a.snapshot.BrowserPairings); err != nil {
			return fmt.Errorf("import account %q: %w", a.id, err)
		}
	}
	destinationConfig := source.deploymentConfig
	destinationConfig.Database = filepath.Join(destinationDir, "gateway.db")
	config, err := json.MarshalIndent(destinationConfig, "", "  ")
	if err != nil {
		return err
	}
	config = append(config, '\n')
	if err = os.WriteFile(filepath.Join(stage, "gateway.json"), config, 0600); err != nil {
		return err
	}
	if err = syncMigrationTree(stage); err != nil {
		return fmt.Errorf("sync migration: %w", err)
	}
	if err = publishMigration(stage, destinationDir); err != nil {
		if errors.Is(err, os.ErrExist) {
			return errors.New("migration destination already exists")
		}
		return fmt.Errorf("publish migration: %w", err)
	}
	if err = syncDirectory(parent); err != nil {
		return fmt.Errorf("sync migration parent: %w", err)
	}
	return nil
}

func syncMigrationTree(root string) error {
	var dirs []string
	err := filepath.WalkDir(root, func(path string, entry os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if entry.Type().IsRegular() {
			f, err := os.Open(path)
			if err != nil {
				return err
			}
			err = errors.Join(f.Sync(), f.Close())
			return err
		}
		if entry.IsDir() {
			dirs = append(dirs, path)
		}
		return nil
	})
	if err != nil {
		return err
	}
	for i := len(dirs) - 1; i >= 0; i-- {
		if err := syncDirectory(dirs[i]); err != nil {
			return err
		}
	}
	return nil
}

func syncDirectory(path string) error {
	dir, err := os.Open(path)
	if err != nil {
		return err
	}
	return errors.Join(dir.Sync(), dir.Close())
}

// The old writer disguised private policies as denials for rollback safety.
// Normalize that representation once; runtime catalogues use plain JSON.
func migrateCatalogue(raw []byte) ([]byte, error) {
	if len(raw) == 0 {
		return raw, nil
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(raw, &fields); err != nil {
		return nil, err
	}
	var old struct {
		Integrations              []gateway.Integration
		ToolDefaults              map[string]string
		PrivateConnectionPolicies []struct{ ID, Default string }
		PrivateToolDefaults       []string
		Tools                     []struct {
			gateway.Tool
			PrivatePolicy *string
			Private       bool
		}
	}
	if err := json.Unmarshal(raw, &old); err != nil {
		return nil, err
	}
	private := make(map[string]bool, len(old.PrivateConnectionPolicies))
	if old.ToolDefaults == nil {
		old.ToolDefaults = map[string]string{}
	}
	privateChanged := old.PrivateConnectionPolicies != nil || old.PrivateToolDefaults != nil
	for id, policy := range old.ToolDefaults {
		if policy == "private" {
			private[id], old.ToolDefaults[id], privateChanged = true, "allow", true
		}
	}
	for _, policy := range old.PrivateConnectionPolicies {
		private[policy.ID] = true
		if policy.Default == "" {
			delete(old.ToolDefaults, policy.ID)
		} else {
			old.ToolDefaults[policy.ID] = policy.Default
		}
	}
	for _, id := range old.PrivateToolDefaults {
		private[id], old.ToolDefaults[id] = true, "allow"
	}
	tools := make([]gateway.Tool, 0, len(old.Tools))
	for _, tool := range old.Tools {
		if tool.PrivatePolicy != nil {
			tool.Policy = *tool.PrivatePolicy
			privateChanged = true
		} else if tool.Private || tool.Policy == "private" {
			tool.Policy, private[tool.Connection], privateChanged = "allow", true, true
		}
		tools = append(tools, tool.Tool)
	}
	flyChanged := migrateFlyPolicies(old.Integrations, tools)
	if !privateChanged && !flyChanged {
		return raw, nil
	}
	if privateChanged {
		delete(fields, "PrivateConnectionPolicies")
		delete(fields, "PrivateToolDefaults")
		fields["PrivateConnections"], _ = json.Marshal(private)
		fields["ToolDefaults"], _ = json.Marshal(old.ToolDefaults)
		fields["Tools"], _ = json.Marshal(tools)
	}
	if flyChanged {
		fields["Integrations"], _ = json.Marshal(old.Integrations)
	}
	return json.Marshal(fields)
}

// Version 0 could store native policy on a generated tool rather than its
// integration. Preserve that choice, including explicit denials, once offline.
func migrateFlyPolicies(integrations []gateway.Integration, tools []gateway.Tool) bool {
	changed := false
	for i := range integrations {
		if integrations[i].ID != "fly" || integrations[i].Provider != "fly" || integrations[i].Policy != "" {
			continue
		}
		for _, tool := range tools {
			if tool.ID == "fly.request_token" && tool.Connection == "fly" && tool.Name == "request_token" && tool.Policy != "" {
				integrations[i].Policy = tool.Policy
				changed = true
			}
		}
	}
	return changed
}

func cleanLegacyTokens(tokens map[string][]byte) map[string][]byte {
	clean := make(map[string][]byte, len(tokens))
	for id, value := range tokens {
		if id == legacyRegistryKey || id == legacyProvisioningKey || id == legacyIdentityKey || strings.HasPrefix(id, "account-links/v1/") {
			continue
		}
		clean[id] = bytes.Clone(value)
	}
	return clean
}

func importSnapshot(ctx context.Context, path, key string, catalogue []byte, tokens, pairings map[string][]byte) error {
	s, err := store.Open(path, key)
	if err != nil {
		return err
	}
	if len(catalogue) != 0 {
		err = s.SaveCatalogue(ctx, catalogue)
	}
	for id, value := range tokens {
		if err == nil {
			err = s.SaveToken(ctx, id, value)
		}
	}
	for id, value := range pairings {
		if err == nil {
			err = s.SaveBrowserPairing(ctx, id, value)
		}
	}
	if closeErr := s.Close(); err == nil {
		err = closeErr
	}
	if err != nil {
		return err
	}
	verify, err := store.Open(path, key)
	if err != nil {
		return err
	}
	defer verify.Close()
	gotCatalogue, err := verify.LoadCatalogue(ctx)
	if err != nil || !bytes.Equal(gotCatalogue, catalogue) {
		return errors.New("catalogue verification failed")
	}
	for id, value := range tokens {
		got, loadErr := verify.LoadToken(ctx, id)
		if loadErr != nil || !bytes.Equal(got, value) {
			return fmt.Errorf("token %q verification failed", id)
		}
	}
	gotPairings, err := verify.LoadBrowserPairings(ctx)
	if err != nil || len(gotPairings) != len(pairings) {
		return errors.New("browser pairing verification failed")
	}
	for id, value := range pairings {
		if !bytes.Equal(gotPairings[id], value) {
			return fmt.Errorf("browser pairing %q verification failed", id)
		}
	}
	return nil
}

func legacyAccountKey(master, purpose string, identity []byte) (string, error) {
	key, err := base64.StdEncoding.Strict().DecodeString(master)
	if err != nil || len(key) != 32 {
		return "", errors.New("account master keys must be base64-encoded 32 bytes")
	}
	mac := hmac.New(sha256.New, key)
	mac.Write([]byte("amp-mcp-gateway/account/v1/" + purpose + "\x00"))
	mac.Write(identity)
	return base64.StdEncoding.EncodeToString(mac.Sum(nil)), nil
}
