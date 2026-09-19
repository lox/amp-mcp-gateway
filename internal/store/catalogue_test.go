package store

import (
	"bytes"
	"encoding/base64"
	"strings"
	"testing"
)

func TestCatalogueEncryptionRestartAndRevocation(t *testing.T) {
	s, path, key := testStore(t)
	ctx := t.Context()
	raw := []byte(`{"Connections":[{"BearerToken":"private-catalogue-credential"}]}`)
	if err := s.SaveCatalogue(ctx, raw); err != nil {
		t.Fatal(err)
	}
	var ciphertext []byte
	if err := s.db.QueryRow("SELECT payload FROM catalogue").Scan(&ciphertext); err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(ciphertext, []byte("private-catalogue-credential")) {
		t.Fatal("catalogue stored in plaintext")
	}
	s.Close()
	wrong, err := Open(path, base64.StdEncoding.EncodeToString([]byte(strings.Repeat("z", 32))))
	if err == nil {
		wrong.Close()
		t.Fatal("wrong key accepted on catalogue-only database")
	}
	s, err = Open(path, key)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	got, err := s.LoadCatalogue(ctx)
	if err != nil || !bytes.Equal(got, raw) {
		t.Fatal("catalogue lost across restart")
	}
	for _, status := range []string{"ready", "pending"} {
		if _, err := s.Submit(ctx, operation(status, status)); err != nil {
			t.Fatal(err)
		}
	}
	running, err := s.Claim(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.SaveCatalogue(ctx, []byte("changed")); err == nil {
		t.Fatal("catalogue changed during dispatch")
	}
	got, _ = s.LoadCatalogue(ctx)
	if !bytes.Equal(got, raw) {
		t.Fatal("failed update was not atomic")
	}
	if err := s.Finish(ctx, running, "succeeded", nil); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Submit(ctx, operation("second-ready", "ready")); err != nil {
		t.Fatal(err)
	}
	if err := s.SaveCatalogue(ctx, []byte("changed")); err != nil {
		t.Fatal(err)
	}
	for _, id := range []string{"pending", "second-ready"} {
		o, err := s.Get(ctx, id)
		if err != nil || o.Status != "denied" {
			t.Fatal("queued authority survived update")
		}
	}
	events, err := s.Events(ctx)
	if err != nil {
		t.Fatal(err)
	}
	revoked := 0
	for _, e := range events {
		if e.Actor == "catalogue-changed" && e.Kind == "denied" {
			revoked++
		}
	}
	if revoked != 2 {
		t.Fatal("missing revocation audit")
	}
}
