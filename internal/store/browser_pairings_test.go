package store

import (
	"bytes"
	"encoding/base64"
	"path/filepath"
	"testing"
)

func TestBrowserPairingEncryptedAndPersisted(t *testing.T) {
	path := filepath.Join(t.TempDir(), "pairings.db")
	key := base64.StdEncoding.EncodeToString(make([]byte, 32))
	s, err := Open(path, key)
	if err != nil {
		t.Fatal(err)
	}
	payload := []byte(`{"reconnect":"private-browser-authority"}`)
	if err := s.SaveBrowserPairing(t.Context(), "browser", payload); err != nil {
		t.Fatal(err)
	}
	var encrypted []byte
	if err := s.db.QueryRow("SELECT payload FROM browser_pairings WHERE id='browser'").Scan(&encrypted); err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(encrypted, []byte("private-browser-authority")) {
		t.Fatal("browser pairing stored in plaintext")
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}

	s, err = Open(path, key)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	pairings, err := s.LoadBrowserPairings(t.Context())
	if err != nil || !bytes.Equal(pairings["browser"], payload) {
		t.Fatalf("restored browser pairing = %q, %v", pairings["browser"], err)
	}
	if err := s.DeleteBrowserPairing(t.Context(), "browser"); err != nil {
		t.Fatal(err)
	}
	pairings, err = s.LoadBrowserPairings(t.Context())
	if err != nil || len(pairings) != 0 {
		t.Fatalf("browser pairing survived revocation: %#v, %v", pairings, err)
	}
}
