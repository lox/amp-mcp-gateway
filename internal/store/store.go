// Package store persists encrypted credentials and the single-owner operation ledger.
package store

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"golang.org/x/sys/unix"
	_ "modernc.org/sqlite"
)

// Store is a single-process SQLite ledger. Payloads and credentials are encrypted.
type Store struct {
	db   *sql.DB
	aead cipher.AEAD
	lock *os.File
}

// Operation is an immutable request with mutable execution state.
type Operation struct {
	ID          string          `json:"id"`
	Tool        string          `json:"tool"`
	Connection  string          `json:"connection"`
	Account     string          `json:"account"`
	Subject     string          `json:"subject"`
	AmpUserID   string          `json:"amp_user_id,omitempty"`
	AmpThreadID string          `json:"amp_thread_id,omitempty"`
	Model       string          `json:"model_reported,omitempty"`
	Arguments   map[string]any  `json:"arguments"`
	Digest      string          `json:"digest"`
	Binding     string          `json:"binding"`
	Status      string          `json:"status"`
	Created     int64           `json:"created"`
	Expires     int64           `json:"expires"`
	Result      json.RawMessage `json:"result,omitempty"`
}

// Event records a durable state transition without tool payloads or credentials.
type Event struct {
	Sequence               int64
	Operation, Kind, Actor string
	Time                   int64
}

// Open opens the database, excludes other gateway processes, and recovers ambiguous dispatches.
func Open(path, key string) (*Store, error) {
	b, err := base64.StdEncoding.DecodeString(key)
	if err != nil || len(b) != 32 {
		return nil, errors.New("encryption key must be base64-encoded 32 bytes")
	}
	block, err := aes.NewCipher(b)
	if err != nil {
		return nil, err
	}
	aead, err := cipher.NewGCMWithRandomNonce(block)
	if err != nil {
		return nil, err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return nil, err
	}
	lock, err := os.OpenFile(path+".lock", os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		return nil, err
	}
	if err = unix.Flock(int(lock.Fd()), unix.LOCK_EX|unix.LOCK_NB); err != nil {
		lock.Close()
		return nil, errors.New("database already in use by another gateway")
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		lock.Close()
		return nil, err
	}
	f.Close()
	db, err := sql.Open("sqlite", path)
	if err != nil {
		lock.Close()
		return nil, err
	}
	db.SetMaxOpenConns(1)
	s := &Store{db: db, aead: aead, lock: lock}
	_, err = db.Exec(`PRAGMA journal_mode=WAL; PRAGMA synchronous=FULL; PRAGMA busy_timeout=5000;
CREATE TABLE IF NOT EXISTS tokens (id TEXT PRIMARY KEY, payload BLOB NOT NULL);
CREATE TABLE IF NOT EXISTS operations (id TEXT PRIMARY KEY, status TEXT NOT NULL, created INTEGER NOT NULL, expires INTEGER NOT NULL, payload BLOB NOT NULL);
CREATE TABLE IF NOT EXISTS events (sequence INTEGER PRIMARY KEY AUTOINCREMENT, operation TEXT NOT NULL, kind TEXT NOT NULL, actor TEXT NOT NULL, time INTEGER NOT NULL);`)
	if err != nil {
		s.Close()
		return nil, err
	}
	// Reject a wrong key before recovery mutates an existing ledger.
	var id string
	var payload []byte
	err = db.QueryRow(`SELECT 'token:'||id,payload FROM tokens UNION ALL SELECT 'operation:'||id,payload FROM operations LIMIT 1`).Scan(&id, &payload)
	if err == nil {
		_, err = s.open(id, payload)
	}
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		s.Close()
		return nil, errors.New("cannot decrypt existing ledger: check encryption key and database integrity")
	}
	_, err = db.Exec(`BEGIN; INSERT INTO events(operation,kind,actor,time) SELECT id,'unknown','restart',unixepoch() FROM operations WHERE status='running'; UPDATE operations SET status='unknown' WHERE status='running'; COMMIT;`)
	if err != nil {
		s.Close()
		return nil, err
	}
	return s, nil
}

// Close releases the database and process lock.
func (s *Store) Close() error { return errors.Join(s.db.Close(), s.lock.Close()) }

func (s *Store) seal(id string, b []byte) []byte {
	return s.aead.Seal(nil, nil, b, []byte(id))
}
func (s *Store) open(id string, b []byte) ([]byte, error) {
	return s.aead.Open(nil, nil, b, []byte(id))
}

// LoadToken implements upstream.TokenStore.
func (s *Store) LoadToken(ctx context.Context, id string) ([]byte, error) {
	var b []byte
	err := s.db.QueryRowContext(ctx, "SELECT payload FROM tokens WHERE id=?", id).Scan(&b)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return s.open("token:"+id, b)
}

// SaveToken implements upstream.TokenStore, persisting rotation before dispatch.
func (s *Store) SaveToken(ctx context.Context, id string, b []byte) error {
	_, err := s.db.ExecContext(ctx, "INSERT INTO tokens VALUES (?,?) ON CONFLICT(id) DO UPDATE SET payload=excluded.payload", id, s.seal("token:"+id, b))
	return err
}

// Reauthorize invalidates queued requests when a human replaces an OAuth grant.
// A running request must finish first so it cannot switch accounts mid-dispatch.
func (s *Store) Reauthorize(ctx context.Context, id string, b []byte) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var running int
	if err := tx.QueryRowContext(ctx, "SELECT count(*) FROM operations WHERE status='running'").Scan(&running); err != nil {
		return err
	}
	if running != 0 {
		return errors.New("wait for running operations before reconnecting")
	}
	if _, err := tx.ExecContext(ctx, "INSERT INTO events(operation,kind,actor,time) SELECT id,'denied','connection-reauthorized',unixepoch() FROM operations WHERE status IN ('pending','ready')"); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, "UPDATE operations SET status='denied' WHERE status IN ('pending','ready')"); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, "INSERT INTO tokens VALUES (?,?) ON CONFLICT(id) DO UPDATE SET payload=excluded.payload", id, s.seal("token:"+id, b)); err != nil {
		return err
	}
	return tx.Commit()
}

type scanner interface{ Scan(...any) error }

func (s *Store) decode(row scanner) (Operation, error) {
	var o Operation
	var id, status string
	var b []byte
	if err := row.Scan(&id, &status, &b); err != nil {
		return o, err
	}
	raw, err := s.open("operation:"+id, b)
	if err != nil {
		return o, err
	}
	err = json.Unmarshal(raw, &o)
	o.Status = status
	return o, err
}

// Get retrieves a stored operation.
func (s *Store) Get(ctx context.Context, id string) (Operation, error) {
	return s.decode(s.db.QueryRowContext(ctx, "SELECT id,status,payload FROM operations WHERE id=?", id))
}

// Submit persists intent and audit atomically. Reusing an ID for another request is rejected.
func (s *Store) Submit(ctx context.Context, o Operation) (Operation, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return o, err
	}
	defer tx.Rollback()
	existing, err := s.decode(tx.QueryRowContext(ctx, "SELECT id,status,payload FROM operations WHERE id=?", o.ID))
	if err == nil {
		if existing.Digest != o.Digest {
			return o, errors.New("request ID already used for different arguments or authority")
		}
		return existing, nil
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return o, err
	}
	b, err := json.Marshal(o)
	if err != nil {
		return o, err
	}
	if _, err = tx.ExecContext(ctx, "INSERT INTO operations VALUES (?,?,?,?,?)", o.ID, o.Status, o.Created, o.Expires, s.seal("operation:"+o.ID, b)); err != nil {
		return o, err
	}
	actor := o.Subject
	if o.AmpUserID != "" {
		actor = "amp:" + o.AmpUserID
	}
	if err = event(ctx, tx, o.ID, o.Status, actor); err != nil {
		return o, err
	}
	return o, tx.Commit()
}

func event(ctx context.Context, tx *sql.Tx, id, kind, actor string) error {
	_, err := tx.ExecContext(ctx, "INSERT INTO events(operation,kind,actor,time) VALUES (?,?,?,?)", id, kind, actor, time.Now().Unix())
	return err
}

// Decide consumes an unexpired approval once; it cannot modify the stored request.
func (s *Store) Decide(ctx context.Context, id, actor string, approve bool) error {
	status := "denied"
	if approve {
		status = "ready"
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	r, err := tx.ExecContext(ctx, "UPDATE operations SET status=? WHERE id=? AND status='pending' AND expires>?", status, id, time.Now().Unix())
	if err != nil {
		return err
	}
	n, err := r.RowsAffected()
	if err != nil {
		return err
	}
	if n != 1 {
		return errors.New("operation no longer awaiting approval or expired")
	}
	if err = event(ctx, tx, id, status, actor); err != nil {
		return err
	}
	return tx.Commit()
}

// Claim atomically marks one unexpired operation running before any network dispatch.
func (s *Store) Claim(ctx context.Context) (Operation, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return Operation{}, err
	}
	defer tx.Rollback()
	now := time.Now().Unix()
	if _, err = tx.ExecContext(ctx, "INSERT INTO events(operation,kind,actor,time) SELECT id,'expired','gateway',? FROM operations WHERE status IN ('pending','ready') AND expires<=?", now, now); err != nil {
		return Operation{}, err
	}
	if _, err = tx.ExecContext(ctx, "UPDATE operations SET status='expired' WHERE status IN ('pending','ready') AND expires<=?", now); err != nil {
		return Operation{}, err
	}
	o, err := s.decode(tx.QueryRowContext(ctx, "UPDATE operations SET status='running' WHERE id=(SELECT id FROM operations WHERE status='ready' ORDER BY created,id LIMIT 1) RETURNING id,status,payload"))
	if errors.Is(err, sql.ErrNoRows) {
		if commitErr := tx.Commit(); commitErr != nil {
			return o, commitErr
		}
		return o, err
	}
	if err != nil {
		return o, err
	}
	if err = event(ctx, tx, o.ID, "running", "gateway"); err != nil {
		return o, err
	}
	return o, tx.Commit()
}

// Finish persists the outcome and corresponding audit event atomically.
func (s *Store) Finish(ctx context.Context, o Operation, status string, result json.RawMessage) error {
	if status != "succeeded" && status != "failed" && status != "unknown" && status != "denied" {
		return errors.New("invalid terminal status")
	}
	o.Result = result
	b, err := json.Marshal(o)
	if err != nil {
		return err
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	r, err := tx.ExecContext(ctx, "UPDATE operations SET status=?,payload=? WHERE id=? AND status='running'", status, s.seal("operation:"+o.ID, b), o.ID)
	if err != nil {
		return err
	}
	n, err := r.RowsAffected()
	if err != nil {
		return err
	}
	if n != 1 {
		return fmt.Errorf("operation %s not running", o.ID)
	}
	if err = event(ctx, tx, o.ID, status, "gateway"); err != nil {
		return err
	}
	return tx.Commit()
}

// List returns the most recent operations.
func (s *Store) List(ctx context.Context) ([]Operation, error) {
	rows, err := s.db.QueryContext(ctx, "SELECT id,status,payload FROM operations ORDER BY created DESC,id LIMIT 100")
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []Operation{}
	for rows.Next() {
		o, err := s.decode(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, o)
	}
	return out, rows.Err()
}

// Events returns the most recent payload-free audit events.
func (s *Store) Events(ctx context.Context) ([]Event, error) {
	rows, err := s.db.QueryContext(ctx, "SELECT sequence,operation,kind,actor,time FROM events ORDER BY sequence DESC LIMIT 200")
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []Event{}
	for rows.Next() {
		var e Event
		if err := rows.Scan(&e.Sequence, &e.Operation, &e.Kind, &e.Actor, &e.Time); err != nil {
			return nil, err
		}
		out = append(out, e)
	}
	return out, rows.Err()
}
