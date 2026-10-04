package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"net/url"
	"os"

	"golang.org/x/sys/unix"
)

// Snapshot contains the connection catalogue and provider tokens exported from
// a legacy ledger. It deliberately excludes operations and audit history.
type Snapshot struct {
	Catalogue []byte
	Tokens    map[string][]byte
}

// LegacySnapshotReader holds every legacy database lock it acquires until
// Close. This lets an offline migration take a coherent multi-database
// snapshot without allowing a gateway to restart between account reads.
type LegacySnapshotReader struct {
	locks []*os.File
}

// NewLegacySnapshotReader creates a reader for an offline legacy data set.
func NewLegacySnapshotReader() *LegacySnapshotReader { return &LegacySnapshotReader{} }

// ReadLegacySnapshot reads credentials from a locked legacy database without
// creating or mutating it. Callers must migrate the returned data explicitly.
func ReadLegacySnapshot(ctx context.Context, path, key string) (Snapshot, error) {
	r := NewLegacySnapshotReader()
	defer r.Close()
	return r.Read(ctx, path, key)
}

// Read locks path until the reader is closed and reads one consistent SQLite
// transaction. Only legacy schema version 0 databases are accepted.
func (r *LegacySnapshotReader) Read(ctx context.Context, path, key string) (Snapshot, error) {
	var snapshot Snapshot
	if _, err := os.Stat(path); err != nil {
		return snapshot, fmt.Errorf("open legacy database: %w", err)
	}
	aead, err := newAEAD(key)
	if err != nil {
		return snapshot, err
	}
	lock, err := os.OpenFile(path+".lock", os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		return snapshot, err
	}
	if err := unix.Flock(int(lock.Fd()), unix.LOCK_EX|unix.LOCK_NB); err != nil {
		lock.Close()
		return snapshot, errors.New("database already in use by another gateway")
	}
	r.locks = append(r.locks, lock)
	dsn := (&url.URL{Scheme: "file", Path: path}).String() + "?mode=ro"
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return snapshot, err
	}
	defer db.Close()
	tx, err := db.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if err != nil {
		return snapshot, err
	}
	defer tx.Rollback()
	var version int
	if err := tx.QueryRowContext(ctx, "PRAGMA user_version").Scan(&version); err != nil {
		return snapshot, err
	}
	if version != 0 {
		return snapshot, fmt.Errorf("legacy database has schema version %d (expected 0)", version)
	}
	open := func(id string, payload []byte) ([]byte, error) { return aead.Open(nil, nil, payload, []byte(id)) }
	var encrypted []byte
	err = tx.QueryRowContext(ctx, "SELECT payload FROM catalogue WHERE id=1").Scan(&encrypted)
	if err == nil {
		snapshot.Catalogue, err = open("catalogue", encrypted)
	}
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return Snapshot{}, errors.New("cannot decrypt legacy database: check encryption key and database integrity")
	}
	snapshot.Tokens = make(map[string][]byte)
	rows, err := tx.QueryContext(ctx, "SELECT id,payload FROM tokens")
	if err != nil {
		return Snapshot{}, err
	}
	defer rows.Close()
	for rows.Next() {
		var id string
		if err := rows.Scan(&id, &encrypted); err != nil {
			return Snapshot{}, err
		}
		value, err := open("token:"+id, encrypted)
		if err != nil {
			return Snapshot{}, errors.New("cannot decrypt legacy database: check encryption key and database integrity")
		}
		snapshot.Tokens[id] = value
	}
	if err := rows.Err(); err != nil {
		return Snapshot{}, err
	}
	if err := rows.Close(); err != nil {
		return Snapshot{}, err
	}
	if err := tx.Commit(); err != nil {
		return Snapshot{}, err
	}
	return snapshot, nil
}

// Close releases all source locks held by the reader.
func (r *LegacySnapshotReader) Close() error {
	var err error
	for i := len(r.locks) - 1; i >= 0; i-- {
		err = errors.Join(err, r.locks[i].Close())
	}
	r.locks = nil
	return err
}
