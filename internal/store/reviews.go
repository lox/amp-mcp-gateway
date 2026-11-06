package store

import (
	"context"
	"errors"
)

// ReviewRecord indexes an encrypted review snapshot in this owner's database.
// Scope is the immutable App configuration ID; Revision fences stale workers.
type ReviewRecord struct {
	ID, Scope, Delivery, Head, Pull, Status string
	Revision, Created                       int64
	Payload                                 []byte
	Cleanup                                 bool
	MaintenanceAt                           int64
}

// ErrReviewConflict means a delivery/head already exists or a worker lost its claim.
var ErrReviewConflict = errors.New("review already exists or changed")

// InitReviews creates the additive review ledger without changing MCP recovery.
func (s *Store) InitReviews(ctx context.Context) error {
	_, err := s.db.ExecContext(ctx, `CREATE TABLE IF NOT EXISTS reviews (
id TEXT PRIMARY KEY, scope TEXT NOT NULL, delivery TEXT NOT NULL,
head TEXT NOT NULL, pull TEXT NOT NULL, status TEXT NOT NULL,
revision INTEGER NOT NULL, created INTEGER NOT NULL, payload BLOB NOT NULL,
cleanup INTEGER NOT NULL, maintenance_at INTEGER NOT NULL,
UNIQUE(scope,delivery));
CREATE INDEX IF NOT EXISTS reviews_queue ON reviews(status,created,id);
CREATE INDEX IF NOT EXISTS reviews_head ON reviews(scope,head);
CREATE INDEX IF NOT EXISTS reviews_pull ON reviews(scope,pull);
CREATE INDEX IF NOT EXISTS reviews_maintenance ON reviews(cleanup,maintenance_at);`)
	return err
}

// InsertReview atomically deduplicates deliveries and heads and bounds each
// account's queue. Missing-webhook reconciliation never repeats a known head.
func (s *Store) InsertReview(ctx context.Context, r ReviewRecord, missing bool) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var count int
	if err = tx.QueryRowContext(ctx, `SELECT count(*) FROM reviews WHERE status IN ('queued','running','cancelling')`).Scan(&count); err != nil {
		return err
	}
	if count >= 100 {
		return errors.New("review queue capacity reached")
	}
	query := `SELECT count(*) FROM reviews WHERE scope=? AND (delivery=? OR (head=? AND status IN ('queued','running','cancelling','unknown')))`
	if missing {
		query = `SELECT count(*) FROM reviews WHERE scope=? AND (delivery=? OR head=?)`
	}
	if err = tx.QueryRowContext(ctx, query, r.Scope, r.Delivery, r.Head).Scan(&count); err != nil {
		return err
	}
	if count != 0 {
		return ErrReviewConflict
	}
	_, err = tx.ExecContext(ctx, `INSERT INTO reviews VALUES (?,?,?,?,?,?,?,?,?,?,?)`, r.ID, r.Scope, r.Delivery, r.Head, r.Pull, r.Status, 1, r.Created, s.seal("review:"+r.ID, r.Payload), r.Cleanup, r.MaintenanceAt)
	if err != nil {
		return err
	}
	return tx.Commit()
}

// Reviews returns a bounded page, newest first. An empty status lists all states.
func (s *Store) Reviews(ctx context.Context, status string, before int64, limit int) ([]ReviewRecord, error) {
	if limit < 1 || limit > 1000 {
		return nil, errors.New("invalid review page size")
	}
	query := `SELECT id,scope,delivery,head,pull,status,revision,created,payload FROM reviews WHERE (?='' OR status=?) AND (?=0 OR created<?) ORDER BY created DESC,id DESC LIMIT ?`
	args := []any{status, status, before, before, limit}
	if status == "maintenance" {
		query = `SELECT id,scope,delivery,head,pull,status,revision,created,payload FROM reviews WHERE cleanup=1 OR status='unknown' ORDER BY maintenance_at,created,id LIMIT ?`
		args = []any{limit}
	}
	rows, err := s.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var records []ReviewRecord
	for rows.Next() {
		r, err := s.scanReview(rows)
		if err != nil {
			return nil, err
		}
		records = append(records, r)
	}
	return records, rows.Err()
}

// Review retrieves one snapshot, including its revision fence.
func (s *Store) Review(ctx context.Context, id string) (ReviewRecord, error) {
	return s.scanReview(s.db.QueryRowContext(ctx, `SELECT id,scope,delivery,head,pull,status,revision,created,payload FROM reviews WHERE id=?`, id))
}

func (s *Store) scanReview(row interface{ Scan(...any) error }) (ReviewRecord, error) {
	var r ReviewRecord
	err := row.Scan(&r.ID, &r.Scope, &r.Delivery, &r.Head, &r.Pull, &r.Status, &r.Revision, &r.Created, &r.Payload)
	if err == nil {
		r.Payload, err = s.open("review:"+r.ID, r.Payload)
	}
	return r, err
}

// UpdateReview claims or transitions a snapshot only if its revision still owns it.
func (s *Store) UpdateReview(ctx context.Context, r ReviewRecord) error {
	result, err := s.db.ExecContext(ctx, `UPDATE reviews SET status=?,revision=revision+1,payload=?,cleanup=?,maintenance_at=? WHERE id=? AND scope=? AND revision=?`, r.Status, s.seal("review:"+r.ID, r.Payload), r.Cleanup, r.MaintenanceAt, r.ID, r.Scope, r.Revision)
	if err != nil {
		return err
	}
	n, err := result.RowsAffected()
	if err == nil && n != 1 {
		return ErrReviewConflict
	}
	return err
}

// RecoverReviews never replays an ambiguous external write after a crash.
// The service can recover known checks/threads from their persisted snapshots.
func (s *Store) RecoverReviews(ctx context.Context) error {
	_, err := s.db.ExecContext(ctx, `UPDATE reviews SET status='unknown',revision=revision+1 WHERE status IN ('running','cancelling')`)
	return err
}
