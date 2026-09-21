package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
)

// ErrCapacity pauses new intents without preventing existing work from finishing.
var ErrCapacity = errors.New("ledger admission capacity reached")

type ledgerUsage struct {
	operations, events, bytes, outstanding int64
}

// checkAdmission runs inside the same transaction as the new intent and its
// event. Count retained history, including results and expired/denied requests.
// Completion bypasses admission: losing a known outcome would be worse than
// exceeding this admission threshold. These are not physical SQLite size caps.
func (s *Store) checkAdmission(ctx context.Context, tx *sql.Tx, delta ledgerUsage) error {
	var used ledgerUsage
	if err := tx.QueryRowContext(ctx, `SELECT count(*), coalesce(sum(length(payload)),0),
coalesce(sum(status IN ('pending','ready','running')),0) FROM operations`).Scan(&used.operations, &used.bytes, &used.outstanding); err != nil {
		return err
	}
	if used.operations+delta.operations > s.limits.operations {
		return fmt.Errorf("%w: retained operation limit", ErrCapacity)
	}
	if delta.outstanding > 0 && used.outstanding+delta.outstanding > s.limits.outstanding {
		return fmt.Errorf("%w: finish or deny pending operations before submitting more", ErrCapacity)
	}
	var eventBytes int64
	if err := tx.QueryRowContext(ctx, `SELECT count(*), coalesce(sum(length(cast(operation AS BLOB))+
length(cast(kind AS BLOB))+length(cast(actor AS BLOB))),0) FROM events`).Scan(&used.events, &eventBytes); err != nil {
		return err
	}
	if used.events+delta.events > s.limits.events {
		return fmt.Errorf("%w: retained audit event limit", ErrCapacity)
	}
	if used.bytes+eventBytes+delta.bytes > s.limits.bytes {
		return fmt.Errorf("%w: retained payload and audit byte limit", ErrCapacity)
	}
	return nil
}

// AdmitEvent persists a new non-operation intent only if retained history fits.
// Use RecordEvent or a state transition for decisions on already admitted work.
func (s *Store) AdmitEvent(ctx context.Context, e Event) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	delta := ledgerUsage{events: 1, bytes: int64(len(e.Operation) + len(e.Kind) + len(e.Actor))}
	if err := s.checkAdmission(ctx, tx, delta); err != nil {
		return err
	}
	if err := event(ctx, tx, e.Operation, e.Kind, e.Actor); err != nil {
		return err
	}
	return tx.Commit()
}
