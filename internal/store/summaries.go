package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
)

// OperationSummary contains only the metadata shown on the dashboard.
type OperationSummary struct {
	ID      string `json:"-"`
	Status  string `json:"-"`
	Tool    string `json:"tool"`
	Account string `json:"account"`
}

func (s *Store) saveSummary(ctx context.Context, tx *sql.Tx, o OperationSummary) error {
	b, err := json.Marshal(o)
	if err != nil {
		return err
	}
	_, err = tx.ExecContext(ctx, "INSERT INTO operation_summaries VALUES (?,?)", o.ID, s.seal("operation-summary:"+o.ID, b))
	return err
}

// Backfill one legacy payload at a time before recovery can change the ledger.
// Keep the original ciphertext and operation schema intact for older binaries.
func (s *Store) backfillSummaries() error {
	ctx := context.Background()
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var after any
	for {
		var id string
		var b []byte
		query := `SELECT o.id,o.payload FROM operations o
LEFT JOIN operation_summaries s ON s.id=o.id
WHERE s.id IS NULL`
		var args []any
		if after != nil {
			query += " AND o.id>?"
			args = append(args, after)
		}
		err := tx.QueryRowContext(ctx, query+" ORDER BY o.id LIMIT 1", args...).Scan(&id, &b)
		if errors.Is(err, sql.ErrNoRows) {
			return tx.Commit()
		}
		if err != nil {
			return err
		}
		raw, err := s.open("operation:"+id, b)
		if err != nil {
			return err
		}
		var summary OperationSummary
		if err := json.Unmarshal(raw, &summary); err != nil {
			return err
		}
		summary.ID = id
		if err := s.saveSummary(ctx, tx, summary); err != nil {
			return err
		}
		after = id
	}
}

// List returns the most recent metadata without reading arguments or results.
func (s *Store) List(ctx context.Context) ([]OperationSummary, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT o.id,o.status,s.payload FROM operations o
LEFT JOIN operation_summaries s ON s.id=o.id ORDER BY o.created DESC,o.id LIMIT 100`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []OperationSummary{}
	for rows.Next() {
		var o OperationSummary
		var b []byte
		if err := rows.Scan(&o.ID, &o.Status, &b); err != nil {
			return nil, err
		}
		raw, err := s.open("operation-summary:"+o.ID, b)
		if err != nil {
			return nil, err
		}
		if err := json.Unmarshal(raw, &o); err != nil {
			return nil, err
		}
		out = append(out, o)
	}
	return out, rows.Err()
}
