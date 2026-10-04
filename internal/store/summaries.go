package store

import (
	"context"
	"database/sql"
	"encoding/json"
)

// OperationSummary contains list and audit metadata, never arguments or results.
type OperationSummary struct {
	ID                  string `json:"-"`
	Status              string `json:"-"`
	Created             int64  `json:"-"`
	Tool                string `json:"tool"`
	Account             string `json:"account"`
	Connection          string `json:"connection"`
	AmpUserID           string `json:"amp_user_id,omitempty"`
	ApprovalScope       string `json:"approval_scope,omitempty"`
	ApprovalGrantSource string `json:"approval_grant_source,omitempty"`
}

func (s *Store) saveSummary(ctx context.Context, tx *sql.Tx, o OperationSummary) error {
	b, err := json.Marshal(o)
	if err != nil {
		return err
	}
	_, err = tx.ExecContext(ctx, "INSERT INTO operation_summaries VALUES (?,?) ON CONFLICT(id) DO UPDATE SET payload=excluded.payload", o.ID, s.seal("operation-summary:"+o.ID, b))
	return err
}

// List returns the most recent metadata without reading arguments or results.
func (s *Store) List(ctx context.Context) ([]OperationSummary, error) {
	return s.ListStatus(ctx, "")
}

// ListStatus filters before limiting the list; an empty status includes all states.
func (s *Store) ListStatus(ctx context.Context, status string) ([]OperationSummary, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT o.id,o.status,s.payload FROM operations o
LEFT JOIN operation_summaries s ON s.id=o.id WHERE (?='' OR o.status=?)
ORDER BY o.created DESC,o.id LIMIT 100`, status, status)
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
