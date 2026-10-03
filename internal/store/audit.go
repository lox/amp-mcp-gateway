package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"strings"
)

// AuditFilter selects request history. Time bounds are inclusive creation times;
// BeforeCreated and BeforeID together form an exclusive newest-first cursor.
type AuditFilter struct {
	Query, Connection, Outcome string
	Since, Until               int64
	BeforeCreated              int64
	BeforeID                   string
}

// AuditRequest pairs a request's current outcome with its chronological events.
type AuditRequest struct {
	Operation        OperationSummary
	Events           []Event
	StandingApproval *Event
}

// Audit returns at most 25 matching requests and whether another page exists.
// Tool and connection metadata stay encrypted: matching those fields requires
// scanning candidate summaries, never the full arguments or results.
func (s *Store) Audit(ctx context.Context, f AuditFilter) ([]AuditRequest, bool, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, false, err
	}
	defer tx.Rollback()
	query := `SELECT o.id,o.status,o.created,s.payload FROM operations o
LEFT JOIN operation_summaries s ON s.id=o.id WHERE o.created>=?`
	args := []any{f.Since}
	if f.Until != 0 {
		query += " AND o.created<=?"
		args = append(args, f.Until)
	}
	if f.BeforeID != "" {
		query += " AND (o.created<? OR (o.created=? AND o.id<?))"
		args = append(args, f.BeforeCreated, f.BeforeCreated, f.BeforeID)
	}
	if f.Outcome == "investigate" {
		query += " AND status IN ('failed','unknown')"
	} else if f.Outcome == "active" {
		query += " AND status IN ('ready','running')"
	} else if f.Outcome != "" {
		query += " AND status=?"
		args = append(args, f.Outcome)
	}
	rows, err := tx.QueryContext(ctx, query+" ORDER BY o.created DESC,o.id DESC", args...)
	if err != nil {
		return nil, false, err
	}
	defer rows.Close()
	var out []AuditRequest
	q := strings.ToLower(f.Query)
	for rows.Next() {
		var o OperationSummary
		var b []byte
		if err := rows.Scan(&o.ID, &o.Status, &o.Created, &b); err != nil {
			return nil, false, err
		}
		raw, err := s.open("operation-summary:"+o.ID, b)
		if err != nil {
			return nil, false, err
		}
		if err := json.Unmarshal(raw, &o); err != nil {
			return nil, false, err
		}
		if f.Connection != "" && o.Connection != f.Connection {
			continue
		}
		if q != "" && !strings.Contains(strings.ToLower(o.Tool), q) && !strings.Contains(strings.ToLower(o.ID), q) {
			continue
		}
		out = append(out, AuditRequest{Operation: o})
		if len(out) == 26 {
			break
		}
	}
	if err := rows.Err(); err != nil {
		return nil, false, err
	}
	if err := rows.Close(); err != nil {
		return nil, false, err
	}
	more := len(out) > 25
	if more {
		out = out[:25]
	}
	for i := range out {
		events, err := tx.QueryContext(ctx, "SELECT sequence,operation,kind,actor,time FROM events WHERE operation=? ORDER BY sequence", out[i].Operation.ID)
		if err != nil {
			return nil, false, err
		}
		for events.Next() {
			var e Event
			if err := events.Scan(&e.Sequence, &e.Operation, &e.Kind, &e.Actor, &e.Time); err != nil {
				events.Close()
				return nil, false, err
			}
			out[i].Events = append(out[i].Events, e)
		}
		err = events.Err()
		closeErr := events.Close()
		if err != nil {
			return nil, false, err
		}
		if closeErr != nil {
			return nil, false, closeErr
		}
		if op := out[i].Operation; op.ApprovalGrantSource != "" {
			var e Event
			err := tx.QueryRowContext(ctx, "SELECT sequence,operation,kind,actor,time FROM events WHERE operation=? AND kind=? ORDER BY sequence LIMIT 1", op.ApprovalGrantSource, "approval-"+op.ApprovalScope).Scan(&e.Sequence, &e.Operation, &e.Kind, &e.Actor, &e.Time)
			if err == nil {
				out[i].StandingApproval = &e
			} else if !errors.Is(err, sql.ErrNoRows) {
				return nil, false, err
			}
		}
	}
	return out, more, tx.Commit()
}
