package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
)

const (
	maxHTTPAttempts      = 10
	maxHTTPRequestBytes  = 64 << 10
	maxHTTPResponseBytes = 2 << 20
	maxHTTPAttemptBytes  = 8 << 20
)

// HTTPAttempt is an ordered HTTP dispatch journal entry. A missing Response
// means dispatch may have happened; it is never permission to replay a request.
type HTTPAttempt struct {
	Sequence int             `json:"sequence"`
	Request  json.RawMessage `json:"request"`
	Response json.RawMessage `json:"response,omitempty"`
}

func httpAttemptAAD(operationID string, sequence int, field string) string {
	return fmt.Sprintf("http-attempt:%s:%d:%s", operationID, sequence, field)
}

// sealOperation keeps journaled operations unreadable to older binaries, even
// after Finish or a catalogue change rewrites their payload. Ordinary operations
// retain their existing AAD and schema compatibility.
func (s *Store) sealOperation(ctx context.Context, tx *sql.Tx, id string, payload []byte) ([]byte, error) {
	var journaled bool
	if err := tx.QueryRowContext(ctx, "SELECT EXISTS(SELECT 1 FROM http_attempts WHERE operation=?)", id).Scan(&journaled); err != nil {
		return nil, err
	}
	aad := "operation:" + id
	if journaled {
		aad = "http-journal:" + aad
	}
	return s.seal(aad, payload), nil
}

func requireRunning(ctx context.Context, tx *sql.Tx, operationID string) error {
	var status string
	if err := tx.QueryRowContext(ctx, "SELECT status FROM operations WHERE id=?", operationID).Scan(&status); err != nil {
		return err
	}
	if status != "running" {
		return fmt.Errorf("operation %s not running", operationID)
	}
	return nil
}

func (s *Store) httpAttemptUsage(ctx context.Context, tx *sql.Tx, operationID string) (int, int64, error) {
	var count int
	var size int64
	err := tx.QueryRowContext(ctx, `SELECT count(*),
coalesce(sum(length(request)+coalesce(length(response),0)),0)-(count(*)+count(response))*?
FROM http_attempts WHERE operation=?`, s.aead.Overhead(), operationID).Scan(&count, &size)
	return count, size, err
}

// BeginHTTPAttempt durably records sanitized JSON before dispatch and returns a
// one-based sequence. The caller must omit authorization headers and credentials;
// this opaque journal does not sanitize HTTP data. Only running parents may append.
func (s *Store) BeginHTTPAttempt(ctx context.Context, operationID string, request json.RawMessage) (int, error) {
	if len(request) > maxHTTPRequestBytes || !json.Valid(request) {
		return 0, errors.New("HTTP attempt request must be valid JSON at most 64 KiB")
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return 0, err
	}
	defer tx.Rollback()
	if err := requireRunning(ctx, tx, operationID); err != nil {
		return 0, err
	}
	count, size, err := s.httpAttemptUsage(ctx, tx, operationID)
	if err != nil {
		return 0, err
	}
	if count >= maxHTTPAttempts || size+int64(len(request)) > maxHTTPAttemptBytes {
		return 0, fmt.Errorf("%w: operation HTTP attempt limit", ErrCapacity)
	}
	sequence := count + 1
	encrypted := s.seal(httpAttemptAAD(operationID, sequence, "request"), request)
	if err := s.checkAdmission(ctx, tx, ledgerUsage{bytes: int64(len(encrypted) + len(operationID))}); err != nil {
		return 0, err
	}
	if _, err := tx.ExecContext(ctx, "INSERT INTO http_attempts(operation,sequence,request) VALUES(?,?,?)", operationID, sequence, encrypted); err != nil {
		return 0, err
	}
	if count == 0 {
		var payload []byte
		if err := tx.QueryRowContext(ctx, "SELECT payload FROM operations WHERE id=?", operationID).Scan(&payload); err != nil {
			return 0, err
		}
		raw, err := s.open("operation:"+operationID, payload)
		if err != nil {
			return 0, err
		}
		if _, err := tx.ExecContext(ctx, "UPDATE operations SET payload=? WHERE id=?", s.seal("http-journal:operation:"+operationID, raw), operationID); err != nil {
			return 0, err
		}
	}
	if err := tx.Commit(); err != nil {
		return 0, err
	}
	return sequence, nil
}

// CompleteHTTPAttempt records a known sanitized JSON response exactly once while
// its parent is running. Like Finish, it bypasses ledger admission, but not the
// per-response or per-operation payload bounds.
func (s *Store) CompleteHTTPAttempt(ctx context.Context, operationID string, sequence int, response json.RawMessage) error {
	if sequence < 1 || sequence > maxHTTPAttempts || len(response) > maxHTTPResponseBytes || !json.Valid(response) {
		return errors.New("HTTP attempt requires sequence 1..10 and valid JSON response at most 2 MiB")
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if err := requireRunning(ctx, tx, operationID); err != nil {
		return err
	}
	_, size, err := s.httpAttemptUsage(ctx, tx, operationID)
	if err != nil {
		return err
	}
	if size+int64(len(response)) > maxHTTPAttemptBytes {
		return fmt.Errorf("%w: operation HTTP attempt payload limit", ErrCapacity)
	}
	r, err := tx.ExecContext(ctx, "UPDATE http_attempts SET response=? WHERE operation=? AND sequence=? AND response IS NULL", s.seal(httpAttemptAAD(operationID, sequence, "response"), response), operationID, sequence)
	if err != nil {
		return err
	}
	n, err := r.RowsAffected()
	if err != nil {
		return err
	}
	if n != 1 {
		return errors.New("HTTP attempt missing or already completed")
	}
	return tx.Commit()
}

// HTTPAttempts reads the journal in dispatch order, including potentially
// dispatched entries with no known response. Reading never schedules work.
func (s *Store) HTTPAttempts(ctx context.Context, operationID string) ([]HTTPAttempt, error) {
	rows, err := s.db.QueryContext(ctx, "SELECT sequence,request,response FROM http_attempts WHERE operation=? ORDER BY sequence", operationID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var attempts []HTTPAttempt
	for rows.Next() {
		var attempt HTTPAttempt
		var request, response []byte
		if err := rows.Scan(&attempt.Sequence, &request, &response); err != nil {
			return nil, err
		}
		attempt.Request, err = s.open(httpAttemptAAD(operationID, attempt.Sequence, "request"), request)
		if err != nil {
			return nil, err
		}
		if response != nil {
			attempt.Response, err = s.open(httpAttemptAAD(operationID, attempt.Sequence, "response"), response)
			if err != nil {
				return nil, err
			}
		}
		attempts = append(attempts, attempt)
	}
	return attempts, rows.Err()
}
