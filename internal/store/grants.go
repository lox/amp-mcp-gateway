package store

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"strings"
	"time"
)

// ApprovalGrant is durable authority for future calls in one Amp identity scope.
// Its target and identity details are encrypted in the ledger.
type ApprovalGrant struct {
	ID             string `json:"id"`
	Scope          string `json:"scope"`
	Tool           string `json:"tool"`
	Connection     string `json:"connection"`
	Binding        string `json:"binding"`
	AmpUserID      string `json:"amp_user_id"`
	AmpWorkspaceID string `json:"amp_workspace_id,omitempty"`
	AmpProjectID   string `json:"amp_project_id,omitempty"`
	AmpThreadID    string `json:"amp_thread_id,omitempty"`
	OperationID    string `json:"operation_id"`
	Created        int64  `json:"created"`
}

func approvalGrant(o Operation, scope string) (ApprovalGrant, error) {
	g := ApprovalGrant{
		Scope: scope, Tool: o.Tool, Connection: o.Connection, Binding: o.Binding,
		AmpUserID: o.AmpUserID, AmpWorkspaceID: o.AmpWorkspaceID, AmpProjectID: o.AmpProjectID,
		OperationID: o.ID,
	}
	switch scope {
	case "thread":
		if o.AmpUserID == "" || o.AmpThreadID == "" {
			return g, errors.New("thread approval requires verified Amp user and thread identity")
		}
		g.AmpThreadID = o.AmpThreadID
	case "project":
		if o.AmpUserID == "" || o.AmpProjectID == "" {
			return g, errors.New("project approval requires verified Amp user and project identity")
		}
	default:
		return g, errors.New("invalid approval scope")
	}
	g.ID = grantID(g)
	return g, nil
}

func grantID(g ApprovalGrant) string {
	raw, _ := json.Marshal([]any{"approval-grant-v1", g.Scope, g.Tool, g.Connection, g.Binding, g.AmpUserID, g.AmpWorkspaceID, g.AmpProjectID, g.AmpThreadID})
	h := sha256.Sum256(raw)
	return hex.EncodeToString(h[:])
}

func approvalGrantIDs(o Operation) []string {
	ids := []string{}
	for _, scope := range []string{"thread", "project"} {
		if g, err := approvalGrant(o, scope); err == nil {
			ids = append(ids, g.ID)
		}
	}
	return ids
}

func (s *Store) activeGrant(ctx context.Context, tx *sql.Tx, id string) (*ApprovalGrant, error) {
	g, err := s.decodeGrant(tx.QueryRowContext(ctx, "SELECT id,payload FROM approval_grants WHERE id=? AND active=1", id))
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return &g, nil
}

func (s *Store) saveGrant(ctx context.Context, tx *sql.Tx, o Operation, scope string) error {
	g, err := approvalGrant(o, scope)
	if err != nil {
		return err
	}
	g.Created = time.Now().Unix()
	raw, err := json.Marshal(g)
	if err != nil {
		return err
	}
	_, err = tx.ExecContext(ctx, `INSERT INTO approval_grants(id,active,created,payload) VALUES(?,1,?,?)
ON CONFLICT(id) DO UPDATE SET active=1,created=excluded.created,payload=excluded.payload`, g.ID, g.Created, s.seal("approval-grant:"+g.ID, raw))
	return err
}

// Approve authorizes a pending operation once and optionally grants its exact
// tool and binding to the verified Amp thread or project in the same transaction.
func (s *Store) Approve(ctx context.Context, id, actor, scope string) error {
	return s.decide(ctx, id, actor, true, scope)
}

func (s *Store) decodeGrant(row scanner) (ApprovalGrant, error) {
	var g ApprovalGrant
	var id string
	var payload []byte
	if err := row.Scan(&id, &payload); err != nil {
		return g, err
	}
	raw, err := s.open("approval-grant:"+id, payload)
	if err != nil {
		return g, err
	}
	if err := json.Unmarshal(raw, &g); err != nil {
		return g, err
	}
	if g.ID != id || grantID(g) != id {
		return g, errors.New("approval grant identity mismatch")
	}
	return g, nil
}

// ApprovalGrants returns active standing approvals, newest first.
func (s *Store) ApprovalGrants(ctx context.Context) ([]ApprovalGrant, error) {
	rows, err := s.db.QueryContext(ctx, "SELECT id,payload FROM approval_grants WHERE active=1 ORDER BY created DESC,id")
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	grants := []ApprovalGrant{}
	for rows.Next() {
		g, err := s.decodeGrant(rows)
		if err != nil {
			return nil, err
		}
		grants = append(grants, g)
	}
	return grants, rows.Err()
}

// RevokeApprovalGrant prevents the grant from authorizing future submissions.
func (s *Store) RevokeApprovalGrant(ctx context.Context, id, actor string) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	g, err := s.decodeGrant(tx.QueryRowContext(ctx, "SELECT id,payload FROM approval_grants WHERE id=? AND active=1", id))
	if errors.Is(err, sql.ErrNoRows) {
		return errors.New("approval grant unavailable or already revoked")
	}
	if err != nil {
		return err
	}
	r, err := tx.ExecContext(ctx, "UPDATE approval_grants SET active=0 WHERE id=? AND active=1", id)
	if err != nil {
		return err
	}
	n, err := r.RowsAffected()
	if err != nil {
		return err
	}
	if n != 1 {
		return errors.New("approval grant unavailable or already revoked")
	}
	if err := event(ctx, tx, g.OperationID, "approval-revoked", actor); err != nil {
		return err
	}
	return tx.Commit()
}

func (s *Store) revokeConnectionGrants(ctx context.Context, tx *sql.Tx, credentialKey string) error {
	connection, _, ok := strings.Cut(credentialKey, ":")
	if !ok {
		return nil
	}
	rows, err := tx.QueryContext(ctx, "SELECT id,payload FROM approval_grants WHERE active=1")
	if err != nil {
		return err
	}
	var ids []string
	for rows.Next() {
		g, err := s.decodeGrant(rows)
		if err != nil {
			rows.Close()
			return err
		}
		if g.Connection == connection {
			ids = append(ids, g.ID)
		}
	}
	if err := rows.Close(); err != nil {
		return err
	}
	for _, id := range ids {
		if _, err := tx.ExecContext(ctx, "UPDATE approval_grants SET active=0 WHERE id=?", id); err != nil {
			return err
		}
	}
	return nil
}
