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
	Breadth        string `json:"breadth,omitempty"`
	Expiry         string `json:"expiry,omitempty"`
	Tool           string `json:"tool"`
	Connection     string `json:"connection"`
	Binding        string `json:"binding"`
	Arguments      string `json:"arguments,omitempty"`
	AmpUserID      string `json:"amp_user_id"`
	AmpWorkspaceID string `json:"amp_workspace_id,omitempty"`
	AmpProjectID   string `json:"amp_project_id,omitempty"`
	AmpThreadID    string `json:"amp_thread_id,omitempty"`
	OperationID    string `json:"operation_id"`
	Created        int64  `json:"created"`
}

// Expires returns zero for indefinite consent. Legacy grants retain one hour.
func (g ApprovalGrant) Expires() time.Time {
	if g.Expiry == "never" {
		return time.Time{}
	}
	if g.Expiry == "24h" {
		return time.Unix(g.Created, 0).Add(24 * time.Hour)
	}
	return time.Unix(g.Created, 0).Add(time.Hour)
}

// ApprovalOptions describes reusable consent. All fields are required.
type ApprovalOptions struct {
	Breadth string
	Scope   string
	Expiry  string
}

func argumentsDigest(arguments map[string]any) string {
	raw, _ := json.Marshal(arguments)
	h := sha256.Sum256(raw)
	return hex.EncodeToString(h[:])
}

func approvalGrant(o Operation, options ApprovalOptions) (ApprovalGrant, error) {
	g := ApprovalGrant{
		Scope: options.Scope, Breadth: options.Breadth, Expiry: options.Expiry,
		Tool: o.Tool, Connection: o.Connection, Binding: o.Binding,
		AmpUserID: o.AmpUserID, AmpWorkspaceID: o.AmpWorkspaceID, AmpProjectID: o.AmpProjectID,
		OperationID: o.ID,
	}
	switch options.Breadth {
	case "exact":
		g.Arguments = argumentsDigest(o.Arguments)
	case "tool":
	case "connection":
		if o.ConnectionBinding == "" {
			return g, errors.New("connection approval requires connection binding")
		}
		g.Tool, g.Binding = "", o.ConnectionBinding
	default:
		return g, errors.New("invalid approval breadth")
	}
	if options.Expiry != "1h" && options.Expiry != "24h" && options.Expiry != "never" {
		return g, errors.New("invalid approval expiry")
	}
	switch options.Scope {
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
	version := "approval-grant-v2"
	if g.Breadth == "" {
		version = "approval-grant-v1"
	}
	raw, _ := json.Marshal([]any{version, g.Scope, g.Breadth, g.Tool, g.Connection, g.Binding, g.Arguments, g.AmpUserID, g.AmpWorkspaceID, g.AmpProjectID, g.AmpThreadID})
	if version == "approval-grant-v1" {
		raw, _ = json.Marshal([]any{version, g.Scope, g.Tool, g.Connection, g.Binding, g.AmpUserID, g.AmpWorkspaceID, g.AmpProjectID, g.AmpThreadID})
	}
	h := sha256.Sum256(raw)
	return hex.EncodeToString(h[:])
}

func approvalGrantIDs(o Operation) []string {
	ids := []string{}
	for _, scope := range []string{"thread", "project"} {
		// Legacy grants were tool-wide and expire after one hour.
		legacy := ApprovalGrant{Scope: scope, Tool: o.Tool, Connection: o.Connection, Binding: o.Binding, AmpUserID: o.AmpUserID, AmpWorkspaceID: o.AmpWorkspaceID, AmpProjectID: o.AmpProjectID, OperationID: o.ID}
		validLegacy := o.AmpUserID != ""
		if scope == "thread" {
			legacy.AmpThreadID = o.AmpThreadID
			validLegacy = validLegacy && o.AmpThreadID != ""
		} else {
			validLegacy = validLegacy && o.AmpProjectID != ""
		}
		if validLegacy {
			legacy.ID = grantID(legacy)
			ids = append(ids, legacy.ID)
		}
		for _, breadth := range []string{"exact", "tool", "connection"} {
			if g, err := approvalGrant(o, ApprovalOptions{Breadth: breadth, Scope: scope, Expiry: "1h"}); err == nil {
				// Expiry is deliberately not part of grant identity, allowing renewal.
				ids = append(ids, g.ID)
			}
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
	if expiry := g.Expires(); !expiry.IsZero() && !time.Now().Before(expiry) {
		return nil, nil
	}
	return &g, nil
}

func (s *Store) saveGrant(ctx context.Context, tx *sql.Tx, o Operation, options ApprovalOptions) error {
	g, err := approvalGrant(o, options)
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
	if scope == "once" {
		return s.Decide(ctx, id, actor, true)
	}
	return s.decide(ctx, id, actor, true, &ApprovalOptions{Breadth: "tool", Scope: scope, Expiry: "1h"})
}

// ApproveWithOptions atomically approves an operation and stores reusable consent.
func (s *Store) ApproveWithOptions(ctx context.Context, id, actor string, options ApprovalOptions) error {
	return s.decide(ctx, id, actor, true, &options)
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

// ApprovalGrants returns unexpired active standing approvals, newest first.
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
		if expiry := g.Expires(); expiry.IsZero() || time.Now().Before(expiry) {
			grants = append(grants, g)
		}
	}
	return grants, rows.Err()
}

// RevokeApprovalGrant prevents future submissions and claims using this consent.
// It cannot cancel operations already claimed or directly approved by the owner.
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
