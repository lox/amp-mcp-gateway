package store

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"time"
)

// Grant records browser consent for future calls to one pinned tool. ID is the
// originating operation ID; subsequent operations retain it for audit attribution.
type Grant struct {
	ID, Scope, Subject, AmpUserID, AmpThreadID, AmpProjectID, AmpWorkspaceID string
	Tool, Connection, Account, Actor                                         string
	Expires                                                                  time.Time
}

func grantKey(o Operation, scope string) string {
	identity := o.AmpThreadID
	if scope == "project" {
		identity = o.AmpProjectID
	}
	b, _ := json.Marshal([]string{scope, o.Subject, o.AmpUserID, o.AmpWorkspaceID, identity, o.Tool, o.Connection, o.Binding})
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:])
}

// ApproveScope approves the immutable request once and creates a one-hour grant
// in the same transaction. The gateway supplies its current reviewed binding.
func (s *Store) ApproveScope(ctx context.Context, id, actor, scope, binding string) error {
	if scope != "thread" && scope != "project" {
		return errors.New("invalid grant scope")
	}
	return s.decide(ctx, id, actor, true, scope, binding)
}

func (s *Store) createGrant(ctx context.Context, tx *sql.Tx, o Operation, actor, scope, binding string) error {
	if actor == "" || actor != o.Subject || o.AmpUserID == "" || o.AmpThreadID == "" ||
		binding == "" || binding != o.Binding || (scope == "project" && o.AmpProjectID == "") {
		return errors.New("grant requires matching owner, verified identity and current binding")
	}
	g := Grant{ID: o.ID, Scope: scope, Subject: o.Subject, AmpUserID: o.AmpUserID,
		AmpThreadID: o.AmpThreadID, AmpProjectID: o.AmpProjectID, AmpWorkspaceID: o.AmpWorkspaceID,
		Tool: o.Tool, Connection: o.Connection, Account: o.Account, Actor: actor,
		Expires: time.Now().Add(time.Hour).Truncate(time.Second)}
	b, err := json.Marshal(g)
	if err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, "INSERT INTO grants VALUES (?,?,?,0,?)", g.ID, grantKey(o, scope), g.Expires.Unix(), s.seal("grant:"+g.ID, b)); err != nil {
		return err
	}
	return event(ctx, tx, o.ID, "grant-created:"+scope, actor)
}

// Grants lists all unexpired, unrevoked grants for the browser owner.
func (s *Store) Grants(ctx context.Context, owner string) ([]Grant, error) {
	rows, err := s.db.QueryContext(ctx, "SELECT id,payload FROM grants WHERE revoked=0 AND expires>? ORDER BY expires,id", time.Now().Unix())
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var grants []Grant
	for rows.Next() {
		var id string
		var b []byte
		if err := rows.Scan(&id, &b); err != nil {
			return nil, err
		}
		b, err = s.open("grant:"+id, b)
		if err != nil {
			return nil, err
		}
		var g Grant
		if err := json.Unmarshal(b, &g); err != nil {
			return nil, err
		}
		if g.Subject == owner {
			grants = append(grants, g)
		}
	}
	return grants, rows.Err()
}

// RevokeGrant prevents later claims. Already claimed calls cannot be cancelled.
func (s *Store) RevokeGrant(ctx context.Context, id, actor string) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var b []byte
	if err := tx.QueryRowContext(ctx, "SELECT payload FROM grants WHERE id=? AND revoked=0", id).Scan(&b); err != nil {
		return err
	}
	b, err = s.open("grant:"+id, b)
	if err != nil {
		return err
	}
	var g Grant
	if err := json.Unmarshal(b, &g); err != nil {
		return err
	}
	if actor == "" || g.Subject != actor {
		return errors.New("grant owner mismatch")
	}
	if _, err := tx.ExecContext(ctx, "UPDATE grants SET revoked=1 WHERE id=?", id); err != nil {
		return err
	}
	if err := event(ctx, tx, id, "grant-revoked", actor); err != nil {
		return err
	}
	return tx.Commit()
}

func revokeAllGrants(ctx context.Context, tx *sql.Tx, actor string) error {
	if _, err := tx.ExecContext(ctx, "INSERT INTO events(operation,kind,actor,time) SELECT id,'grant-revoked',?,unixepoch() FROM grants WHERE revoked=0", actor); err != nil {
		return err
	}
	_, err := tx.ExecContext(ctx, "UPDATE grants SET revoked=1 WHERE revoked=0")
	return err
}
