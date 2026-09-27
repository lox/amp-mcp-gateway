package store

import (
	"context"
	"crypto/subtle"
	"database/sql"
	"encoding/json"
	"errors"
	"time"
)

// ErrCredentialLeaseCapacity means no credential was issued and the caller may
// retry with a new operation after an outstanding lease is redeemed or expires.
var ErrCredentialLeaseCapacity = errors.New("too many unredeemed credential leases")

// CredentialLease holds an approved right to derive a credential until one
// authenticated redemption. The parent credential remains in the catalogue.
type CredentialLease struct {
	ID               string `json:"id"`
	OperationID      string `json:"operation_id"`
	Integration      string `json:"integration"`
	CredentialDigest string `json:"credential_digest"`
	LifetimeSeconds  int64  `json:"lifetime_seconds"`
	AmpSubject       string `json:"amp_subject,omitempty"`
	AmpUserID        string `json:"amp_user_id,omitempty"`
	AmpWorkspaceID   string `json:"amp_workspace_id,omitempty"`
	AmpProjectID     string `json:"amp_project_id,omitempty"`
	AmpThreadID      string `json:"amp_thread_id,omitempty"`
	Expires          int64  `json:"expires"`
}

// CreateCredentialLease persists a ready, short-lived redemption capability.
func (s *Store) CreateCredentialLease(ctx context.Context, lease CredentialLease) error {
	raw, err := json.Marshal(lease)
	if err != nil {
		return err
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	now := time.Now().Unix()
	if _, err := tx.ExecContext(ctx, "DELETE FROM credential_leases WHERE expires<=?", now); err != nil {
		return err
	}
	var ready int
	if err := tx.QueryRowContext(ctx, "SELECT count(*) FROM credential_leases").Scan(&ready); err != nil {
		return err
	}
	if ready >= 32 {
		return ErrCredentialLeaseCapacity
	}
	if _, err := tx.ExecContext(ctx, "INSERT INTO credential_leases(id,expires,payload) VALUES(?,?,?)", lease.ID, lease.Expires, s.seal("credential-lease:"+lease.ID, raw)); err != nil {
		return err
	}
	if err := event(ctx, tx, lease.OperationID, "lease-ready", "gateway"); err != nil {
		return err
	}
	return tx.Commit()
}

// RedeemCredentialLease atomically consumes a lease bound to the authenticated caller.
func (s *Store) RedeemCredentialLease(ctx context.Context, id string, caller CredentialLease) (CredentialLease, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return CredentialLease{}, err
	}
	defer tx.Rollback()
	var payload []byte
	err = tx.QueryRowContext(ctx, "SELECT payload FROM credential_leases WHERE id=? AND expires>?", id, time.Now().Unix()).Scan(&payload)
	if errors.Is(err, sql.ErrNoRows) {
		return CredentialLease{}, errors.New("credential lease unavailable or expired")
	}
	if err != nil {
		return CredentialLease{}, err
	}
	raw, err := s.open("credential-lease:"+id, payload)
	if err != nil {
		return CredentialLease{}, err
	}
	var lease CredentialLease
	if err := json.Unmarshal(raw, &lease); err != nil {
		return CredentialLease{}, err
	}
	if lease.ID != id || !sameLeaseCaller(lease, caller) {
		return CredentialLease{}, errors.New("credential lease belongs to another caller")
	}
	actor := lease.AmpUserID
	if actor != "" {
		actor = "amp:" + actor
	} else {
		actor = "gateway-client"
	}
	if lease.Integration != caller.Integration || subtle.ConstantTimeCompare([]byte(lease.CredentialDigest), []byte(caller.CredentialDigest)) != 1 {
		if _, err := tx.ExecContext(ctx, "DELETE FROM credential_leases WHERE id=?", id); err != nil {
			return CredentialLease{}, err
		}
		if err := event(ctx, tx, lease.OperationID, "lease-invalidated", actor); err != nil {
			return CredentialLease{}, err
		}
		if err := tx.Commit(); err != nil {
			return CredentialLease{}, err
		}
		return CredentialLease{}, errors.New("credential lease authority changed")
	}
	r, err := tx.ExecContext(ctx, "DELETE FROM credential_leases WHERE id=?", id)
	if err != nil {
		return CredentialLease{}, err
	}
	if n, err := r.RowsAffected(); err != nil || n != 1 {
		return CredentialLease{}, errors.New("credential lease already redeemed")
	}
	if err := event(ctx, tx, lease.OperationID, "lease-redeemed", actor); err != nil {
		return CredentialLease{}, err
	}
	return lease, tx.Commit()
}

func sameLeaseCaller(a, b CredentialLease) bool {
	left, _ := json.Marshal([]string{a.AmpSubject, a.AmpUserID, a.AmpWorkspaceID, a.AmpProjectID, a.AmpThreadID})
	right, _ := json.Marshal([]string{b.AmpSubject, b.AmpUserID, b.AmpWorkspaceID, b.AmpProjectID, b.AmpThreadID})
	return subtle.ConstantTimeCompare(left, right) == 1
}
