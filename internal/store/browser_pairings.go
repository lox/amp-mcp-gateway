package store

import "context"

// LoadBrowserPairings returns encrypted-at-rest reconnect authorities keyed by
// browser connection ID.
func (s *Store) LoadBrowserPairings(ctx context.Context) (map[string][]byte, error) {
	rows, err := s.db.QueryContext(ctx, "SELECT id,payload FROM browser_pairings")
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	pairings := make(map[string][]byte)
	for rows.Next() {
		var id string
		var encrypted []byte
		if err := rows.Scan(&id, &encrypted); err != nil {
			return nil, err
		}
		payload, err := s.open("browser-pairing:"+id, encrypted)
		if err != nil {
			return nil, err
		}
		pairings[id] = payload
	}
	return pairings, rows.Err()
}

// SaveBrowserPairing persists reconnect authority before acknowledging it to
// the extension.
func (s *Store) SaveBrowserPairing(ctx context.Context, id string, payload []byte) error {
	_, err := s.db.ExecContext(ctx, "INSERT INTO browser_pairings VALUES (?,?) ON CONFLICT(id) DO UPDATE SET payload=excluded.payload", id, s.seal("browser-pairing:"+id, payload))
	return err
}

// DeleteBrowserPairing revokes persisted reconnect authority.
func (s *Store) DeleteBrowserPairing(ctx context.Context, id string) error {
	_, err := s.db.ExecContext(ctx, "DELETE FROM browser_pairings WHERE id=?", id)
	return err
}
