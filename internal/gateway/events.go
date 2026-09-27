package gateway

import (
	"context"
	"fmt"
	"net/http"
	"time"
)

// ledgerEvents sends invalidations, never ledger data. Every connection starts
// with a refresh, so missed events and process restarts need no replay buffer.
func (g *Gateway) ledgerEvents(w http.ResponseWriter, r *http.Request) {
	// Bound the authenticated stream's lifetime. Reconnects pass through owner
	// authentication again; every fragment GET also checks the current session.
	ctx, cancel := context.WithTimeout(r.Context(), time.Minute)
	defer cancel()
	sequence, err := g.store.EventSequence(ctx)
	if err != nil {
		http.Error(w, "ledger unavailable", http.StatusServiceUnavailable)
		return
	}
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Accel-Buffering", "no")
	if r.Method == http.MethodHead {
		return
	}
	controller := http.NewResponseController(w)
	send := func(frame string) error {
		// A stalled browser must not retain its handler indefinitely.
		if err := controller.SetWriteDeadline(time.Now().Add(5 * time.Second)); err != nil {
			return err
		}
		defer controller.SetWriteDeadline(time.Time{})
		if _, err := fmt.Fprint(w, frame); err != nil {
			return err
		}
		return controller.Flush()
	}
	const changed = "event: ledger\ndata: changed\n\n"
	if err := send("retry: 1000\n" + changed); err != nil {
		return
	}
	tick := time.NewTicker(250 * time.Millisecond)
	defer tick.Stop()
	heartbeat := time.NewTicker(15 * time.Second)
	defer heartbeat.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-heartbeat.C:
			if err := send(": keepalive\n\n"); err != nil {
				return
			}
		case <-tick.C:
			next, err := g.store.EventSequence(ctx)
			if err != nil {
				return
			}
			if next != sequence {
				if err := send(changed); err != nil {
					return
				}
				sequence = next
			}
		}
	}
}
