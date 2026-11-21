package reviews

import (
	"context"
	"errors"
	"time"

	"ampcode.com/lox/amp-mcp-gateway/internal/store"
)

// DailyUsage attributes all attempts to the review's UTC creation day.
// Known counts distinguish recorded zero costs from missing usage.
type DailyUsage struct {
	Date                               time.Time
	Reviews, Threads, Known, Estimates int
	Credits, ProviderEstimate          float64
}

// UsageSummary returns today's partial UTC day and the preceding 29 days,
// including records beyond the history list's page limit.
func (s *Service) UsageSummary(ctx context.Context, now time.Time) ([]DailyUsage, error) {
	start := now.UTC().Truncate(24*time.Hour).AddDate(0, 0, -29)
	days := make([]DailyUsage, 30)
	for i := range days {
		days[i].Date = start.AddDate(0, 0, i)
	}
	err := s.store.VisitReviews(ctx, start.UnixNano(), now.UnixNano(), func(r store.ReviewRecord) error {
		j, err := decode(r)
		if err != nil {
			return err
		}
		if j.OwnerID != s.owner {
			return errors.New("review owner mismatch")
		}
		d := &days[time.Unix(0, r.Created).Sub(start)/(24*time.Hour)]
		d.Reviews++
		d.Threads += len(j.Threads)
		for _, thread := range j.Threads {
			if thread.Usage == nil {
				continue
			}
			d.Known++
			d.Credits += thread.Usage.CostUSD
			if thread.Usage.ProviderEstimateUSD != nil {
				d.Estimates++
				d.ProviderEstimate += *thread.Usage.ProviderEstimateUSD
			}
		}
		return nil
	})
	return days, err
}
