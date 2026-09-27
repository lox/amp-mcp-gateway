package gateway

import (
	"context"
	"time"

	"ampcode.com/lox/amp-mcp-gateway/internal/policy"
	"golang.org/x/sync/errgroup"
)

// suggestPolicies changes only newly discovered, unconfigured tools in this
// unpublished draft. Existing choices and changed-tool restrictions win.
func (draft *toolDraft) suggestPolicies(ctx context.Context, enabled bool, client policy.Client, previous []Tool) {
	draft.Suggestions = make(map[string]policy.Suggestion)
	draft.SuggestionNotice = "Jev suggestions skipped. New tools require approval; existing choices and blocked defaults are preserved."
	if client.Key == "" {
		draft.SuggestionNotice = "Jev is unavailable: TYPESAFE_API_KEY is not set. New tools require approval; existing choices and blocked defaults are preserved."
	} else if enabled {
		draft.SuggestionNotice = "Jev suggestions are ready for review. Existing choices are preserved. Unavailable or uncertain classifications require approval. Nothing changes until you save."
	}
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	results := make([]policy.Suggestion, len(draft.Tools))
	var group errgroup.Group
	group.SetLimit(4)
	reviewed := map[string]bool{}
	for _, tool := range previous {
		reviewed[tool.Name] = true
	}
	for i, tool := range draft.Tools {
		if draft.Changes[tool.ID] != "New" || tool.Policy != "" || reviewed[tool.Name] {
			continue
		}
		if draft.Default == "deny" {
			continue
		}
		// The connection default may allow calls, but new suggestions must fail closed.
		results[i] = policy.Suggestion{Policy: "require_approval", Reason: "Classification skipped; owner review required"}
		if !enabled || client.Key == "" {
			continue
		}
		group.Go(func() error {
			if ctx.Err() == nil {
				results[i] = client.Suggest(ctx, policy.Tool{Name: tool.Name, Description: tool.Description, InputSchema: tool.InputSchema})
			}
			return nil
		})
	}
	_ = group.Wait() // Workers return only advisory results, including safe fallbacks.
	for i, result := range results {
		if result.Policy == "" {
			continue
		}
		draft.Tools[i].Policy = result.Policy
		draft.Suggestions[draft.Tools[i].ID] = result
	}
}
