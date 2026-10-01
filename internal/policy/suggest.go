// Package policy proposes tool policies for owner review; it never authorizes execution.
package policy

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"time"
)

// Tool contains only the metadata needed for classification.
type Tool struct {
	Name, Description string
	InputSchema       map[string]any
}

// Client sends tool metadata, never connection settings or call arguments, to Jev.
type Client struct {
	Key  string
	HTTP *http.Client
}

// Suggestion records the recommendation and the model used for human review.
type Suggestion struct {
	Policy, Model, Reason string
}

// Suggest fails closed on incomplete evaluations. The caller selects eligible tools.
func (c Client) Suggest(ctx context.Context, tool Tool) Suggestion {
	fallback := Suggestion{Policy: "require_approval", Reason: "Jev is unavailable or returned an incomplete assessment. Approval is required until you choose otherwise."}
	if c.Key == "" {
		return fallback
	}
	risks := []struct{ key, question, effect string }{
		{"writes", "Can the tool create or modify stored data?", "modify stored data"},
		{"deletes", "Can the tool delete stored data?", "delete stored data"},
		{"communicates", "Can the tool send messages or publish content to other people?", "send messages or publish content"},
		{"spends", "Can the tool spend money or initiate financial transactions?", "spend money"},
		{"permissions", "Can the tool change permissions or account security settings?", "change permissions or account security"},
		{"credentials", "Can the tool retrieve credentials, tokens, keys or other secrets?", "access credentials or secrets"},
		{"sensitive", "Can the tool read private personal or business data?", "read private personal or business data"},
		{"execution", "Can the tool execute caller-supplied code, SQL or shell commands?", "execute caller-supplied code or queries"},
		{"requests", "Can the tool make network requests to arbitrary caller-supplied destinations?", "make arbitrary network requests"},
	}
	questions := map[string]any{"safe": map[string]string{"type": "noul", "instructions": "Does the tool only read public, non-sensitive information?"}}
	for _, risk := range risks {
		questions[risk.key] = map[string]string{"type": "noul", "instructions": risk.question}
	}
	body, err := json.Marshal(map[string]any{
		"model":     "jev-latest",
		"state":     map[string]any{"name": tool.Name, "description": tool.Description, "input_schema": tool.InputSchema},
		"questions": questions,
	})
	if err != nil {
		return fallback
	}
	ctx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, "https://api.typesafe.ai/v1/systemone", bytes.NewReader(body))
	if err != nil {
		return fallback
	}
	req.Header.Set("Authorization", "Bearer "+c.Key)
	req.Header.Set("Content-Type", "application/json")
	client := c.HTTP
	if client == nil {
		client = &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	}
	resp, err := client.Do(req)
	if err != nil {
		return fallback
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fallback
	}
	var result struct {
		Model   string `json:"model"`
		Answers map[string]struct {
			Type        string   `json:"type"`
			Probability *float64 `json:"noul"`
		} `json:"answers"`
	}
	b, err := io.ReadAll(io.LimitReader(resp.Body, 64*1024+1))
	if err != nil || len(b) > 64*1024 || json.Unmarshal(b, &result) != nil || result.Model == "" {
		return fallback
	}
	for key := range questions {
		a := result.Answers[key]
		if a.Type != "noul" || a.Probability == nil || *a.Probability < 0 || *a.Probability > 1 {
			return fallback
		}
	}
	safe := *result.Answers["safe"].Probability
	var reasons []string
	for _, risk := range risks {
		probability := *result.Answers[risk.key].Probability
		if probability > 0.05 {
			prefix := "Cannot rule out the ability to "
			if probability >= 0.5 {
				prefix = "May "
			}
			reasons = append(reasons, prefix+risk.effect+".")
		}
	}
	suggestion := Suggestion{Policy: "require_approval", Model: result.Model}
	if len(reasons) == 0 && safe >= 0.95 {
		suggestion.Policy = "allow"
		suggestion.Reason = "Appears limited to public, non-sensitive reads with no identified side effects. Calls can run without approval."
	} else {
		if len(reasons) == 0 {
			reasons = append(reasons, "Uncertain whether this tool only reads public, non-sensitive information.")
		}
		suggestion.Reason = strings.Join(reasons, " ") + " Approval recommended."
	}
	return suggestion
}
