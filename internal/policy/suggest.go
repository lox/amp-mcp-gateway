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
// Class is a suggested capability class (read, write or high_risk), empty when
// Jev did not complete an assessment. It never authorizes anything until the
// owner saves it.
type Suggestion struct {
	Policy, Model, Reason, Class string
}

// Suggest fails closed on incomplete evaluations. The caller selects eligible tools.
func (c Client) Suggest(ctx context.Context, tool Tool) Suggestion {
	fallback := Suggestion{Policy: "require_approval", Reason: "Jev is unavailable or returned an incomplete assessment. Approval is required until you choose otherwise."}
	if c.Key == "" {
		return fallback
	}
	// class is the capability class a risk that cannot be ruled out implies.
	// Private reads stay Read: read trust warns about private data instead.
	risks := []struct{ key, question, effect, class string }{
		{"writes", "Can the tool create or modify stored data?", "modify stored data", "write"},
		{"deletes", "Can the tool delete stored data?", "delete stored data", "high_risk"},
		{"communicates", "Can the tool send messages or publish content to other people?", "send messages or publish content", "high_risk"},
		{"spends", "Can the tool spend money or initiate financial transactions?", "spend money", "high_risk"},
		{"permissions", "Can the tool change permissions or account security settings?", "change permissions or account security", "high_risk"},
		{"credentials", "Can the tool retrieve credentials, tokens, keys or other secrets?", "access credentials or secrets", "high_risk"},
		{"sensitive", "Can the tool read private personal or business data?", "read private personal or business data", "read"},
		{"execution", "Can the tool execute caller-supplied code, SQL or shell commands?", "execute caller-supplied code or queries", "high_risk"},
		{"requests", "Can the tool make network requests to arbitrary caller-supplied destinations?", "make arbitrary network requests", "high_risk"},
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
	class, rank := "read", map[string]int{"read": 0, "write": 1, "high_risk": 2}
	for _, risk := range risks {
		probability := *result.Answers[risk.key].Probability
		if probability > 0.05 {
			// A tool with mixed capabilities takes its highest class.
			if rank[risk.class] > rank[class] {
				class = risk.class
			}
			prefix := "Cannot rule out the ability to "
			if probability >= 0.5 {
				prefix = "May "
			}
			reasons = append(reasons, prefix+risk.effect+".")
		}
	}
	suggestion := Suggestion{Policy: "require_approval", Model: result.Model, Class: class}
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
