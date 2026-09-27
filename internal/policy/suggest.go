// Package policy proposes tool policies for owner review; it never authorizes execution.
package policy

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
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
	fallback := Suggestion{Policy: "require_approval", Reason: "classification unavailable or invalid; review required"}
	if c.Key == "" {
		return fallback
	}
	questions := map[string]any{}
	for key, question := range map[string]string{
		"safe":         "Does the tool only read public, non-sensitive information?",
		"writes":       "Can the tool create, modify or delete stored data?",
		"communicates": "Can the tool send messages or publish content to other people?",
		"spends":       "Can the tool spend money or initiate financial transactions?",
		"permissions":  "Can the tool change permissions or account security settings?",
		"sensitive":    "Can the tool retrieve credentials or private personal or business data?",
		"execution":    "Can the tool execute caller-supplied code, SQL, shell commands or arbitrary HTTP requests?",
	} {
		questions[key] = map[string]string{"type": "noul", "instructions": question}
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
	risk := 0.0
	for key := range questions {
		a := result.Answers[key]
		if a.Type != "noul" || a.Probability == nil || *a.Probability < 0 || *a.Probability > 1 {
			return fallback
		}
		if key != "safe" {
			risk = max(risk, *a.Probability)
		}
	}
	safe := *result.Answers["safe"].Probability
	suggestion := Suggestion{Policy: "require_approval", Model: result.Model, Reason: fmt.Sprintf("public-read=%.4f max-risk=%.4f; owner review required", safe, risk)}
	if safe >= 0.95 && risk <= 0.05 {
		suggestion.Policy = "allow"
	}
	return suggestion
}
