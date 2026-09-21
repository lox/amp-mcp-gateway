package gateway

import (
	"errors"
	"strings"
)

// Bound decoded search work before acquiring the catalogue lock. Repeated terms
// do not change the existing AND search semantics and need only one comparison.
func searchTerms(query string) ([]string, error) {
	if len(query) > 1024 {
		return nil, errors.New("search query exceeds 1024 bytes")
	}
	words := []string{}
	seen := map[string]bool{}
	for _, word := range strings.Fields(strings.ToLower(query)) {
		if seen[word] {
			continue
		}
		if len(words) == 32 {
			return nil, errors.New("search query exceeds 32 distinct terms")
		}
		seen[word] = true
		words = append(words, word)
	}
	return words, nil
}
