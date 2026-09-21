package gateway

import (
	"bytes"
	"encoding/json"
)

// Preserve JSON tokens, including duplicate keys and large numbers. If readable
// indentation would amplify the input, show complete compact JSON instead.
func prettyJSON(raw []byte) string {
	var compact bytes.Buffer
	if json.Compact(&compact, raw) != nil {
		return string(raw)
	}
	data := compact.Bytes()
	if !boundedIndent(data) {
		return string(data)
	}
	var out bytes.Buffer
	if json.Indent(&out, data, "", "  ") == nil {
		return out.String()
	}
	return string(data)
}

// Preflight valid compact JSON before json.Indent can allocate indentation.
// Charge every possible newline/space, including empty containers (an upper
// bound). Permit at most twice the input size plus 4 KiB of added whitespace.
func boundedIndent(raw []byte) bool {
	remaining := 2*len(raw) + 4096
	depth := 0
	quoted, escaped := false, false
	for _, c := range raw {
		if quoted {
			if escaped {
				escaped = false
			} else if c == '\\' {
				escaped = true
			} else if c == '"' {
				quoted = false
			}
			continue
		}
		switch c {
		case '"':
			quoted = true
		case '{', '[':
			depth++
			remaining -= 1 + 2*depth
		case '}', ']':
			depth--
			remaining -= 1 + 2*depth
		case ',':
			remaining -= 1 + 2*depth
		case ':':
			remaining--
		}
		if remaining < 0 {
			return false
		}
	}
	return true
}
