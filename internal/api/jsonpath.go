package api

import (
	"bytes"
	"encoding/json"
	"io"
)

func bytesReader(b []byte) io.Reader { return bytes.NewReader(b) }

// getString returns parsed[p1][p2]... as a string, or "" if any link is missing
// or not a string.
func getString(parsed map[string]any, path ...string) string {
	v, ok := getAt(parsed, path)
	if !ok {
		return ""
	}
	s, ok := v.(string)
	if !ok {
		return ""
	}
	return s
}

// getInt walks the path and converts the leaf to int. Returns (0, false) if
// missing or not numeric. Accepts json.Number, float64, and int.
func getInt(parsed map[string]any, path ...string) (int, bool) {
	v, ok := getAt(parsed, path)
	if !ok || v == nil {
		return 0, false
	}
	switch n := v.(type) {
	case json.Number:
		i, err := n.Int64()
		if err != nil {
			f, err := n.Float64()
			if err != nil {
				return 0, false
			}
			return int(f), true
		}
		return int(i), true
	case float64:
		return int(n), true
	case int:
		return n, true
	}
	return 0, false
}

func getNumber(parsed map[string]any, path ...string) (float64, bool) {
	v, ok := getAt(parsed, path)
	if !ok || v == nil {
		return 0, false
	}
	switch n := v.(type) {
	case json.Number:
		f, err := n.Float64()
		if err != nil {
			return 0, false
		}
		return f, true
	case float64:
		return n, true
	case int:
		return float64(n), true
	}
	return 0, false
}

func getStringSlice(parsed map[string]any, path ...string) []string {
	arr, ok := getArray(parsed, path...)
	if !ok {
		return nil
	}
	out := make([]string, 0, len(arr))
	for _, e := range arr {
		if s, ok := e.(string); ok {
			out = append(out, s)
		}
	}
	return out
}

func getArray(parsed map[string]any, path ...string) ([]any, bool) {
	v, ok := getAt(parsed, path)
	if !ok {
		return nil, false
	}
	arr, ok := v.([]any)
	return arr, ok
}

func getAt(parsed map[string]any, path []string) (any, bool) {
	cur := any(parsed)
	for _, key := range path {
		m, ok := cur.(map[string]any)
		if !ok {
			return nil, false
		}
		cur, ok = m[key]
		if !ok {
			return nil, false
		}
	}
	return cur, true
}

// strPtr returns nil when v is empty so optional fields land as SQL NULL.
func strPtr(v string) *string {
	if v == "" {
		return nil
	}
	return &v
}

func intPtr(v int) *int {
	if v == 0 {
		return nil
	}
	return &v
}

// intPtrOrNil takes (int, bool) — the (value, ok) pair returned by getInt —
// and returns *int that is nil when ok=false.
func intPtrOrNil(v int, ok bool) *int {
	if !ok {
		return nil
	}
	return &v
}

func floatPtr(v float64, ok bool) *float64 {
	if !ok {
		return nil
	}
	return &v
}
