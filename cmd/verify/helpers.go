package main

import (
	"encoding/json"
	"os"
)

func hwm(m map[string]any) int64 { return int64(num(m["contiguousHighWatermark"])) }

func num(v any) float64 {
	if f, ok := v.(float64); ok {
		return f
	}
	return -1
}

func asSlice(v any) []any {
	if s, ok := v.([]any); ok {
		return s
	}
	return nil
}

func errCode(m map[string]any) string {
	if e, ok := m["error"].(map[string]any); ok {
		if c, ok := e["code"].(string); ok {
			return c
		}
	}
	return ""
}

func errCodeAny(b []byte) string {
	var m map[string]any
	_ = json.Unmarshal(b, &m)
	return errCode(m)
}

func toJSON(v any) []byte { b, _ := json.Marshal(v); return b }

func mustJSON(b []byte, v any) {
	if err := json.Unmarshal(b, v); err != nil {
		panic(err)
	}
}

func envOr(k, d string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return d
}

func trimSlash(s string) string {
	for len(s) > 0 && s[len(s)-1] == '/' {
		s = s[:len(s)-1]
	}
	return s
}
