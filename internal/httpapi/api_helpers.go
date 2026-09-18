package httpapi

import (
	"encoding/json"
	"sort"

	"telemetry/internal/canonical"
	"telemetry/internal/store"
)

func sortStrings(keys []string) { sort.Strings(keys) }

// canonicalFromJSON parses JSON into canonical value types.
func canonicalFromJSON(raw []byte) (any, error) { return canonical.Parse(raw) }

// conflictsToAPI renders conflict projections for JSON responses.
func conflictsToAPI(cs []store.ConflictInfo) []map[string]any {
	out := make([]map[string]any, 0, len(cs))
	for _, c := range cs {
		out = append(out, conflictToAPI(c))
	}
	return out
}

func conflictToAPI(c store.ConflictInfo) map[string]any {
	m := map[string]any{
		"sequence": c.Sequence,
		"reason":   c.Reason,
		"status":   c.Status,
		"revision": c.Revision,
	}
	if c.Resolution != nil {
		m["resolution"] = *c.Resolution
	}
	if c.ChosenDigest != "" {
		m["chosenDigest"] = c.ChosenDigest
	}
	if len(c.Candidates) > 0 {
		cands := make([]map[string]any, 0, len(c.Candidates))
		for _, cand := range c.Candidates {
			cands = append(cands, map[string]any{
				"digest":     cand.Digest,
				"eventId":    cand.EventID,
				"keyVersion": cand.KeyVersion,
				"status":     cand.Status,
				"firstSeen":  cand.FirstSeen.UTC().Format("2006-01-02T15:04:05.999999999Z07:00"),
			})
		}
		m["candidates"] = cands
	}
	return m
}

func checkpointToAPI(c *store.Checkpoint) map[string]any {
	return map[string]any{
		"deviceId":    c.DeviceID,
		"sequence":    c.Sequence,
		"digest":      c.Digest,
		"generatedAt": c.Generated.UTC().Format("2006-01-02T15:04:05.999999999Z07:00"),
		"signature":   c.Signature,
	}
}

var _ = json.Marshal
