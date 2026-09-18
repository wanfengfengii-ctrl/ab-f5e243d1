// Command verify is the one-shot acceptance job for docker compose. It drives
// the whole service exclusively through the public HTTP API (the gateway by
// default) and exits non-zero on the first failed expectation.
package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"sync"
	"time"

	"telemetry/internal/envelope"
)

type verifier struct {
	base       string
	adminToken string
	runSuffix  string
	http       *http.Client
	failures   int
}

func main() {
	base := envOr("BASE_URL", "http://gateway:8080")
	token := os.Getenv("ADMIN_TOKEN")
	if token == "" {
		fmt.Fprintln(os.Stderr, "ADMIN_TOKEN is required")
		os.Exit(2)
	}
	v := &verifier{
		base:       trimSlash(base),
		adminToken: token,
		runSuffix:  strconv.FormatInt(time.Now().UnixNano(), 10),
		http:       &http.Client{Timeout: 45 * time.Second},
	}
	v.run(context.Background())
	if v.failures != 0 {
		fmt.Printf("\nVERIFY FAILED: %d expectation(s) failed\n", v.failures)
		os.Exit(1)
	}
	fmt.Println("\nVERIFY OK: all acceptance checks passed")
}

func (v *verifier) run(ctx context.Context) {
	v.check("healthz", func() {
		code, body := v.req(ctx, "GET", "/healthz", "", nil)
		v.expect(code == 200, "healthz status %d", code)
		v.expect(bytes.Contains(body, []byte(`"ok"`)), "healthz body %s", body)
	})
	v.check("readyz", func() {
		code, _ := v.req(ctx, "GET", "/readyz", "", nil)
		v.expect(code == 200, "readyz status %d", code)
	})

	suffix := strconv.FormatInt(time.Now().UnixNano(), 10)
	devA, devDiv, devRot := "verify-a-"+suffix, "verify-div-"+suffix, "verify-rot-"+suffix
	devCompact, devWait, devAdmin := "verify-compact-"+suffix, "verify-wait-"+suffix, "verify-admin-"+suffix
	devIdem, devOther := "verify-idem-"+suffix, "verify-other-"+suffix
	keyA, keyDiv, keyRot := genKey(), genKey(), genKey()
	keyCompact, keyWait, keyIdem := genKey(), genKey(), genKey()

	v.register(ctx, devA, keyA)
	v.register(ctx, devDiv, keyDiv)
	v.register(ctx, devRot, keyRot)
	v.register(ctx, devCompact, keyCompact)
	v.register(ctx, devWait, keyWait)
	v.register(ctx, devIdem, keyIdem)
	v.register(ctx, devOther, genKey())
	v.register(ctx, devAdmin, genKey())

	v.scenarioOrderedAndOutOfOrder(ctx, devA, keyA)
	v.scenarioPagination(ctx, devA, devOther)
	v.scenarioIdempotency(ctx, devIdem, keyIdem)
	v.scenarioDeterministicDivergence(ctx, devDiv, keyDiv)
	v.scenarioRotationBoundary(ctx, devRot, keyRot)
	v.scenarioCompaction(ctx, devCompact, keyCompact)
	v.scenarioWait(ctx, devWait, keyWait)
	v.scenarioAdminGuards(ctx, devAdmin)
}

func (v *verifier) scenarioOrderedAndOutOfOrder(ctx context.Context, dev string, k *deviceKey) {
	v.check("ingest: gap then backfill advances many", func() {
		events, _ := chain(k, dev, 6, 1)
		_, b := v.ingest(ctx, dev, "a1", events[0])
		v.expect(hwm(b) == 1, "hwm after seq1 = %v", b["contiguousHighWatermark"])
		_, b = v.ingest(ctx, dev, "a3", events[2])
		v.expect(hwm(b) == 1, "gap must hold watermark at 1: %v", b)
		_, b = v.ingest(ctx, dev, "a-rest", events[1], events[3], events[4], events[5])
		v.expect(hwm(b) == 6, "backfill must reach 6: %v", b["contiguousHighWatermark"])
		v.expect(len(asSlice(b["advancedSequences"])) == 5, "advanced=%v", b["advancedSequences"])
	})
}

func (v *verifier) scenarioPagination(ctx context.Context, dev, otherDev string) {
	v.check("pagination: fixed view, tampered and cross-device cursors", func() {
		var cursor, pageCursor string
		view := ""
		total := 0
		for page := 0; page < 10; page++ {
			path := "/api/v1/devices/" + dev + "/events?limit=2"
			if cursor != "" {
				path += "&cursor=" + url.QueryEscape(cursor)
			}
			code, body := v.req(ctx, "GET", path, "", nil)
			v.expect(code == 200, "events page %d: %d", page, code)
			var pg map[string]any
			mustJSON(body, &pg)
			if page == 0 {
				view, _ = pg["viewId"].(string)
				pageCursor, _ = pg["nextCursor"].(string)
				v.expect(num(pg["viewHighWatermark"]) == 6, "viewHighWatermark=%v", pg["viewHighWatermark"])
			} else {
				v.expect(pg["viewId"] == view, "view id changed across pages")
			}
			for _, ev := range asSlice(pg["events"]) {
				total++
				m := ev.(map[string]any)
				v.expect(num(m["sequence"]) == float64(total), "non-contiguous page order")
			}
			cursor, _ = pg["nextCursor"].(string)
			if cursor == "" {
				break
			}
		}
		v.expect(total == 6, "paged %d events, want 6", total)

		code, _ := v.req(ctx, "GET",
			"/api/v1/devices/"+dev+"/events?cursor="+url.QueryEscape(pageCursor+"AA"), "", nil)
		v.expect(code == http.StatusBadRequest, "tampered cursor status=%d", code)
		code, _ = v.req(ctx, "GET",
			"/api/v1/devices/"+otherDev+"/events?cursor="+url.QueryEscape(pageCursor), "", nil)
		v.expect(code == http.StatusBadRequest, "cross-device cursor status=%d", code)
	})
}

func (v *verifier) scenarioIdempotency(ctx context.Context, dev string, k *deviceKey) {
	v.check("ingest: requestId idempotency and signature rejection", func() {
		events, _ := chain(k, dev, 2, 100)
		code1, b1 := v.ingest(ctx, dev, "idem-"+dev, events[0], events[1])
		v.expect(code1 == 200, "first ingest %d", code1)
		code2, b2 := v.ingest(ctx, dev, "idem-"+dev, events[0], events[1])
		v.expect(code2 == 200 && string(toJSON(b2)) == string(toJSON(b1)),
			"retry response differs: %d vs %d", code1, code2)

		tampered := cloneEvent(events[1])
		raw, _ := base64.StdEncoding.DecodeString(tampered["signature"].(string))
		raw[0] ^= 1
		tampered["signature"] = base64.StdEncoding.EncodeToString(raw)
		code3, b3 := v.ingest(ctx, dev, "idem-bad-"+dev, tampered)
		v.expect(code3 == http.StatusUnprocessableEntity, "bad signature not rejected: %d", code3)
		v.expect(errCode(b3) == "bad_signature", "code=%v", b3)
	})
}

func (v *verifier) scenarioDeterministicDivergence(ctx context.Context, dev string, k *deviceKey) {
	v.check("conflicts: divergent candidates, adjudication, stale revisions", func() {
		_, digests := chain(k, dev, 4, 200)
		occ := time.Date(2026, 9, 19, 10, 0, 0, 0, time.UTC)
		candA := signed(k, dev, 3, "evt-3-a", digests[1], occ, 1, map[string]any{"v": "a"})
		candB := signed(k, dev, 3, "evt-3-b", digests[1], occ.Add(time.Second), 1, map[string]any{"v": "b"})

		c1, _ := v.ingest(ctx, dev, "div-a", candA)
		c2, _ := v.ingest(ctx, dev, "div-b", candB)
		v.expect(c1 == 200 && c2 == 200, "staging divergent candidates failed")

		events, _ := chain(k, dev, 2, 200)
		_, b := v.ingest(ctx, dev, "div-fill", events[0], events[1])
		v.expect(hwm(b) == 2, "watermark must stop at 2: %v", b["contiguousHighWatermark"])

		code, raw := v.req(ctx, "GET", "/api/v1/devices/"+dev+"/conflicts/3", "", nil)
		v.expect(code == 200, "conflict lookup %d", code)
		var cf struct {
			Conflict struct {
				Status     string `json:"status"`
				Reason     string `json:"reason"`
				Revision   int64  `json:"revision"`
				Candidates []any  `json:"candidates"`
			} `json:"conflict"`
		}
		mustJSON(raw, &cf)
		v.expect(cf.Conflict.Status == "open" && cf.Conflict.Reason == "divergent_candidates",
			"conflict state=%+v", cf.Conflict)
		v.expect(len(cf.Conflict.Candidates) == 2, "candidate count=%d", len(cf.Conflict.Candidates))

		rev := cf.Conflict.Revision
		code, bStale := v.adjudicate(ctx, dev, 3, "stale-"+dev, rev-1, "reject_all", "")
		v.expect(code == 409, "stale revision status=%d body=%s", code, bStale)

		code, bb := v.adjudicate(ctx, dev, 3, "choose-"+dev, rev, "choose_candidate",
			candB["_digest"].(string))
		v.expect(code == 200, "adjudicate choose: %d %s", code, bb)
		code2, bb2 := v.adjudicate(ctx, dev, 3, "choose-"+dev, rev, "choose_candidate",
			candB["_digest"].(string))
		v.expect(code2 == 200 && string(bb2) == string(bb),
			"adjudication not idempotent: %d", code2)

		ev4 := signed(k, dev, 4, "evt-4", candB["_digest"].(string),
			occ.Add(2*time.Second), 1, map[string]any{"v": 4})
		_, b4 := v.ingest(ctx, dev, "div-4", ev4)
		v.expect(hwm(b4) == 4, "hwm after adjudication+backfill = %v", b4["contiguousHighWatermark"])
	})
}

func (v *verifier) scenarioRotationBoundary(ctx context.Context, dev string, k1 *deviceKey) {
	v.check("key rotation: generation boundary and revision guards", func() {
		k2 := genKey()
		events, digests := chain(k1, dev, 3, 300)
		v.ingest(ctx, dev, "rot-123", events[0], events[1], events[2])

		code, body := v.rotate(ctx, dev, "rot-cmd", 2, k2.pubB64(), 5, 0)
		v.expect(code == 200, "rotation failed: %d %s", code, body)
		code, body = v.rotate(ctx, dev, "rot-cmd", 2, k2.pubB64(), 5, 0)
		v.expect(code == 200, "rotation replay failed: %d", code)
		code, body = v.rotate(ctx, dev, "rot-other", 3, k2.pubB64(), 6, 0)
		v.expect(code == 409 && errCodeAny(body) == "control_revision_stale",
			"stale revision not rejected: %d %s", code, body)
		code, body = v.rotate(ctx, dev, "rot-dup", 2, k2.pubB64(), 6, 1)
		v.expect(code == 409, "duplicate version status=%d", code)

		ev4 := signed(k1, dev, 4, "evt-4", digests[2],
			time.Date(2026, 9, 19, 11, 0, 0, 0, time.UTC), 1, map[string]any{"n": 4})
		_, b := v.ingest(ctx, dev, "rot-seq4", ev4)
		v.expect(hwm(b) == 4, "old-key seq4 hwm=%v", b["contiguousHighWatermark"])

		old5 := signed(k1, dev, 5, "evt-5-old", ev4["_digest"].(string),
			time.Date(2026, 9, 19, 11, 0, 1, 0, time.UTC), 1, map[string]any{"n": 5})
		code, b2 := v.ingest(ctx, dev, "rot-seq5-old", old5)
		v.expect(code == 422 && errCode(b2) == "key_generation_mismatch",
			"old key after boundary: %d %v", code, b2)

		new5 := signed(k2, dev, 5, "evt-5-new", ev4["_digest"].(string),
			time.Date(2026, 9, 19, 11, 0, 2, 0, time.UTC), 2, map[string]any{"n": 5})
		code, b3 := v.ingest(ctx, dev, "rot-seq5-new", new5)
		v.expect(code == 200 && hwm(b3) == 5, "new key seq5: %d %v", code, b3)
	})
}

func (v *verifier) scenarioCompaction(ctx context.Context, dev string, k *deviceKey) {
	v.check("compaction: signed checkpoint, resume point, no unreadable gap", func() {
		events, digests := chain(k, dev, 10, 400)
		v.ingest(ctx, dev, "compact-ten", events...)

		code, body := v.adminJSON(ctx, "POST",
			"/api/v1/devices/"+dev+"/compaction/run",
			map[string]any{"keepRecent": 2, "minEventAgeSeconds": 0})
		v.expect(code == 200, "compaction run: %d %s", code, body)
		var run map[string]any
		mustJSON(body, &run)
		v.expect(num(run["checkpointSequence"]) == 8, "checkpoint seq=%v", run["checkpointSequence"])
		v.expect(run["checkpointDigest"] == digests[7], "checkpoint digest mismatch")

		code, raw := v.req(ctx, "GET", "/api/v1/devices/"+dev+"/checkpoint", "", nil)
		v.expect(code == 200, "checkpoint GET %d", code)
		var cpResp struct {
			Checkpoint struct {
				Sequence int64  `json:"sequence"`
				Digest   string `json:"digest"`
			} `json:"checkpoint"`
		}
		mustJSON(raw, &cpResp)
		v.expect(cpResp.Checkpoint.Sequence == 8, "checkpoint payload seq=%d", cpResp.Checkpoint.Sequence)

		code, body = v.req(ctx, "GET",
			"/api/v1/devices/"+dev+"/events?startAfterSequence=8&limit=10", "", nil)
		v.expect(code == 200, "resume read %d", code)
		var pg struct {
			Events []struct {
				Sequence float64 `json:"sequence"`
				Digest   string  `json:"digest"`
			} `json:"events"`
		}
		mustJSON(body, &pg)
		v.expect(len(pg.Events) == 2, "resumed events=%d", len(pg.Events))
		if len(pg.Events) == 2 {
			v.expect(pg.Events[0].Sequence == 9 && pg.Events[1].Sequence == 10,
				"resume order %f %f", pg.Events[0].Sequence, pg.Events[1].Sequence)
			v.expect(pg.Events[1].Digest == digests[9], "last digest mismatch")
		}
	})
}

func (v *verifier) scenarioWait(ctx context.Context, dev string, k *deviceKey) {
	v.check("wait: empty timeout and no-lost-notification delivery", func() {
		events, digests := chain(k, dev, 2, 500)
		v.ingest(ctx, dev, "wait-12", events[0], events[1])

		code, body := v.req(ctx, "GET",
			"/api/v1/devices/"+dev+"/wait?afterSequence=2&timeoutSeconds=1", "", nil)
		v.expect(code == 200, "wait timeout %d", code)
		var wb map[string]any
		mustJSON(body, &wb)
		v.expect(wb["timedOut"] == true && len(asSlice(wb["events"])) == 0,
			"timeout body=%v", wb)

		var wg sync.WaitGroup
		wg.Add(1)
		got := 0
		go func() {
			defer wg.Done()
			c, raw := v.req(ctx, "GET",
				"/api/v1/devices/"+dev+"/wait?afterSequence=2&timeoutSeconds=15", "", nil)
			if c != 200 {
				return
			}
			var r struct {
				Events   []json.RawMessage `json:"events"`
				TimedOut bool              `json:"timedOut"`
			}
			_ = json.Unmarshal(raw, &r)
			if !r.TimedOut && len(r.Events) >= 1 {
				got = len(r.Events)
			}
		}()
		time.Sleep(500 * time.Millisecond)
		ev3 := signed(k, dev, 3, "evt-3", digests[1],
			time.Date(2026, 9, 19, 12, 0, 0, 0, time.UTC), 1, map[string]any{"n": 3})
		c, b := v.ingest(ctx, dev, "wait-3", ev3)
		v.expect(c == 200 && hwm(b) == 3, "post-wait ingest: %d", c)
		wg.Wait()
		v.expect(got >= 1, "waiter missed the notification")
	})
}

func (v *verifier) scenarioAdminGuards(ctx context.Context, dev string) {
	v.check("admin endpoints require bearer token", func() {
		code, _ := v.reqJSON(ctx, "POST", "/api/v1/devices/"+dev+"/keys", map[string]any{
			"commandId": "x", "keyVersion": 2, "publicKey": genKey().pubB64(),
			"effectiveSequence": 2, "expectedControlRevision": 0,
		})
		v.expect(code == 401, "unauthenticated rotation status=%d", code)
	})
}

// --- plumbing --------------------------------------------------------------

func (v *verifier) register(ctx context.Context, dev string, k *deviceKey) {
	code, body := v.reqJSON(ctx, "POST", "/api/v1/devices", map[string]any{
		"deviceId": dev, "publicKey": k.pubB64(),
	})
	if code != http.StatusCreated {
		v.fail("register %s: %d %s", dev, code, body)
	}
}

func (v *verifier) ingest(ctx context.Context, dev, requestID string, events ...map[string]any) (int, map[string]any) {
	wire := make([]map[string]any, len(events))
	for i, e := range events {
		wire[i] = stripDigest(e)
	}
	code, raw := v.reqJSON(ctx, "POST", "/api/v1/devices/"+dev+"/ingest",
		map[string]any{"requestId": requestID + "-" + v.runSuffix, "events": wire})
	var m map[string]any
	_ = json.Unmarshal(raw, &m)
	return code, m
}

func (v *verifier) adjudicate(ctx context.Context, dev string, seq int64, commandID string,
	rev int64, decision, digest string) (int, []byte) {
	return v.adminJSON(ctx, "POST",
		fmt.Sprintf("/api/v1/devices/%s/conflicts/%d/adjudicate", dev, seq),
		map[string]any{
			"commandId": commandID + "-" + v.runSuffix, "expectedConflictRevision": rev,
			"decision": decision, "candidateDigest": digest,
		})
}

func (v *verifier) rotate(ctx context.Context, dev, commandID string, version int,
	pubB64 string, effective, expectedRev int64) (int, []byte) {
	return v.adminJSON(ctx, "POST", "/api/v1/devices/"+dev+"/keys", map[string]any{
		"commandId": commandID + "-" + v.runSuffix, "keyVersion": version, "publicKey": pubB64,
		"effectiveSequence": effective, "expectedControlRevision": expectedRev,
	})
}

func (v *verifier) reqJSON(ctx context.Context, method, path string, payload any) (int, []byte) {
	return v.req(ctx, method, path, "", payload)
}

func (v *verifier) adminJSON(ctx context.Context, method, path string, payload any) (int, []byte) {
	return v.req(ctx, method, path, v.adminToken, payload)
}

func (v *verifier) req(ctx context.Context, method, path, token string, payload any) (int, []byte) {
	var rdr io.Reader
	if payload != nil {
		raw, _ := json.Marshal(payload)
		rdr = bytes.NewReader(raw)
	}
	req, err := http.NewRequestWithContext(ctx, method, v.base+path, rdr)
	if err != nil {
		v.fail("request build: %v", err)
		return 0, nil
	}
	if payload != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	resp, err := v.http.Do(req)
	if err != nil {
		v.fail("%s %s: %v", method, path, err)
		return 0, nil
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, body
}

func (v *verifier) check(name string, fn func()) {
	fmt.Printf("==> %s ... ", name)
	before := v.failures
	fn()
	if v.failures != before {
		fmt.Println("FAIL")
	} else {
		fmt.Println("ok")
	}
}

func (v *verifier) expect(cond bool, format string, args ...any) {
	if !cond {
		v.fail(format, args...)
	}
}

func (v *verifier) fail(format string, args ...any) {
	v.failures++
	fmt.Printf("\n    FAIL: "+format+"\n", args...)
}

// device key helpers

type deviceKey struct {
	priv ed25519.PrivateKey
	pub  ed25519.PublicKey
}

func genKey() *deviceKey {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		panic(err)
	}
	return &deviceKey{priv: priv, pub: pub}
}

func (k *deviceKey) pubB64() string { return base64.StdEncoding.EncodeToString(k.pub) }

func chain(k *deviceKey, dev string, n, base int) ([]map[string]any, []string) {
	occ := time.Date(2026, 9, 19, 8, 0, 0, 0, time.UTC)
	events := make([]map[string]any, n)
	digests := make([]string, n)
	prev := envelope.GenesisDigest
	for i := 1; i <= n; i++ {
		ev := signed(k, dev, int64(i), fmt.Sprintf("evt-%d-%d", base, i), prev,
			occ.Add(time.Duration(base+i)*time.Second), 1, map[string]any{"i": base + i})
		events[i-1] = ev
		digests[i-1] = ev["_digest"].(string)
		prev = digests[i-1]
	}
	return events, digests
}

func signed(k *deviceKey, dev string, seq int64, eventID, prev string,
	occ time.Time, keyVersion int, payload any) map[string]any {
	payloadRaw, _ := json.Marshal(payload)
	pc, err := envelope.CanonicalPayload(payloadRaw)
	if err != nil {
		panic(err)
	}
	ev := &envelope.Event{
		DeviceID: dev, Sequence: seq, EventID: eventID, OccurredAt: occ.UTC(),
		KeyVersion: keyVersion, PrevDigest: prev, Payload: payloadRaw,
	}
	dg, err := envelope.ComputeDigest(ev, pc)
	if err != nil {
		panic(err)
	}
	sig, err := envelope.Sign(k.priv, ev, pc)
	if err != nil {
		panic(err)
	}
	var pj any
	_ = json.Unmarshal(pc, &pj)
	return map[string]any{
		"deviceId": dev, "sequence": seq, "eventId": eventID,
		"occurredAt": occ.UTC().Format(time.RFC3339Nano), "keyVersion": keyVersion,
		"prevDigest": prev, "payload": pj, "signature": sig, "_digest": dg.String(),
	}
}

func stripDigest(in map[string]any) map[string]any {
	out := map[string]any{}
	for k, val := range in {
		if k != "_digest" {
			out[k] = val
		}
	}
	return out
}

func cloneEvent(in map[string]any) map[string]any { return stripDigest(stripDigest(in)) }
