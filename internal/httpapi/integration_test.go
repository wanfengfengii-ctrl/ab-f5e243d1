package httpapi_test

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"sync"
	"testing"
	"time"

	"telemetry/internal/envelope"
	"telemetry/internal/serverkey"
	"telemetry/internal/store"
)

func payloadFor(seq int) any {
	return map[string]any{"seq": seq, "ok": true, "temp": 20.5}
}

// 1) Out-of-order delivery, multi-event advancement, fixed-view pagination,
// cursor tampering and cross-device cursor rejection.
func TestOutOfOrderAndPagination(t *testing.T) {
	e := newEnv(t)
	d := e.uniqueDevice("ooo")
	k := genDeviceKey()
	e.register(d, k)

	events, digests := buildChain(k, d, 7, payloadFor)

	// Deliver 1, then 3, then 2..7 (gap fill advances many at once).
	code, b := e.ingest(d, "r1", events[0])
	mustOK(t, code, b)
	if hwmOf(b) != 1 {
		t.Fatalf("hwm after seq1 = %v", b["contiguousHighWatermark"])
	}
	code, b = e.ingest(d, "r3", events[2])
	mustOK(t, code, b)
	if hwmOf(b) != 1 {
		t.Fatal("gap must not advance watermark")
	}
	code, b = e.ingest(d, "rb", events[1], events[3], events[4], events[5], events[6])
	mustOK(t, code, b)
	if hwmOf(b) != 7 {
		t.Fatalf("gap fill should reach 7, got %v", b["contiguousHighWatermark"])
	}
	if len(advanceSeqs(b)) != 6 {
		t.Fatalf("advanced sequences = %v", b["advancedSequences"])
	}

	// Fixed-view pagination: page size is 3 in tests; new commits must not
	// bleed into the view.
	var all []map[string]any
	var cursor string
	viewID := ""
	for page := 0; page < 5; page++ {
		path := "/api/v1/devices/" + d + "/events?limit=3"
		if cursor != "" {
			path += "&cursor=" + url.QueryEscape(cursor)
		}
		code, body := e.do("GET", path, "", nil)
		if code != http.StatusOK {
			t.Fatalf("events page %d: %d %s", page, code, body)
		}
		var pg map[string]any
		_ = json.Unmarshal(body, &pg)
		if page == 0 {
			viewID = pg["viewId"].(string)
			if vhwm := pg["viewHighWatermark"].(float64); vhwm != 7 {
				t.Fatalf("viewHighWatermark=%v want 7", vhwm)
			}
		} else if pg["viewId"].(string) != viewID {
			t.Fatal("view id changed across pages")
		}
		for _, ev := range pg["events"].([]any) {
			all = append(all, ev.(map[string]any))
		}
		next, _ := pg["nextCursor"].(string)
		cursor = next
		if cursor == "" {
			break
		}
	}
	if len(all) != 7 {
		t.Fatalf("paged %d events, want 7", len(all))
	}
	for i, ev := range all {
		if int64(ev["sequence"].(float64)) != int64(i+1) {
			t.Fatalf("page sequence order wrong at %d: %v", i, ev["sequence"])
		}
		if ev["digest"].(string) != digests[i] {
			t.Fatalf("digest mismatch at %d", i+1)
		}
	}

	// Tampered cursor rejected.
	if code, _ := e.do("GET",
		"/api/v1/devices/"+d+"/events?cursor="+url.QueryEscape(cursor+"x"), "", nil); code != http.StatusBadRequest {
		t.Fatalf("tampered cursor status=%d want 400", code)
	}
	// Cursor is bound to its device: reuse d's page cursor against another
	// registered device and expect rejection.
	d2 := e.uniqueDevice("ooo-other")
	e.register(d2, k)
	_, firstBody := e.do("GET", "/api/v1/devices/"+d+"/events?limit=2", "", nil)
	var fb map[string]any
	_ = json.Unmarshal(firstBody, &fb)
	tok := fb["nextCursor"].(string)
	if code, _ := e.do("GET",
		"/api/v1/devices/"+d2+"/events?cursor="+url.QueryEscape(tok), "", nil); code != http.StatusBadRequest {
		t.Fatalf("cross-device cursor status=%d want 400", code)
	}
}

func advanceSeqs(b map[string]any) []any {
	if v, ok := b["advancedSequences"].([]any); ok {
		return v
	}
	return nil
}

// 2) Idempotent ingest and the requestId content conflict.
func TestIngestIdempotency(t *testing.T) {
	e := newEnv(t)
	d := e.uniqueDevice("idem")
	k := genDeviceKey()
	e.register(d, k)
	events, _ := buildChain(k, d, 2, payloadFor)

	code1, body1 := e.ingest(d, "fixed-req-id", events[0], events[1])
	mustOK(t, code1, body1)
	code2, body2 := e.ingest(d, "fixed-req-id", events[0], events[1])
	mustOK(t, code2, body2)
	if string(mustJSON(body1)) != string(mustJSON(body2)) {
		t.Fatalf("idempotent responses differ:\n%s\n%s", body1, body2)
	}
	if hwmOf(body2) != 2 {
		t.Fatal("retry changed state")
	}
	// Same requestId, different canonical content -> stable 409.
	other, _ := buildChain(k, d, 1, func(seq int) any { return map[string]any{"different": true} })
	other[0]["eventId"] = "evt-x" // different event content but sequence 1 already sealed ->
	// requestId mismatch is detected before sealing rules:
	code3, body3 := e.ingest(d, "fixed-req-id", other[0])
	if code3 != http.StatusConflict {
		t.Fatalf("content mismatch status=%d want 409 body=%v", code3, body3)
	}
	if errCode(body3) != "idempotency_content_mismatch" {
		t.Fatalf("code=%v", body3)
	}
	// Stable on repeat.
	code4, body4 := e.ingest(d, "fixed-req-id", other[0])
	if code4 != http.StatusConflict || errCode(body4) != "idempotency_content_mismatch" {
		t.Fatal("conflict must be stable across retries")
	}
}

// 3) A batch containing one invalid event leaves nothing behind; the failure
// is itself replayable under the same requestId.
func TestBatchAtomicity(t *testing.T) {
	e := newEnv(t)
	d := e.uniqueDevice("atom")
	k := genDeviceKey()
	e.register(d, k)
	events, _ := buildChain(k, d, 3, payloadFor)

	bad := cloneEvent(events[1])
	{
		// Flip a byte in the otherwise valid 64-byte Ed25519 signature.
		raw, _ := base64.StdEncoding.DecodeString(bad["signature"].(string))
		raw[0] ^= 0xFF
		bad["signature"] = base64.StdEncoding.EncodeToString(raw)
	}
	code, body := e.ingest(d, "atomic-batch", events[0], bad, events[2])
	if code != http.StatusUnprocessableEntity {
		t.Fatalf("bad signature status=%d body=%v want 422", code, body)
	}
	// Nothing visible and nothing staged: a corrected batch starts cleanly.
	st, _ := e.status(d)
	if st["contiguousHighWatermark"].(float64) != 0 {
		t.Fatalf("partial data survived failed batch: %v", st)
	}
	// Replaying the identical failed request returns the same terminal error.
	code2, body2 := e.ingest(d, "atomic-batch", events[0], bad, events[2])
	if code2 != code || errCode(body2) != errCode(body) {
		t.Fatal("failed batch must be idempotently replayed")
	}
	// Fixed batch under a new requestId succeeds fully.
	code3, body3 := e.ingest(d, "atomic-good", events[0], events[1], events[2])
	mustOK(t, code3, body3)
	if hwmOf(body3) != 3 {
		t.Fatalf("hwm=%v", body3["contiguousHighWatermark"])
	}
}

// 4) Divergent candidates block, adjudication picks one and advances;
// reject-all followed by re-upload also recovers.
func TestDivergentConflictAndAdjudication(t *testing.T) {
	e := newEnv(t)
	d := e.uniqueDevice("div")
	k := genDeviceKey()
	e.register(d, k)
	events, digests := buildChain(k, d, 4, payloadFor)

	e.ingest(d, "d1", events[0]) // hwm 1

	// Two different seq-2 candidates must arrive concurrently so neither is
	// alone at the frontier; the staging barrier makes the divergence
	// deterministic.
	candA := events[1]
	occ := time.Date(2026, 9, 18, 9, 0, 0, 0, time.UTC)
	candB := signedEvent(k, d, 2, "evt-2-alt", digests[0], occ, 1,
		map[string]any{"alt": true})
	results := e.concurrentStage(d, []func() (int, map[string]any){
		func() (int, map[string]any) { return e.ingest(d, "d2a", candA) },
		func() (int, map[string]any) { return e.ingest(d, "d2b", candB) },
	})
	for _, r := range results {
		if r.code != http.StatusOK {
			t.Fatalf("concurrent divergent upload: %d %v", r.code, r.body)
		}
	}

	stNow, _ := e.status(d)
	if int64(stNow["contiguousHighWatermark"].(float64)) != 1 {
		t.Fatal("watermark must stop before divergent seq2")
	}
	var raw []byte
	code, raw := e.do("GET", "/api/v1/devices/"+d+"/conflicts/2", "", nil)
	if code != http.StatusOK {
		t.Fatalf("get conflict: %d %s", code, raw)
	}
	var cf map[string]any
	_ = json.Unmarshal(raw, &cf)
	cands := cf["conflict"].(map[string]any)["candidates"].([]any)
	if len(cands) != 2 {
		t.Fatalf("candidates=%d", len(cands))
	}

	st, _ := e.status(d)
	revBefore := int64(st["conflictRevision"].(float64))

	// Stale revision rejected.
	code, staleBody := e.adjudicate(d, 2, "cmd-stale-"+d, revBefore-1, "choose_candidate", digests[1])
	if code != http.StatusConflict {
		t.Fatalf("stale revision status=%d body=%v", code, staleBody)
	}

	// Choose B (the alternative) by digest.
	code, body := e.adjudicate(d, 2, "cmd-choose-"+d, revBefore, "choose_candidate", digestOf(candB))
	mustOK(t, code, body)
	if got := body["chosenDigest"]; got != digestOf(candB) {
		t.Fatalf("chosen=%v", got)
	}
	if hwmOf(body) != 2 || len(body["advancedSequences"].([]any)) != 1 {
		// seq1 already exists and B chains correctly, so seq2 accepts; seq3/4
		// are still missing.
		t.Fatalf("hwm after choosing chained seq2 = %v advanced=%v",
			hwmOf(body), body["advancedSequences"])
	}
	// Idempotent adjudication replay.
	code2, body2 := e.adjudicate(d, 2, "cmd-choose-"+d, revBefore, "choose_candidate", digestOf(candB))
	if code2 != http.StatusOK || string(mustJSON(body2)) != string(mustJSON(body)) {
		t.Fatalf("adjudication replay differs: %d %v vs %v", code2, body2, body)
	}

	// Now deliver 3 and 4 chained from B's digest.
	occ3 := time.Date(2026, 9, 18, 9, 1, 0, 0, time.UTC)
	ev3 := signedEvent(k, d, 3, "evt-3", digestOf(candB), occ3, 1, payloadFor(3))
	dig3 := digestOf(ev3)
	ev4 := signedEvent(k, d, 4, "evt-4", dig3, occ3.Add(time.Second), 1, payloadFor(4))
	code, b34 := e.ingest(d, "d34", ev3, ev4)
	mustOK(t, code, b34)
	if hwmOf(b34) != 4 {
		t.Fatalf("hwm after filling chain = %v", hwmOf(b34))
	}

	// Reject-all path on a fresh device.
	d2 := e.uniqueDevice("divrej")
	e.register(d2, k)
	evs2, dgs2 := buildChain(k, d2, 2, payloadFor)
	alt := signedEvent(k, d2, 2, "alt-2", dgs2[0],
		time.Date(2026, 9, 18, 10, 0, 0, 0, time.UTC), 1, map[string]any{"x": 1})
	e.ingest(d2, "j1", evs2[0])
	rs := e.concurrentStage(d2, []func() (int, map[string]any){
		func() (int, map[string]any) { return e.ingest(d2, "j2a", evs2[1]) },
		func() (int, map[string]any) { return e.ingest(d2, "j2b", alt) },
	})
	for _, r := range rs {
		if r.code != http.StatusOK {
			t.Fatalf("reject-path concurrent upload: %d %v", r.code, r.body)
		}
	}
	st2, _ := e.status(d2)
	rev2 := int64(st2["conflictRevision"].(float64))
	code, br := e.adjudicate(d2, 2, "reject-"+d2, rev2, "reject_all", "")
	mustOK(t, code, br)
	// Re-upload the canonical seq2: rejected identical candidate is revived.
	code, br = e.ingest(d2, "j2again", evs2[1])
	mustOK(t, code, br)
	if hwmOf(br) != 2 {
		t.Fatalf("hwm after reject-all + reupload = %v", hwmOf(br))
	}
}

// 5) Wrong predecessor is a blocking conflict; choosing it cannot bypass hash
// chain verification; uploading the correct candidate resolves everything.
func TestWrongPredecessorConflict(t *testing.T) {
	e := newEnv(t)
	d := e.uniqueDevice("wrongprev")
	k := genDeviceKey()
	e.register(d, k)
	events, digests := buildChain(k, d, 3, payloadFor)

	e.ingest(d, "w1", events[0]) // hwm1

	// seq2 with prevDigest = genesis instead of digest(seq1).
	occ := time.Date(2026, 9, 18, 11, 0, 0, 0, time.UTC)
	wrong := signedEvent(k, d, 2, "evt-2-wrong", envelope.GenesisDigest, occ, 1, payloadFor(2))
	code, b := e.ingest(d, "w2-wrong", wrong)
	mustOK(t, code, b)
	if hwmOf(b) != 1 || len(b["conflicts"].([]any)) != 1 {
		t.Fatalf("wrong predecessor must block: %v", b)
	}
	if b["conflicts"].([]any)[0].(map[string]any)["reason"] != "wrong_predecessor" {
		t.Fatalf("reason=%v", b["conflicts"])
	}

	st, _ := e.status(d)
	rev := int64(st["conflictRevision"].(float64))
	// Adjudicating the invalid candidate cannot make it visible: the conflict
	// reopens with wrong_predecessor during advancement.
	code, b = e.adjudicate(d, 2, "pickwrong-"+d, rev, "choose_candidate", digestOf(wrong))
	mustOK(t, code, b)
	if b["reopenedAs"] != "wrong_predecessor" || hwmOf(b) != 1 {
		t.Fatalf("invalid predecessor became visible: %v", b)
	}

	// Uploading the correct seq2 creates a divergent conflict; choose it.
	code, b = e.ingest(d, "w2-right", events[1])
	mustOK(t, code, b)
	st2, _ := e.status(d)
	rev2 := int64(st2["conflictRevision"].(float64))
	code, b = e.adjudicate(d, 2, "pickright-"+d, rev2, "choose_candidate", digests[1])
	mustOK(t, code, b)

	// seq3 completes the chain.
	code, b = e.ingest(d, "w3", events[2])
	mustOK(t, code, b)
	if hwmOf(b) != 3 {
		t.Fatalf("hwm=%v want 3", hwmOf(b))
	}
}

// 6) Key rotation boundaries, out-of-order old-key events, stale revisions and
// command idempotency.
func TestKeyRotation(t *testing.T) {
	e := newEnv(t)
	d := e.uniqueDevice("rotate")
	k1 := genDeviceKey()
	k2 := genDeviceKey()
	e.register(d, k1)
	events, digests := buildChain(k1, d, 6, payloadFor)
	e.ingest(d, "k123", events[0], events[1], events[2]) // hwm3, revision0

	// Staged seq5 (signed k1, chained from seq4) must block a rotation whose
	// new range would include it.
	occ := time.Date(2026, 9, 18, 12, 0, 0, 0, time.UTC)
	staged5 := signedEvent(k1, d, 5, "evt-5-early", digests[3], occ, 1, map[string]any{"early": true})
	code, b := e.ingest(d, "early5", staged5)
	mustOK(t, code, b)
	if hwmOf(b) != 3 {
		t.Fatal("seq5 with missing seq4 must stay staged")
	}

	// Rotation at 5 rejected: boundary occupied.
	code, body := e.rotate(d, "rot5-"+d, 2, k2.pubB64(), 5, 0)
	if code != http.StatusConflict || errCode(body) != "rotation_boundary_occupied" {
		t.Fatalf("boundary occupied: %d %v", code, body)
	}
	// Rotation at 6 accepted (seq5 remains in the old generation's range).
	code, body = e.rotate(d, "rot6-"+d, 2, k2.pubB64(), 6, 0)
	if code != http.StatusOK {
		t.Fatalf("rotate at 6: %d %v", code, body)
	}
	// Replay is idempotent and does not bump revision again.
	code2, body2 := e.rotate(d, "rot6-"+d, 2, k2.pubB64(), 6, 0)
	if code2 != http.StatusOK || body2["controlRevision"] != body["controlRevision"] {
		t.Fatalf("rotation replay: %d %v", code2, body2)
	}
	// Same commandId, different content -> conflict.
	code3, body3 := e.rotate(d, "rot6-"+d, 3, k2.pubB64(), 7, 0)
	if code3 != http.StatusConflict || errCode(body3) != "command_content_mismatch" {
		t.Fatalf("rotation command reuse: %d %v", code3, body3)
	}
	// Stale revision now (revision is 1).
	code4, body4 := e.rotate(d, "rot7-"+d, 3, k2.pubB64(), 7, 0)
	if code4 != http.StatusConflict || errCode(body4) != "control_revision_stale" {
		t.Fatalf("stale rotation: %d %v", code4, body4)
	}
	// Duplicate key version at current revision.
	code5, body5 := e.rotate(d, "rotdup-"+d, 2, k2.pubB64(), 7, 1)
	if code5 != http.StatusConflict || errCode(body5) != "duplicate_key_version" {
		t.Fatalf("duplicate version: %d %v", code5, body5)
	}

	// Out-of-order delivery: canonical seq4 (same content staged5 chains to)
	// must still validate under k1 and promote 4..5.
	code, b = e.ingest(d, "seq4-oldkey", events[3])
	mustOK(t, code, b)
	if hwmOf(b) != 5 {
		t.Fatalf("old-key seq4/5 chain hwm=%v want 5", hwmOf(b))
	}

	// seq6 signed by the OLD key must be rejected.
	dig5 := digestOf(staged5)
	old6 := signedEvent(k1, d, 6, "evt-6-old", dig5,
		occ.Add(2*time.Second), 1, map[string]any{"old": 1})
	code, b = e.ingest(d, "seq6-oldkey", old6)
	if code != http.StatusUnprocessableEntity || errCode(b) != "key_generation_mismatch" {
		t.Fatalf("old key after boundary: %d %v", code, b)
	}
	// Same event signed by the NEW key succeeds.
	new6 := signedEvent(k2, d, 6, "evt-6-new", dig5,
		occ.Add(2*time.Second), 2, map[string]any{"new": 1})
	code, b = e.ingest(d, "seq6-newkey", new6)
	mustOK(t, code, b)
	if hwmOf(b) != 6 {
		t.Fatalf("new key hwm=%v want 6", hwmOf(b))
	}
}

// 7) Wait: blocking notification with no lost-wakeup race, and timeout.
func TestWaitForEvents(t *testing.T) {
	e := newEnv(t)
	d := e.uniqueDevice("wait")
	k := genDeviceKey()
	e.register(d, k)
	events, _ := buildChain(k, d, 3, payloadFor)
	e.ingest(d, "w123", events[0], events[1], events[2])

	// Timeout with no new events.
	code, body := e.do("GET",
		"/api/v1/devices/"+d+"/wait?afterSequence=3&timeoutSeconds=1", "", nil)
	if code != http.StatusOK {
		t.Fatalf("wait timeout status=%d", code)
	}
	var wb map[string]any
	_ = json.Unmarshal(body, &wb)
	if wb["timedOut"] != true || len(wb["events"].([]any)) != 0 {
		t.Fatalf("expected empty timeout: %v", wb)
	}

	// Wait then publish concurrently; LISTEN-before-read guarantees delivery.
	type wres struct {
		code int
		body map[string]any
	}
	resCh := make(chan wres, 1)
	go func() {
		c, raw := e.do("GET",
			"/api/v1/devices/"+d+"/wait?afterSequence=3&timeoutSeconds=8", "", nil)
		var m map[string]any
		_ = json.Unmarshal(raw, &m)
		resCh <- wres{c, m}
	}()
	time.Sleep(400 * time.Millisecond) // let the waiter register LISTEN
	occ := time.Date(2026, 9, 18, 13, 0, 0, 0, time.UTC)
	prev := digestOf(events[2])
	ev4 := signedEvent(k, d, 4, "evt-wait-4", prev, occ, 1, map[string]any{"n": 4})
	c4, b4 := e.ingest(d, "w4", ev4)
	mustOK(t, c4, b4)

	select {
	case r := <-resCh:
		if r.code != http.StatusOK || r.body["timedOut"] == true {
			t.Fatalf("wait result=%v", r)
		}
		if len(r.body["events"].([]any)) != 1 {
			t.Fatalf("wait events=%v", r.body["events"])
		}
	case <-time.After(10 * time.Second):
		t.Fatal("wait was not notified after ingest")
	}
}

// 8) Compaction produces a verifiable checkpoint, stale cursors get 410 with a
// recovery point, and active views pin the events they still need.
func TestCompactionCheckpointsAndViews(t *testing.T) {
	e := newEnv(t)
	d := e.uniqueDevice("compact")
	k := genDeviceKey()
	e.register(d, k)
	events, digests := buildChain(k, d, 10, payloadFor)
	e.ingest(d, "ten", events...)

	// Open a view and page to position 3.
	_, raw := e.do("GET", "/api/v1/devices/"+d+"/events?limit=3", "", nil)
	var pg map[string]any
	_ = json.Unmarshal(raw, &pg)
	cursorAt3 := pg["nextCursor"].(string)

	// Compaction must respect the active view's floor (3): cutoff == 3.
	res, err := e.st.CompactDevice(testCtx(t), d, store.CompactionPolicy{
		KeepRecent: 0, MinEventAge: 0,
	}, signCheckpoint(e.skey))
	if err != nil {
		t.Fatal(err)
	}
	if !res.Compacted || res.CutoffSequence != 3 {
		t.Fatalf("view-floored compaction=%+v", res)
	}

	// The cursor at 3 still reads 4..6; this moves the view floor to 6.
	code, body := e.do("GET",
		"/api/v1/devices/"+d+"/events?limit=3&cursor="+url.QueryEscape(cursorAt3), "", nil)
	if code != http.StatusOK {
		t.Fatalf("paged after view-safe compaction: %d %s", code, body)
	}

	// Next compaction: desired cutoff hwm-2 = 8, but the active view floor is
	// 6, so the checkpoint stops at 6.
	res, err = e.st.CompactDevice(testCtx(t), d, store.CompactionPolicy{
		KeepRecent: 2, MinEventAge: 0,
	}, signCheckpoint(e.skey))
	if err != nil {
		t.Fatal(err)
	}
	if !res.Compacted || res.CutoffSequence != 6 {
		t.Fatalf("compaction=%+v want cutoff 6", res)
	}
	if res.CutoffDigest != digests[5] {
		t.Fatal("checkpoint digest does not match the real contiguous prefix")
	}

	// Checkpoint is signed and verifies against the server public key.
	cp, err := e.st.GetCheckpoint(testCtx(t), d)
	if err != nil {
		t.Fatal(err)
	}
	doc := store.CheckpointDoc{
		DeviceID: cp.DeviceID, Sequence: cp.Sequence, Digest: cp.Digest,
		GeneratedAt: cp.Generated.UTC().Format("2006-01-02T15:04:05.999999999Z07:00"),
	}
	payload, err := store.CheckpointSignPayload(doc)
	if err != nil {
		t.Fatal(err)
	}
	if err := serverkey.Verify(e.skey.Public(), payload, cp.Signature); err != nil {
		t.Fatalf("checkpoint signature: %v", err)
	}

	// A cursor behind the checkpoint now receives 410 + checkpoint + resume.
	code, body = e.do("GET",
		"/api/v1/devices/"+d+"/events?limit=2&cursor="+url.QueryEscape(cursorAt3), "", nil)
	if code != http.StatusGone {
		t.Fatalf("stale cursor status=%d want 410 body=%s", code, body)
	}
	var gone map[string]any
	_ = json.Unmarshal(body, &gone)
	det := gone["error"].(map[string]any)["details"].(map[string]any)
	if det["resumeFromSequence"].(float64) != 7 {
		t.Fatalf("resume point=%v", det)
	}
	if det["checkpoint"].(map[string]any)["digest"] != digests[5] {
		t.Fatalf("checkpoint payload=%v", det)
	}

	// A fresh view can start at the checkpoint and read 9..10.
	code, body = e.do("GET",
		"/api/v1/devices/"+d+"/events?startAfterSequence=8&limit=10", "", nil)
	if code != http.StatusOK {
		t.Fatalf("resume read: %d %s", code, body)
	}
	var pg2 map[string]any
	_ = json.Unmarshal(body, &pg2)
	evs := pg2["events"].([]any)
	if len(evs) != 2 {
		t.Fatalf("resumed events=%d", len(evs))
	}
}

// 9) Concurrent uploads of adjacent sequences through interleaved batches end
// in one dense contiguous prefix with no duplicates and no gaps.
func TestConcurrentAdjacentIngest(t *testing.T) {
	e := newEnv(t)
	d := e.uniqueDevice("conc")
	k := genDeviceKey()
	e.register(d, k)

	const n = 12
	events, digests := buildChain(k, d, n, payloadFor)

	var wg sync.WaitGroup
	errs := make(chan error, n)
	for i := range events {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			req := fmt.Sprintf("conc-%s-%d", d, idx+1)
			code, b := e.ingest(d, req, events[idx])
			if code != http.StatusOK {
				errs <- fmt.Errorf("seq %d status %d body %v", idx+1, code, b)
			}
		}(i)
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Fatal(err)
	}

	st, _ := e.status(d)
	if st["contiguousHighWatermark"].(float64) != n {
		t.Fatalf("final hwm=%v want %d", st["contiguousHighWatermark"], n)
	}

	// Read everything: exactly n unique sequences with the expected digests.
	_, raw := e.do("GET", "/api/v1/devices/"+d+"/events?limit=50", "", nil)
	var pg map[string]any
	_ = json.Unmarshal(raw, &pg)
	evs := pg["events"].([]any)
	if len(evs) != n {
		t.Fatalf("read %d events", len(evs))
	}
	for i, ev := range evs {
		m := ev.(map[string]any)
		if int64(m["sequence"].(float64)) != int64(i+1) || m["digest"] != digests[i] {
			t.Fatalf("event %d mismatch: %v", i+1, m)
		}
	}
}

// 10) Concurrent identical retries of the same candidate produce exactly one
// candidate even though another distinct candidate exists at the same
// sequence.
func TestConcurrentIdenticalRetry(t *testing.T) {
	e := newEnv(t)
	d := e.uniqueDevice("samecand")
	k := genDeviceKey()
	e.register(d, k)
	events, digests := buildChain(k, d, 3, payloadFor)
	e.ingest(d, "base1", events[0]) // hwm1; seq2/3 missing

	// Two distinct seq3 candidates (both stay pending due to the seq2 gap).
	candA := events[2]
	candB := signedEvent(k, d, 3, "evt-3-alt", digests[1],
		time.Date(2026, 9, 18, 14, 0, 0, 0, time.UTC), 1, map[string]any{"alt": 9})

	// Identical candidate A uploaded concurrently under one shared requestId.
	var wg sync.WaitGroup
	for i := 0; i < 4; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if code, b := e.ingest(d, "same-req-"+d, candA); code != http.StatusOK {
				t.Errorf("concurrent identical retry: %d %v", code, b)
			}
		}()
	}
	wg.Wait()
	if code, b := e.ingest(d, "alt-req-"+d, candB); code != http.StatusOK {
		t.Fatalf("distinct candidate: %d %v", code, b)
	}

	// Exactly two candidates at seq3, divergence open, watermark still 1.
	c, err := e.st.GetConflict(testCtx(t), d, 3)
	if err != nil {
		t.Fatal(err)
	}
	if len(c.Candidates) != 2 {
		t.Fatalf("candidates=%d want 2: %+v", len(c.Candidates), c.Candidates)
	}
	st, _ := e.status(d)
	if st["contiguousHighWatermark"].(float64) != 1 {
		t.Fatalf("hwm=%v want 1", st["contiguousHighWatermark"])
	}

	// Fill seq2: hwm advances to 2 and the seq3 conflict remains blocking.
	if code, b := e.ingest(d, "fill2", events[1]); code != http.StatusOK || hwmOf(b) != 2 {
		t.Fatalf("after filling seq2: %v", b)
	}
	c2, err := e.st.GetConflict(testCtx(t), d, 3)
	if err != nil || c2.Status != "open" {
		t.Fatalf("seq3 conflict must remain: %+v err=%v", c2, err)
	}
}
