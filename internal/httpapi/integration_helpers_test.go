package httpapi_test

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"sync/atomic"
	"testing"
	"time"

	"telemetry/internal/config"
	"telemetry/internal/envelope"
	"telemetry/internal/httpapi"
	"telemetry/internal/serverkey"
	"telemetry/internal/store"
)

const (
	testAdminToken = "test-admin-token"
	// Deterministic server checkpoint-signing seed for tests.
	testServerSeedHex = "2222222222222222222222222222222222222222222222222222222222222222"
)

type env struct {
	t       *testing.T
	st      *store.Store
	srv     *httptest.Server
	skey    *serverkey.Key
	counter atomic.Int64
	runID   string
}

func testDatabaseURL() string {
	if v := os.Getenv("DATABASE_URL"); v != "" {
		return v
	}
	return "host=/tmp port=5439 user=postgres dbname=telemetry sslmode=disable"
}

func newEnv(t *testing.T) *env {
	t.Helper()
	if os.Getenv("RUN_DB_TESTS") == "" && os.Getenv("DATABASE_URL") == "" {
		t.Skip("set DATABASE_URL or RUN_DB_TESTS=1 to run integration tests")
	}
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelError}))
	st, err := store.New(context.Background(), testDatabaseURL())
	if err != nil {
		t.Skipf("database not available: %v", err)
	}
	t.Cleanup(st.Close)
	if err := st.Migrate(context.Background()); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	seed, _ := hex.DecodeString(testServerSeedHex)
	skey := mustServerKey(seed)
	cfg := config.Config{
		DatabaseURL:      testDatabaseURL(),
		AdminToken:       testAdminToken,
		MaxBodyBytes:     4 << 20,
		DefaultPageSize:  3,
		MaxPageSize:      50,
		WaitMaxSeconds:   30,
		ViewTTL:          time.Minute,
		CompactionCutoff: 200,
	}
	srv := httpapi.NewServer(st, cfg, logger, skey)
	ts := httptest.NewServer(srv.Handler())
	t.Cleanup(ts.Close)
	return &env{t: t, st: st, srv: ts, skey: skey,
		runID: fmt.Sprintf("%d", time.Now().UnixNano())}
}

// rid namespaces a caller-provided request/command id for this test run so
// suites can run repeatedly against the same database.
func (e *env) rid(id string) string { return id + "-" + e.runID }

func mustServerKey(seed []byte) *serverkey.Key {
	k, err := serverkey.FromSeed(base64.StdEncoding.EncodeToString(seed))
	if err != nil {
		panic(err)
	}
	return k
}

// uniqueDevice returns a per-test unique device id.
func (e *env) uniqueDevice(prefix string) string {
	n := e.counter.Add(1)
	return fmt.Sprintf("%s-%d-%d", prefix, time.Now().UnixNano(), n)
}

// deviceKey bundles an Ed25519 key pair.
type deviceKey struct {
	priv ed25519.PrivateKey
	pub  ed25519.PublicKey
}

func genDeviceKey() *deviceKey {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		panic(err)
	}
	return &deviceKey{priv: priv, pub: pub}
}

func (k *deviceKey) pubB64() string { return base64.StdEncoding.EncodeToString(k.pub) }

func (e *env) register(deviceID string, k *deviceKey) {
	e.t.Helper()
	code, body := e.do("POST", "/api/v1/devices", "", map[string]any{
		"deviceId":  deviceID,
		"publicKey": k.pubB64(),
	})
	if code != http.StatusCreated {
		e.t.Fatalf("register: status=%d body=%s", code, body)
	}
}

func (e *env) do(method, path, token string, body any) (int, []byte) {
	e.t.Helper()
	var rdr io.Reader
	if body != nil {
		raw, _ := json.Marshal(body)
		rdr = bytes.NewReader(raw)
	}
	req, err := http.NewRequest(method, e.srv.URL+path, rdr)
	if err != nil {
		e.t.Fatal(err)
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		e.t.Fatal(err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, raw
}

func (e *env) admin(method, path string, body any) (int, []byte) {
	return e.do(method, path, testAdminToken, body)
}

// signedEvent builds one signed ingest wire event.
func signedEvent(k *deviceKey, deviceID string, seq int64, eventID, prevDigest string,
	occurredAt time.Time, keyVersion int, payload any) map[string]any {
	payloadRaw, _ := json.Marshal(payload)
	pc, err := envelope.CanonicalPayload(payloadRaw)
	if err != nil {
		panic(err)
	}
	ev := &envelope.Event{
		DeviceID: deviceID, Sequence: seq, EventID: eventID,
		OccurredAt: occurredAt.UTC(), KeyVersion: keyVersion, PrevDigest: prevDigest,
		Payload: payloadRaw,
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
		"deviceId":   deviceID,
		"sequence":   seq,
		"eventId":    eventID,
		"occurredAt": occurredAt.UTC().Format(time.RFC3339Nano),
		"keyVersion": keyVersion,
		"prevDigest": prevDigest,
		"payload":    pj,
		"signature":  sig,
		"_digest":    dg.String(),
	}
}

func digestOf(ev map[string]any) string { return ev["_digest"].(string) }

func withoutDigest(ev map[string]any) map[string]any {
	out := map[string]any{}
	for k, v := range ev {
		if k != "_digest" {
			out[k] = v
		}
	}
	return out
}

// ingest posts a batch and returns (status, decoded body).
func (e *env) ingest(deviceID, requestID string, events ...map[string]any) (int, map[string]any) {
	wire := make([]map[string]any, len(events))
	for i, ev := range events {
		wire[i] = withoutDigest(ev)
	}
	code, body := e.do("POST", "/api/v1/devices/"+deviceID+"/ingest", "",
		map[string]any{"requestId": e.rid(requestID), "events": wire})
	var m map[string]any
	_ = json.Unmarshal(body, &m)
	return code, m
}

func mustOK(t *testing.T, code int, body map[string]any) map[string]any {
	t.Helper()
	if code != http.StatusOK {
		t.Fatalf("status=%d body=%v", code, body)
	}
	return body
}

func hwmOf(m map[string]any) int64 {
	return int64(m["contiguousHighWatermark"].(float64))
}

// buildChain returns signed events 1..n chained from the genesis digest, in
// order. payloadFn lets callers vary payloads.
func buildChain(k *deviceKey, deviceID string, n int,
	payloadFn func(seq int) any) ([]map[string]any, []string) {
	occ := time.Date(2026, 9, 18, 8, 0, 0, 0, time.UTC)
	events := make([]map[string]any, n)
	digests := make([]string, n)
	prev := envelope.GenesisDigest
	for i := 1; i <= n; i++ {
		ev := signedEvent(k, deviceID, int64(i), fmt.Sprintf("evt-%d", i),
			prev, occ.Add(time.Duration(i)*time.Second), 1, payloadFn(i))
		events[i-1] = ev
		digests[i-1] = digestOf(ev)
		prev = digests[i-1]
	}
	return events, digests
}

func (e *env) status(deviceID string) (map[string]any, []byte) {
	code, body := e.do("GET", "/api/v1/devices/"+deviceID, "", nil)
	if code != http.StatusOK {
		e.t.Fatalf("status: %d %s", code, body)
	}
	var m map[string]any
	_ = json.Unmarshal(body, &m)
	return m, body
}

func (e *env) adjudicate(deviceID string, seq int64, commandID string,
	expectedRevision int64, decision, candidateDigest string) (int, map[string]any) {
	code, body := e.admin("POST",
		fmt.Sprintf("/api/v1/devices/%s/conflicts/%d/adjudicate", deviceID, seq),
		map[string]any{
			"commandId":                e.rid(commandID),
			"expectedConflictRevision": expectedRevision,
			"decision":                 decision,
			"candidateDigest":          candidateDigest,
		})
	var m map[string]any
	_ = json.Unmarshal(body, &m)
	return code, m
}

func (e *env) rotate(deviceID, commandID string, keyVersion int,
	publicKey string, effectiveSequence, expectedRevision int64) (int, map[string]any) {
	code, body := e.admin("POST", "/api/v1/devices/"+deviceID+"/keys", map[string]any{
		"commandId":               e.rid(commandID),
		"keyVersion":              keyVersion,
		"publicKey":               publicKey,
		"effectiveSequence":       effectiveSequence,
		"expectedControlRevision": expectedRevision,
	})
	var m map[string]any
	_ = json.Unmarshal(body, &m)
	return code, m
}

func cloneEvent(in map[string]any) map[string]any {
	out := make(map[string]any, len(in))
	for k, v := range in {
		out[k] = v
	}
	return out
}

func mustJSON(m map[string]any) []byte {
	b, err := json.Marshal(m)
	if err != nil {
		panic(err)
	}
	return b
}

func errCode(m map[string]any) string {
	if m == nil {
		return ""
	}
	if eobj, ok := m["error"].(map[string]any); ok {
		if c, ok := eobj["code"].(string); ok {
			return c
		}
	}
	return ""
}

func testCtx(t *testing.T) context.Context {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	t.Cleanup(cancel)
	return ctx
}

func signCheckpoint(k *serverkey.Key) func(store.CheckpointDoc) (string, error) {
	return func(doc store.CheckpointDoc) (string, error) {
		payload, err := store.CheckpointSignPayload(doc)
		if err != nil {
			return "", err
		}
		return k.Sign(payload), nil
	}
}

// concurrentStage holds an external shared staging barrier while posting the
// given requests concurrently, forcing all of them to have staged before any
// advancement runs. It returns (status, body) per request in start order.
type stageResult struct {
	code int
	body map[string]any
}

func (e *env) concurrentStage(deviceID string, requests []func() (int, map[string]any)) []stageResult {
	ctx := testCtx(e.t)
	conn, err := e.st.Pool().Acquire(ctx)
	if err != nil {
		e.t.Fatal(err)
	}
	defer conn.Release()
	key := e.st.BarrierKey(deviceID)
	if _, err := conn.Exec(ctx, "SELECT pg_advisory_lock_shared($1)", key); err != nil {
		e.t.Fatal(err)
	}
	released := false
	release := func() {
		if !released {
			_, _ = conn.Exec(context.Background(), "SELECT pg_advisory_unlock_shared($1)", key)
			released = true
		}
	}
	defer release()

	resCh := make(chan stageResult, len(requests))
	for _, fn := range requests {
		fn := fn
		go func() {
			c, b := fn()
			resCh <- stageResult{c, b}
		}()
	}
	// Wait until every candidate is staged (events rows exist for the batch
	// sequences) while advancement remains blocked.
	deadline := time.Now().Add(10 * time.Second)
	for {
		var n int
		if err := conn.QueryRow(ctx,
			`SELECT COUNT(*) FROM events WHERE device_id=$1
			   AND status IN ('pending','chosen')`, deviceID).Scan(&n); err != nil {
			e.t.Fatal(err)
		}
		if n >= len(requests) {
			break
		}
		if time.Now().After(deadline) {
			e.t.Fatalf("timed out waiting for %d staged candidates, saw %d", len(requests), n)
		}
		time.Sleep(5 * time.Millisecond)
	}
	release()
	out := make([]stageResult, 0, len(requests))
	for range requests {
		select {
		case r := <-resCh:
			out = append(out, r)
		case <-time.After(10 * time.Second):
			e.t.Fatal("staged requests did not finish after barrier release")
		}
	}
	return out
}
