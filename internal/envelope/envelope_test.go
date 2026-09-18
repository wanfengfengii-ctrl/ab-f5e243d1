package envelope

import (
	"crypto/ed25519"
	"encoding/hex"
	"testing"
	"time"
)

// These vectors are the exact worked example reproduced in the README. Any
// change that alters them is a wire-breaking protocol change.
func TestGoldenVectors(t *testing.T) {
	seed, _ := hex.DecodeString("1111111111111111111111111111111111111111111111111111111111111111")
	priv := ed25519.NewKeyFromSeed(seed)
	pub := priv.Public().(ed25519.PublicKey)

	const wantPub = "0EqyMnQrtKs6E2i9RhXk5tAiSrcaAWuvhSCjMsl3hzc="
	if b64(pub) != wantPub {
		t.Fatalf("public key vector mismatch: %s", b64(pub))
	}

	rawPayload := []byte(`{"unit":"°C","reading":21.5,"tags":["line-a","press-3"]}`) // out-of-order, float
	pc, err := CanonicalPayload(rawPayload)
	if err != nil {
		t.Fatal(err)
	}
	const wantPayload = `{"reading":21.5,"tags":["line-a","press-3"],"unit":"°C"}`
	if string(pc) != wantPayload {
		t.Fatalf("payload canonical mismatch:\n got %s\nwant %s", pc, wantPayload)
	}

	occ, _ := time.Parse(time.RFC3339Nano, "2026-09-18T08:15:00.123456789Z")
	e := &Event{
		DeviceID: "plant-7/line-a", Sequence: 1, EventID: "evt-0001",
		OccurredAt: occ.UTC(), KeyVersion: 1, PrevDigest: GenesisDigest,
	}

	const wantRecord = `{"deviceId":"plant-7/line-a","eventId":"evt-0001","keyVersion":1,"occurredAt":"2026-09-18T08:15:00.123456789Z","payload":{"reading":21.5,"tags":["line-a","press-3"],"unit":"°C"},"prevDigest":"sha256:0000000000000000000000000000000000000000000000000000000000000000","sequence":1}`
	rec, err := RecordBytes(e, pc)
	if err != nil {
		t.Fatal(err)
	}
	if string(rec) != wantRecord {
		t.Fatalf("record mismatch:\n got %s\nwant %s", rec, wantRecord)
	}

	sb, err := SigningBytes(e, pc)
	if err != nil {
		t.Fatal(err)
	}
	wantSigned := `telemetry-event-v1
{"deviceId":"plant-7/line-a","domain":"telemetry-event-v1","eventId":"evt-0001","keyVersion":1,"occurredAt":"2026-09-18T08:15:00.123456789Z","payload":{"reading":21.5,"tags":["line-a","press-3"],"unit":"°C"},"prevDigest":"sha256:0000000000000000000000000000000000000000000000000000000000000000","sequence":1}`
	if string(sb) != wantSigned {
		t.Fatalf("signing bytes mismatch:\n got %q\nwant %q", sb, wantSigned)
	}

	dg, err := ComputeDigest(e, pc)
	if err != nil {
		t.Fatal(err)
	}
	const wantDigest = "sha256:a9791269d4cb57eed90af1067db55da593225f40725a121c7d0e6a8c85332a52"
	if dg.String() != wantDigest {
		t.Fatalf("digest mismatch: got %s want %s", dg, wantDigest)
	}

	sig, err := Sign(priv, e, pc)
	if err != nil {
		t.Fatal(err)
	}
	const wantSig = "O3ObFvT7bEMo1LpCBmktYjbreXj8imu9mQC7VAX6rZlgfSLfWtGLYpgDs8DaO07tDNt7Nl/11H/4ag7rhDS3CA=="
	if sig != wantSig {
		t.Fatalf("signature mismatch:\n got %s\nwant %s", sig, wantSig)
	}
	if err := VerifySignature(pub, e, pc, []byte(sig)); err != nil {
		t.Fatalf("signature did not verify: %v", err)
	}

	// Tamper detection: a genuinely changed payload value changes the digest.
	tampered := []byte(`{"reading":21.6,"tags":["line-a","press-3"],"unit":"°C"}`)
	tpc, _ := CanonicalPayload(tampered)
	td, _ := ComputeDigest(e, tpc)
	if td.String() == wantDigest {
		t.Fatal("digest failed to distinguish a changed payload")
	}
	if err := VerifySignature(pub, e, tpc, []byte(sig)); err == nil {
		t.Fatal("signature verified over altered payload")
	}
}

func b64(b []byte) string {
	return stdB64(b)
}
func mustB64(s string) []byte {
	b, err := decB64(s)
	if err != nil {
		panic(err)
	}
	return b
}
