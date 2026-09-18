// Package envelope defines event wire fields, the signing envelope, digest
// derivation and Ed25519 verification.
package envelope

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"telemetry/internal/canonical"
)

// DigestPrefix and SignDomain provide domain separation.
const (
	DigestPrefix = "sha256"
	SignDomain   = "telemetry-event-v1"
	GenesisLabel = "GENESIS"
)

// GenesisDigest is the required prevDigest of sequence 1 events: the SHA-256
// digest of the all-zero 32-byte genesis anchor.
const GenesisDigest = DigestPrefix + ":" +
	"0000000000000000000000000000000000000000000000000000000000000000"

// Event is the wire representation of one telemetry event.
type Event struct {
	DeviceID   string          `json:"deviceId"`
	Sequence   int64           `json:"sequence"`
	EventID    string          `json:"eventId"`
	OccurredAt time.Time       `json:"occurredAt"`
	KeyVersion int             `json:"keyVersion"`
	PrevDigest string          `json:"prevDigest"`
	Payload    json.RawMessage `json:"payload"`
	Signature  string          `json:"signature"`
}

// signingEnvelope is the exact object that gets signed. Its field order is
// irrelevant for signing because the object is canonicalized before signing;
// canonicalization sorts members by key.
type signingEnvelope struct {
	Domain     string `json:"domain"`
	DeviceID   string `json:"deviceId"`
	EventID    string `json:"eventId"`
	KeyVersion int    `json:"keyVersion"`
	OccurredAt string `json:"occurredAt"`
	Payload    any    `json:"payload"`
	PrevDigest string `json:"prevDigest"`
	Sequence   int64  `json:"sequence"`
}

// Digest is "sha256:" + lowercase hex(SHA-256(canonical event record)).
//
// The digested record is a JSON object with exactly these members (canonical
// key order is applied, so declaration order does not matter):
//
//	{"deviceId":...,"eventId":...,"keyVersion":...,"occurredAt":...,
//	 "payload":<canonical payload>,"prevDigest":...,"sequence":...}
//
// i.e. the signing envelope without "domain" and without "signature".
type Digest struct {
	Bytes [32]byte
}

func (d Digest) String() string { return DigestPrefix + ":" + hex.EncodeToString(d.Bytes[:]) }

// ParseDigest parses the canonical textual digest form and verifies length.
func ParseDigest(s string) (Digest, error) {
	var d Digest
	if len(s) != len(DigestPrefix)+1+64 || s[:len(DigestPrefix)+1] != DigestPrefix+":" {
		return d, fmt.Errorf("invalid digest %q", s)
	}
	n, err := hex.Decode(d.Bytes[:], []byte(s[len(DigestPrefix)+1:]))
	if err != nil || n != 32 {
		return d, fmt.Errorf("invalid digest %q", s)
	}
	return d, nil
}

// CanonicalPayload parses and re-encodes raw JSON payload canonically. It
// rejects empty payloads (clients must send an explicit JSON value).
func CanonicalPayload(raw json.RawMessage) ([]byte, error) {
	if len(raw) == 0 {
		return nil, errors.New("payload is required")
	}
	v, err := canonical.Parse(raw)
	if err != nil {
		return nil, fmt.Errorf("payload is not canonicalizable JSON: %w", err)
	}
	return canonical.Encode(v)
}

// RecordBytes returns the canonical bytes of the event record (the digest
// input), given an already-canonicalized payload.
func RecordBytes(e *Event, canonicalPayload []byte) ([]byte, error) {
	pv, err := canonical.Parse(canonicalPayload)
	if err != nil {
		return nil, err
	}
	rec := &canonical.Object{Members: []canonical.Member{
		{Key: "deviceId", Value: e.DeviceID},
		{Key: "eventId", Value: e.EventID},
		{Key: "keyVersion", Value: json.Number(strconvInt(int64(e.KeyVersion)))},
		{Key: "occurredAt", Value: e.OccurredAt.UTC().Format(time.RFC3339Nano)},
		{Key: "payload", Value: pv},
		{Key: "prevDigest", Value: e.PrevDigest},
		{Key: "sequence", Value: json.Number(strconvInt(e.Sequence))},
	}}
	return canonical.Encode(rec)
}

// SigningBytes returns the exact bytes covered by the Ed25519 signature:
//
//	"TELEMETRY-EVENT-V1\n" + canonical({"domain":"telemetry-event-v1",
//	  ...record fields..., "payload":<canonical payload>})
//
// The trailing newline is part of the signed input. The record fields are the
// same object that feeds the digest, with "domain" prepended.
func SigningBytes(e *Event, canonicalPayload []byte) ([]byte, error) {
	pv, err := canonical.Parse(canonicalPayload)
	if err != nil {
		return nil, err
	}
	env := &canonical.Object{Members: []canonical.Member{
		{Key: "deviceId", Value: e.DeviceID},
		{Key: "domain", Value: SignDomain},
		{Key: "eventId", Value: e.EventID},
		{Key: "keyVersion", Value: json.Number(strconvInt(int64(e.KeyVersion)))},
		{Key: "occurredAt", Value: e.OccurredAt.UTC().Format(time.RFC3339Nano)},
		{Key: "payload", Value: pv},
		{Key: "prevDigest", Value: e.PrevDigest},
		{Key: "sequence", Value: json.Number(strconvInt(e.Sequence))},
	}}
	cb, err := canonical.Encode(env)
	if err != nil {
		return nil, err
	}
	out := make([]byte, 0, len(SignDomain)+2+len(cb))
	out = append(out, SignDomain...)
	out = append(out, '\n')
	out = append(out, cb...)
	return out, nil
}

// ComputeDigest returns the digest of the canonical event record.
func ComputeDigest(e *Event, canonicalPayload []byte) (Digest, error) {
	rec, err := RecordBytes(e, canonicalPayload)
	if err != nil {
		return Digest{}, err
	}
	return Digest{Bytes: sha256.Sum256(rec)}, nil
}

// VerifySignature checks an Ed25519 signature over SigningBytes. sig is
// standard base64 (padded or unpadded accepted) of the 64-byte signature.
func VerifySignature(pub ed25519.PublicKey, e *Event, canonicalPayload, sig []byte) error {
	if len(pub) != ed25519.PublicKeySize {
		return errors.New("invalid public key length")
	}
	msg, err := SigningBytes(e, canonicalPayload)
	if err != nil {
		return err
	}
	sig = decodeB64(sig)
	if len(sig) != ed25519.SignatureSize {
		return errors.New("invalid signature length")
	}
	if !ed25519.Verify(pub, msg, sig) {
		return errors.New("signature verification failed")
	}
	return nil
}

// Sign is a helper for clients/tests.
func Sign(priv ed25519.PrivateKey, e *Event, canonicalPayload []byte) (string, error) {
	msg, err := SigningBytes(e, canonicalPayload)
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(ed25519.Sign(priv, msg)), nil
}

func decodeB64(s []byte) []byte {
	if d, err := base64.StdEncoding.DecodeString(string(s)); err == nil {
		return d
	}
	d, _ := base64.RawStdEncoding.DecodeString(string(s))
	return d
}

func strconvInt(n int64) string {
	return fmt.Sprintf("%d", n)
}
