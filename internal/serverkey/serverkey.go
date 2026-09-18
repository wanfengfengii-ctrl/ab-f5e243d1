// Package serverkey holds the Ed25519 key the server uses to sign checkpoints.
package serverkey

import (
	"crypto/ed25519"
	"encoding/base64"
	"errors"
	"fmt"
)

// Key wraps an Ed25519 private key and exposes its public part.
type Key struct {
	priv ed25519.PrivateKey
	pub  ed25519.PublicKey
}

// FromSeed parses a base64-encoded 32-byte Ed25519 seed (standard or raw URL
// alphabet accepted).
func FromSeed(encoded string) (*Key, error) {
	seed, err := decodeLoose(encoded)
	if err != nil {
		return nil, fmt.Errorf("SERVER_SIGNING_KEY: %w", err)
	}
	if len(seed) != ed25519.SeedSize {
		return nil, fmt.Errorf("SERVER_SIGNING_KEY: expected %d seed bytes, got %d",
			ed25519.SeedSize, len(seed))
	}
	priv := ed25519.NewKeyFromSeed(seed)
	return &Key{priv: priv, pub: priv.Public().(ed25519.PublicKey)}, nil
}

// Sign returns standard base64 of the Ed25519 signature over msg.
func (k *Key) Sign(msg []byte) string {
	return base64.StdEncoding.EncodeToString(ed25519.Sign(k.priv, msg))
}

// Public returns the raw 32-byte public key.
func (k *Key) Public() ed25519.PublicKey { return k.pub }

// Verify checks a standard-base64 checkpoint signature (helper for clients and
// the verify acceptance job).
func Verify(pub ed25519.PublicKey, msg []byte, signatureB64 string) error {
	sig, err := decodeLoose(signatureB64)
	if err != nil {
		return err
	}
	if len(sig) != ed25519.SignatureSize {
		return errors.New("bad signature length")
	}
	if !ed25519.Verify(pub, msg, sig) {
		return errors.New("checkpoint signature mismatch")
	}
	return nil
}

func decodeLoose(s string) ([]byte, error) {
	if b, err := base64.StdEncoding.DecodeString(s); err == nil {
		return b, nil
	}
	if b, err := base64.RawStdEncoding.DecodeString(s); err == nil {
		return b, nil
	}
	if b, err := base64.RawURLEncoding.DecodeString(s); err == nil {
		return b, nil
	}
	return nil, errors.New("invalid base64")
}
