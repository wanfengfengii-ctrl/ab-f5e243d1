// Package cursor implements unforgeable, device- and view-bound page cursors.
package cursor

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
)

// Claims are bound into every cursor.
type Claims struct {
	Version    int    `json:"v"`
	DeviceID   string `json:"d"`
	ViewID     string `json:"w"`
	Position   int64  `json:"p"` // last sequence delivered within the view
	IssuedAtMS int64  `json:"i"`
}

// Coder seals and opens cursors with a secret HMAC key.
type Coder struct {
	key []byte
}

// NewCoder derives the cursor HMAC key from the server secret material.
func NewCoder(serverSecret []byte) *Coder {
	mac := hmac.New(sha256.New, append([]byte("telemetry-cursor-v1\n"), serverSecret...))
	return &Coder{key: mac.Sum(nil)}
}

// Seal returns the compact token for the claims.
func (c *Coder) Seal(cl Claims) (string, error) {
	cl.Version = 1
	raw, err := json.Marshal(cl)
	if err != nil {
		return "", err
	}
	payload := make([]byte, 0, len(raw)+32)
	payload = append(payload, raw...)
	payload = append(payload, c.tag(raw)...)
	return base64.RawURLEncoding.EncodeToString(payload), nil
}

// Open validates integrity and returns the claims.
func (c *Coder) Open(token string) (Claims, error) {
	var cl Claims
	payload, err := base64.RawURLEncoding.DecodeString(token)
	if err != nil || len(payload) < 32 {
		return cl, errors.New("malformed cursor")
	}
	raw := payload[:len(payload)-32]
	tag := payload[len(payload)-32:]
	if !hmac.Equal(tag, c.tag(raw)) {
		return cl, errors.New("cursor signature mismatch")
	}
	if err := json.Unmarshal(raw, &cl); err != nil {
		return cl, fmt.Errorf("malformed cursor payload: %w", err)
	}
	if cl.Version != 1 || cl.ViewID == "" || cl.DeviceID == "" {
		return cl, errors.New("cursor missing bindings")
	}
	return cl, nil
}

func (c *Coder) tag(raw []byte) []byte {
	mac := hmac.New(sha256.New, c.key)
	mac.Write(raw)
	return mac.Sum(nil)
}
