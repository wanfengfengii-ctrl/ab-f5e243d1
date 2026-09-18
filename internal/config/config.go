// Package config loads process configuration from the environment.
package config

import (
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"
)

// Config holds all runtime settings.
type Config struct {
	DatabaseURL string
	// Role is "api", "worker" or "gateway".
	Role string
	// HTTPAddr is the listen address for api/gateway.
	HTTPAddr string
	// UpstreamURL is the proxy upstream for the gateway role.
	UpstreamURL string

	// AdminToken is the bearer credential required for management commands
	// (key rotation, conflict adjudication, compaction control).
	AdminToken string
	// ServerSigningKey is the Ed25519 seed (base64 of 32 bytes) used to sign
	// checkpoints.
	ServerSigningKey string

	MaxBodyBytes    int64
	ShutdownTimeout time.Duration
	WaitMaxSeconds  int
	DefaultPageSize int
	MaxPageSize     int

	// Worker settings.
	CompactionInterval time.Duration
	CompactionMinAge   time.Duration
	ViewTTL            time.Duration
	CompactionCutoff   int64 // keep at least this many newest contiguous events per device

	// Observability.
	LogLevel string
}

// FromEnv builds Config from environment variables, applying defaults.
func FromEnv() (Config, error) {
	c := Config{
		DatabaseURL:        os.Getenv("DATABASE_URL"),
		Role:               envOr("ROLE", "api"),
		HTTPAddr:           envOr("HTTP_ADDR", ":8080"),
		UpstreamURL:        os.Getenv("UPSTREAM_URL"),
		AdminToken:         os.Getenv("ADMIN_TOKEN"),
		ServerSigningKey:   os.Getenv("SERVER_SIGNING_KEY"),
		MaxBodyBytes:       envInt64("MAX_BODY_BYTES", 4<<20),
		ShutdownTimeout:    time.Duration(envInt("SHUTDOWN_TIMEOUT_SECONDS", 20)) * time.Second,
		WaitMaxSeconds:     envInt("WAIT_MAX_SECONDS", 30),
		DefaultPageSize:    envInt("DEFAULT_PAGE_SIZE", 100),
		MaxPageSize:        envInt("MAX_PAGE_SIZE", 500),
		CompactionInterval: time.Duration(envInt("COMPACTION_INTERVAL_SECONDS", 30)) * time.Second,
		CompactionMinAge:   time.Duration(envInt("COMPACTION_MIN_AGE_SECONDS", 120)) * time.Second,
		ViewTTL:            time.Duration(envInt("VIEW_TTL_SECONDS", 600)) * time.Second,
		CompactionCutoff:   envInt64("COMPACTION_KEEP_EVENTS", 200),
		LogLevel:           envOr("LOG_LEVEL", "info"),
	}
	if c.DatabaseURL == "" {
		return c, fmt.Errorf("DATABASE_URL is required")
	}
	if c.AdminToken == "" {
		return c, fmt.Errorf("ADMIN_TOKEN is required")
	}
	if c.ServerSigningKey == "" {
		return c, fmt.Errorf("SERVER_SIGNING_KEY is required")
	}
	if c.Role == "gateway" && c.UpstreamURL == "" {
		return c, fmt.Errorf("UPSTREAM_URL is required for gateway role")
	}
	c.Role = strings.ToLower(c.Role)
	return c, nil
}

func envOr(k, d string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return d
}

func envInt(k string, d int) int {
	if v := os.Getenv(k); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			return n
		}
	}
	return d
}

func envInt64(k string, d int64) int64 {
	if v := os.Getenv(k); v != "" {
		if n, err := strconv.ParseInt(v, 10, 64); err == nil {
			return n
		}
	}
	return d
}
