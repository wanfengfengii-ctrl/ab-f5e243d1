package main

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"time"
)

// runHealthcheck is the container-local, dependency-free health probe used by
// Docker HEALTHCHECK. It checks HEALTHCHECK_URL (default
// http://127.0.0.1:8080/readyz) and exits 0 only on HTTP 200.
func runHealthcheck() int {
	target := envOrHealth("http://127.0.0.1:8080/readyz")
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, target, nil)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		fmt.Fprintf(os.Stderr, "status %d\n", resp.StatusCode)
		return 1
	}
	return 0
}

func envOrHealth(d string) string {
	if v := os.Getenv("HEALTHCHECK_URL"); v != "" {
		return v
	}
	return d
}
