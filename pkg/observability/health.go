package observability

import (
	"context"
	"encoding/json"
	"net/http"
	"time"
)

// Pinger is a dependency whose readiness can be probed.
type Pinger interface {
	Ping(ctx context.Context) error
}

// Health reports liveness and readiness. Liveness never touches dependencies;
// readiness probes Postgres and Redis with a short deadline.
type Health struct {
	Postgres Pinger
	Redis    Pinger
	Timeout  time.Duration
	Version  string
}

type healthResponse struct {
	Status   string            `json:"status"`
	Version  string            `json:"version,omitempty"`
	Checks   map[string]string `json:"checks,omitempty"`
	Duration string            `json:"duration,omitempty"`
}

// Live answers /healthz: the process is running and can serve traffic.
func (h *Health) Live(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, healthResponse{Status: "ok", Version: h.Version})
}

// Ready answers /readyz: every dependency answered within the deadline.
func (h *Health) Ready(w http.ResponseWriter, r *http.Request) {
	timeout := h.Timeout
	if timeout <= 0 {
		timeout = 2 * time.Second
	}
	ctx, cancel := context.WithTimeout(r.Context(), timeout)
	defer cancel()

	start := time.Now()
	checks := make(map[string]string, 2)
	status := http.StatusOK
	overall := "ok"

	if h.Postgres == nil {
		checks["postgres"] = "not configured"
		status = http.StatusServiceUnavailable
		overall = "degraded"
	} else if err := h.Postgres.Ping(ctx); err != nil {
		checks["postgres"] = "unavailable"
		status = http.StatusServiceUnavailable
		overall = "degraded"
	} else {
		checks["postgres"] = "ok"
	}

	if h.Redis == nil {
		checks["redis"] = "not configured"
		status = http.StatusServiceUnavailable
		overall = "degraded"
	} else if err := h.Redis.Ping(ctx); err != nil {
		checks["redis"] = "unavailable"
		status = http.StatusServiceUnavailable
		overall = "degraded"
	} else {
		checks["redis"] = "ok"
	}

	writeJSON(w, status, healthResponse{
		Status:   overall,
		Version:  h.Version,
		Checks:   checks,
		Duration: time.Since(start).String(),
	})
}

func writeJSON(w http.ResponseWriter, status int, payload healthResponse) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(payload)
}
