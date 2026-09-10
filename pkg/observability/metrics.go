package observability

import (
	"strconv"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/collectors"
)

// Metrics is the service metric set bound to its own registry, so tests can
// build several instances without duplicate-registration panics.
type Metrics struct {
	registry *prometheus.Registry

	httpRequests   *prometheus.CounterVec
	httpDuration   *prometheus.HistogramVec
	httpInFlight   prometheus.Gauge
	tokenIssued    *prometheus.CounterVec
	tokenFailures  *prometheus.CounterVec
	verifyResults  *prometheus.CounterVec
	refreshReuse   prometheus.Counter
	activeSessions prometheus.Gauge
	loginAttempts  *prometheus.CounterVec
}

// NewMetrics registers and returns the metric set.
func NewMetrics() *Metrics {
	registry := prometheus.NewRegistry()
	m := &Metrics{
		registry: registry,
		httpRequests: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "iam_http_requests_total",
			Help: "Total number of HTTP requests handled by the service.",
		}, []string{"route", "method", "status"}),
		httpDuration: prometheus.NewHistogramVec(prometheus.HistogramOpts{
			Name:    "iam_http_request_duration_seconds",
			Help:    "HTTP request latency in seconds.",
			Buckets: []float64{0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5},
		}, []string{"route", "method"}),
		httpInFlight: prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "iam_http_in_flight_requests",
			Help: "Number of HTTP requests currently being served.",
		}),
		tokenIssued: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "iam_token_issued_total",
			Help: "Total number of token endpoint responses carrying an access token.",
		}, []string{"grant_type", "client_id"}),
		tokenFailures: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "iam_token_failures_total",
			Help: "Total number of failed token endpoint requests by error code.",
		}, []string{"grant_type", "error"}),
		verifyResults: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "iam_verify_total",
			Help: "Outcomes of the /verify endpoint used by the reverse proxy.",
		}, []string{"result"}),
		refreshReuse: prometheus.NewCounter(prometheus.CounterOpts{
			Name: "iam_refresh_reuse_detected_total",
			Help: "Number of refresh token reuse attempts that revoked a token family.",
		}),
		activeSessions: prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "iam_active_sessions",
			Help: "Number of sessions in Redis, sampled periodically.",
		}),
		loginAttempts: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "iam_login_attempts_total",
			Help: "Login form submissions by outcome.",
		}, []string{"result"}),
	}

	registry.MustRegister(
		collectors.NewGoCollector(),
		collectors.NewProcessCollector(collectors.ProcessCollectorOpts{}),
		m.httpRequests, m.httpDuration, m.httpInFlight, m.tokenIssued, m.tokenFailures,
		m.verifyResults, m.refreshReuse, m.activeSessions, m.loginAttempts,
	)
	return m
}

// Registry exposes the registry serving /metrics.
func (m *Metrics) Registry() *prometheus.Registry { return m.registry }

// HTTPMiddleware records request counts and latency per route.
func (m *Metrics) HTTPMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		start := time.Now()
		m.httpInFlight.Inc()
		c.Next()
		m.httpInFlight.Dec()

		route := c.FullPath()
		if route == "" {
			route = "unmatched"
		}
		method := c.Request.Method
		m.httpRequests.WithLabelValues(route, method, strconv.Itoa(c.Writer.Status())).Inc()
		m.httpDuration.WithLabelValues(route, method).Observe(time.Since(start).Seconds())
	}
}

// TokenIssued records a successful token response.
func (m *Metrics) TokenIssued(grantType, clientID string) {
	m.tokenIssued.WithLabelValues(grantType, clientID).Inc()
}

// TokenFailure records a rejected token request.
func (m *Metrics) TokenFailure(grantType, errorCode string) {
	if grantType == "" {
		grantType = "unknown"
	}
	m.tokenFailures.WithLabelValues(grantType, errorCode).Inc()
}

// VerifyResult records the outcome of a /verify call.
func (m *Metrics) VerifyResult(result string) {
	m.verifyResults.WithLabelValues(result).Inc()
}

// RefreshReuseDetected records a detected refresh token replay.
func (m *Metrics) RefreshReuseDetected() { m.refreshReuse.Inc() }

// SetActiveSessions publishes the sampled session count.
func (m *Metrics) SetActiveSessions(count float64) { m.activeSessions.Set(count) }

// LoginAttempt records a login form submission outcome.
func (m *Metrics) LoginAttempt(result string) {
	m.loginAttempts.WithLabelValues(result).Inc()
}
