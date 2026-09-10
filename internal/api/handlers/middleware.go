// Package handlers contains the HTTP handlers that are not part of the OAuth
// protocol surface: the pages of the authorization server, the /verify endpoint
// used by the reverse proxy, session management and cross-cutting middleware.
package handlers

import (
	"crypto/rand"
	"encoding/base64"
	"net/http"
	"net/netip"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"

	"iam-service/internal/service"
)

// Context keys used by the middleware chain.
const ctxRequestID = "iam.request_id"

// RequestIDHeader is the header carrying the correlation id.
const RequestIDHeader = "X-Request-ID"

// RequestID reuses the id supplied by the reverse proxy or generates one, and
// echoes it back so a request can be traced across Nginx, this service and the
// backends.
func RequestID() gin.HandlerFunc {
	return func(c *gin.Context) {
		id := strings.TrimSpace(c.GetHeader(RequestIDHeader))
		if id == "" || len(id) > 128 {
			id = newRequestID()
		}
		c.Set(ctxRequestID, id)
		c.Header(RequestIDHeader, id)
		c.Next()
	}
}

// Logger writes one structured line per request. Secrets are never logged: the
// query string is dropped and the body is never read.
func Logger(logger *zap.Logger) gin.HandlerFunc {
	return func(c *gin.Context) {
		start := time.Now()
		c.Next()

		route := c.FullPath()
		if route == "" {
			route = "unmatched"
		}
		fields := []zap.Field{
			zap.String("method", c.Request.Method),
			zap.String("route", route),
			zap.Int("status", c.Writer.Status()),
			zap.Duration("duration", time.Since(start)),
			zap.String("client_ip", ClientIP(c).String()),
			zap.String("request_id", RequestIDFrom(c)),
		}
		switch {
		case c.Writer.Status() >= 500:
			logger.Error("request failed", fields...)
		case c.Writer.Status() >= 400:
			logger.Warn("request rejected", fields...)
		default:
			logger.Info("request served", fields...)
		}
	}
}

// BodyLimit rejects oversized bodies before they are read.
func BodyLimit(maxBytes int64) gin.HandlerFunc {
	return func(c *gin.Context) {
		if c.Request.ContentLength > maxBytes {
			c.AbortWithStatusJSON(http.StatusRequestEntityTooLarge, gin.H{"error": "request body too large"})
			return
		}
		c.Request.Body = http.MaxBytesReader(c.Writer, c.Request.Body, maxBytes)
		c.Next()
	}
}

// SecurityHeaders adds conservative headers to every response.
func SecurityHeaders() gin.HandlerFunc {
	return func(c *gin.Context) {
		c.Header("X-Content-Type-Options", "nosniff")
		c.Header("X-Frame-Options", "DENY")
		c.Header("Referrer-Policy", "no-referrer")
		c.Next()
	}
}

// RequestIDFrom reads the correlation id of the current request.
func RequestIDFrom(c *gin.Context) string {
	if v, ok := c.Get(ctxRequestID); ok {
		if id, ok := v.(string); ok {
			return id
		}
	}
	return ""
}

// ClientIP returns the client address. gin resolves it from X-Forwarded-For only
// when the peer is a trusted proxy (configured via SetTrustedProxies), so a
// direct client cannot spoof its address into the rate limiter.
func ClientIP(c *gin.Context) netip.Addr {
	if addr, err := netip.ParseAddr(c.ClientIP()); err == nil {
		return addr
	}
	return netip.Addr{}
}

// RequestMeta builds the audit metadata of the current request.
func RequestMeta(c *gin.Context) service.RequestContext {
	return service.RequestContext{
		IP:        ClientIP(c),
		UserAgent: c.Request.UserAgent(),
		RequestID: RequestIDFrom(c),
	}
}

func newRequestID() string {
	buf := make([]byte, 12)
	if _, err := rand.Read(buf); err != nil {
		return "unknown"
	}
	return base64.RawURLEncoding.EncodeToString(buf)
}
