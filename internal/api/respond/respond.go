// Package respond holds the small response helpers shared by the HTTP handlers:
// protocol error rendering, no-store marking and bearer token extraction.
package respond

import (
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/gin-gonic/gin"

	apierr "iam-service/internal/pkg/errors"
)

// NoStore marks a response as uncacheable. Every token and authorization
// response must carry it (RFC 6749 §5.1).
func NoStore(c *gin.Context) {
	c.Header("Cache-Control", "no-store")
	c.Header("Pragma", "no-cache")
}

// Error renders a protocol error as JSON with the matching status code. The
// public payload only ever contains the error code and a safe description.
func Error(c *gin.Context, err error) {
	protoErr := apierr.From(err)
	if protoErr == nil {
		protoErr = apierr.ServerError("an internal error occurred")
	}
	NoStore(c)
	if protoErr.RetryAfter > 0 {
		c.Header("Retry-After", RetryAfter(protoErr.RetryAfter))
	}
	c.AbortWithStatusJSON(protoErr.Status(), gin.H{
		"error":             protoErr.Code,
		"error_description": protoErr.Description,
	})
}

// Bearer extracts the token of an Authorization: Bearer header.
func Bearer(c *gin.Context) string {
	header := c.GetHeader("Authorization")
	const prefix = "Bearer "
	if len(header) <= len(prefix) || !strings.EqualFold(header[:len(prefix)], prefix) {
		return ""
	}
	return strings.TrimSpace(header[len(prefix):])
}

// RetryAfter renders a duration as whole seconds, never below one.
func RetryAfter(d time.Duration) string {
	seconds := int(d.Seconds())
	if seconds < 1 {
		seconds = 1
	}
	return strconv.Itoa(seconds)
}

// JSON writes a JSON payload with the standard content type.
func JSON(c *gin.Context, status int, payload any) {
	c.JSON(status, payload)
}

// HTML writes an HTML body.
func HTML(c *gin.Context, status int, body string) {
	c.Header("Content-Type", "text/html; charset=utf-8")
	c.String(status, body)
}

// StatusNoContent is re-exported to keep handlers free of net/http constants in
// the common "nothing to say" case.
const StatusNoContent = http.StatusNoContent
