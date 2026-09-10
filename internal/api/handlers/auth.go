package handlers

import (
	"errors"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"

	"iam-service/internal/api/respond"
	"iam-service/internal/model"
	apierr "iam-service/internal/pkg/errors"
	"iam-service/internal/repository"
	"iam-service/internal/service"
)

// VerifyMetrics is the metric surface the verify handler reports to.
type VerifyMetrics interface {
	VerifyResult(result string)
}

// VerifyHandler answers the auth_request subrequests of the reverse proxy. It is
// the single decision point for every request that reaches a backend service.
//
// A token is accepted only when the signature verifies, the session still exists
// in Redis (so revocation is immediate) and the account is active. When Redis is
// unreachable the handler fails closed unless the configuration explicitly
// disables that.
type VerifyHandler struct {
	tokens     *service.TokenService
	sessions   *service.SessionService
	metrics    VerifyMetrics
	logger     *zap.Logger
	failClosed bool
}

// NewVerifyHandler builds the verify handler.
func NewVerifyHandler(tokens *service.TokenService, sessions *service.SessionService, metrics VerifyMetrics, logger *zap.Logger, failClosed bool) *VerifyHandler {
	return &VerifyHandler{tokens: tokens, sessions: sessions, metrics: metrics, logger: logger, failClosed: failClosed}
}

// Verify implements GET /verify. Success is a bare 200: the decision travels in
// headers, and the body would only be forwarded to the client by Nginx.
//
// Nginx auth_request understands only 2xx (allow), 401 and 403 (deny); any other
// status becomes a 500 for the client. Every rejection is therefore expressed as
// 401, and an infrastructure outage is flagged with X-Auth-Reason so the proxy
// can answer with an accurate 503 instead.
func (h *VerifyHandler) Verify(c *gin.Context) {
	token := respond.Bearer(c)
	if token == "" {
		h.reject(c, apierr.InvalidToken("missing bearer token"))
		return
	}

	claims, err := h.tokens.VerifyAccess(token)
	if err != nil {
		h.reject(c, apierr.InvalidToken("invalid or expired token").WithCause(err))
		return
	}

	if claims.IsUserToken() && !h.verifyUserSession(c, claims) {
		return
	}

	// Headers consumed by Nginx through auth_request_set and forwarded to the
	// backend services.
	c.Header("X-User-ID", claims.Subject)
	c.Header("X-Client-ID", claims.ClientID)
	c.Header("X-Scopes", claims.Scope)
	if claims.SessionID != "" {
		c.Header("X-Session-ID", claims.SessionID)
	}
	if claims.AuthTime > 0 {
		c.Header("X-Auth-Time", strconv.FormatInt(claims.AuthTime, 10))
	}
	if len(claims.Roles) > 0 {
		c.Header("X-User-Roles", strings.Join(claims.Roles, ","))
	}

	h.metrics.VerifyResult("allowed")
	c.Status(http.StatusOK)
}

func (h *VerifyHandler) verifyUserSession(c *gin.Context, claims *model.AccessClaims) bool {
	ctx := c.Request.Context()

	session, err := h.sessions.Get(ctx, claims.SessionID)
	if err != nil {
		if errors.Is(err, repository.ErrNotFound) {
			h.reject(c, apierr.InvalidToken("session was revoked"))
			return false
		}
		h.dependencyFailure(c, "session store unavailable", err)
		return false
	}
	if session.UserID != claims.Subject {
		h.reject(c, apierr.InvalidToken("token does not match its session"))
		return false
	}
	if session.Expired(time.Now()) {
		h.reject(c, apierr.InvalidToken("session expired"))
		return false
	}

	active, err := h.sessions.IsUserActive(ctx, claims.Subject)
	if err != nil {
		h.dependencyFailure(c, "user store unavailable", err)
		return false
	}
	if !active {
		h.reject(c, apierr.InvalidToken("account is not active"))
		return false
	}
	return true
}

// dependencyFailure enforces the fail-closed policy: a broken dependency must
// never turn into an authorization decision.
//
// The response is pinned to 401 — the only denial Nginx understands — and marked
// with X-Auth-Reason: unavailable, which the proxy turns into a 503 with
// Retry-After. Clients and operators then still see an outage rather than a
// permissions problem.
func (h *VerifyHandler) dependencyFailure(c *gin.Context, message string, cause error) {
	if h.failClosed {
		h.metrics.VerifyResult("unavailable")
		h.logger.Error("verify dependency failure", zap.String("error", cause.Error()))
		c.Header("X-Auth-Reason", "unavailable")
		c.Header("Retry-After", "1")
		respond.NoStore(c)
		c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{
			"error":             apierr.CodeTemporarilyUnavailable,
			"error_description": message,
		})
		return
	}
	h.metrics.VerifyResult("degraded_allow")
	h.logger.Warn("verify dependency failure, allowing request because fail_closed is disabled",
		zap.String("error", cause.Error()))
	c.Status(http.StatusOK)
}

// reject answers a denial. Errors that map to any other status are narrowed to
// 401 with an invalid_token body, because Nginx cannot act on 400/503 from an
// auth subrequest.
func (h *VerifyHandler) reject(c *gin.Context, err error) {
	protoErr := apierr.From(err)
	h.metrics.VerifyResult("rejected")
	h.logger.Debug("verify rejected", zap.String("error", protoErr.Code))

	if status := protoErr.Status(); status != http.StatusUnauthorized && status != http.StatusForbidden {
		c.Header("WWW-Authenticate", apierr.WWWAuthenticate(apierr.InvalidToken(protoErr.Description)))
		if protoErr.RetryAfter > 0 {
			c.Header("Retry-After", strconv.Itoa(int(protoErr.RetryAfter.Seconds())+1))
		}
		respond.NoStore(c)
		c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{
			"error":             apierr.CodeInvalidToken,
			"error_description": protoErr.Description,
		})
		return
	}

	c.Header("WWW-Authenticate", apierr.WWWAuthenticate(protoErr))
	respond.Error(c, protoErr)
}
