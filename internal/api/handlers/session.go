package handlers

import (
	"errors"
	"net/http"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"

	"iam-service/internal/api/respond"
	"iam-service/internal/model"
	apierr "iam-service/internal/pkg/errors"
	"iam-service/internal/repository"
	"iam-service/internal/service"
)

// SessionHandler exposes the session management endpoints that use a user token
// rather than the OAuth protocol.
type SessionHandler struct {
	tokens   *service.TokenService
	sessions *service.SessionService
	audit    *repository.AuditRepo
	logger   *zap.Logger
}

// NewSessionHandler builds the session handler.
func NewSessionHandler(tokens *service.TokenService, sessions *service.SessionService, audit *repository.AuditRepo, logger *zap.Logger) *SessionHandler {
	return &SessionHandler{tokens: tokens, sessions: sessions, audit: audit, logger: logger}
}

// Logout revokes the session behind the presented access token.
// POST /oauth/logout
func (h *SessionHandler) Logout(c *gin.Context) {
	claims, ok := h.claims(c)
	if !ok {
		return
	}
	if claims.SessionID == "" {
		// A client_credentials token has no session; there is nothing to revoke.
		c.Status(http.StatusNoContent)
		return
	}
	if err := h.sessions.Revoke(c.Request.Context(), claims.SessionID); err != nil {
		respond.Error(c, apierr.ServerError("could not revoke session").WithCause(err))
		return
	}
	h.record(c, model.EventLogout, claims)
	c.Status(http.StatusNoContent)
}

// LogoutAll revokes every session of the authenticated user.
// POST /api/v1/sessions/logout-all
func (h *SessionHandler) LogoutAll(c *gin.Context) {
	claims, ok := h.claims(c)
	if !ok {
		return
	}
	if claims.SessionID == "" {
		respond.Error(c, apierr.InvalidToken("access token is not bound to a user"))
		return
	}
	revoked, err := h.sessions.RevokeAll(c.Request.Context(), claims.Subject)
	if err != nil {
		respond.Error(c, apierr.ServerError("could not revoke sessions").WithCause(err))
		return
	}
	h.record(c, model.EventSessionsRevokedAll, claims)
	c.JSON(http.StatusOK, gin.H{"revoked_sessions": revoked})
}

// List returns the live sessions of the authenticated user.
// GET /api/v1/sessions
func (h *SessionHandler) List(c *gin.Context) {
	claims, ok := h.claims(c)
	if !ok {
		return
	}
	if claims.SessionID == "" {
		respond.Error(c, apierr.InvalidToken("access token is not bound to a user"))
		return
	}
	sessions, err := h.sessions.List(c.Request.Context(), claims.Subject)
	if err != nil {
		respond.Error(c, apierr.ServerError("could not list sessions").WithCause(err))
		return
	}

	type sessionView struct {
		ID        string `json:"id"`
		ClientID  string `json:"client_id"`
		Scope     string `json:"scope"`
		IP        string `json:"ip,omitempty"`
		UserAgent string `json:"user_agent,omitempty"`
		CreatedAt string `json:"created_at"`
		ExpiresAt string `json:"expires_at"`
		Current   bool   `json:"current"`
	}
	views := make([]sessionView, 0, len(sessions))
	for _, session := range sessions {
		views = append(views, sessionView{
			ID:        session.ID,
			ClientID:  session.ClientID,
			Scope:     session.Scope,
			IP:        session.IPAddress,
			UserAgent: session.UserAgent,
			CreatedAt: session.CreatedAt.UTC().Format("2006-01-02T15:04:05Z07:00"),
			ExpiresAt: session.ExpiresAt.UTC().Format("2006-01-02T15:04:05Z07:00"),
			Current:   session.ID == claims.SessionID,
		})
	}
	c.JSON(http.StatusOK, gin.H{"sessions": views})
}

// claims validates the bearer token of a session endpoint and answers 401 itself
// when it is not usable.
func (h *SessionHandler) claims(c *gin.Context) (*model.AccessClaims, bool) {
	token := respond.Bearer(c)
	if token == "" {
		c.Header("WWW-Authenticate", `Bearer realm="iam"`)
		respond.Error(c, apierr.InvalidToken("missing bearer token"))
		return nil, false
	}
	claims, err := h.tokens.VerifyAccess(token)
	if err != nil {
		c.Header("WWW-Authenticate", apierr.WWWAuthenticate(apierr.InvalidToken("invalid or expired token")))
		respond.Error(c, apierr.InvalidToken("invalid or expired token"))
		return nil, false
	}
	if claims.SessionID != "" {
		if _, err := h.sessions.Get(c.Request.Context(), claims.SessionID); err != nil {
			if errors.Is(err, repository.ErrNotFound) {
				c.Header("WWW-Authenticate", apierr.WWWAuthenticate(apierr.InvalidToken("session was revoked")))
				respond.Error(c, apierr.InvalidToken("session was revoked"))
				return nil, false
			}
			respond.Error(c, apierr.ServerError("could not read session").WithCause(err))
			return nil, false
		}
	}
	return claims, true
}

func (h *SessionHandler) record(c *gin.Context, eventType string, claims *model.AccessClaims) {
	meta := RequestMeta(c)
	event := model.NewAuthEvent(eventType, true).
		WithUser(claims.Subject).
		WithClient(claims.ClientID).
		WithSession(claims.SessionID).
		WithIP(meta.IP).
		WithAgent(meta.UserAgent).
		WithRequest(meta.RequestID)
	if err := h.audit.Insert(c.Request.Context(), event); err != nil {
		h.logger.Warn("audit write failed", zap.String("event", eventType), zap.String("error", err.Error()))
	}
}
