// Package oauth implements the protocol endpoints of the authorization server:
// /oauth/authorize, /oauth/token, /oauth/userinfo, /oauth/revoke,
// /oauth/end_session and the discovery/JWKS documents.
package oauth

import (
	"context"
	"net/http"
	"net/url"
	"strings"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"

	"iam-service/internal/api/respond"
	"iam-service/internal/config"
	"iam-service/internal/model"
	apierr "iam-service/internal/pkg/errors"
	"iam-service/internal/repository"
	"iam-service/internal/service"
)

// AuthorizeHandler implements the authorization endpoint (RFC 6749 §4.1,
// OAuth 2.1 §4.1 with mandatory PKCE).
type AuthorizeHandler struct {
	clients *service.ClientService
	state   *repository.SessionRepo
	limiter *repository.RateLimitRepo
	audit   *repository.AuditRepo
	metrics service.MetricsRecorder
	cfg     config.Config
	logger  *zap.Logger
}

// NewAuthorizeHandler builds the authorization endpoint handler.
func NewAuthorizeHandler(
	clients *service.ClientService,
	state *repository.SessionRepo,
	limiter *repository.RateLimitRepo,
	audit *repository.AuditRepo,
	metrics service.MetricsRecorder,
	cfg config.Config,
	logger *zap.Logger,
) *AuthorizeHandler {
	if metrics == nil {
		metrics = service.NopMetrics{}
	}
	return &AuthorizeHandler{clients: clients, state: state, limiter: limiter, audit: audit, metrics: metrics, cfg: cfg, logger: logger}
}

// Authorize starts an authorization code flow. It validates the request against
// the client registration, stores the pending request as an interaction and
// hands over to the login page.
func (h *AuthorizeHandler) Authorize(c *gin.Context) {
	ctx := c.Request.Context()

	if result, err := h.limiter.Allow(ctx, "authorize:ip:"+c.ClientIP(), h.cfg.RateLimit.AuthorizePerIP, h.cfg.RateLimit.Window); err != nil {
		h.logger.Warn("rate limiter unavailable", zap.String("error", err.Error()))
	} else if !result.Allowed {
		c.Header("Retry-After", respond.RetryAfter(result.RetryAfter))
		respond.Error(c, apierr.RateLimited("too many authorization requests, try again later", result.RetryAfter))
		return
	}

	query := c.Request.URL.Query()
	clientID := strings.TrimSpace(query.Get("client_id"))
	redirectURI := query.Get("redirect_uri")
	state := query.Get("state")

	// Until the client is known and the redirect URI is verified, errors must be
	// rendered locally: redirecting to an unverified URI would turn this endpoint
	// into an open redirector (RFC 6749 §4.1.2.1).
	client, err := h.clients.Lookup(ctx, clientID)
	if err != nil {
		respond.Error(c, err)
		return
	}
	if !client.IsRegisteredRedirectURI(redirectURI) {
		h.auditRejection(ctx, clientID, "unregistered_redirect_uri")
		respond.Error(c, apierr.InvalidRequest("redirect_uri is not registered for this client"))
		return
	}

	responseType := query.Get("response_type")
	if responseType != model.ResponseTypeCode {
		h.auditRejection(ctx, clientID, "unsupported_response_type")
		h.redirectError(c, redirectURI, state, apierr.UnsupportedResponseType("only response_type=code is supported"))
		return
	}

	challenge := strings.TrimSpace(query.Get("code_challenge"))
	method := strings.TrimSpace(query.Get("code_challenge_method"))
	if challenge == "" || method != model.PKCEMethodS256 {
		h.auditRejection(ctx, clientID, "invalid_pkce")
		h.redirectError(c, redirectURI, state, apierr.InvalidRequest("code_challenge with code_challenge_method=S256 is required"))
		return
	}
	if len(challenge) < 43 || len(challenge) > 128 {
		h.auditRejection(ctx, clientID, "invalid_pkce_length")
		h.redirectError(c, redirectURI, state, apierr.InvalidRequest("code_challenge length is not within 43..128 characters"))
		return
	}

	scope, err := h.clients.ValidateScope(client, query.Get("scope"))
	if err != nil {
		h.auditRejection(ctx, clientID, "invalid_scope")
		h.redirectError(c, redirectURI, state, err)
		return
	}

	nonce := query.Get("nonce")
	if len(nonce) > 512 || len(state) > 512 {
		h.redirectError(c, redirectURI, state, apierr.InvalidRequest("state and nonce must not exceed 512 characters"))
		return
	}

	interactionID, err := service.NewOpaqueToken(24)
	if err != nil {
		respond.Error(c, apierr.ServerError("could not start the authorization request").WithCause(err))
		return
	}
	csrfToken, err := service.NewOpaqueToken(24)
	if err != nil {
		respond.Error(c, apierr.ServerError("could not start the authorization request").WithCause(err))
		return
	}

	interaction := &model.Interaction{
		ID:                  interactionID,
		ClientID:            client.ClientID,
		RedirectURI:         redirectURI,
		Scope:               scope,
		State:               state,
		Nonce:               nonce,
		CodeChallenge:       challenge,
		CodeChallengeMethod: method,
		CSRFToken:           csrfToken,
	}
	if err := h.state.SaveInteraction(ctx, interactionID, interaction, h.cfg.OAuth.InteractionTTL); err != nil {
		respond.Error(c, apierr.ServerError("could not start the authorization request").WithCause(err))
		return
	}

	c.Header("Cache-Control", "no-store")
	c.Redirect(http.StatusFound, "/login?interaction="+url.QueryEscape(interactionID))
}

// redirectError returns an error to the client via the validated redirect URI.
func (h *AuthorizeHandler) redirectError(c *gin.Context, redirectURI, state string, err error) {
	protoErr := apierr.From(err)
	target, parseErr := url.Parse(redirectURI)
	if parseErr != nil {
		respond.Error(c, protoErr)
		return
	}
	query := target.Query()
	query.Set("error", protoErr.Code)
	if protoErr.Description != "" {
		query.Set("error_description", protoErr.Description)
	}
	if state != "" {
		query.Set("state", state)
	}
	target.RawQuery = query.Encode()
	c.Header("Cache-Control", "no-store")
	c.Redirect(http.StatusFound, target.String())
}

func (h *AuthorizeHandler) auditRejection(ctx context.Context, clientID, reason string) {
	if h.audit == nil {
		return
	}
	event := model.NewAuthEvent(model.EventInvalidAuthorize, false).WithClient(clientID).WithError(reason)
	if err := h.audit.Insert(ctx, event); err != nil {
		h.logger.Warn("audit write failed", zap.String("event", model.EventInvalidAuthorize), zap.String("error", err.Error()))
	}
}
