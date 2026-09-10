package oauth

import (
	"net/http"
	"net/url"
	"strings"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"

	"iam-service/internal/api/handlers"
	"iam-service/internal/api/respond"
	apierr "iam-service/internal/pkg/errors"
	"iam-service/internal/service"
)

// RevokeHandler implements the token revocation endpoint (RFC 7009).
type RevokeHandler struct {
	clients *service.ClientService
	grants  *service.GrantService
	logger  *zap.Logger
}

// NewRevokeHandler builds the revocation handler.
func NewRevokeHandler(clients *service.ClientService, grants *service.GrantService, logger *zap.Logger) *RevokeHandler {
	return &RevokeHandler{clients: clients, grants: grants, logger: logger}
}

// Revoke handles POST /oauth/revoke. Per RFC 7009 §2.2 the endpoint answers 200
// even for unknown or already revoked tokens: it must not be usable to probe
// token validity.
func (h *RevokeHandler) Revoke(c *gin.Context) {
	respond.NoStore(c)

	if err := c.Request.ParseForm(); err != nil {
		respond.Error(c, apierr.InvalidRequest("could not parse the request body"))
		return
	}
	clientID, clientSecret := clientCredentials(c)
	client, err := h.clients.Authenticate(c.Request.Context(), clientID, clientSecret)
	if err != nil {
		c.Header("WWW-Authenticate", `Basic realm="iam"`)
		respond.Error(c, err)
		return
	}

	token := c.PostForm("token")
	if token == "" {
		respond.Error(c, apierr.InvalidRequest("token is required"))
		return
	}
	if err := h.grants.Revoke(c.Request.Context(), client, token, c.PostForm("token_type_hint"), handlers.RequestMeta(c)); err != nil {
		respond.Error(c, err)
		return
	}
	c.Status(http.StatusOK)
}

// EndSessionHandler implements RP-initiated logout (OpenID Connect
// RP-Initiated Logout). The access token identifies the session to end; a
// post-logout redirect is only honoured when it is a registered redirect URI of
// the client that owns the token.
type EndSessionHandler struct {
	tokens   *service.TokenService
	sessions *service.SessionService
	clients  *service.ClientService
	logger   *zap.Logger
}

// NewEndSessionHandler builds the end-session handler.
func NewEndSessionHandler(tokens *service.TokenService, sessions *service.SessionService, clients *service.ClientService, logger *zap.Logger) *EndSessionHandler {
	return &EndSessionHandler{tokens: tokens, sessions: sessions, clients: clients, logger: logger}
}

// EndSession handles GET /oauth/end_session.
func (h *EndSessionHandler) EndSession(c *gin.Context) {
	respond.NoStore(c)

	token := respond.Bearer(c)
	if token == "" {
		respond.Error(c, apierr.InvalidRequest("bearer access token or id_token_hint is required"))
		return
	}
	claims, err := h.tokens.VerifyAccess(token)
	if err != nil {
		respond.Error(c, apierr.InvalidToken("invalid or expired token"))
		return
	}
	if claims.SessionID == "" {
		respond.Error(c, apierr.InvalidToken("access token is not bound to a user session"))
		return
	}

	if err := h.sessions.Revoke(c.Request.Context(), claims.SessionID); err != nil {
		respond.Error(c, apierr.ServerError("could not end the session").WithCause(err))
		return
	}

	redirectTarget := c.Query("post_logout_redirect_uri")
	if redirectTarget == "" {
		c.Status(http.StatusNoContent)
		return
	}
	client, err := h.clients.Lookup(c.Request.Context(), claims.ClientID)
	if err != nil || !client.IsRegisteredRedirectURI(redirectTarget) {
		h.logger.Warn("rejected post_logout_redirect_uri",
			zap.String("client_id", claims.ClientID),
			zap.String("redirect_uri", redirectTarget))
		c.Status(http.StatusNoContent)
		return
	}

	target, err := url.Parse(redirectTarget)
	if err != nil {
		c.Status(http.StatusNoContent)
		return
	}
	if state := c.Query("state"); state != "" && len(state) <= 512 {
		query := target.Query()
		query.Set("state", strings.TrimSpace(state))
		target.RawQuery = query.Encode()
	}
	c.Redirect(http.StatusFound, target.String())
}
