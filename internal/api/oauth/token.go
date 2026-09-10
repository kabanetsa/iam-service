package oauth

import (
	"net/http"
	"net/url"
	"strings"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"

	"iam-service/internal/api/handlers"
	"iam-service/internal/api/respond"
	"iam-service/internal/config"
	"iam-service/internal/model"
	apierr "iam-service/internal/pkg/errors"
	"iam-service/internal/repository"
	"iam-service/internal/service"
)

// TokenHandler implements the token endpoint: authorization_code, refresh_token
// and client_credentials (RFC 6749 §4, §5).
type TokenHandler struct {
	clients *service.ClientService
	grants  *service.GrantService
	limiter *repository.RateLimitRepo
	metrics service.MetricsRecorder
	cfg     config.Config
	logger  *zap.Logger
}

// NewTokenHandler builds the token endpoint handler.
func NewTokenHandler(
	clients *service.ClientService,
	grants *service.GrantService,
	limiter *repository.RateLimitRepo,
	metrics service.MetricsRecorder,
	cfg config.Config,
	logger *zap.Logger,
) *TokenHandler {
	if metrics == nil {
		metrics = service.NopMetrics{}
	}
	return &TokenHandler{clients: clients, grants: grants, limiter: limiter, metrics: metrics, cfg: cfg, logger: logger}
}

// Token handles POST /oauth/token.
func (h *TokenHandler) Token(c *gin.Context) {
	respond.NoStore(c)

	if contentType := c.ContentType(); contentType != "" && !strings.HasPrefix(contentType, "application/x-www-form-urlencoded") {
		respond.Error(c, apierr.InvalidRequest("the token endpoint requires application/x-www-form-urlencoded"))
		return
	}
	if err := c.Request.ParseForm(); err != nil {
		respond.Error(c, apierr.InvalidRequest("could not parse the request body"))
		return
	}

	grantType := strings.TrimSpace(c.PostForm("grant_type"))
	clientID, clientSecret := clientCredentials(c)

	client, err := h.clients.Authenticate(c.Request.Context(), clientID, clientSecret)
	if err != nil {
		h.metrics.TokenFailure(grantType, apierr.CodeInvalidClient)
		c.Header("WWW-Authenticate", `Basic realm="iam"`)
		respond.Error(c, err)
		return
	}

	if result, limiterErr := h.limiter.Allow(c.Request.Context(),
		"token:client:"+client.ClientID, h.cfg.RateLimit.TokenPerClient, h.cfg.RateLimit.Window); limiterErr != nil {
		h.logger.Warn("rate limiter unavailable", zap.String("error", limiterErr.Error()))
	} else if !result.Allowed {
		h.metrics.TokenFailure(grantType, apierr.CodeRateLimited)
		c.Header("Retry-After", respond.RetryAfter(result.RetryAfter))
		respond.Error(c, apierr.RateLimited("too many token requests, try again later", result.RetryAfter))
		return
	}

	meta := handlers.RequestMeta(c)

	var pair *model.TokenPair
	switch grantType {
	case model.GrantAuthorizationCode:
		pair, err = h.grants.ExchangeCode(c.Request.Context(), client, service.TokenRequestParams{
			GrantType:    grantType,
			Code:         c.PostForm("code"),
			RedirectURI:  c.PostForm("redirect_uri"),
			CodeVerifier: c.PostForm("code_verifier"),
		}, meta)

	case model.GrantRefreshToken:
		pair, err = h.grants.Refresh(c.Request.Context(), client, c.PostForm("refresh_token"), meta)

	case model.GrantClientCredentials:
		if !h.cfg.OAuth.ClientCredentials {
			err = apierr.UnsupportedGrantType("the client_credentials grant is disabled")
			break
		}
		scope, scopeErr := h.clients.ValidateScope(client, c.PostForm("scope"))
		if scopeErr != nil {
			err = scopeErr
			break
		}
		pair, err = h.grants.ClientCredentials(c.Request.Context(), client, scope, meta)

	case "":
		err = apierr.InvalidRequest("grant_type is required")

	default:
		err = apierr.UnsupportedGrantType("unsupported grant_type")
	}

	if err != nil {
		protoErr := apierr.From(err)
		h.metrics.TokenFailure(grantType, protoErr.Code)
		respond.Error(c, protoErr)
		return
	}

	c.JSON(http.StatusOK, pair)
}

// clientCredentials reads client authentication from the Basic header (with the
// URL-decoding required by RFC 6749 §2.3.1) or, failing that, from the form body.
func clientCredentials(c *gin.Context) (string, string) {
	if id, secret, ok := c.Request.BasicAuth(); ok {
		if decoded, err := url.QueryUnescape(id); err == nil {
			id = decoded
		}
		if decoded, err := url.QueryUnescape(secret); err == nil {
			secret = decoded
		}
		return id, secret
	}
	return c.PostForm("client_id"), c.PostForm("client_secret")
}
