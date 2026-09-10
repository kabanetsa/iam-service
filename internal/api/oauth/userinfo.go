package oauth

import (
	"errors"
	"net/http"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"

	"iam-service/internal/api/respond"
	apierr "iam-service/internal/pkg/errors"
	"iam-service/internal/repository"
	"iam-service/internal/service"
)

// UserInfoHandler implements the OIDC userinfo endpoint.
type UserInfoHandler struct {
	tokens   *service.TokenService
	sessions *service.SessionService
	oidc     *service.OIDCService
	logger   *zap.Logger
}

// NewUserInfoHandler builds the userinfo handler.
func NewUserInfoHandler(tokens *service.TokenService, sessions *service.SessionService, oidc *service.OIDCService, logger *zap.Logger) *UserInfoHandler {
	return &UserInfoHandler{tokens: tokens, sessions: sessions, oidc: oidc, logger: logger}
}

// UserInfo handles GET/POST /oauth/userinfo.
func (h *UserInfoHandler) UserInfo(c *gin.Context) {
	respond.NoStore(c)

	token := respond.Bearer(c)
	if token == "" {
		h.unauthorized(c, apierr.InvalidToken("missing bearer token"))
		return
	}

	claims, err := h.tokens.VerifyAccess(token)
	if err != nil {
		h.unauthorized(c, apierr.InvalidToken("invalid or expired token"))
		return
	}
	if claims.SessionID != "" {
		if _, err := h.sessions.Get(c.Request.Context(), claims.SessionID); err != nil {
			if errors.Is(err, repository.ErrNotFound) {
				h.unauthorized(c, apierr.InvalidToken("session was revoked"))
				return
			}
			respond.Error(c, apierr.ServerError("could not read session").WithCause(err))
			return
		}
	}

	info, err := h.oidc.UserInfo(c.Request.Context(), claims)
	if err != nil {
		h.unauthorized(c, err)
		return
	}
	c.JSON(http.StatusOK, info)
}

func (h *UserInfoHandler) unauthorized(c *gin.Context, err error) {
	protoErr := apierr.From(err)
	c.Header("WWW-Authenticate", apierr.WWWAuthenticate(protoErr))
	respond.Error(c, protoErr)
}
