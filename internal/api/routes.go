// Package api wires the HTTP surface of the service.
package api

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"

	"iam-service/internal/api/handlers"
	"iam-service/internal/api/oauth"
	"iam-service/internal/config"
	"iam-service/internal/repository"
	"iam-service/internal/service"
	"iam-service/internal/web"
	"iam-service/pkg/observability"
)

// RouterDeps is everything the router needs, built once in main so that the
// wiring stays explicit and testable.
type RouterDeps struct {
	Config  *config.Config
	Logger  *zap.Logger
	Metrics *observability.Metrics

	Auth     *service.AuthService
	Clients  *service.ClientService
	Tokens   *service.TokenService
	Sessions *service.SessionService
	Grants   *service.GrantService
	OIDC     *service.OIDCService

	Users   *repository.UserRepo
	State   *repository.SessionRepo
	Limiter *repository.RateLimitRepo
	Audit   *repository.AuditRepo

	Pages web.Pages

	// Dependencies probed by /readyz.
	Postgres observability.Pinger
	Redis    observability.Pinger
	Version  string
}

// NewRouter builds the gin engine with every route of the service.
func NewRouter(deps RouterDeps) (*gin.Engine, error) {
	cfg := deps.Config

	router := gin.New()
	router.Use(
		gin.Recovery(),
		handlers.RequestID(),
		handlers.SecurityHeaders(),
		handlers.BodyLimit(cfg.Server.MaxBodyBytes),
		handlers.Logger(deps.Logger),
		deps.Metrics.HTTPMiddleware(),
	)
	// Client addresses are only trusted when they come from the reverse proxy;
	// otherwise X-Forwarded-For would let anybody evade the rate limiter.
	if err := router.SetTrustedProxies(cfg.Server.TrustedProxies); err != nil {
		return nil, err
	}

	verifyHandler := handlers.NewVerifyHandler(deps.Tokens, deps.Sessions, deps.Metrics, deps.Logger, cfg.Redis.FailClosed)
	authorizeHandler := oauth.NewAuthorizeHandler(deps.Clients, deps.State, deps.Limiter, deps.Audit, deps.Metrics, *cfg, deps.Logger)
	tokenHandler := oauth.NewTokenHandler(deps.Clients, deps.Grants, deps.Limiter, deps.Metrics, *cfg, deps.Logger)
	userInfoHandler := oauth.NewUserInfoHandler(deps.Tokens, deps.Sessions, deps.OIDC, deps.Logger)
	documentsHandler := oauth.NewDocumentsHandler(deps.OIDC)
	revokeHandler := oauth.NewRevokeHandler(deps.Clients, deps.Grants, deps.Logger)
	endSessionHandler := oauth.NewEndSessionHandler(deps.Tokens, deps.Sessions, deps.Clients, deps.Logger)
	sessionHandler := handlers.NewSessionHandler(deps.Tokens, deps.Sessions, deps.Audit, deps.Logger)
	webHandler := handlers.NewWebHandler(deps.Pages, deps.State, deps.Auth, deps.Clients, deps.Grants, deps.Users, deps.Audit, deps.Metrics, cfg.OAuth, deps.Logger)

	health := &observability.Health{
		Postgres: deps.Postgres,
		Redis:    deps.Redis,
		Timeout:  cfg.Database.HealthTimeout,
		Version:  deps.Version,
	}
	router.GET("/healthz", gin.WrapF(health.Live))
	router.GET("/readyz", gin.WrapF(health.Ready))

	router.GET("/.well-known/openid-configuration", documentsHandler.Discovery)
	router.GET("/.well-known/jwks.json", documentsHandler.JWKS)

	// Internal endpoint used by Nginx auth_request. The reverse proxy must deny
	// it on the public listener; it is never meant to be called by clients.
	router.GET("/verify", verifyHandler.Verify)

	oauthGroup := router.Group("/oauth")
	{
		oauthGroup.GET("/authorize", authorizeHandler.Authorize)
		oauthGroup.POST("/token", tokenHandler.Token)
		oauthGroup.GET("/userinfo", userInfoHandler.UserInfo)
		oauthGroup.POST("/userinfo", userInfoHandler.UserInfo)
		oauthGroup.POST("/revoke", revokeHandler.Revoke)
		oauthGroup.POST("/logout", sessionHandler.Logout)
		oauthGroup.GET("/end_session", endSessionHandler.EndSession)
	}

	router.GET("/login", webHandler.LoginPage)
	router.POST("/login", webHandler.LoginSubmit)
	router.GET("/consent", webHandler.ConsentPage)
	router.POST("/consent", webHandler.ConsentSubmit)

	api := router.Group("/api/v1")
	{
		api.GET("/sessions", sessionHandler.List)
		api.POST("/sessions/logout-all", sessionHandler.LogoutAll)
	}

	router.NoRoute(func(c *gin.Context) {
		c.JSON(http.StatusNotFound, gin.H{"error": "not_found"})
	})

	return router, nil
}
