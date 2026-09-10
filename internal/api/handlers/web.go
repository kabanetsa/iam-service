package handlers

import (
	"crypto/subtle"
	"errors"
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
	"iam-service/internal/web"
)

// WebHandler renders and processes the authorization server's own pages: the
// login form and the consent screen. Both are bound to a pending /authorize
// request (an interaction) and protected by its CSRF token, so neither the
// login nor the consent step can be replayed against another request.
type WebHandler struct {
	pages   web.Pages
	state   *repository.SessionRepo
	auth    *service.AuthService
	clients *service.ClientService
	grants  *service.GrantService
	users   *repository.UserRepo
	audit   *repository.AuditRepo
	metrics service.MetricsRecorder
	cfg     config.OAuthConfig
	logger  *zap.Logger
}

// NewWebHandler builds the page handler.
func NewWebHandler(
	pages web.Pages,
	state *repository.SessionRepo,
	auth *service.AuthService,
	clients *service.ClientService,
	grants *service.GrantService,
	users *repository.UserRepo,
	audit *repository.AuditRepo,
	metrics service.MetricsRecorder,
	cfg config.OAuthConfig,
	logger *zap.Logger,
) *WebHandler {
	if metrics == nil {
		metrics = service.NopMetrics{}
	}
	return &WebHandler{
		pages: pages, state: state, auth: auth, clients: clients, grants: grants,
		users: users, audit: audit, metrics: metrics, cfg: cfg, logger: logger,
	}
}

// pageData is the shape understood by the embedded templates.
type pageData struct {
	Title         string
	ClientName    string
	InteractionID string
	CSRFToken     string
	Email         string
	Error         string
	Scopes        []string
	UserEmail     string
	Message       string
	ErrorCode     string
	BackURL       string
}

// LoginPage renders the login form for a pending interaction.
// GET /login?interaction=<id>
func (h *WebHandler) LoginPage(c *gin.Context) {
	interaction, ok := h.loadInteraction(c, c.Query("interaction"))
	if !ok {
		return
	}
	client, err := h.clients.Lookup(c.Request.Context(), interaction.ClientID)
	if err != nil {
		respond.Error(c, err)
		return
	}
	h.render(c, http.StatusOK, web.PageLogin, pageData{
		Title:         "Вход · ERP Lite",
		ClientName:    client.Name,
		InteractionID: interaction.ID,
		CSRFToken:     interaction.CSRFToken,
	})
}

// LoginSubmit authenticates the user and continues the authorization request.
// POST /login
func (h *WebHandler) LoginSubmit(c *gin.Context) {
	interaction, ok := h.loadInteraction(c, c.PostForm("interaction"))
	if !ok {
		return
	}
	if !validCSRF(c.PostForm("csrf_token"), interaction.CSRFToken) {
		h.renderError(c, http.StatusBadRequest, "Сессия входа истекла", "Форма была открыта в другой вкладке или устарела. Начните вход заново.", "invalid_csrf", "")
		return
	}
	client, err := h.clients.Lookup(c.Request.Context(), interaction.ClientID)
	if err != nil {
		respond.Error(c, err)
		return
	}

	result, err := h.auth.Authenticate(c.Request.Context(), service.LoginInput{
		Email:     c.PostForm("email"),
		Password:  c.PostForm("password"),
		IP:        ClientIP(c),
		UserAgent: c.Request.UserAgent(),
		RequestID: RequestIDFrom(c),
	})
	if err != nil {
		protoErr := apierr.From(err)
		h.metrics.LoginAttempt(protoErr.Code)
		h.render(c, protoErr.Status(), web.PageLogin, pageData{
			Title:         "Вход · ERP Lite",
			ClientName:    client.Name,
			InteractionID: interaction.ID,
			CSRFToken:     interaction.CSRFToken,
			Email:         strings.TrimSpace(c.PostForm("email")),
			Error:         protoErr.Description,
		})
		return
	}
	h.metrics.LoginAttempt("success")

	interaction.AuthenticatedUserID = result.User.ID
	if err := h.state.SaveInteraction(c.Request.Context(), interaction.ID, interaction, h.cfg.InteractionTTL); err != nil {
		respond.Error(c, apierr.ServerError("could not continue the authorization request").WithCause(err))
		return
	}

	if h.clients.RequiresConsent(client, h.cfg.RequireConsentDefault) {
		c.Redirect(http.StatusFound, "/consent?interaction="+url.QueryEscape(interaction.ID))
		return
	}
	h.completeAuthorization(c, interaction, client, result.User)
}

// ConsentPage renders the consent screen for an authenticated interaction.
// GET /consent?interaction=<id>
func (h *WebHandler) ConsentPage(c *gin.Context) {
	interaction, ok := h.loadInteraction(c, c.Query("interaction"))
	if !ok {
		return
	}
	client, err := h.clients.Lookup(c.Request.Context(), interaction.ClientID)
	if err != nil {
		respond.Error(c, err)
		return
	}
	if interaction.AuthenticatedUserID == "" {
		c.Redirect(http.StatusFound, "/login?interaction="+url.QueryEscape(interaction.ID))
		return
	}
	h.render(c, http.StatusOK, web.PageConsent, pageData{
		Title:         "Согласие на доступ · ERP Lite",
		ClientName:    client.Name,
		InteractionID: interaction.ID,
		CSRFToken:     interaction.CSRFToken,
		Scopes:        describeScopes(interaction.Scope),
		UserEmail:     h.userEmail(c, interaction.AuthenticatedUserID),
	})
}

// ConsentSubmit applies the consent decision.
// POST /consent
func (h *WebHandler) ConsentSubmit(c *gin.Context) {
	interaction, ok := h.loadInteraction(c, c.PostForm("interaction"))
	if !ok {
		return
	}
	if !validCSRF(c.PostForm("csrf_token"), interaction.CSRFToken) {
		h.renderError(c, http.StatusBadRequest, "Сессия истекла", "Повторите вход.", "invalid_csrf", "")
		return
	}
	client, err := h.clients.Lookup(c.Request.Context(), interaction.ClientID)
	if err != nil {
		respond.Error(c, err)
		return
	}
	if interaction.AuthenticatedUserID == "" {
		c.Redirect(http.StatusFound, "/login?interaction="+url.QueryEscape(interaction.ID))
		return
	}

	user, err := h.users.ByID(c.Request.Context(), interaction.AuthenticatedUserID)
	if err != nil {
		respond.Error(c, apierr.ServerError("could not load user").WithCause(err))
		return
	}

	if c.PostForm("decision") != "allow" {
		h.recordConsentDenied(c, interaction)
		h.redirectWithError(c, interaction, apierr.AccessDenied("the user denied the request"))
		return
	}
	h.completeAuthorization(c, interaction, client, user)
}

// completeAuthorization issues the code and redirects back to the client.
func (h *WebHandler) completeAuthorization(c *gin.Context, interaction *model.Interaction, client *model.OAuthClient, user *model.User) {
	code, err := h.grants.IssueCode(c.Request.Context(), client, user, interaction, RequestMeta(c))
	if err != nil {
		respond.Error(c, err)
		return
	}
	if err := h.state.DeleteInteraction(c.Request.Context(), interaction.ID); err != nil {
		h.logger.Warn("failed to delete interaction", zap.String("error", err.Error()))
	}

	target, err := url.Parse(interaction.RedirectURI)
	if err != nil {
		respond.Error(c, apierr.ServerError("registered redirect_uri is not a valid URL").WithCause(err))
		return
	}
	query := target.Query()
	query.Set("code", code)
	if interaction.State != "" {
		query.Set("state", interaction.State)
	}
	target.RawQuery = query.Encode()

	c.Header("Cache-Control", "no-store")
	c.Redirect(http.StatusFound, target.String())
}

// redirectWithError implements the error redirect of RFC 6749 §4.1.2.1.
func (h *WebHandler) redirectWithError(c *gin.Context, interaction *model.Interaction, err error) {
	protoErr := apierr.From(err)
	target, parseErr := url.Parse(interaction.RedirectURI)
	if parseErr != nil {
		respond.Error(c, protoErr)
		return
	}
	query := target.Query()
	query.Set("error", protoErr.Code)
	if protoErr.Description != "" {
		query.Set("error_description", protoErr.Description)
	}
	if interaction.State != "" {
		query.Set("state", interaction.State)
	}
	target.RawQuery = query.Encode()
	c.Header("Cache-Control", "no-store")
	c.Redirect(http.StatusFound, target.String())
}

func (h *WebHandler) recordConsentDenied(c *gin.Context, interaction *model.Interaction) {
	meta := RequestMeta(c)
	event := model.NewAuthEvent(model.EventConsentDenied, false).
		WithUser(interaction.AuthenticatedUserID).
		WithClient(interaction.ClientID).
		WithIP(meta.IP).
		WithAgent(meta.UserAgent).
		WithRequest(meta.RequestID).
		WithError("access_denied")
	if err := h.audit.Insert(c.Request.Context(), event); err != nil {
		h.logger.Warn("audit write failed", zap.String("event", model.EventConsentDenied), zap.String("error", err.Error()))
	}
}

// loadInteraction resolves a pending interaction, answering with a helpful page
// when it expired or was tampered with.
func (h *WebHandler) loadInteraction(c *gin.Context, id string) (*model.Interaction, bool) {
	id = strings.TrimSpace(id)
	if id == "" || len(id) > 128 {
		h.renderError(c, http.StatusBadRequest, "Запрос недействителен", "Параметр interaction отсутствует.", "invalid_request", "")
		return nil, false
	}
	interaction, err := h.state.GetInteraction(c.Request.Context(), id)
	if err != nil {
		if errors.Is(err, repository.ErrNotFound) {
			h.renderError(c, http.StatusGone, "Сессия входа истекла",
				"Запрос на вход устарел. Вернитесь в приложение и попробуйте снова.", "interaction_expired", "")
			return nil, false
		}
		respond.Error(c, apierr.ServerError("could not load the authorization request").WithCause(err))
		return nil, false
	}
	return interaction, true
}

func (h *WebHandler) userEmail(c *gin.Context, userID string) string {
	user, err := h.users.ByID(c.Request.Context(), userID)
	if err != nil {
		return ""
	}
	return user.Email
}

func (h *WebHandler) render(c *gin.Context, status int, page string, data pageData) {
	c.Header("Content-Type", "text/html; charset=utf-8")
	c.Header("Cache-Control", "no-store")
	c.Status(status)
	if err := h.pages.Render(c.Writer, page, data); err != nil {
		h.logger.Error("template rendering failed", zap.String("page", page), zap.String("error", err.Error()))
	}
}

func (h *WebHandler) renderError(c *gin.Context, status int, title, message, code, backURL string) {
	h.render(c, status, web.PageError, pageData{
		Title:     title + " · ERP Lite",
		Message:   message,
		ErrorCode: code,
		BackURL:   backURL,
	})
}

func validCSRF(presented, expected string) bool {
	if presented == "" || expected == "" {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(presented), []byte(expected)) == 1
}

// describeScopes renders human-readable consent lines.
func describeScopes(scope string) []string {
	descriptions := map[string]string{
		model.ScopeOpenID:        "Подтвердить вашу личность (идентификатор пользователя)",
		model.ScopeProfile:       "Имя и логин в системе",
		model.ScopeEmail:         "Адрес электронной почты",
		model.ScopeOfflineAccess: "Доступ без повторного входа (долгоживущая сессия)",
	}
	scopes := model.SplitScope(scope)
	out := make([]string, 0, len(scopes))
	for _, s := range scopes {
		if text, ok := descriptions[s]; ok {
			out = append(out, text)
			continue
		}
		out = append(out, s)
	}
	return out
}
