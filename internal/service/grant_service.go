package service

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"net/netip"
	"time"

	"go.uber.org/zap"

	"iam-service/internal/config"
	"iam-service/internal/model"
	apierr "iam-service/internal/pkg/errors"
	"iam-service/internal/repository"
)

// MetricsRecorder is the slice of the metric set the services report to.
type MetricsRecorder interface {
	TokenIssued(grantType, clientID string)
	TokenFailure(grantType, errorCode string)
	RefreshReuseDetected()
	LoginAttempt(result string)
}

// NopMetrics discards all metrics.
type NopMetrics struct{}

func (NopMetrics) TokenIssued(string, string)  {}
func (NopMetrics) TokenFailure(string, string) {}
func (NopMetrics) RefreshReuseDetected()       {}
func (NopMetrics) LoginAttempt(string)         {}

// GrantService implements the token endpoint grants: authorization_code with
// PKCE, refresh_token with rotation and reuse detection, and client_credentials.
type GrantService struct {
	clients  *repository.ClientRepo
	users    *repository.UserRepo
	state    *repository.SessionRepo
	limiter  *repository.RateLimitRepo
	sessions *SessionService
	tokens   *TokenService
	audit    *repository.AuditRepo
	metrics  MetricsRecorder
	cfg      config.OAuthConfig
	logger   *zap.Logger
	now      func() time.Time
}

// NewGrantService builds the grant service.
func NewGrantService(
	clients *repository.ClientRepo,
	users *repository.UserRepo,
	state *repository.SessionRepo,
	limiter *repository.RateLimitRepo,
	sessions *SessionService,
	tokens *TokenService,
	audit *repository.AuditRepo,
	metrics MetricsRecorder,
	cfg config.OAuthConfig,
	logger *zap.Logger,
) *GrantService {
	if metrics == nil {
		metrics = NopMetrics{}
	}
	return &GrantService{
		clients: clients, users: users, state: state, limiter: limiter,
		sessions: sessions, tokens: tokens, audit: audit, metrics: metrics,
		cfg: cfg, logger: logger, now: time.Now,
	}
}

// RequestContext carries the request metadata recorded in the audit trail.
type RequestContext struct {
	IP        netip.Addr
	UserAgent string
	RequestID string
}

// TokenRequestParams is a parsed, form-decoded token request.
type TokenRequestParams struct {
	GrantType    string
	Code         string
	RedirectURI  string
	CodeVerifier string
	RefreshToken string
	Scope        string
}

// --- authorization code -----------------------------------------------------

// IssueCode creates an authorization code for an authenticated user. The code is
// stored under its hash, bound to the client, redirect URI, scope and PKCE
// challenge of the request.
func (s *GrantService) IssueCode(ctx context.Context, client *model.OAuthClient, user *model.User, interaction *model.Interaction, reqCtx RequestContext) (string, error) {
	code, err := NewOpaqueToken(32)
	if err != nil {
		return "", apierr.ServerError("could not issue authorization code").WithCause(err)
	}
	now := s.now()
	payload := &model.AuthorizationCode{
		ClientID:            client.ClientID,
		UserID:              user.ID,
		RedirectURI:         interaction.RedirectURI,
		Scope:               interaction.Scope,
		CodeChallenge:       interaction.CodeChallenge,
		CodeChallengeMethod: interaction.CodeChallengeMethod,
		Nonce:               interaction.Nonce,
		AuthTime:            now,
		IssuedAt:            now,
	}
	if err := s.state.SaveCode(ctx, code, payload, s.cfg.CodeTTL); err != nil {
		return "", apierr.ServerError("could not store authorization code").WithCause(err)
	}

	s.auditEvent(ctx, reqCtx, model.NewAuthEvent(model.EventCodeIssued, true).
		WithUser(user.ID).WithClient(client.ClientID))
	return code, nil
}

// ExchangeCode redeems an authorization code: it validates the code, the client
// binding, the redirect URI and the PKCE verifier, then creates the session and
// issues the token set.
func (s *GrantService) ExchangeCode(ctx context.Context, client *model.OAuthClient, params TokenRequestParams, reqCtx RequestContext) (*model.TokenPair, error) {
	stored, err := s.state.ConsumeCode(ctx, params.Code)
	if err != nil {
		if errors.Is(err, repository.ErrNotFound) {
			// Either unknown or already consumed. A consumed code is a strong
			// signal of theft, but its family is bound at redemption time, so
			// nothing else can be revoked here.
			s.auditEvent(ctx, reqCtx, model.NewAuthEvent(model.EventCodeReused, false).
				WithClient(client.ClientID).WithError("unknown_or_used_code"))
			return nil, s.grantFailure(client, model.GrantAuthorizationCode, apierr.InvalidGrant("authorization code is invalid, expired or already used"))
		}
		return nil, apierr.ServerError("could not redeem authorization code").WithCause(err)
	}
	if stored.ClientID != client.ClientID {
		return nil, s.grantFailure(client, model.GrantAuthorizationCode, apierr.InvalidGrant("authorization code was issued to another client"))
	}
	if stored.RedirectURI != params.RedirectURI {
		return nil, s.grantFailure(client, model.GrantAuthorizationCode, apierr.InvalidGrant("redirect_uri does not match the authorization request"))
	}
	if err := verifyPKCE(stored.CodeChallenge, params.CodeVerifier); err != nil {
		return nil, s.grantFailure(client, model.GrantAuthorizationCode, err)
	}

	user, err := s.users.ByID(ctx, stored.UserID)
	if err != nil {
		if errors.Is(err, repository.ErrNotFound) {
			return nil, s.grantFailure(client, model.GrantAuthorizationCode, apierr.InvalidGrant("user no longer exists"))
		}
		return nil, apierr.ServerError("could not load user").WithCause(err)
	}
	if !user.IsActive() {
		return nil, s.grantFailure(client, model.GrantAuthorizationCode, apierr.AccessDenied("account is not active"))
	}
	roles, err := s.users.Roles(ctx, user.ID)
	if err != nil && s.logger != nil {
		s.logger.Warn("failed to load roles", zap.String("error", err.Error()))
	}

	now := s.now()
	sid, err := NewOpaqueToken(24)
	if err != nil {
		return nil, apierr.ServerError("could not create session").WithCause(err)
	}
	familyID, err := NewOpaqueToken(24)
	if err != nil {
		return nil, apierr.ServerError("could not create session").WithCause(err)
	}

	sessionTTL := s.tokens.RefreshTTL(client)
	session := &model.Session{
		ID:        sid,
		UserID:    user.ID,
		ClientID:  client.ClientID,
		FamilyID:  familyID,
		Scope:     stored.Scope,
		AuthTime:  stored.AuthTime,
		IPAddress: ipString(reqCtx.IP),
		UserAgent: truncateUA(reqCtx.UserAgent),
		CreatedAt: now,
		ExpiresAt: now.Add(sessionTTL),
	}
	if _, err := s.sessions.Create(ctx, session, sessionTTL); err != nil {
		return nil, apierr.ServerError("could not create session").WithCause(err)
	}

	pair, err := s.issueTokens(client, user, roles, session, stored.Nonce, stored.Scope)
	if err != nil {
		return nil, err
	}

	if pair.RefreshToken != "" {
		hash := repository.HashToken(pair.RefreshToken)
		state := repository.RefreshState{Hash: hash, SessionID: session.ID}
		ttl := s.tokens.RefreshTTL(client)
		if err := s.state.SetRefreshState(ctx, familyID, state, ttl); err != nil {
			return nil, apierr.ServerError("could not store refresh token").WithCause(err)
		}
		if err := s.state.SetRefreshTokenIndex(ctx, hash, familyID, ttl); err != nil {
			return nil, apierr.ServerError("could not store refresh token").WithCause(err)
		}
	}

	s.auditEvent(ctx, reqCtx, model.NewAuthEvent(model.EventTokenIssued, true).
		WithUser(user.ID).WithClient(client.ClientID).WithSession(session.ID))
	s.metrics.TokenIssued(model.GrantAuthorizationCode, client.ClientID)
	return pair, nil
}

// --- refresh token ----------------------------------------------------------

// Refresh rotates a refresh token. The old token is marked as used and cached
// together with the issued pair for a short grace window, so a retried request
// is idempotent while a genuine replay revokes the whole family.
func (s *GrantService) Refresh(ctx context.Context, client *model.OAuthClient, refreshToken string, reqCtx RequestContext) (*model.TokenPair, error) {
	const grant = model.GrantRefreshToken
	if !client.SupportsGrant(grant) {
		return nil, s.grantFailure(client, grant, apierr.UnauthorizedClient("client may not use the refresh_token grant"))
	}
	if refreshToken == "" {
		return nil, s.grantFailure(client, grant, apierr.InvalidRequest("refresh_token is required"))
	}
	if !client.AllowsScope(model.ScopeOfflineAccess) {
		// offline_access is what makes a refresh token available at all: without
		// it no refresh token was ever issued to this client.
		return nil, s.grantFailure(client, grant, apierr.InvalidScope("offline_access is not allowed for this client"))
	}

	hash := repository.HashToken(refreshToken)
	lockName := "refresh:" + hash[:24]
	lockToken, ok, err := s.limiter.WaitForLock(ctx, lockName, s.cfg.RefreshLockTTL, s.cfg.RefreshLockWait)
	if err != nil {
		return nil, apierr.Unavailable("refresh temporarily unavailable").WithCause(err)
	}
	if !ok {
		return nil, s.grantFailure(client, grant, apierr.Unavailable("another refresh is in progress, retry"))
	}
	defer func() {
		if err := s.limiter.ReleaseLock(ctx, lockName, lockToken); err != nil && s.logger != nil {
			s.logger.Warn("failed to release refresh lock", zap.String("error", err.Error()))
		}
	}()

	familyID, err := s.state.GetRefreshTokenIndex(ctx, hash)
	if err != nil {
		if errors.Is(err, repository.ErrNotFound) {
			return nil, s.grantFailure(client, grant, apierr.InvalidGrant("refresh token is invalid or expired"))
		}
		return nil, apierr.ServerError("could not read refresh state").WithCause(err)
	}

	state, err := s.state.GetRefreshState(ctx, familyID)
	if err != nil {
		if errors.Is(err, repository.ErrNotFound) {
			return nil, s.grantFailure(client, grant, apierr.InvalidGrant("refresh token family is no longer valid"))
		}
		return nil, apierr.ServerError("could not read refresh state").WithCause(err)
	}

	if state.Hash != hash {
		return s.handleStaleRefresh(ctx, client, reqCtx, hash, familyID, state)
	}

	session, err := s.sessions.Get(ctx, state.SessionID)
	if err != nil {
		if errors.Is(err, repository.ErrNotFound) {
			return nil, s.grantFailure(client, grant, apierr.InvalidGrant("session was revoked"))
		}
		return nil, apierr.ServerError("could not load session").WithCause(err)
	}
	if session.ClientID != client.ClientID {
		return nil, s.grantFailure(client, grant, apierr.InvalidGrant("refresh token was issued to another client"))
	}

	user, err := s.users.ByID(ctx, session.UserID)
	if err != nil || !user.IsActive() {
		if revokeErr := s.revokeFamily(ctx, familyID, session.ID); revokeErr != nil && s.logger != nil {
			s.logger.Warn("failed to revoke family of inactive user", zap.String("error", revokeErr.Error()))
		}
		return nil, s.grantFailure(client, grant, apierr.InvalidGrant("refresh token is no longer usable"))
	}
	roles, err := s.users.Roles(ctx, user.ID)
	if err != nil && s.logger != nil {
		s.logger.Warn("failed to load roles", zap.String("error", err.Error()))
	}

	if err := s.sessions.Extend(ctx, session); err != nil {
		return nil, s.grantFailure(client, grant, apierr.InvalidGrant("refresh token reached its maximum lifetime"))
	}

	pair, err := s.issueTokens(client, user, roles, session, "", session.Scope)
	if err != nil {
		return nil, err
	}

	ttl := time.Until(session.ExpiresAt)
	newHash := repository.HashToken(pair.RefreshToken)
	if err := s.state.SetRefreshState(ctx, familyID, repository.RefreshState{Hash: newHash, SessionID: session.ID}, ttl); err != nil {
		return nil, apierr.ServerError("could not rotate refresh token").WithCause(err)
	}
	if err := s.state.SetRefreshTokenIndex(ctx, newHash, familyID, ttl); err != nil {
		return nil, apierr.ServerError("could not rotate refresh token").WithCause(err)
	}
	if err := s.state.MarkRefreshUsed(ctx, hash, familyID, s.cfg.RefreshAbsoluteTTL); err != nil && s.logger != nil {
		s.logger.Warn("failed to mark refresh token used", zap.String("error", err.Error()))
	}
	if err := s.state.SaveRefreshReplay(ctx, hash, pair, s.cfg.RefreshReplayGrace); err != nil && s.logger != nil {
		s.logger.Warn("failed to cache refresh replay", zap.String("error", err.Error()))
	}

	s.auditEvent(ctx, reqCtx, model.NewAuthEvent(model.EventTokenRefreshed, true).
		WithUser(user.ID).WithClient(client.ClientID).WithSession(session.ID))
	s.metrics.TokenIssued(grant, client.ClientID)
	return pair, nil
}

// handleStaleRefresh deals with a token that is known but no longer current:
// either a retry inside the grace window, or a replay that must revoke the family.
func (s *GrantService) handleStaleRefresh(ctx context.Context, client *model.OAuthClient, reqCtx RequestContext, hash, familyID string, state *repository.RefreshState) (*model.TokenPair, error) {
	const grant = model.GrantRefreshToken

	if pair, err := s.state.GetRefreshReplay(ctx, hash); err == nil {
		s.metrics.TokenIssued(grant, client.ClientID)
		return pair, nil
	} else if !errors.Is(err, repository.ErrNotFound) && s.logger != nil {
		s.logger.Warn("failed to read refresh replay cache", zap.String("error", err.Error()))
	}

	s.metrics.RefreshReuseDetected()
	if err := s.revokeFamily(ctx, familyID, state.SessionID); err != nil {
		return nil, apierr.ServerError("could not revoke compromised session").WithCause(err)
	}
	s.auditEvent(ctx, reqCtx, model.NewAuthEvent(model.EventRefreshReuse, false).
		WithClient(client.ClientID).WithSession(state.SessionID).WithError("refresh_token_reuse"))
	return nil, s.grantFailure(client, grant, apierr.InvalidGrant("refresh token reuse detected, all sessions of this family were revoked"))
}

// revokeFamily removes the session and the refresh state of a compromised or
// expired family.
func (s *GrantService) revokeFamily(ctx context.Context, familyID, sessionID string) error {
	if err := s.state.DeleteRefreshFamily(ctx, familyID); err != nil {
		return err
	}
	if sessionID != "" {
		return s.sessions.Revoke(ctx, sessionID)
	}
	return nil
}

// --- client credentials -----------------------------------------------------

// ClientCredentials issues a machine-to-machine token for a confidential client.
func (s *GrantService) ClientCredentials(ctx context.Context, client *model.OAuthClient, scope string, reqCtx RequestContext) (*model.TokenPair, error) {
	const grant = model.GrantClientCredentials
	if client.IsPublic {
		return nil, s.grantFailure(client, grant, apierr.UnauthorizedClient("public clients cannot use the client_credentials grant"))
	}
	if !client.SupportsGrant(grant) {
		return nil, s.grantFailure(client, grant, apierr.UnauthorizedClient("client may not use the client_credentials grant"))
	}

	accessToken, expiresIn, err := s.tokens.NewClientAccessToken(client, scope)
	if err != nil {
		return nil, apierr.ServerError("could not issue access token").WithCause(err)
	}

	s.auditEvent(ctx, reqCtx, model.NewAuthEvent(model.EventClientCredentials, true).WithClient(client.ClientID))
	s.metrics.TokenIssued(grant, client.ClientID)
	return &model.TokenPair{
		AccessToken: accessToken,
		TokenType:   "Bearer",
		ExpiresIn:   expiresIn,
		Scope:       scope,
	}, nil
}

// --- revocation -------------------------------------------------------------

// Revoke implements RFC 7009. Unknown tokens, and tokens belonging to another
// client, are answered with success: the endpoint must not be an oracle.
func (s *GrantService) Revoke(ctx context.Context, client *model.OAuthClient, token, tokenTypeHint string, reqCtx RequestContext) error {
	if token == "" {
		return nil
	}

	if tokenTypeHint == "" || tokenTypeHint == "refresh_token" {
		hash := repository.HashToken(token)
		if familyID, err := s.state.GetRefreshTokenIndex(ctx, hash); err == nil {
			state, stateErr := s.state.GetRefreshState(ctx, familyID)
			sessionID := ""
			if stateErr == nil {
				sessionID = state.SessionID
			} else if !errors.Is(stateErr, repository.ErrNotFound) {
				return apierr.ServerError("could not read refresh state").WithCause(stateErr)
			}
			if s.sessionOwnedBy(ctx, sessionID, client.ClientID) {
				if err := s.revokeFamily(ctx, familyID, sessionID); err != nil {
					return apierr.ServerError("could not revoke token").WithCause(err)
				}
				s.auditEvent(ctx, reqCtx, model.NewAuthEvent(model.EventLogout, true).
					WithClient(client.ClientID).WithSession(sessionID))
			}
			return nil
		}
	}

	if claims, err := s.tokens.VerifyAccess(token); err == nil && claims.SessionID != "" {
		if s.sessionOwnedBy(ctx, claims.SessionID, client.ClientID) {
			if err := s.sessions.Revoke(ctx, claims.SessionID); err != nil {
				return apierr.ServerError("could not revoke token").WithCause(err)
			}
			s.auditEvent(ctx, reqCtx, model.NewAuthEvent(model.EventLogout, true).
				WithClient(client.ClientID).WithSession(claims.SessionID))
		}
	}
	return nil
}

func (s *GrantService) sessionOwnedBy(ctx context.Context, sessionID, clientID string) bool {
	if sessionID == "" {
		return false
	}
	session, err := s.sessions.Get(ctx, sessionID)
	if err != nil {
		return false
	}
	return session.ClientID == clientID
}

// --- helpers ----------------------------------------------------------------

// issueTokens mints the access token, the id_token and (for offline_access) a
// refresh token for a session.
func (s *GrantService) issueTokens(client *model.OAuthClient, user *model.User, roles []string, session *model.Session, nonce, scope string) (*model.TokenPair, error) {
	accessToken, expiresIn, err := s.tokens.NewUserAccessToken(AccessTokenInput{
		User:    user,
		Roles:   roles,
		Client:  client,
		Session: session,
		Scope:   scope,
	})
	if err != nil {
		return nil, apierr.ServerError("could not issue access token").WithCause(err)
	}

	pair := &model.TokenPair{
		AccessToken: accessToken,
		TokenType:   "Bearer",
		ExpiresIn:   expiresIn,
		Scope:       scope,
	}

	if containsScope(scope, model.ScopeOfflineAccess) && client.SupportsGrant(model.GrantRefreshToken) {
		refreshToken, err := NewRefreshToken()
		if err != nil {
			return nil, apierr.ServerError("could not issue refresh token").WithCause(err)
		}
		pair.RefreshToken = refreshToken
	}

	if containsScope(scope, model.ScopeOpenID) {
		idToken, err := s.tokens.NewIDToken(IDTokenInput{
			User:    user,
			Roles:   roles,
			Client:  client,
			Session: session,
			Scope:   scope,
			Nonce:   nonce,
		})
		if err != nil {
			return nil, apierr.ServerError("could not issue id token").WithCause(err)
		}
		pair.IDToken = idToken
	}

	return pair, nil
}

// grantFailure records the metric for a rejected token request.
func (s *GrantService) grantFailure(client *model.OAuthClient, grantType string, err error) error {
	code := apierr.CodeServerError
	var protoErr *apierr.Error
	if errors.As(err, &protoErr) {
		code = protoErr.Code
	}
	clientID := ""
	if client != nil {
		clientID = client.ClientID
	}
	s.metrics.TokenFailure(grantType, code)
	if s.logger != nil {
		s.logger.Warn("token request rejected",
			zap.String("grant_type", grantType),
			zap.String("client_id", clientID),
			zap.String("error", code))
	}
	return err
}

func (s *GrantService) auditEvent(ctx context.Context, reqCtx RequestContext, event *model.AuthEvent) {
	event = event.WithIP(reqCtx.IP).WithAgent(truncateUA(reqCtx.UserAgent)).WithRequest(reqCtx.RequestID)
	if err := s.audit.Insert(ctx, event); err != nil && s.logger != nil {
		s.logger.Warn("audit write failed", zap.String("event", event.EventType), zap.String("error", err.Error()))
	}
}

// verifyPKCE checks an S256 code challenge (RFC 7636 §4.6). `plain` is rejected:
// OAuth 2.1 requires S256.
func verifyPKCE(challenge, verifier string) error {
	if challenge == "" {
		return apierr.InvalidRequest("PKCE code_challenge is required")
	}
	if len(verifier) < 43 || len(verifier) > 128 {
		return apierr.InvalidGrant("code_verifier length is not within 43..128 characters")
	}
	sum := sha256.Sum256([]byte(verifier))
	computed := base64.RawURLEncoding.EncodeToString(sum[:])
	if subtle.ConstantTimeCompare([]byte(computed), []byte(challenge)) != 1 {
		return apierr.InvalidGrant("code_verifier does not match the code_challenge")
	}
	return nil
}

func truncateUA(ua string) string {
	const max = 512
	if len(ua) <= max {
		return ua
	}
	return ua[:max]
}

func refreshTokenScopes(client *model.OAuthClient) string {
	return model.JoinScope(client.AllowedScopes)
}
