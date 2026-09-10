package main

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"os"
	"time"

	"go.uber.org/zap"

	"iam-service/internal/config"
	"iam-service/internal/model"
	"iam-service/internal/pkg/password"
	"iam-service/internal/repository"
	"iam-service/internal/service"
	"iam-service/pkg/observability"
)

// seedCommand provisions the accounts and clients a fresh installation needs.
// Self-service registration is deliberately out of scope, so this command (or
// hand-written SQL) is the way records get in.
func seedCommand(args []string) error {
	fs := newFlagSet("seed")
	force := fs.Bool("force", false, "allow seeding outside the development environment")
	adminEmail := fs.String("admin-email", envOr("SEED_ADMIN_EMAIL", "admin@erplite.local"), "email of the administrator account")
	adminPassword := fs.String("admin-password", os.Getenv("SEED_ADMIN_PASSWORD"), "password of the administrator account (generated when empty)")
	if err := fs.Parse(args); err != nil {
		return err
	}

	cfg, err := config.Load()
	if err != nil {
		return err
	}
	if cfg.IsProduction() && !*force {
		return errors.New("refusing to seed a production environment without --force")
	}

	logger, err := observability.NewLogger(cfg.Environment, cfg.Log.Level)
	if err != nil {
		return err
	}
	defer observability.Sync(logger)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	pg, err := repository.NewPostgres(ctx, cfg.Database)
	if err != nil {
		return err
	}
	defer pg.Close()
	if err := pg.WaitForSchema(ctx, 10*time.Second); err != nil {
		return err
	}

	users := repository.NewUserRepo(pg)
	clients := repository.NewClientRepo(pg)

	// The administrator's password is only touched when the account is created:
	// re-seeding an existing installation must not change credentials, and must
	// not print a password that was never applied.
	passwordApplied := false
	user, err := users.ByEmail(ctx, *adminEmail)
	switch {
	case errors.Is(err, repository.ErrNotFound):
		if *adminPassword == "" {
			generated, genErr := randomSecret(24)
			if genErr != nil {
				return genErr
			}
			*adminPassword = generated
		}
		if err := password.Validate(*adminPassword); err != nil {
			return err
		}
		hash, hashErr := password.Hash(*adminPassword)
		if hashErr != nil {
			return hashErr
		}
		user, err = users.Create(ctx, *adminEmail, "Administrator", hash)
		if err != nil {
			return err
		}
		passwordApplied = true
		logger.Info("administrator created", zap.String("email", user.Email), zap.String("id", user.ID))
	case err != nil:
		return err
	default:
		logger.Info("administrator already exists, its password is left untouched",
			zap.String("email", user.Email), zap.String("id", user.ID))
	}

	for _, role := range []string{model.RoleAdmin, model.RoleUser} {
		if err := users.AssignRole(ctx, user.ID, role); err != nil {
			return fmt.Errorf("assign role %s: %w", role, err)
		}
	}

	// The integration client keeps its secret across runs: re-seeding a live
	// installation must not silently invalidate credentials that are already in
	// use. A new secret is generated only when the client does not exist yet.
	integrationSecretHash, generatedSecret, err := existingClientSecret(ctx, clients, "erplite-integration")
	if err != nil {
		return err
	}
	integrationSecret := ""
	if generatedSecret {
		integrationSecret, err = randomSecret(32)
		if err != nil {
			return err
		}
		integrationSecretHash = service.HashClientSecret(integrationSecret)
	}

	seedClients := []*model.OAuthClient{
		{
			ClientID:                "erplite-spa",
			Name:                    "ERP Lite (web)",
			IsPublic:                true,
			TokenEndpointAuthMethod: model.AuthMethodNone,
			RedirectURIs:            []string{"http://localhost:3000/callback", "http://localhost:5173/callback"},
			AllowedScopes:           []string{model.ScopeOpenID, model.ScopeProfile, model.ScopeEmail, model.ScopeOfflineAccess, "api.read", "api.write"},
			GrantTypes:              []string{model.GrantAuthorizationCode, model.GrantRefreshToken},
			RequireConsent:          false,
		},
		{
			ClientID:                "erplite-mobile",
			Name:                    "ERP Lite (mobile)",
			IsPublic:                true,
			TokenEndpointAuthMethod: model.AuthMethodNone,
			RedirectURIs:            []string{"erplite://callback"},
			AllowedScopes:           []string{model.ScopeOpenID, model.ScopeProfile, model.ScopeEmail, model.ScopeOfflineAccess, "api.read", "api.write"},
			GrantTypes:              []string{model.GrantAuthorizationCode, model.GrantRefreshToken},
			RequireConsent:          false,
		},
		{
			ClientID:                "erplite-demo-spa",
			Name:                    "ERP Lite (демо-клиент в браузере)",
			IsPublic:                true,
			TokenEndpointAuthMethod: model.AuthMethodNone,
			// Отдаётся тем же Nginx-ом, что и сам сервис: страница проходит
			// весь цикл в браузере без отдельного фронтенда.
			RedirectURIs:   []string{"http://localhost:8088/demo/callback"},
			AllowedScopes:  []string{model.ScopeOpenID, model.ScopeProfile, model.ScopeEmail, model.ScopeOfflineAccess, "api.read", "api.write"},
			GrantTypes:     []string{model.GrantAuthorizationCode, model.GrantRefreshToken},
			RequireConsent: true,
		},
		{
			ClientID:                "erplite-integration",
			Name:                    "ERP Lite (интеграция, service-to-service)",
			IsPublic:                false,
			TokenEndpointAuthMethod: model.AuthMethodClientSecretBasic,
			ClientSecretHash:        &integrationSecretHash,
			RedirectURIs:            []string{},
			AllowedScopes:           []string{"api.read", "api.write"},
			GrantTypes:              []string{model.GrantClientCredentials},
			RequireConsent:          false,
		},
	}
	for _, client := range seedClients {
		if err := clients.Upsert(ctx, client); err != nil {
			return err
		}
		logger.Info("oauth client seeded", zap.String("client_id", client.ClientID))
	}

	fmt.Println("seed completed")
	fmt.Printf("  issuer:            %s\n", cfg.OAuth.IssuerURL)
	fmt.Printf("  admin email:       %s\n", user.Email)
	switch {
	case !passwordApplied:
		fmt.Printf("  admin password:    (не менялся: пользователь уже существует)\n")
	case os.Getenv("SEED_ADMIN_PASSWORD") == "":
		fmt.Printf("  admin password:    %s   (сгенерирован, сохраните его)\n", *adminPassword)
	default:
		fmt.Printf("  admin password:    (взят из SEED_ADMIN_PASSWORD)\n")
	}
	fmt.Printf("  public clients:    erplite-spa, erplite-mobile (PKCE, no secret)\n")
	fmt.Printf("  browser demo:      erplite-demo-spa → %s/demo/\n", cfg.OAuth.IssuerURL)
	fmt.Printf("  confidential:      erplite-integration\n")
	if integrationSecret != "" {
		fmt.Printf("  client secret:     %s   (generated, store it now)\n", integrationSecret)
	} else {
		fmt.Printf("  client secret:     (не менялся: у клиента уже был секрет)\n")
	}
	return nil
}

// existingClientSecret returns the stored secret hash of a client. It reports
// generated=true when the client does not exist yet or has no secret, which is
// the caller's signal to mint one.
func existingClientSecret(ctx context.Context, clients *repository.ClientRepo, clientID string) (hash string, generated bool, err error) {
	client, err := clients.ByID(ctx, clientID)
	switch {
	case errors.Is(err, repository.ErrNotFound):
		return "", true, nil
	case err != nil:
		return "", false, err
	case client.ClientSecretHash == nil || *client.ClientSecretHash == "":
		return "", true, nil
	default:
		return *client.ClientSecretHash, false, nil
	}
}

func randomSecret(numBytes int) (string, error) {
	buf := make([]byte, numBytes)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(buf), nil
}

func envOr(key, fallback string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return fallback
}
