package main

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os/signal"
	"strconv"
	"syscall"
	"time"

	"github.com/prometheus/client_golang/prometheus/promhttp"
	"go.uber.org/zap"

	"iam-service/internal/api"
	"iam-service/internal/config"
	"iam-service/internal/pkg/jwt"
	"iam-service/internal/repository"
	"iam-service/internal/service"
	"iam-service/internal/web"
	"iam-service/pkg/observability"
)

func serveCommand(args []string) error {
	fs := newFlagSet("serve")
	migrateOnStart := fs.Bool("migrate-on-start", false, "apply pending migrations before serving traffic")
	if err := fs.Parse(args); err != nil {
		return err
	}

	cfg, err := config.Load()
	if err != nil {
		return err
	}
	logger, err := observability.NewLogger(cfg.Environment, cfg.Log.Level)
	if err != nil {
		return err
	}
	defer observability.Sync(logger)

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	if *migrateOnStart {
		if err := runMigrations(ctx, cfg, logger); err != nil {
			return err
		}
	}

	pg, err := repository.NewPostgres(ctx, cfg.Database)
	if err != nil {
		return err
	}
	defer pg.Close()
	if err := pg.WaitForSchema(ctx, 10*time.Second); err != nil {
		return err
	}

	rdb, err := repository.NewRedis(ctx, cfg.Redis)
	if err != nil {
		return err
	}
	defer func() { _ = rdb.Close() }()

	keyring, generated, err := jwt.LoadKeyring(cfg.OAuth.SigningKeyPath, cfg.OAuth.SigningKeyID, cfg.OAuth.AllowDevKeyGeneration && !cfg.IsProduction())
	if err != nil {
		return err
	}
	if generated {
		logger.Warn("generated a development signing key; tokens will not survive a restart and must never be used in production")
	}
	logger.Info("signing key ready", zap.String("kid", keyring.ActiveKID()), zap.String("algorithm", jwt.SigningAlgorithm))

	metrics := observability.NewMetrics()
	signer := jwt.NewSigner(keyring, cfg.OAuth.IssuerURL, cfg.OAuth.Audience, cfg.OAuth.ClockSkew)
	tokens := service.NewTokenService(signer, cfg.OAuth)

	users := repository.NewUserRepo(pg)
	clients := repository.NewClientRepo(pg)
	audit := repository.NewAuditRepo(pg, logger)
	state := repository.NewSessionRepo(rdb)
	limiter := repository.NewRateLimitRepo(rdb)

	sessions := service.NewSessionService(state, users, cfg.OAuth, logger)
	authService := service.NewAuthService(users, limiter, audit, cfg.RateLimit, logger)
	clientService := service.NewClientService(clients, audit, logger)
	grants := service.NewGrantService(clients, users, state, limiter, sessions, tokens, audit, metrics, cfg.OAuth, logger)
	oidc := service.NewOIDCService(tokens, users, cfg.OAuth)

	pages, err := web.Templates()
	if err != nil {
		return err
	}

	router, err := api.NewRouter(api.RouterDeps{
		Config:   cfg,
		Logger:   logger,
		Metrics:  metrics,
		Auth:     authService,
		Clients:  clientService,
		Tokens:   tokens,
		Sessions: sessions,
		Grants:   grants,
		OIDC:     oidc,
		Users:    users,
		State:    state,
		Limiter:  limiter,
		Audit:    audit,
		Pages:    pages,
		Postgres: pg,
		Redis:    rdb,
		Version:  version,
	})
	if err != nil {
		return err
	}

	mainServer := &http.Server{
		Addr:              net.JoinHostPort(cfg.Server.Host, strconv.Itoa(cfg.Server.Port)),
		Handler:           router,
		ReadTimeout:       cfg.Server.ReadTimeout,
		ReadHeaderTimeout: cfg.Server.ReadTimeout,
		WriteTimeout:      cfg.Server.WriteTimeout,
		IdleTimeout:       cfg.Server.IdleTimeout,
	}
	adminServer := &http.Server{
		Addr:              net.JoinHostPort(cfg.Server.AdminHost, strconv.Itoa(cfg.Server.AdminPort)),
		Handler:           adminMux(metrics, pg, rdb, cfg, logger),
		ReadTimeout:       cfg.Server.ReadTimeout,
		ReadHeaderTimeout: cfg.Server.ReadTimeout,
		WriteTimeout:      cfg.Server.WriteTimeout,
		IdleTimeout:       cfg.Server.IdleTimeout,
	}

	samplerCtx, stopSampler := context.WithCancel(ctx)
	defer stopSampler()
	go sampleActiveSessions(samplerCtx, rdb, metrics, cfg.OAuth.ActiveSessionSampler, logger)

	serverErrors := make(chan error, 2)
	go func() {
		logger.Info("http server listening", zap.String("address", mainServer.Addr), zap.String("issuer", cfg.OAuth.IssuerURL))
		if err := mainServer.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			serverErrors <- fmt.Errorf("http server: %w", err)
		}
	}()
	go func() {
		logger.Info("admin server listening", zap.String("address", adminServer.Addr))
		if err := adminServer.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			serverErrors <- fmt.Errorf("admin server: %w", err)
		}
	}()

	select {
	case err := <-serverErrors:
		return err
	case <-ctx.Done():
		logger.Info("shutdown signal received, draining connections")
	}

	shutdownCtx, cancel := context.WithTimeout(context.Background(), cfg.Server.ShutdownTimeout)
	defer cancel()
	mainErr := mainServer.Shutdown(shutdownCtx)
	adminErr := adminServer.Shutdown(shutdownCtx)
	if mainErr != nil {
		return fmt.Errorf("graceful shutdown: %w", mainErr)
	}
	if adminErr != nil {
		return fmt.Errorf("graceful shutdown of the admin server: %w", adminErr)
	}
	logger.Info("shutdown complete")
	return nil
}

// adminMux serves metrics and probes on a separate listener that must not be
// exposed through the reverse proxy.
func adminMux(metrics *observability.Metrics, pg, rdb observability.Pinger, cfg *config.Config, logger *zap.Logger) *http.ServeMux {
	mux := http.NewServeMux()
	health := &observability.Health{Postgres: pg, Redis: rdb, Timeout: cfg.Database.HealthTimeout, Version: version}
	mux.Handle("/metrics", promhttp.HandlerFor(metrics.Registry(), promhttp.HandlerOpts{}))
	mux.HandleFunc("/healthz", health.Live)
	mux.HandleFunc("/readyz", health.Ready)
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		_, _ = w.Write([]byte("iam-service admin endpoint\n"))
	})
	_ = logger
	return mux
}

// sampleActiveSessions publishes the session count periodically. SCAN is
// non-blocking, and the sampler stops with the process context.
func sampleActiveSessions(ctx context.Context, rdb *repository.Redis, metrics *observability.Metrics, interval time.Duration, logger *zap.Logger) {
	if interval <= 0 {
		interval = time.Minute
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			count, err := rdb.CountSessions(ctx)
			if err != nil {
				if ctx.Err() == nil {
					logger.Warn("active session sampler failed", zap.String("error", err.Error()))
				}
				continue
			}
			metrics.SetActiveSessions(float64(count))
		}
	}
}

func runMigrations(ctx context.Context, cfg *config.Config, logger *zap.Logger) error {
	logger.Info("applying database migrations")
	return migrateUp(ctx, cfg)
}
