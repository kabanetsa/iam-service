package main

import (
	"context"
	"database/sql"
	"fmt"
	"strings"

	_ "github.com/jackc/pgx/v5/stdlib"

	"iam-service/internal/config"
	"iam-service/migrations"
)

// migrateCommand implements `iam-service migrate [up|down|status]`.
func migrateCommand(args []string) error {
	action := "up"
	if len(args) > 0 && !strings.HasPrefix(args[0], "-") {
		action = args[0]
		args = args[1:]
	}
	fs := newFlagSet("migrate")
	if err := fs.Parse(args); err != nil {
		return err
	}

	cfg, err := config.Load()
	if err != nil {
		return err
	}
	db, err := openMigrationDB(cfg)
	if err != nil {
		return err
	}
	defer func() { _ = db.Close() }()

	switch action {
	case "up":
		return migrations.Up(db)
	case "down":
		return migrations.Down(db)
	case "status":
		return migrations.Status(db)
	default:
		return fmt.Errorf("unknown migrate action %q (expected up, down or status)", action)
	}
}

// migrateUp applies pending migrations; it is used by `serve --migrate-on-start`.
func migrateUp(_ context.Context, cfg *config.Config) error {
	db, err := openMigrationDB(cfg)
	if err != nil {
		return err
	}
	defer func() { _ = db.Close() }()
	return migrations.Up(db)
}

// openMigrationDB uses database/sql with the pgx stdlib driver, which is what
// goose expects (the service itself uses pgxpool).
func openMigrationDB(cfg *config.Config) (*sql.DB, error) {
	db, err := sql.Open("pgx", cfg.Database.DSN)
	if err != nil {
		return nil, fmt.Errorf("open database: %w", err)
	}
	db.SetMaxOpenConns(2)
	if err := db.Ping(); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("ping database: %w", err)
	}
	return db, nil
}
