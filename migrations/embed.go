// Package migrations embeds the SQL migrations and applies them with goose.
package migrations

import (
	"database/sql"
	"embed"
	"fmt"

	"github.com/pressly/goose/v3"
)

//go:embed *.sql
var files embed.FS

// Up applies every pending migration.
func Up(db *sql.DB) error {
	goose.SetBaseFS(files)
	defer goose.SetBaseFS(nil)

	if err := goose.SetDialect("postgres"); err != nil {
		return fmt.Errorf("migrations: set dialect: %w", err)
	}
	if err := goose.Up(db, "."); err != nil {
		return fmt.Errorf("migrations: up: %w", err)
	}
	return nil
}

// Down rolls the most recent migration back.
func Down(db *sql.DB) error {
	goose.SetBaseFS(files)
	defer goose.SetBaseFS(nil)

	if err := goose.SetDialect("postgres"); err != nil {
		return fmt.Errorf("migrations: set dialect: %w", err)
	}
	if err := goose.Down(db, "."); err != nil {
		return fmt.Errorf("migrations: down: %w", err)
	}
	return nil
}

// Status prints the migration state to stdout.
func Status(db *sql.DB) error {
	goose.SetBaseFS(files)
	defer goose.SetBaseFS(nil)

	if err := goose.SetDialect("postgres"); err != nil {
		return fmt.Errorf("migrations: set dialect: %w", err)
	}
	if err := goose.Status(db, "."); err != nil {
		return fmt.Errorf("migrations: status: %w", err)
	}
	return nil
}
