package main

import (
	"errors"
	"fmt"
	"os"

	"iam-service/internal/config"
	"iam-service/internal/pkg/jwt"
)

// keysCommand implements `iam-service keys generate --path <file>`.
func keysCommand(args []string) error {
	if len(args) == 0 || args[0] != "generate" {
		return errors.New("usage: iam-service keys generate --path <file> [--bits 2048] [--force]")
	}
	fs := newFlagSet("keys generate")
	path := fs.String("path", "", "file to write the private key to (PEM, mode 0600)")
	bits := fs.Int("bits", jwt.DefaultKeyBits, "RSA key size in bits")
	force := fs.Bool("force", false, "overwrite an existing key file")
	if err := fs.Parse(args[1:]); err != nil {
		return err
	}

	// The configuration supplies a default path so that `keys generate` works in
	// the same environment as `serve`.
	if *path == "" {
		if cfg, err := config.Load(); err == nil && cfg.OAuth.SigningKeyPath != "" {
			*path = cfg.OAuth.SigningKeyPath
		}
	}
	if *path == "" {
		return errors.New("--path is required (or set oauth.signing_key_path / OAUTH_SIGNING_KEY_PATH)")
	}
	if !*force {
		if _, err := os.Stat(*path); err == nil {
			return fmt.Errorf("%s already exists, refusing to overwrite it without --force", *path)
		}
	}

	key, err := jwt.GenerateRSA(*bits)
	if err != nil {
		return err
	}
	if err := jwt.WritePrivateKeyPEM(*path, key.Private); err != nil {
		return err
	}

	fmt.Printf("signing key written to %s\n", *path)
	fmt.Printf("  kid:       %s\n", key.KID)
	fmt.Printf("  algorithm: %s\n", jwt.SigningAlgorithm)
	fmt.Printf("  bits:      %d\n", key.Public.N.BitLen())
	fmt.Println("Publish it through /.well-known/jwks.json; keep the file mode at 0600 and out of version control.")
	return nil
}
