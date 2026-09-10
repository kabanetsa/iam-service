// Command iam-service is the OAuth 2.1 / OpenID Connect authorization server of
// ERP Lite.
//
// Usage:
//
//	iam-service serve   [--migrate-on-start]   run the HTTP server
//	iam-service migrate [up|down|status]       apply database migrations
//	iam-service seed    [--force]              create the admin user and dev clients
//	iam-service keys    generate --path <file> generate an RS256 signing key
//	iam-service version                        print the build version
package main

import (
	"flag"
	"fmt"
	"os"
)

// version is overridden at build time with -ldflags "-X main.version=...".
var version = "dev"

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintf(os.Stderr, "iam-service: %v\n", err)
		os.Exit(1)
	}
}

func run(args []string) error {
	command := "serve"
	if len(args) > 0 {
		command = args[0]
	}

	switch command {
	case "serve":
		return serveCommand(args[1:])
	case "migrate":
		return migrateCommand(args[1:])
	case "seed":
		return seedCommand(args[1:])
	case "keys":
		return keysCommand(args[1:])
	case "version", "-version", "--version":
		fmt.Println(version)
		return nil
	case "help", "-h", "--help":
		usage()
		return nil
	default:
		usage()
		return fmt.Errorf("unknown command %q", command)
	}
}

func usage() {
	fmt.Fprint(os.Stderr, `iam-service — OAuth 2.1 / OIDC authorization server

Commands:
  serve   [--migrate-on-start]        start the HTTP server
  migrate [up|down|status]            apply database migrations
  seed    [--force]                   create the admin user and development clients
  keys    generate --path <file>      generate an RS256 signing key
  version                             print the build version

Configuration is read from CONFIG_PATH (default configs/config.yaml) and can be
overridden with environment variables, e.g. DATABASE_URL, REDIS_ADDR,
OAUTH_ISSUER_URL, OAUTH_SIGNING_KEY_PATH.
`)
}

// newFlagSet builds a flag set that reports usage errors instead of exiting.
func newFlagSet(name string) *flag.FlagSet {
	fs := flag.NewFlagSet(name, flag.ContinueOnError)
	fs.Usage = func() { usage() }
	return fs
}
