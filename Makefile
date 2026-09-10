SHELL := /bin/bash
MODULE := iam-service
VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
BIN_DIR := bin
# Keep the Go build cache inside the repository: builds stay hermetic and work in
# sandboxes where $HOME is not writable.
GOCACHE ?= $(CURDIR)/.gocache
export GOCACHE
export GOTOOLCHAIN := local

GOFLAGS := -trimpath
LDFLAGS := -s -w -X main.version=$(VERSION)

# Override to target a specific daemon, e.g. DOCKER='docker --context desktop-linux'.
DOCKER ?= docker
COMPOSE := $(DOCKER) compose -f deployments/docker-compose.yaml
TEST_DATABASE_URL ?= postgres://iam_user:iam_pass@localhost:5432/iam?sslmode=disable
TEST_REDIS_ADDR ?= localhost:6379

.PHONY: help
help: ## Show available targets
	@grep -hE '^[a-zA-Z_-]+:.*?## ' $(MAKEFILE_LIST) | awk 'BEGIN{FS=":.*?## "}{printf "  \033[36m%-20s\033[0m %s\n", $$1, $$2}'

.PHONY: build
build: ## Build the service and the demo backend into ./bin
	@mkdir -p $(BIN_DIR)
	go build $(GOFLAGS) -ldflags "$(LDFLAGS)" -o $(BIN_DIR)/$(MODULE) ./cmd/iam-service
	go build $(GOFLAGS) -ldflags "$(LDFLAGS)" -o $(BIN_DIR)/echo-backend ./cmd/echo

.PHONY: run
run: ## Run the service locally (requires Postgres and Redis)
	go run ./cmd/iam-service serve --migrate-on-start

.PHONY: fmt
fmt: ## Format the sources
	gofmt -l -w ./cmd ./internal ./pkg ./migrations

.PHONY: vet
vet: ## Run go vet
	go vet ./...

.PHONY: lint
lint: fmt vet ## Format and vet

.PHONY: tidy
tidy: ## Tidy go.mod
	go mod tidy

.PHONY: test
test: ## Run unit tests
	go test ./...

.PHONY: test-race
test-race: ## Run unit tests with the race detector
	go test -race ./...

.PHONY: test-integration
test-integration: ## Run integration tests (needs Postgres and Redis)
	TEST_DATABASE_URL='$(TEST_DATABASE_URL)' TEST_REDIS_ADDR='$(TEST_REDIS_ADDR)' \
		go test -tags=integration ./...

.PHONY: cover
cover: ## Run unit tests with coverage
	go test -coverprofile=coverage.out ./...
	go tool cover -func=coverage.out | tail -1

.PHONY: keys
keys: ## Generate an RS256 signing key at configs/keys/signing.pem
	go run ./cmd/iam-service keys generate --path configs/keys/signing.pem --force

.PHONY: migrate-up
migrate-up: ## Apply migrations against DATABASE_URL
	go run ./cmd/iam-service migrate up

.PHONY: migrate-down
migrate-down: ## Roll back the last migration
	go run ./cmd/iam-service migrate down

.PHONY: migrate-status
migrate-status: ## Show migration status
	go run ./cmd/iam-service migrate status

.PHONY: up
up: ## Start the full stack (Postgres, Redis, IAM, Nginx, backend)
	$(COMPOSE) up -d --build
	@echo "waiting for iam-service to become ready..."
	@for i in $$(seq 1 60); do \
		if curl -fsS http://localhost:8088/healthz >/dev/null 2>&1; then echo "ready"; exit 0; fi; \
		sleep 1; \
	done; \
	echo "service did not become ready in time" >&2; exit 1

.PHONY: down
down: ## Stop the stack
	$(COMPOSE) down

.PHONY: clean
clean: ## Stop the stack and remove volumes
	$(COMPOSE) down -v

.PHONY: logs
logs: ## Follow the service logs
	$(COMPOSE) logs -f iam

.PHONY: seed
seed: ## Create the admin user and development OAuth clients inside the stack
	$(COMPOSE) run --rm --no-deps -e ENVIRONMENT=development iam seed --force

.PHONY: demo
demo: ## Open the browser demo client (requires the stack to be up)
	@open http://localhost:8088/demo/ 2>/dev/null || echo "open http://localhost:8088/demo/ in a browser"

.PHONY: smoke
smoke: ## Run the end-to-end OAuth smoke test against the running stack
	BASE_URL=http://localhost:8088 PASSWORD="$${PASSWORD:-}" ./scripts/smoke-oauth.sh
