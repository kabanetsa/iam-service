#!/usr/bin/env bash
# Brings the local stack up and provisions the demo accounts and clients.
#
# Usage: scripts/dev-up.sh [admin-email] [admin-password]
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

ADMIN_EMAIL="${1:-admin@erplite.local}"
ADMIN_PASSWORD="${2:-}"

COMPOSE="docker compose -f deployments/docker-compose.yaml"

echo "==> starting postgres, redis, iam, nginx and the demo backend"
$COMPOSE up -d --build postgres redis iam-migrate iam backend nginx

echo "==> waiting for iam-service to become ready"
for _ in $(seq 1 60); do
  if curl -fsS http://localhost:8088/healthz >/dev/null 2>&1; then
    echo "    ready"
    break
  fi
  sleep 1
done

echo "==> seeding the admin user and OAuth clients"
SEED_OUTPUT=$($COMPOSE run --rm --no-deps \
  -e ENVIRONMENT=development \
  -e "SEED_ADMIN_EMAIL=${ADMIN_EMAIL}" \
  ${ADMIN_PASSWORD:+-e "SEED_ADMIN_PASSWORD=${ADMIN_PASSWORD}"} \
  iam seed --force)

echo "$SEED_OUTPUT"

# Reuse the generated password for the smoke test when the caller did not set one.
if [[ -z "$ADMIN_PASSWORD" ]]; then
  ADMIN_PASSWORD=$(printf '%s\n' "$SEED_OUTPUT" | sed -n 's/.*admin password: *\([^ ]*\).*/\1/p' | head -1)
fi

cat <<EOF

Stack is up.

  issuer            http://localhost:8088
  discovery         http://localhost:8088/.well-known/openid-configuration
  jwks              http://localhost:8088/.well-known/jwks.json
  admin login       ${ADMIN_EMAIL}

Run the end-to-end check:

  BASE_URL=http://localhost:8088 EMAIL=${ADMIN_EMAIL} PASSWORD='${ADMIN_PASSWORD}' ./scripts/smoke-oauth.sh

EOF
