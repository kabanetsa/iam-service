#!/usr/bin/env bash
# End-to-end check of the authorization server against a running stack.
#
# It walks the complete authorization_code + PKCE flow through Nginx, then
# verifies the protected API, refresh rotation, reuse detection and revocation.
#
# Usage:
#   BASE_URL=http://localhost:8088 EMAIL=admin@erplite.local PASSWORD=... ./scripts/smoke-oauth.sh
set -euo pipefail

BASE_URL="${BASE_URL:-http://localhost:8088}"
CLIENT_ID="${CLIENT_ID:-erplite-spa}"
REDIRECT_URI="${REDIRECT_URI:-http://localhost:3000/callback}"
EMAIL="${EMAIL:-admin@erplite.local}"
PASSWORD="${PASSWORD:-}"
SCOPE="${SCOPE:-openid profile email offline_access api.read}"

if [[ -z "$PASSWORD" ]]; then
  echo "PASSWORD is required (see the output of 'make seed')" >&2
  exit 2
fi
for tool in curl jq openssl; do
  command -v "$tool" >/dev/null || { echo "$tool is required" >&2; exit 2; }
done

pass() { printf '   \033[32m✓\033[0m %s\n' "$1"; }
fail() { printf '   \033[31m✗\033[0m %s\n' "$1"; exit 1; }
step() { printf '\n\033[1m== %s\033[0m\n' "$1"; }

urlenc() { jq -rn --arg v "$1" '$v|@uri'; }
location_of() { awk 'tolower($1)=="location:"{print $2}' | tr -d '\r'; }
status_of() { awk 'NR==1{print $2}'; }

# ---------------------------------------------------------------------------
step "Discovery documents"
DISCOVERY=$(curl -fsS "$BASE_URL/.well-known/openid-configuration")
ISSUER=$(jq -r '.issuer' <<<"$DISCOVERY")
[[ "$ISSUER" == "$BASE_URL" ]] || fail "issuer is '$ISSUER', expected '$BASE_URL'"
jq -e '.code_challenge_methods_supported == ["S256"]' <<<"$DISCOVERY" >/dev/null || fail "S256 is not advertised"
jq -e '.token_endpoint and .authorization_endpoint and .jwks_uri and .userinfo_endpoint' <<<"$DISCOVERY" >/dev/null || fail "endpoints missing"
pass "issuer, endpoints and PKCE support advertised"

KID=$(curl -fsS "$BASE_URL/.well-known/jwks.json" | jq -r '.keys[0].kid')
[[ -n "$KID" && "$KID" != "null" ]] || fail "no key published in JWKS"
pass "jwks publishes signing key $KID"

# ---------------------------------------------------------------------------
step "Authorization request (PKCE S256)"
VERIFIER=$(openssl rand -hex 32)
CHALLENGE=$(printf '%s' "$VERIFIER" | openssl dgst -binary -sha256 | openssl base64 | tr -d '=' | tr '+/' '-_')
STATE=$(openssl rand -hex 8)

AUTH_URL="$BASE_URL/oauth/authorize?response_type=code&client_id=$(urlenc "$CLIENT_ID")&redirect_uri=$(urlenc "$REDIRECT_URI")&scope=$(urlenc "$SCOPE")&state=$STATE&code_challenge=$CHALLENGE&code_challenge_method=S256"
LOGIN_LOCATION=$(curl -sS -o /dev/null -D - "$AUTH_URL" | location_of)
[[ "$LOGIN_LOCATION" == *"/login?interaction="* ]] || fail "expected a redirect to the login page, got '$LOGIN_LOCATION'"
INTERACTION=$(sed 's/.*interaction=//' <<<"$LOGIN_LOCATION")
pass "pending interaction created"

step "Login form"
LOGIN_HTML=$(curl -fsS "$BASE_URL$LOGIN_LOCATION")
CSRF=$(grep -o 'name="csrf_token" value="[^"]*"' <<<"$LOGIN_HTML" | head -1 | sed 's/.*value="//; s/"$//')
[[ -n "$CSRF" ]] || fail "the login page has no CSRF token"
pass "login page rendered with a CSRF token"

LOGIN_RESULT=$(curl -sS -o /dev/null -D - -X POST "$BASE_URL/login" \
  --data-urlencode "interaction=$INTERACTION" \
  --data-urlencode "csrf_token=$CSRF" \
  --data-urlencode "email=$EMAIL" \
  --data-urlencode "password=$PASSWORD")
REDIRECT_LOCATION=$(location_of <<<"$LOGIN_RESULT")
[[ "$REDIRECT_LOCATION" == *"code="* ]] || fail "login did not return an authorization code: '$REDIRECT_LOCATION'"
CODE=$(sed -n 's/.*[?&]code=\([^&]*\).*/\1/p' <<<"$REDIRECT_LOCATION")
RETURNED_STATE=$(sed -n 's/.*[?&]state=\([^&]*\).*/\1/p' <<<"$REDIRECT_LOCATION")
[[ "$RETURNED_STATE" == "$STATE" ]] || fail "state was not echoed back"
pass "authorization code issued and state verified"

step "Token exchange"
TOKENS=$(curl -fsS -X POST "$BASE_URL/oauth/token" \
  -H 'Content-Type: application/x-www-form-urlencoded' \
  -d grant_type=authorization_code \
  -d "code=$CODE" \
  -d "redirect_uri=$REDIRECT_URI" \
  -d "client_id=$CLIENT_ID" \
  -d "code_verifier=$VERIFIER")
ACCESS_TOKEN=$(jq -r '.access_token' <<<"$TOKENS")
REFRESH_TOKEN=$(jq -r '.refresh_token // empty' <<<"$TOKENS")
ID_TOKEN=$(jq -r '.id_token // empty' <<<"$TOKENS")
[[ -n "$ACCESS_TOKEN" && "$ACCESS_TOKEN" != "null" ]] || fail "no access token returned: $TOKENS"
[[ -n "$REFRESH_TOKEN" ]] || fail "offline_access was requested but no refresh token was returned"
[[ -n "$ID_TOKEN" ]] || fail "openid was requested but no id_token was returned"
pass "access, refresh and id tokens issued"

step "Token claims"
CLAIMS=$(printf '%s' "$ACCESS_TOKEN" | cut -d. -f2 | tr '_-' '/+' | awk '{l=length($0)%4; if(l>0) $0=$0 substr("====",1,4-l)}1' | base64 -d 2>/dev/null)
[[ "$(jq -r '.iss' <<<"$CLAIMS")" == "$ISSUER" ]] || fail "iss claim does not match the issuer"
# RFC 7519 allows aud to be a string or an array; golang-jwt emits an array.
AUDIENCE=$(jq -r '.aud | if type == "array" then join(" ") else . end' <<<"$CLAIMS")
[[ "$AUDIENCE" == "erplite-api" ]] || fail "unexpected audience: $AUDIENCE"
[[ "$(jq -r '.token_use' <<<"$CLAIMS")" == "access" ]] || fail "token_use is not access"
[[ "$(jq -r '.sid' <<<"$CLAIMS")" != "null" ]] || fail "access token carries no session id"
pass "iss/aud/token_use/sid claims are correct"

# ---------------------------------------------------------------------------
step "Protected API through Nginx"
UNAUTH_STATUS=$(curl -sS -o /dev/null -D - "$BASE_URL/api/ping" | status_of)
[[ "$UNAUTH_STATUS" == "401" ]] || fail "an unauthenticated call returned $UNAUTH_STATUS, expected 401"
pass "anonymous request rejected with 401"

API_RESPONSE=$(curl -fsS "$BASE_URL/api/ping" -H "Authorization: Bearer $ACCESS_TOKEN")
PROXIED_USER=$(jq -r '.headers["x-user-id"]' <<<"$API_RESPONSE")
SUBJECT=$(jq -r '.sub' <<<"$CLAIMS")
[[ "$PROXIED_USER" == "$SUBJECT" ]] || fail "the backend saw X-User-ID '$PROXIED_USER', expected '$SUBJECT'"
jq -e '.headers["x-session-id"] and .headers["x-scopes"]' <<<"$API_RESPONSE" >/dev/null || fail "identity headers are incomplete"
if jq -e '.headers.authorization' <<<"$API_RESPONSE" >/dev/null; then fail "the access token was forwarded to the backend"; fi
pass "identity injected by the proxy, token not forwarded"

# The verification endpoint must not be reachable from outside.
VERIFY_STATUS=$(curl -sS -o /dev/null -D - "$BASE_URL/verify" -H "Authorization: Bearer $ACCESS_TOKEN" | status_of)
[[ "$VERIFY_STATUS" == "404" ]] || fail "/verify is exposed publicly with status $VERIFY_STATUS"
pass "/verify is not exposed publicly"

step "OIDC userinfo"
USERINFO=$(curl -fsS "$BASE_URL/oauth/userinfo" -H "Authorization: Bearer $ACCESS_TOKEN")
[[ "$(jq -r '.sub' <<<"$USERINFO")" == "$SUBJECT" ]] || fail "userinfo subject mismatch"
[[ "$(jq -r '.email' <<<"$USERINFO")" == "$EMAIL" ]] || fail "userinfo email mismatch"
pass "userinfo returns sub and email for the granted scopes"

# ---------------------------------------------------------------------------
step "Refresh rotation"
ROTATED=$(curl -fsS -X POST "$BASE_URL/oauth/token" \
  -H 'Content-Type: application/x-www-form-urlencoded' \
  -d grant_type=refresh_token \
  -d "refresh_token=$REFRESH_TOKEN" \
  -d "client_id=$CLIENT_ID")
NEW_ACCESS=$(jq -r '.access_token' <<<"$ROTATED")
NEW_REFRESH=$(jq -r '.refresh_token' <<<"$ROTATED")
[[ -n "$NEW_REFRESH" && "$NEW_REFRESH" != "null" ]] || fail "rotation returned no refresh token"
[[ "$NEW_REFRESH" != "$REFRESH_TOKEN" ]] || fail "the refresh token was not rotated"
pass "a new token pair was issued"

step "Idempotent retry inside the grace window"
REPLAY=$(curl -sS -X POST "$BASE_URL/oauth/token" \
  -H 'Content-Type: application/x-www-form-urlencoded' \
  -d grant_type=refresh_token -d "refresh_token=$REFRESH_TOKEN" -d "client_id=$CLIENT_ID")
REPLAYED_ACCESS=$(jq -r '.access_token // empty' <<<"$REPLAY")
[[ "$REPLAYED_ACCESS" == "$NEW_ACCESS" ]] || fail "a retried request did not return the same pair: $REPLAY"
pass "retry within the grace window is idempotent"

# ---------------------------------------------------------------------------
step "Refresh token reuse detection"
sleep 11 # outlive the grace window
REUSE_RESPONSE=$(curl -sS -X POST "$BASE_URL/oauth/token" \
  -H 'Content-Type: application/x-www-form-urlencoded' \
  -d grant_type=refresh_token -d "refresh_token=$REFRESH_TOKEN" -d "client_id=$CLIENT_ID")
[[ "$(jq -r '.error // empty' <<<"$REUSE_RESPONSE")" == "invalid_grant" ]] \
  || fail "reuse was not rejected: $REUSE_RESPONSE"
pass "replayed refresh token rejected with invalid_grant"

REVOKED_STATUS=$(curl -sS -o /dev/null -D - "$BASE_URL/api/ping" -H "Authorization: Bearer $NEW_ACCESS" | status_of)
[[ "$REVOKED_STATUS" == "401" ]] || fail "the token family survived reuse detection (got $REVOKED_STATUS)"
pass "the whole family was revoked, existing access tokens stopped working"

# ---------------------------------------------------------------------------
step "Logout"
LOGIN_LOCATION=$(curl -sS -o /dev/null -D - "$AUTH_URL" | location_of)
INTERACTION=$(sed 's/.*interaction=//' <<<"$LOGIN_LOCATION")
LOGIN_HTML=$(curl -fsS "$BASE_URL/login?interaction=$INTERACTION")
CSRF=$(grep -o 'name="csrf_token" value="[^"]*"' <<<"$LOGIN_HTML" | head -1 | sed 's/.*value="//; s/"$//')
LOGIN_RESULT=$(curl -sS -o /dev/null -D - -X POST "$BASE_URL/login" \
  --data-urlencode "interaction=$INTERACTION" --data-urlencode "csrf_token=$CSRF" \
  --data-urlencode "email=$EMAIL" --data-urlencode "password=$PASSWORD")
CODE=$(sed -n 's/.*[?&]code=\([^&]*\).*/\1/p' <<<"$(location_of <<<"$LOGIN_RESULT")")
TOKENS=$(curl -fsS -X POST "$BASE_URL/oauth/token" \
  -H 'Content-Type: application/x-www-form-urlencoded' \
  -d grant_type=authorization_code -d "code=$CODE" -d "redirect_uri=$REDIRECT_URI" \
  -d "client_id=$CLIENT_ID" -d "code_verifier=$VERIFIER")
LOGOUT_TOKEN=$(jq -r '.access_token' <<<"$TOKENS")

LOGOUT_STATUS=$(curl -sS -o /dev/null -D - -X POST "$BASE_URL/oauth/logout" -H "Authorization: Bearer $LOGOUT_TOKEN" | status_of)
[[ "$LOGOUT_STATUS" == "204" ]] || fail "logout returned $LOGOUT_STATUS"
AFTER_LOGOUT=$(curl -sS -o /dev/null -D - "$BASE_URL/api/ping" -H "Authorization: Bearer $LOGOUT_TOKEN" | status_of)
[[ "$AFTER_LOGOUT" == "401" ]] || fail "the token still worked after logout ($AFTER_LOGOUT)"
pass "logout revokes the session immediately"

# ---------------------------------------------------------------------------
step "Authorization code single use"
LOGIN_LOCATION=$(curl -sS -o /dev/null -D - "$AUTH_URL" | location_of)
INTERACTION=$(sed 's/.*interaction=//' <<<"$LOGIN_LOCATION")
LOGIN_HTML=$(curl -fsS "$BASE_URL/login?interaction=$INTERACTION")
CSRF=$(grep -o 'name="csrf_token" value="[^"]*"' <<<"$LOGIN_HTML" | head -1 | sed 's/.*value="//; s/"$//')
LOGIN_RESULT=$(curl -sS -o /dev/null -D - -X POST "$BASE_URL/login" \
  --data-urlencode "interaction=$INTERACTION" --data-urlencode "csrf_token=$CSRF" \
  --data-urlencode "email=$EMAIL" --data-urlencode "password=$PASSWORD")
CODE=$(sed -n 's/.*[?&]code=\([^&]*\).*/\1/p' <<<"$(location_of <<<"$LOGIN_RESULT")")

curl -fsS -X POST "$BASE_URL/oauth/token" -H 'Content-Type: application/x-www-form-urlencoded' \
  -d grant_type=authorization_code -d "code=$CODE" -d "redirect_uri=$REDIRECT_URI" \
  -d "client_id=$CLIENT_ID" -d "code_verifier=$VERIFIER" >/dev/null
SECOND_USE=$(curl -sS -X POST "$BASE_URL/oauth/token" -H 'Content-Type: application/x-www-form-urlencoded' \
  -d grant_type=authorization_code -d "code=$CODE" -d "redirect_uri=$REDIRECT_URI" \
  -d "client_id=$CLIENT_ID" -d "code_verifier=$VERIFIER")
[[ "$(jq -r '.error // empty' <<<"$SECOND_USE")" == "invalid_grant" ]] || fail "the code was redeemable twice: $SECOND_USE"
pass "a code cannot be redeemed twice"

step "Wrong PKCE verifier"
LOGIN_LOCATION=$(curl -sS -o /dev/null -D - "$AUTH_URL" | location_of)
INTERACTION=$(sed 's/.*interaction=//' <<<"$LOGIN_LOCATION")
LOGIN_HTML=$(curl -fsS "$BASE_URL/login?interaction=$INTERACTION")
CSRF=$(grep -o 'name="csrf_token" value="[^"]*"' <<<"$LOGIN_HTML" | head -1 | sed 's/.*value="//; s/"$//')
LOGIN_RESULT=$(curl -sS -o /dev/null -D - -X POST "$BASE_URL/login" \
  --data-urlencode "interaction=$INTERACTION" --data-urlencode "csrf_token=$CSRF" \
  --data-urlencode "email=$EMAIL" --data-urlencode "password=$PASSWORD")
CODE=$(sed -n 's/.*[?&]code=\([^&]*\).*/\1/p' <<<"$(location_of <<<"$LOGIN_RESULT")")
BAD_PKCE=$(curl -sS -X POST "$BASE_URL/oauth/token" -H 'Content-Type: application/x-www-form-urlencoded' \
  -d grant_type=authorization_code -d "code=$CODE" -d "redirect_uri=$REDIRECT_URI" \
  -d "client_id=$CLIENT_ID" -d "code_verifier=$(openssl rand -hex 32)")
[[ "$(jq -r '.error // empty' <<<"$BAD_PKCE")" == "invalid_grant" ]] || fail "a wrong verifier was accepted: $BAD_PKCE"
pass "a wrong code_verifier is rejected"

step "Consent screen"
# erplite-demo-spa зарегистрирован с require_consent = true, поэтому после входа
# сервис обязан показать экран согласия, а не сразу выдать код.
DEMO_CLIENT_ID="${DEMO_CLIENT_ID:-erplite-demo-spa}"
DEMO_REDIRECT_URI="$BASE_URL/demo/callback"
DEMO_VERIFIER=$(openssl rand -hex 32)
DEMO_CHALLENGE=$(printf '%s' "$DEMO_VERIFIER" | openssl dgst -binary -sha256 | openssl base64 | tr -d '=' | tr '+/' '-_')
DEMO_AUTH_URL="$BASE_URL/oauth/authorize?response_type=code&client_id=$DEMO_CLIENT_ID&redirect_uri=$(urlenc "$DEMO_REDIRECT_URI")&scope=$(urlenc "openid email offline_access")&state=consent-demo&code_challenge=$DEMO_CHALLENGE&code_challenge_method=S256"

LOGIN_LOCATION=$(curl -sS -o /dev/null -D - "$DEMO_AUTH_URL" | location_of)
INTERACTION=$(sed 's/.*interaction=//' <<<"$LOGIN_LOCATION")
LOGIN_HTML=$(curl -fsS "$BASE_URL$LOGIN_LOCATION")
CSRF=$(grep -o 'name="csrf_token" value="[^"]*"' <<<"$LOGIN_HTML" | head -1 | sed 's/.*value="//; s/"$//')

CONSENT_LOCATION=$(curl -sS -o /dev/null -D - -X POST "$BASE_URL/login" \
  --data-urlencode "interaction=$INTERACTION" \
  --data-urlencode "csrf_token=$CSRF" \
  --data-urlencode "email=$EMAIL" \
  --data-urlencode "password=$PASSWORD" | location_of)
[[ "$CONSENT_LOCATION" == *"/consent?interaction="* ]] \
  || fail "login skipped the consent screen: '$CONSENT_LOCATION'"
CONSENT_HTML=$(curl -fsS "$BASE_URL$CONSENT_LOCATION")
grep -q 'Разрешить доступ' <<<"$CONSENT_HTML" || fail "consent page was not rendered"
grep -q '<li>' <<<"$CONSENT_HTML" || fail "consent page does not list any scope"
pass "login leads to the consent screen with a scope list"

# Отказ возвращает клиенту access_denied (RFC 6749 §4.1.2.1).
DENY_LOCATION=$(curl -sS -o /dev/null -D - -X POST "$BASE_URL/consent" \
  --data-urlencode "interaction=$INTERACTION" \
  --data-urlencode "csrf_token=$CSRF" \
  --data-urlencode "decision=deny" | location_of)
[[ "$DENY_LOCATION" == *"error=access_denied"* ]] || fail "deny did not return access_denied: '$DENY_LOCATION'"
pass "deny returns error=access_denied with the original state"

# Согласие выдаёт код, который обменивается на токены.
ALLOW_LOCATION=$(curl -sS -o /dev/null -D - -X POST "$BASE_URL/consent" \
  --data-urlencode "interaction=$INTERACTION" \
  --data-urlencode "csrf_token=$CSRF" \
  --data-urlencode "decision=allow" | location_of)
DEMO_CODE=$(sed -n 's/.*[?&]code=\([^&]*\).*/\1/p' <<<"$ALLOW_LOCATION")
[[ -n "$DEMO_CODE" ]] || fail "consent allow did not return an authorization code: '$ALLOW_LOCATION'"

DEMO_TOKENS=$(curl -fsS -X POST "$BASE_URL/oauth/token" \
  -H 'Content-Type: application/x-www-form-urlencoded' \
  -d grant_type=authorization_code -d "code=$DEMO_CODE" -d "redirect_uri=$DEMO_REDIRECT_URI" \
  -d "client_id=$DEMO_CLIENT_ID" -d "code_verifier=$DEMO_VERIFIER")
[[ -n "$(jq -r '.access_token // empty' <<<"$DEMO_TOKENS")" ]] || fail "no token after consent: $DEMO_TOKENS"
pass "consent allow issues a usable token set"

step "Browser demo client"
DEMO_STATUS=$(curl -sS -o /dev/null -w '%{http_code}' "$BASE_URL/demo/")
[[ "$DEMO_STATUS" == "200" ]] || fail "the demo client is not served ($DEMO_STATUS)"
CALLBACK_STATUS=$(curl -sS -o /dev/null -w '%{http_code}' "$BASE_URL/demo/callback")
[[ "$CALLBACK_STATUS" == "200" ]] || fail "the demo callback route is not served ($CALLBACK_STATUS)"
curl -sS -o /dev/null -D - "$BASE_URL/demo/" | grep -qi 'content-security-policy' \
  || fail "the demo client is served without a CSP header"
pass "demo client and its callback route are served with a CSP"

step "Client credentials"
read -r INTEGRATION_SECRET < <(printf '%s\n' "${INTEGRATION_CLIENT_SECRET:-}")
if [[ -n "${INTEGRATION_CLIENT_SECRET:-}" ]]; then
  CC_TOKENS=$(curl -fsS -X POST "$BASE_URL/oauth/token" \
    -u "erplite-integration:$INTEGRATION_CLIENT_SECRET" \
    -d grant_type=client_credentials -d "scope=api.read")
  CC_ACCESS=$(jq -r '.access_token // empty' <<<"$CC_TOKENS")
  [[ -n "$CC_ACCESS" ]] || fail "no machine token issued: $CC_TOKENS"
  jq -e '.refresh_token == null' <<<"$CC_TOKENS" >/dev/null || fail "a machine token must not carry a refresh token"
  CC_STATUS=$(curl -sS -o /dev/null -D - "$BASE_URL/api/ping" -H "Authorization: Bearer $CC_ACCESS" | status_of)
  [[ "$CC_STATUS" == "200" ]] || fail "the machine token was rejected by the API ($CC_STATUS)"
  pass "client_credentials token works against the API"
else
  printf '   \033[33m–\033[0m skipped (set INTEGRATION_CLIENT_SECRET to include it)\n'
fi

step "Rate limiting"
# The per-account limiter is exercised with a random, non-existent address: it
# keeps the probe from locking the administrator account for 15 minutes, which a
# brute-force run against a real account would do.
PROBE_EMAIL="rate-limit-probe-$(openssl rand -hex 6)@example.com"
LOGIN_LOCATION=$(curl -sS -o /dev/null -D - "$AUTH_URL" | location_of)
INTERACTION=$(sed 's/.*interaction=//' <<<"$LOGIN_LOCATION")
LOGIN_HTML=$(curl -fsS "$BASE_URL/login?interaction=$INTERACTION")
CSRF=$(grep -o 'name="csrf_token" value="[^"]*"' <<<"$LOGIN_HTML" | head -1 | sed 's/.*value="//; s/"$//')

ATTEMPTS=0
LIMITED=0
for _ in $(seq 1 8); do
  ATTEMPTS=$((ATTEMPTS + 1))
  STATUS=$(curl -sS -o /dev/null -w '%{http_code}' -X POST "$BASE_URL/login" \
    --data-urlencode "interaction=$INTERACTION" \
    --data-urlencode "csrf_token=$CSRF" \
    --data-urlencode "email=$PROBE_EMAIL" \
    --data-urlencode "password=definitely-not-the-password")
  if [[ "$STATUS" == "429" ]]; then
    LIMITED=1
    break
  fi
done
[[ "$LIMITED" == "1" ]] || fail "repeated failed logins were never rate limited"
pass "the limiter answers 429 after $ATTEMPTS failed attempts"

step "Audit trail"
if command -v psql >/dev/null 2>&1; then
  EVENTS=$(psql "${DATABASE_URL:-postgres://iam_user:iam_pass@localhost:5432/iam?sslmode=disable}" -tAc \
    "SELECT count(*) FROM auth_events WHERE created_at > now() - interval '10 minutes'" 2>/dev/null || echo "")
  if [[ -n "$EVENTS" && "$EVENTS" -gt 0 ]]; then
    pass "auth_events holds $EVENTS events from this run"
  else
    printf '   \033[33m–\033[0m skipped (cannot query the database from the host)\n'
  fi
else
  printf '   \033[33m–\033[0m skipped (psql is not installed)\n'
fi

printf '\n\033[32mAll checks passed.\033[0m\n'
printf 'Note: the administrator account was not locked by this run; the probe used a throwaway address.\n'
