#!/bin/sh
# SPDX-License-Identifier: AGPL-3.0-or-later
set -eu

unset CDPATH
root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
cd "$root"

random_secret() {
  openssl rand -base64 48 | tr -d '\n'
}

export POSTGRES_PASSWORD=$(openssl rand -hex 32)
export HYDRA_SYSTEM_SECRET=$(random_secret)
export HYDRA_DSN="postgres://shauth:${POSTGRES_PASSWORD}@postgres:5432/hydra?sslmode=disable"
export SHAUTH_DATABASE_URL="postgres://shauth:${POSTGRES_PASSWORD}@postgres:5432/shauth?sslmode=disable"
export GITHUB_CLIENT_ID=local-integration-client
export GITHUB_CLIENT_SECRET=local-integration-secret
export SHAUTH_BOOTSTRAP_ADMIN_PASSWORD=$(random_secret)
export SHAUTH_OIDC_CLIENT_SECRET=$(random_secret)
cookie_jar=$(mktemp)
consent_page=$(mktemp)

cleanup() {
	status=$?
	if [ "$status" -ne 0 ]; then
		docker compose logs --no-color >&2 || true
	fi
	 docker compose down --volumes --remove-orphans
	 rm -f "$cookie_jar" "$consent_page"
	return "$status"
}
trap cleanup EXIT INT TERM

cleanup
docker compose up --build --detach

attempt=0
while [ "$attempt" -lt 300 ]; do
  if curl --fail --silent http://localhost:8080/healthz >/dev/null 2>&1 && \
     curl --fail --silent http://localhost:4444/health/ready >/dev/null 2>&1; then
    break
  fi
  attempt=$((attempt + 1))
  sleep 1
done

if [ "$attempt" -eq 300 ]; then
  docker compose logs --no-color
  exit 1
fi

curl --fail --silent --show-error http://localhost:8080/login | grep -q 'id="main-content"'
curl --fail --silent --show-error http://localhost:8080/login | grep -q 'aria-label="Primary navigation"'
curl --fail --silent --show-error http://localhost:8080/assets/theme.js | grep -q 'theme-toggle'
curl --fail --silent --show-error --dump-header - --output /dev/null http://localhost:8080/login | grep -qi "content-security-policy: default-src 'self'; script-src 'self' https://unpkg.com"

curl --fail --silent --show-error --location --cookie-jar "$cookie_jar" --cookie "$cookie_jar" --header 'Origin: http://localhost:8080' \
  --data-urlencode 'username=admin' \
  --data-urlencode "password=${SHAUTH_BOOTSTRAP_ADMIN_PASSWORD}" \
  --data-urlencode 'next=/' \
  http://localhost:8080/login | grep -q 'Welcome back, admin.'
curl --fail --silent --show-error --location --cookie-jar "$cookie_jar" --cookie "$cookie_jar" --header 'Origin: http://localhost:8080' \
  --data-urlencode 'client_id=shauth-integration-client' \
  --data-urlencode 'client_name=Shauth integration client' \
  --data-urlencode "client_secret=${SHAUTH_OIDC_CLIENT_SECRET}" \
  --data-urlencode 'redirect_uris=http://localhost:5555/callback' \
  http://localhost:8080/admin/clients | grep -q 'shauth-integration-client'
curl --fail --silent --show-error --location --cookie-jar "$cookie_jar" --cookie "$cookie_jar" --header 'Origin: http://localhost:8080' \
  --data-urlencode 'slug=integration-app' \
  --data-urlencode 'name=Integration app' \
  --data-urlencode 'description=End-to-end managed app catalog coverage.' \
  --data-urlencode 'launch_url=https://integration.dev.e6qu.dev' \
  --data-urlencode 'oidc_client_id=shauth-integration-client' \
  --data-urlencode 'health_url=https://integration.example.test/health' \
  --data-urlencode 'monitoring_url=https://integration.example.test/monitoring' \
  http://localhost:8080/admin/apps | grep -q 'Integration app'
login_location=$(curl --fail --silent --show-error --dump-header - --output /dev/null --cookie-jar "$cookie_jar" --cookie "$cookie_jar" \
  'http://localhost:4444/oauth2/auth?client_id=shauth-integration-client&response_type=code&scope=openid%20offline_access&redirect_uri=http%3A%2F%2Flocalhost%3A5555%2Fcallback&state=integration' |
  awk '/^[Ll]ocation:/{sub(/\r$/, "", $2); print $2}')
consent_location=$(curl --fail --silent --show-error --dump-header - --output /dev/null --cookie-jar "$cookie_jar" --cookie "$cookie_jar" "$login_location" |
  awk '/^[Ll]ocation:/{sub(/\r$/, "", $2); print $2}')
consent_page_location=$(curl --fail --silent --show-error --dump-header - --output /dev/null --cookie-jar "$cookie_jar" --cookie "$cookie_jar" "$consent_location" |
  awk '/^[Ll]ocation:/{sub(/\r$/, "", $2); print $2}')
curl --fail --silent --show-error --cookie-jar "$cookie_jar" --cookie "$cookie_jar" "$consent_page_location" >"$consent_page"
consent_challenge=$(grep -o 'name="challenge" value="[^"]*"' "$consent_page" | head -1 | cut -d '"' -f4)
callback_location=$(curl --fail --silent --show-error --dump-header - --output /dev/null --cookie-jar "$cookie_jar" --cookie "$cookie_jar" --header 'Origin: http://localhost:8080' \
  --data-urlencode "challenge=${consent_challenge}" \
  --data-urlencode 'scope=openid' \
  --data-urlencode 'scope=offline_access' \
  http://localhost:8080/oauth/consent |
  awk '/^[Ll]ocation:/{sub(/\r$/, "", $2); print $2}')
final_callback_location=$(curl --fail --silent --show-error --dump-header - --output /dev/null --cookie-jar "$cookie_jar" --cookie "$cookie_jar" "$callback_location" |
  awk '/^[Ll]ocation:/{sub(/\r$/, "", $2); print $2}')
authorization_code=$(printf '%s' "$final_callback_location" | sed -n 's/.*[?&]code=\([^&]*\).*/\1/p')
printf '%s\n' 'exchanging authorization code'
token_response=$(curl --fail --silent --show-error \
	--data-urlencode 'grant_type=authorization_code' \
	--data-urlencode "code=${authorization_code}" \
	--data-urlencode 'redirect_uri=http://localhost:5555/callback' \
	--data-urlencode 'client_id=shauth-integration-client' \
	--data-urlencode "client_secret=${SHAUTH_OIDC_CLIENT_SECRET}" \
	http://localhost:4444/oauth2/token)
refresh_token=$(printf '%s' "$token_response" | sed -n 's/.*"refresh_token":"\([^"]*\)".*/\1/p')
[ -n "$refresh_token" ]
printf '%s\n' 'refreshing access token'
curl --fail --silent --show-error \
	--data-urlencode 'grant_type=refresh_token' \
	--data-urlencode "refresh_token=${refresh_token}" \
	--data-urlencode 'client_id=shauth-integration-client' \
	--data-urlencode "client_secret=${SHAUTH_OIDC_CLIENT_SECRET}" \
	http://localhost:4444/oauth2/token | grep -q '"access_token"'
curl --fail --silent --show-error --cookie "$cookie_jar" http://localhost:8080/admin/users | grep -q 'admin@localhost.test'
curl --fail --silent --show-error --cookie "$cookie_jar" http://localhost:8080/admin | grep -q 'Private administration'
curl --fail --silent --show-error --location --cookie "$cookie_jar" --header 'Origin: http://localhost:8080' \
  --data-urlencode 'kind=user' \
  --data-urlencode 'target=integration-github-user' \
  --data-urlencode 'role=developer' \
  http://localhost:8080/admin/github | grep -q 'integration-github-user'
github_mapping_id=$(docker compose exec -T postgres psql -U shauth -d shauth -Atc "SELECT id FROM github_role_mappings WHERE kind = 'user' AND target = 'integration-github-user'")
curl --fail --silent --show-error --location --cookie "$cookie_jar" --header 'Origin: http://localhost:8080' --data '' "http://localhost:8080/admin/github/${github_mapping_id}/delete" | grep -q 'GitHub access rules'
developer_mapping_id=$(docker compose exec -T postgres psql -U shauth -d shauth -Atc "SELECT id FROM github_role_mappings WHERE kind = 'team' AND target = 'e6qu-org/e6qu-org-members'")
curl --fail --silent --show-error --location --cookie "$cookie_jar" --header 'Origin: http://localhost:8080' --data '' "http://localhost:8080/admin/github/${developer_mapping_id}/delete" >/dev/null
docker compose restart shauth >/dev/null
attempt=0
while [ "$attempt" -lt 30 ] && ! curl --fail --silent http://localhost:8080/healthz >/dev/null 2>&1; do
  attempt=$((attempt + 1))
  sleep 1
done
remaining_developer_mappings=$(docker compose exec -T postgres psql -U shauth -d shauth -Atc "SELECT count(*) FROM github_role_mappings WHERE kind = 'team' AND target = 'e6qu-org/e6qu-org-members'")
if [ "$attempt" -eq 30 ] || [ "$remaining_developer_mappings" != 0 ]; then
  docker compose logs --no-color
  exit 1
fi
curl --fail --silent --show-error --cookie "$cookie_jar" http://localhost:8080/monitoring | grep -q 'Ory Hydra authorization provider'
curl --fail --silent --show-error --cookie "$cookie_jar" http://localhost:8080/monitoring | grep -q 'Active browser sessions'
attempt=0
while [ "$attempt" -lt 30 ]; do
  if curl --fail --silent http://localhost:8080/.well-known/openid-configuration 2>/dev/null | grep -q 'issuer'; then
    break
  fi
  attempt=$((attempt + 1))
  sleep 1
done
if [ "$attempt" -eq 30 ]; then
  docker compose logs --no-color
  exit 1
fi

# Browser form posts must remain same-origin. Relying applications use Hydra's
# front-channel logout endpoint instead of posting directly to Shauth.
[ "$(curl --silent --output /dev/null --write-out '%{http_code}' --cookie "$cookie_jar" --header 'Origin: https://attacker.example.test' --data '' http://localhost:8080/logout)" = 403 ]
[ "$(curl --silent --output /dev/null --write-out '%{http_code}' --cookie "$cookie_jar" --header 'Origin: https://attacker.example.test' --data-urlencode 'challenge=invalid' http://localhost:8080/oauth/logout)" = 403 ]
curl --fail --silent --show-error --cookie "$cookie_jar" http://localhost:8080/logout | grep -q 'Sign out of Shauth?'
logout_start=$(curl --fail --silent --show-error --dump-header - --output /dev/null --cookie-jar "$cookie_jar" --cookie "$cookie_jar" --header 'Origin: http://localhost:8080' --data '' http://localhost:8080/logout |
	awk '/^[Ll]ocation:/{sub(/\r$/, "", $2); print $2}')
[ "$logout_start" = /oauth2/sessions/logout ]
logout_callback=$(curl --fail --silent --show-error --dump-header - --output /dev/null --cookie-jar "$cookie_jar" --cookie "$cookie_jar" "http://localhost:8080${logout_start}" |
	awk '/^[Ll]ocation:/{sub(/\r$/, "", $2); print $2}')
case "$logout_callback" in
	http://localhost:8080/oauth/logout?logout_challenge=*) ;;
	*) echo "unexpected Hydra logout callback: ${logout_callback}" >&2; exit 1 ;;
esac
logout_verifier=$(curl --fail --silent --show-error --dump-header - --output /dev/null --cookie-jar "$cookie_jar" --cookie "$cookie_jar" "$logout_callback" |
	awk '/^[Ll]ocation:/{sub(/\r$/, "", $2); print $2}')
case "$logout_verifier" in
	http://localhost:4444/oauth2/sessions/logout?logout_verifier=*) ;;
	*) echo "unexpected Hydra logout verifier: ${logout_verifier}" >&2; exit 1 ;;
esac
curl --fail --silent --show-error --location --cookie-jar "$cookie_jar" --cookie "$cookie_jar" "$logout_verifier" | grep -q 'One secure sign-in for your e6qu services.'
apps_status=$(curl --silent --output /dev/null --write-out '%{http_code}' --cookie "$cookie_jar" http://localhost:8080/apps)
[ "$apps_status" = 303 ]

# Continue the administrative revocation coverage with a fresh local session
# after testing normal browser logout.
curl --fail --silent --show-error --location --cookie-jar "$cookie_jar" --cookie "$cookie_jar" --header 'Origin: http://localhost:8080' \
  --data-urlencode 'username=admin' \
  --data-urlencode "password=${SHAUTH_BOOTSTRAP_ADMIN_PASSWORD}" \
  --data-urlencode 'next=/' \
  http://localhost:8080/login >/dev/null
admin_id=$(docker compose exec -T postgres psql -U shauth -d shauth -Atc "SELECT id FROM users WHERE username = 'admin'")
curl --fail --silent --show-error --location --cookie "$cookie_jar" --header 'Origin: http://localhost:8080' --data '' "http://localhost:8080/admin/users/${admin_id}/sessions/revoke" >/dev/null
curl --fail --silent --show-error --location --cookie-jar "$cookie_jar" --cookie "$cookie_jar" --header 'Origin: http://localhost:8080' \
  --data-urlencode 'username=admin' \
  --data-urlencode "password=${SHAUTH_BOOTSTRAP_ADMIN_PASSWORD}" \
  --data-urlencode 'next=/' \
  http://localhost:8080/login >/dev/null
curl --fail --silent --show-error --cookie "$cookie_jar" http://localhost:8080/admin/users/${admin_id}/sessions | grep -q 'Revoked'

# Subject-wide invalidation must revoke Hydra's refresh grants as well as each
# Shauth browser session. A successful refresh here would leave a revoked user
# able to access a relying application.
if curl --fail --silent \
	--data-urlencode 'grant_type=refresh_token' \
	--data-urlencode "refresh_token=${refresh_token}" \
	--data-urlencode 'client_id=shauth-integration-client' \
	--data-urlencode "client_secret=${SHAUTH_OIDC_CLIENT_SECRET}" \
	http://localhost:4444/oauth2/token >/dev/null 2>&1; then
	echo 'revoked OIDC refresh token was accepted' >&2
	exit 1
fi
