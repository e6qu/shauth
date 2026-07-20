#!/bin/sh
# SPDX-License-Identifier: AGPL-3.0-or-later
set -eu

unset CDPATH
root=$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd)
cd "$root"

npm ci
npx playwright install --with-deps chromium

random_secret() {
  openssl rand -base64 48 | tr -d '\n'
}

POSTGRES_PASSWORD=$(openssl rand -hex 32)
export POSTGRES_PASSWORD
HYDRA_SYSTEM_SECRET=$(random_secret)
export HYDRA_SYSTEM_SECRET
export HYDRA_DSN="postgres://shauth:${POSTGRES_PASSWORD}@postgres:5432/hydra?sslmode=disable"
export HYDRA_PUBLIC_URL=http://localhost:8080
export SHAUTH_DATABASE_URL="postgres://shauth:${POSTGRES_PASSWORD}@postgres:5432/shauth?sslmode=disable"
export GITHUB_CLIENT_ID=local-integration-client
export GITHUB_CLIENT_SECRET=local-integration-secret
SHAUTH_BOOTSTRAP_ADMIN_PASSWORD=$(random_secret)
export SHAUTH_BOOTSTRAP_ADMIN_PASSWORD
SHAUTH_OIDC_CLIENT_SECRET=$(random_secret)
export SHAUTH_OIDC_CLIENT_SECRET
SHAUTH_BOOTSTRAP_APP_CLIENT_SECRET=$(random_secret)
export SHAUTH_BOOTSTRAP_APP_CLIENT_SECRET
SHAUTH_GATEWAY_CLIENT_SECRET=$(random_secret)
export SHAUTH_GATEWAY_CLIENT_SECRET
SHAUTH_GATEWAY_SECONDARY_CLIENT_SECRET=$(random_secret)
export SHAUTH_GATEWAY_SECONDARY_CLIENT_SECRET
SHAUTH_GATEWAY_COOKIE_SECRET=$(random_secret)
export SHAUTH_GATEWAY_COOKIE_SECRET
SHAUTH_GATEWAY_SECONDARY_COOKIE_SECRET=$(random_secret)
export SHAUTH_GATEWAY_SECONDARY_COOKIE_SECRET
SHAUTH_BOOTSTRAP_APPS_JSON=$(printf '[{"slug":"bootstrap-app","name":"Bootstrap app","description":"Bootstrap reconciliation coverage.","launch_url":"https://bootstrap.dev.e6qu.dev","oidc_client_id":"bootstrap-app","oidc_client_secret":"%s","redirect_uris":["https://bootstrap.dev.e6qu.dev/oidc/initial"],"post_logout_redirect_uris":["https://bootstrap.dev.e6qu.dev/"],"frontchannel_logout_uri":"https://bootstrap.dev.e6qu.dev/oidc/frontchannel-logout","health_url":"https://bootstrap.dev.e6qu.dev/health","monitoring_url":""},{"slug":"gateway-integration","name":"Gateway integration","description":"First relying-party acceptance coverage.","launch_url":"http://localhost:5556/","oidc_client_id":"gateway-integration","oidc_client_secret":"%s","redirect_uris":["http://localhost:5556/auth/callback"],"post_logout_redirect_uris":["http://localhost:5556/auth/signed-out"],"frontchannel_logout_uri":"http://localhost:5556/auth/frontchannel-logout","backchannel_logout_uri":"http://localhost:5556/auth/backchannel-logout","health_url":"http://localhost:5556/auth/healthz","monitoring_url":""},{"slug":"gateway-secondary","name":"Gateway secondary","description":"Second relying-party single sign-on and logout coverage.","launch_url":"http://localhost:5558/","oidc_client_id":"gateway-secondary","oidc_client_secret":"%s","redirect_uris":["http://localhost:5558/auth/callback"],"post_logout_redirect_uris":["http://localhost:5558/auth/signed-out"],"frontchannel_logout_uri":"http://localhost:5558/auth/frontchannel-logout","backchannel_logout_uri":"http://localhost:5558/auth/backchannel-logout","health_url":"http://localhost:5558/auth/healthz","monitoring_url":""}]' "$SHAUTH_BOOTSTRAP_APP_CLIENT_SECRET" "$SHAUTH_GATEWAY_CLIENT_SECRET" "$SHAUTH_GATEWAY_SECONDARY_CLIENT_SECRET")
export SHAUTH_BOOTSTRAP_APPS_JSON
cookie_jar=$(mktemp)
gateway_binary=$(mktemp)
gateway_pid=
gateway_secondary_pid=

cleanup() {
	status=$?
	if [ "$status" -ne 0 ]; then
		docker compose logs --no-color --tail=120 shauth hydra >&2 || true
	fi
	if [ -n "$gateway_pid" ]; then
		kill "$gateway_pid" 2>/dev/null || true
		wait "$gateway_pid" 2>/dev/null || true
	fi
	if [ -n "$gateway_secondary_pid" ]; then
		kill "$gateway_secondary_pid" 2>/dev/null || true
		wait "$gateway_secondary_pid" 2>/dev/null || true
	fi
	 docker compose down --volumes --remove-orphans
	rm -f "$cookie_jar" "$gateway_binary"
	return "$status"
}
trap cleanup EXIT INT TERM

cleanup
docker compose build shauth
docker compose up --no-build --detach

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
curl --fail --silent --show-error http://localhost:8080/login | grep -q 'src="/assets/htmx-2.0.8.min.js"'
curl --fail --silent --show-error http://localhost:8080/assets/htmx-2.0.8.min.js | grep -q 'htmx'
curl --fail --silent --show-error --dump-header - --output /dev/null http://localhost:8080/login | grep -qi "content-security-policy: default-src 'self'; script-src 'self';"
if curl --fail --silent --show-error http://localhost:8080/login | grep -q 'unpkg.com'; then
	echo 'Shauth rendered an external browser asset' >&2
	exit 1
fi
curl --fail --silent --show-error http://localhost:4445/admin/clients/bootstrap-app | grep -q 'https://bootstrap.dev.e6qu.dev/oidc/initial'
curl --fail --silent --show-error http://localhost:4445/admin/clients/bootstrap-app | grep -q 'https://bootstrap.dev.e6qu.dev/oidc/frontchannel-logout'

curl --fail --silent --show-error --cookie-jar "$cookie_jar" http://localhost:8080/login >/dev/null
csrf_token=$(awk '$6 == "shauth_csrf" { print $7 }' "$cookie_jar")
[ -n "$csrf_token" ]

SHAUTH_GATEWAY_CLIENT_SECRET=$(random_secret)
SHAUTH_GATEWAY_SECONDARY_CLIENT_SECRET=$(random_secret)
SHAUTH_BOOTSTRAP_APPS_JSON=$(printf '[{"slug":"bootstrap-app","name":"Bootstrap app updated","description":"Updated bootstrap reconciliation coverage.","launch_url":"https://bootstrap.dev.e6qu.dev/apps","oidc_client_id":"bootstrap-app","oidc_client_secret":"%s","redirect_uris":["https://bootstrap.dev.e6qu.dev/oidc/updated"],"post_logout_redirect_uris":["https://bootstrap.dev.e6qu.dev/signed-out"],"frontchannel_logout_uri":"https://bootstrap.dev.e6qu.dev/oidc/frontchannel-logout","health_url":"https://bootstrap.dev.e6qu.dev/ready","monitoring_url":"https://bootstrap.dev.e6qu.dev/monitoring"},{"slug":"gateway-integration","name":"Gateway integration","description":"First relying-party acceptance coverage.","launch_url":"http://localhost:5556/","oidc_client_id":"gateway-integration","oidc_client_secret":"%s","redirect_uris":["http://localhost:5556/auth/callback"],"post_logout_redirect_uris":["http://localhost:5556/auth/signed-out"],"frontchannel_logout_uri":"http://localhost:5556/auth/frontchannel-logout","backchannel_logout_uri":"http://localhost:5556/auth/backchannel-logout","health_url":"http://localhost:5556/auth/healthz","monitoring_url":""},{"slug":"gateway-secondary","name":"Gateway secondary","description":"Second relying-party single sign-on and logout coverage.","launch_url":"http://localhost:5558/","oidc_client_id":"gateway-secondary","oidc_client_secret":"%s","redirect_uris":["http://localhost:5558/auth/callback"],"post_logout_redirect_uris":["http://localhost:5558/auth/signed-out"],"frontchannel_logout_uri":"http://localhost:5558/auth/frontchannel-logout","backchannel_logout_uri":"http://localhost:5558/auth/backchannel-logout","health_url":"http://localhost:5558/auth/healthz","monitoring_url":""}]' "$SHAUTH_BOOTSTRAP_APP_CLIENT_SECRET" "$SHAUTH_GATEWAY_CLIENT_SECRET" "$SHAUTH_GATEWAY_SECONDARY_CLIENT_SECRET")
export SHAUTH_BOOTSTRAP_APPS_JSON
docker compose up --force-recreate --no-deps --detach shauth
attempt=0
while [ "$attempt" -lt 30 ] && ! curl --fail --silent http://localhost:8080/healthz >/dev/null 2>&1; do
  attempt=$((attempt + 1))
  sleep 1
done
if [ "$attempt" -eq 30 ]; then
  docker compose logs --no-color
  exit 1
fi
curl --fail --silent --show-error http://localhost:4445/admin/clients/bootstrap-app | grep -q 'https://bootstrap.dev.e6qu.dev/oidc/updated'
for client_id in bootstrap-app gateway-integration gateway-secondary; do
	client_registration=$(curl --fail --silent --show-error "http://localhost:4445/admin/clients/${client_id}")
	printf '%s' "$client_registration" | grep -q '"token_endpoint_auth_method":"client_secret_post"'
	printf '%s' "$client_registration" | grep -q '"grant_types":\["authorization_code","refresh_token"\]'
	printf '%s' "$client_registration" | grep -q '"response_types":\["code"\]'
done
# The browser reaches test relying parties through host loopback, while Hydra
# reaches their real back-channel endpoints across the container boundary.
for client_port in gateway-integration:5556 gateway-secondary:5558; do
	client_id=${client_port%:*}
	port=${client_port#*:}
	client_registration=$(curl --fail --silent --show-error "http://localhost:4445/admin/clients/${client_id}")
	client_registration=$(printf '%s' "$client_registration" | sed "s#http://localhost:${port}/auth/backchannel-logout#http://host.docker.internal:${port}/auth/backchannel-logout#")
	curl --fail --silent --show-error --request PUT --header 'Content-Type: application/json' \
		--data "$client_registration" "http://localhost:4445/admin/clients/${client_id}" >/dev/null
done
bootstrap_app=$(docker compose exec -T postgres psql -U shauth -d shauth -Atc "SELECT concat_ws('|',name,description,launch_url,oidc_client_id,health_url,monitoring_url) FROM managed_apps WHERE slug='bootstrap-app'")
[ "$bootstrap_app" = 'Bootstrap app updated|Updated bootstrap reconciliation coverage.|https://bootstrap.dev.e6qu.dev/apps|bootstrap-app|https://bootstrap.dev.e6qu.dev/ready|https://bootstrap.dev.e6qu.dev/monitoring' ]

curl --fail --silent --show-error --location --cookie-jar "$cookie_jar" --cookie "$cookie_jar" --header 'Origin: http://localhost:8080' \
  --data-urlencode "_csrf=${csrf_token}" \
  --data-urlencode 'username=admin' \
  --data-urlencode "password=${SHAUTH_BOOTSTRAP_ADMIN_PASSWORD}" \
  --data-urlencode 'next=/' \
  http://localhost:8080/login | grep -q 'Welcome back, admin.'
curl --fail --silent --show-error --location --cookie-jar "$cookie_jar" --cookie "$cookie_jar" --header 'Origin: http://localhost:8080' \
  --data-urlencode "_csrf=${csrf_token}" \
  --data-urlencode 'client_id=shauth-integration-client' \
  --data-urlencode 'client_name=Shauth integration client' \
  --data-urlencode "client_secret=${SHAUTH_OIDC_CLIENT_SECRET}" \
  --data-urlencode 'redirect_uris=http://localhost:5555/callback' \
  --data-urlencode 'post_logout_redirect_uris=http://localhost:5555/signed-out' \
  --data-urlencode 'frontchannel_logout_uri=http://localhost:5555/frontchannel-logout' \
  --data-urlencode 'backchannel_logout_uri=http://localhost:5555/backchannel-logout' \
  http://localhost:8080/admin/clients | grep -q 'shauth-integration-client'
curl --fail --silent --show-error --cookie "$cookie_jar" http://localhost:8080/admin/session-policy | grep -q 'Session time limits'
curl --fail --silent --show-error --location --cookie "$cookie_jar" --header 'Origin: http://localhost:8080' \
  --data-urlencode "_csrf=${csrf_token}" \
  --data-urlencode 'browser_absolute_hours=720' \
  --data-urlencode 'browser_idle_minutes=720' \
  --data-urlencode 'oidc_sso_hours=720' \
  --data-urlencode 'access_token_minutes=15' \
  --data-urlencode 'id_token_minutes=15' \
  --data-urlencode 'refresh_token_hours=720' \
  http://localhost:8080/admin/session-policy | grep -q 'were saved and applied'
curl --fail --silent --show-error --location --cookie-jar "$cookie_jar" --cookie "$cookie_jar" --header 'Origin: http://localhost:8080' \
  --data-urlencode "_csrf=${csrf_token}" \
  --data-urlencode 'slug=integration-app' \
  --data-urlencode 'name=Integration app' \
  --data-urlencode 'description=End-to-end managed app catalog coverage.' \
  --data-urlencode 'launch_url=http://localhost:5555/' \
  --data-urlencode 'oidc_client_id=shauth-integration-client' \
  --data-urlencode 'health_url=http://localhost:5555/health' \
  --data-urlencode 'monitoring_url=http://localhost:5555/monitoring' \
  http://localhost:8080/admin/apps | grep -q 'Integration app'
npm run test:browser

go build -o "$gateway_binary" ./cmd/shauth-gateway
OIDC_GATEWAY_ISSUER=http://localhost:8080 \
OIDC_GATEWAY_CLIENT_ID=gateway-integration \
OIDC_GATEWAY_CLIENT_SECRET="$SHAUTH_GATEWAY_CLIENT_SECRET" \
OIDC_GATEWAY_PUBLIC_URL=http://localhost:5556 \
OIDC_GATEWAY_UPSTREAM_URL=http://127.0.0.1:5557 \
OIDC_GATEWAY_POST_LOGOUT_URL=http://localhost:5556/auth/signed-out \
OIDC_GATEWAY_COOKIE_SECRET="$SHAUTH_GATEWAY_COOKIE_SECRET" \
OIDC_GATEWAY_ALLOW_INSECURE_COOKIE=true \
OIDC_GATEWAY_LISTEN_ADDRESS=0.0.0.0:5556 \
DATABASE_URL="postgres://shauth:${POSTGRES_PASSWORD}@127.0.0.1:55432/shauth?sslmode=disable" \
"$gateway_binary" &
gateway_pid=$!
OIDC_GATEWAY_ISSUER=http://localhost:8080 \
OIDC_GATEWAY_CLIENT_ID=gateway-secondary \
OIDC_GATEWAY_CLIENT_SECRET="$SHAUTH_GATEWAY_SECONDARY_CLIENT_SECRET" \
OIDC_GATEWAY_PUBLIC_URL=http://localhost:5558 \
OIDC_GATEWAY_UPSTREAM_URL=http://127.0.0.1:5559 \
OIDC_GATEWAY_POST_LOGOUT_URL=http://localhost:5558/auth/signed-out \
OIDC_GATEWAY_COOKIE_SECRET="$SHAUTH_GATEWAY_SECONDARY_COOKIE_SECRET" \
OIDC_GATEWAY_ALLOW_INSECURE_COOKIE=true \
OIDC_GATEWAY_LISTEN_ADDRESS=0.0.0.0:5558 \
DATABASE_URL="postgres://shauth:${POSTGRES_PASSWORD}@127.0.0.1:55432/shauth?sslmode=disable" \
"$gateway_binary" &
gateway_secondary_pid=$!
attempt=0
while [ "$attempt" -lt 60 ] && { ! curl --fail --silent http://localhost:5556/auth/healthz >/dev/null 2>&1 || ! curl --fail --silent http://localhost:5558/auth/healthz >/dev/null 2>&1; }; do
  attempt=$((attempt + 1))
  sleep 1
done
if [ "$attempt" -eq 60 ]; then
  exit 1
fi
npm run test:gateway
login_location=$(curl --fail --silent --show-error --dump-header - --output /dev/null --cookie-jar "$cookie_jar" --cookie "$cookie_jar" \
  'http://localhost:8080/oauth2/auth?client_id=shauth-integration-client&response_type=code&scope=openid%20profile%20email%20offline_access&redirect_uri=http%3A%2F%2Flocalhost%3A5555%2Fcallback&state=integration' |
  awk '/^[Ll]ocation:/{sub(/\r$/, "", $2); print $2}')
consent_location=$(curl --fail --silent --show-error --dump-header - --output /dev/null --cookie-jar "$cookie_jar" --cookie "$cookie_jar" "$login_location" |
  awk '/^[Ll]ocation:/{sub(/\r$/, "", $2); print $2}')
consent_page_location=$(curl --fail --silent --show-error --dump-header - --output /dev/null --cookie-jar "$cookie_jar" --cookie "$cookie_jar" "$consent_location" |
  awk '/^[Ll]ocation:/{sub(/\r$/, "", $2); print $2}')
# Shauth-owned managed applications receive the first-party grant without a
# per-application browser form. The app is still registered with Ory Hydra,
# and Shauth records a durable consent grant for normal OAuth revocation.
callback_location=$(curl --fail --silent --show-error --dump-header - --output /dev/null --cookie-jar "$cookie_jar" --cookie "$cookie_jar" "$consent_page_location" |
	awk '/^[Ll]ocation:/{sub(/\r$/, "", $2); print $2}')
case "$callback_location" in
	http://localhost:8080/oauth2/auth?*consent_verifier=*) ;;
	*) echo "managed application did not receive automatic consent: ${callback_location}" >&2; exit 1 ;;
esac
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
	http://localhost:8080/oauth2/token)
access_token=$(printf '%s' "$token_response" | sed -n 's/.*"access_token":"\([^"]*\)".*/\1/p')
refresh_token=$(printf '%s' "$token_response" | sed -n 's/.*"refresh_token":"\([^"]*\)".*/\1/p')
[ -n "$access_token" ]
[ -n "$refresh_token" ]
printf '%s\n' 'reading OpenID Connect UserInfo through Shauth'
userinfo_response=$(curl --fail --silent --show-error \
	--header "Authorization: Bearer ${access_token}" \
	http://localhost:8080/userinfo)
printf '%s' "$userinfo_response" | grep -q '"email":"admin@localhost.test"'
printf '%s' "$userinfo_response" | grep -q '"preferred_username":"admin"'
printf '%s' "$userinfo_response" | grep -q '"role":"admin"'
printf '%s' "$userinfo_response" | grep -q '"email_verified":true'
printf '%s\n' 'refreshing access token'
curl --fail --silent --show-error \
	--data-urlencode 'grant_type=refresh_token' \
	--data-urlencode "refresh_token=${refresh_token}" \
	--data-urlencode 'client_id=shauth-integration-client' \
	--data-urlencode "client_secret=${SHAUTH_OIDC_CLIENT_SECRET}" \
	http://localhost:8080/oauth2/token | grep -q '"access_token"'
curl --fail --silent --show-error --cookie "$cookie_jar" http://localhost:8080/admin/users | grep -q 'admin@localhost.test'
curl --fail --silent --show-error --cookie "$cookie_jar" http://localhost:8080/admin | grep -q 'Private administration'
curl --fail --silent --show-error --location --cookie "$cookie_jar" --header 'Origin: http://localhost:8080' \
  --data-urlencode "_csrf=${csrf_token}" \
  --data-urlencode 'kind=user' \
  --data-urlencode 'target=integration-github-user' \
  --data-urlencode 'role=developer' \
  http://localhost:8080/admin/github | grep -q 'integration-github-user'
github_mapping_id=$(docker compose exec -T postgres psql -U shauth -d shauth -Atc "SELECT id FROM github_role_mappings WHERE kind = 'user' AND target = 'integration-github-user'")
curl --fail --silent --show-error --location --cookie "$cookie_jar" --header 'Origin: http://localhost:8080' --data-urlencode "_csrf=${csrf_token}" "http://localhost:8080/admin/github/${github_mapping_id}/delete" | grep -q 'GitHub access rules'
developer_mapping_id=$(docker compose exec -T postgres psql -U shauth -d shauth -Atc "SELECT id FROM github_role_mappings WHERE kind = 'team' AND target = 'e6qu-org/e6qu-org-members'")
curl --fail --silent --show-error --location --cookie "$cookie_jar" --header 'Origin: http://localhost:8080' --data-urlencode "_csrf=${csrf_token}" "http://localhost:8080/admin/github/${developer_mapping_id}/delete" >/dev/null
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

# Browser form posts must remain same-origin. Relying applications use Ory
# Hydra's published logout endpoint instead of posting directly to Shauth.
[ "$(curl --silent --output /dev/null --write-out '%{http_code}' --cookie "$cookie_jar" --header 'Origin: https://attacker.example.test' --data '' http://localhost:8080/logout)" = 403 ]
[ "$(curl --silent --output /dev/null --write-out '%{http_code}' --cookie "$cookie_jar" --header 'Origin: https://attacker.example.test' --data-urlencode 'challenge=invalid' http://localhost:8080/oauth/logout)" = 403 ]
curl --fail --silent --show-error --cookie "$cookie_jar" http://localhost:8080/logout | grep -q 'Sign out everywhere?'
logout_start=$(curl --fail --silent --show-error --dump-header - --output /dev/null --cookie-jar "$cookie_jar" --cookie "$cookie_jar" --header 'Origin: http://localhost:8080' --data-urlencode "_csrf=${csrf_token}" http://localhost:8080/logout |
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
	http://localhost:8080/oauth2/sessions/logout?logout_verifier=*) ;;
	*) echo "unexpected Hydra logout verifier: ${logout_verifier}" >&2; exit 1 ;;
esac
logout_propagation=$(curl --fail --silent --show-error --location --cookie-jar "$cookie_jar" --cookie "$cookie_jar" "$logout_verifier")
printf '%s' "$logout_propagation" | grep -q 'frontchannel-logout'
apps_status=$(curl --silent --output /dev/null --write-out '%{http_code}' --cookie "$cookie_jar" http://localhost:8080/apps)
[ "$apps_status" = 303 ]

# Continue the administrative revocation coverage with a fresh local session
# after testing normal browser logout.
curl --fail --silent --show-error --location --cookie-jar "$cookie_jar" --cookie "$cookie_jar" --header 'Origin: http://localhost:8080' \
  --data-urlencode "_csrf=${csrf_token}" \
  --data-urlencode 'username=admin' \
  --data-urlencode "password=${SHAUTH_BOOTSTRAP_ADMIN_PASSWORD}" \
  --data-urlencode 'next=/' \
  http://localhost:8080/login >/dev/null
admin_id=$(docker compose exec -T postgres psql -U shauth -d shauth -Atc "SELECT id FROM users WHERE username = 'admin'")
single_session_setup=$(curl --fail --silent --show-error --dump-header - --output /dev/null --cookie-jar "$cookie_jar" --cookie "$cookie_jar" \
	'http://localhost:8080/oauth2/auth?client_id=gateway-integration&response_type=code&scope=openid%20profile%20email&redirect_uri=http%3A%2F%2Flocalhost%3A5556%2Fauth%2Fcallback&state=single-session-setup&nonce=single-session-setup&code_challenge=6ZPyvBxk3i_6fw7GZ1sKcSmw5Q3e4V1uNQf2JgQJ9bU&code_challenge_method=S256' |
	awk '/^[Ll]ocation:/{sub(/\r$/, "", $2); print $2}')
case "$single_session_setup" in
	http://localhost:8080/oauth/login?login_challenge=*) ;;
	*) echo "fresh OpenID Connect session did not request Shauth login: ${single_session_setup}" >&2; exit 1 ;;
esac
single_session_accept=$(curl --fail --silent --show-error --dump-header - --output /dev/null --cookie-jar "$cookie_jar" --cookie "$cookie_jar" "$single_session_setup" |
	awk '/^[Ll]ocation:/{sub(/\r$/, "", $2); print $2}')
case "$single_session_accept" in
	http://localhost:8080/oauth2/auth?*login_verifier=*) ;;
	*) echo "Shauth did not accept the OpenID Connect login session: ${single_session_accept}" >&2; exit 1 ;;
esac
curl --fail --silent --show-error --dump-header - --output /dev/null --cookie-jar "$cookie_jar" --cookie "$cookie_jar" "$single_session_accept" >/dev/null
current_session_id=$(docker compose exec -T postgres psql -U shauth -d shauth -Atc "SELECT id FROM sessions WHERE user_id='${admin_id}'::uuid AND revoked_at IS NULL ORDER BY created_at DESC LIMIT 1")
curl --fail --silent --show-error --output /dev/null --cookie "$cookie_jar" --header 'Origin: http://localhost:8080' --header 'Referer: http://localhost:8080/admin/users' --data-urlencode "_csrf=${csrf_token}" "http://localhost:8080/admin/sessions/${current_session_id}/revoke"
[ "$(curl --silent --output /dev/null --write-out '%{http_code}' --cookie "$cookie_jar" http://localhost:8080/apps)" = 303 ]
single_session_login=$(curl --fail --silent --show-error --dump-header - --output /dev/null --cookie-jar "$cookie_jar" --cookie "$cookie_jar" \
	'http://localhost:8080/oauth2/auth?client_id=gateway-integration&response_type=code&scope=openid%20profile%20email&redirect_uri=http%3A%2F%2Flocalhost%3A5556%2Fauth%2Fcallback&state=single-session-revocation&nonce=single-session-revocation&code_challenge=6ZPyvBxk3i_6fw7GZ1sKcSmw5Q3e4V1uNQf2JgQJ9bU&code_challenge_method=S256' |
	awk '/^[Ll]ocation:/{sub(/\r$/, "", $2); print $2}')
case "$single_session_login" in
	http://localhost:8080/oauth/login?login_challenge=*) ;;
	*) echo "revoked OpenID Connect session was still remembered: ${single_session_login}" >&2; exit 1 ;;
esac
curl --fail --silent --show-error --location --cookie-jar "$cookie_jar" --cookie "$cookie_jar" --header 'Origin: http://localhost:8080' \
	--data-urlencode "_csrf=${csrf_token}" \
	--data-urlencode 'username=admin' \
	--data-urlencode "password=${SHAUTH_BOOTSTRAP_ADMIN_PASSWORD}" \
	--data-urlencode 'next=/' \
	http://localhost:8080/login >/dev/null
curl --fail --silent --show-error --location --cookie "$cookie_jar" --header 'Origin: http://localhost:8080' --data-urlencode "_csrf=${csrf_token}" "http://localhost:8080/admin/users/${admin_id}/sessions/revoke" >/dev/null
curl --fail --silent --show-error --location --cookie-jar "$cookie_jar" --cookie "$cookie_jar" --header 'Origin: http://localhost:8080' \
  --data-urlencode "_csrf=${csrf_token}" \
  --data-urlencode 'username=admin' \
  --data-urlencode "password=${SHAUTH_BOOTSTRAP_ADMIN_PASSWORD}" \
  --data-urlencode 'next=/' \
  http://localhost:8080/login >/dev/null
curl --fail --silent --show-error --cookie "$cookie_jar" "http://localhost:8080/admin/users/${admin_id}/sessions" | grep -q 'Revoked'

# Subject-wide invalidation must revoke Hydra's refresh grants as well as each
# Shauth browser session. A successful refresh here would leave a revoked user
# able to access a relying application.
if curl --fail --silent \
	--data-urlencode 'grant_type=refresh_token' \
	--data-urlencode "refresh_token=${refresh_token}" \
	--data-urlencode 'client_id=shauth-integration-client' \
	--data-urlencode "client_secret=${SHAUTH_OIDC_CLIENT_SECRET}" \
	http://localhost:8080/oauth2/token >/dev/null 2>&1; then
	echo 'revoked OIDC refresh token was accepted' >&2
	exit 1
fi

docker compose exec -T postgres psql -U shauth -d shauth -v ON_ERROR_STOP=1 -c "INSERT INTO managed_apps (id,slug,name,description,launch_url,oidc_client_id,health_url,monitoring_url,created_at) VALUES ('00000000-0000-4000-8000-000000000001','protected-app','Protected app','Administrator-owned app.','https://protected.dev.e6qu.dev','protected-client','https://protected.dev.e6qu.dev/health',NULL,now())" >/dev/null
protected_client_secret=$(random_secret)
SHAUTH_BOOTSTRAP_APPS_JSON=$(printf '[{"slug":"protected-app","name":"Takeover attempt","description":"Bootstrap must not replace an administrator-owned app.","launch_url":"https://takeover.dev.e6qu.dev","oidc_client_id":"takeover-client","oidc_client_secret":"%s","redirect_uris":["https://takeover.dev.e6qu.dev/oidc/callback"],"post_logout_redirect_uris":["https://takeover.dev.e6qu.dev/"],"backchannel_logout_uri":"https://takeover.dev.e6qu.dev/oidc/backchannel-logout","health_url":"https://takeover.dev.e6qu.dev/health","monitoring_url":""}]' "$protected_client_secret")
export SHAUTH_BOOTSTRAP_APPS_JSON
docker compose up --force-recreate --no-deps --detach shauth
attempt=0
shauth_status=running
while [ "$attempt" -lt 30 ]; do
	shauth_container=$(docker compose ps --all --quiet shauth)
	shauth_status=$(docker inspect --format '{{.State.Status}}' "$shauth_container")
	[ "$shauth_status" = exited ] && break
	attempt=$((attempt + 1))
	sleep 1
done
if [ "$shauth_status" != exited ] || [ "$(docker inspect --format '{{.State.ExitCode}}' "$shauth_container")" -eq 0 ]; then
	echo 'Shauth accepted a bootstrap app takeover with another OpenID Connect client' >&2
	exit 1
fi
docker compose logs --no-color shauth | grep -q 'managed app slug "protected-app" or OpenID Connect client "takeover-client" belongs to another registration'
if curl --fail --silent http://localhost:4445/admin/clients/takeover-client >/dev/null 2>&1; then
	echo 'Shauth mutated Ory Hydra before rejecting a bootstrap ownership conflict' >&2
	exit 1
fi
