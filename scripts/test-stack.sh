#!/bin/sh
# SPDX-License-Identifier: AGPL-3.0-or-later
set -eu

unset CDPATH
root=$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd)
cd "$root"

case ${SHAUTH_STACK_FOCUS:-} in
	''|logout-correlation|browser-global-logout) ;;
	*)
		echo "unknown SHAUTH_STACK_FOCUS: ${SHAUTH_STACK_FOCUS}" >&2
		exit 2
		;;
esac

./scripts/test-workflow-timeouts.sh
./scripts/check-workflow-timeouts.sh
./scripts/test-process-wait.sh
./scripts/check-gateway-test-coordinates.sh
npm ci
node node_modules/playwright/cli.js install --with-deps chromium
npm run test:validator-security

random_secret() {
  openssl rand -base64 48 | tr -d '\n'
}

. "$root/scripts/process-wait.sh"

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
unset SHAUTH_VALIDATOR_TOKEN
SHAUTH_VALIDATOR_TOKEN=$(random_secret)
unset SHAUTH_VALIDATION_STATUS_TOKEN
SHAUTH_VALIDATION_STATUS_TOKEN=$(random_secret)

# Keep the reusable validator queue credential out of the ambient process
# environment. Only Shauth and its validator receive it in production.
compose() {
  SHAUTH_VALIDATOR_TOKEN=$SHAUTH_VALIDATOR_TOKEN \
    SHAUTH_VALIDATION_STATUS_TOKEN=$SHAUTH_VALIDATION_STATUS_TOKEN \
    command docker compose "$@"
}

prepare_test_app_coordinates() {
	node -e 'let body="";process.stdin.on("data",value=>body+=value);process.stdin.on("end",()=>{const apps=JSON.parse(body);for(const app of apps){if(app.slug.startsWith("gateway-")){const launch=new URL(app.launch_url);app.validation_url=new URL("/auth/validation",launch).toString();app.backchannel_logout_uri="http://"+app.slug+".localhost:"+launch.port+"/auth/backchannel-logout"}app.post_logout_redirect_uris=[new URL("/auth/shauth/logout/complete",app.launch_url).toString()]}process.stdout.write(JSON.stringify(apps))})'
}
if env | grep -Eq '^SHAUTH_VALIDATOR_TOKEN=|^SHAUTH_VALIDATION_STATUS_TOKEN='; then
  echo 'browser-validation secrets leaked into the ambient process environment' >&2
  exit 1
fi
SHAUTH_OIDC_CLIENT_SECRET=$(random_secret)
export SHAUTH_OIDC_CLIENT_SECRET
SHAUTH_BOOTSTRAP_APP_CLIENT_SECRET=$(random_secret)
export SHAUTH_BOOTSTRAP_APP_CLIENT_SECRET
SHAUTH_GATEWAY_CLIENT_SECRET=$(random_secret)
export SHAUTH_GATEWAY_CLIENT_SECRET
SHAUTH_GATEWAY_SECONDARY_CLIENT_SECRET=$(random_secret)
export SHAUTH_GATEWAY_SECONDARY_CLIENT_SECRET
SHAUTH_GATEWAY_TERTIARY_CLIENT_SECRET=$(random_secret)
export SHAUTH_GATEWAY_TERTIARY_CLIENT_SECRET
SHAUTH_GATEWAY_COOKIE_SECRET=$(random_secret)
export SHAUTH_GATEWAY_COOKIE_SECRET
SHAUTH_GATEWAY_SECONDARY_COOKIE_SECRET=$(random_secret)
export SHAUTH_GATEWAY_SECONDARY_COOKIE_SECRET
SHAUTH_GATEWAY_TERTIARY_COOKIE_SECRET=$(random_secret)
export SHAUTH_GATEWAY_TERTIARY_COOKIE_SECRET
SHAUTH_GATEWAY_PRIMARY_DATABASE=shauth_gateway_primary
export SHAUTH_GATEWAY_PRIMARY_DATABASE
SHAUTH_GATEWAY_SECONDARY_DATABASE=shauth_gateway_secondary
export SHAUTH_GATEWAY_SECONDARY_DATABASE
SHAUTH_GATEWAY_TERTIARY_DATABASE=shauth_gateway_tertiary
export SHAUTH_GATEWAY_TERTIARY_DATABASE
SHAUTH_BOOTSTRAP_APPS_JSON=$(printf '[{"slug":"bootstrap-app","name":"Bootstrap app","description":"Bootstrap reconciliation coverage.","launch_url":"https://bootstrap.dev.e6qu.dev","oidc_client_id":"bootstrap-app","oidc_client_secret":"%s","redirect_uris":["https://bootstrap.dev.e6qu.dev/oidc/initial"],"post_logout_redirect_uris":["https://bootstrap.dev.e6qu.dev/"],"frontchannel_logout_uri":"https://bootstrap.dev.e6qu.dev/oidc/frontchannel-logout","health_url":"https://bootstrap.dev.e6qu.dev/health","monitoring_url":"","validation_url":"https://bootstrap.dev.e6qu.dev/","signed_out_url":"https://bootstrap.dev.e6qu.dev/signed-out","release_revision":"111111111111"},{"slug":"gateway-integration","name":"Gateway integration","description":"First relying-party acceptance coverage.","launch_url":"http://gateway-integration.localhost:5556/","oidc_client_id":"gateway-integration","oidc_client_secret":"%s","redirect_uris":["http://gateway-integration.localhost:5556/auth/callback"],"post_logout_redirect_uris":["http://gateway-integration.localhost:5556/auth/signed-out"],"frontchannel_logout_uri":"http://gateway-integration.localhost:5556/auth/frontchannel-logout","backchannel_logout_uri":"http://gateway-integration.localhost:5556/auth/backchannel-logout","health_url":"http://gateway-integration.localhost:5556/auth/healthz","monitoring_url":"","validation_url":"http://gateway-integration.localhost:5556/","signed_out_url":"http://gateway-integration.localhost:5556/auth/signed-out","release_revision":"222222222222"},{"slug":"gateway-secondary","name":"Gateway secondary","description":"Second relying-party single sign-on and logout coverage.","launch_url":"http://gateway-secondary.localhost:5558/","oidc_client_id":"gateway-secondary","oidc_client_secret":"%s","redirect_uris":["http://gateway-secondary.localhost:5558/auth/callback"],"post_logout_redirect_uris":["http://gateway-secondary.localhost:5558/auth/signed-out"],"frontchannel_logout_uri":"http://gateway-secondary.localhost:5558/auth/frontchannel-logout","backchannel_logout_uri":"http://gateway-secondary.localhost:5558/auth/backchannel-logout","health_url":"http://gateway-secondary.localhost:5558/auth/healthz","monitoring_url":"","validation_url":"http://gateway-secondary.localhost:5558/","signed_out_url":"http://gateway-secondary.localhost:5558/auth/signed-out","release_revision":"333333333333"},{"slug":"gateway-tertiary","name":"Gateway tertiary","description":"Third relying-party single sign-on and logout coverage.","launch_url":"http://gateway-tertiary.localhost:5560/","oidc_client_id":"gateway-tertiary","oidc_client_secret":"%s","redirect_uris":["http://gateway-tertiary.localhost:5560/auth/callback"],"post_logout_redirect_uris":["http://gateway-tertiary.localhost:5560/auth/signed-out"],"frontchannel_logout_uri":"http://gateway-tertiary.localhost:5560/auth/frontchannel-logout","backchannel_logout_uri":"http://gateway-tertiary.localhost:5560/auth/backchannel-logout","health_url":"http://gateway-tertiary.localhost:5560/auth/healthz","monitoring_url":"","validation_url":"http://gateway-tertiary.localhost:5560/","signed_out_url":"http://gateway-tertiary.localhost:5560/auth/signed-out","release_revision":"444444444444"}]' "$SHAUTH_BOOTSTRAP_APP_CLIENT_SECRET" "$SHAUTH_GATEWAY_CLIENT_SECRET" "$SHAUTH_GATEWAY_SECONDARY_CLIENT_SECRET" "$SHAUTH_GATEWAY_TERTIARY_CLIENT_SECRET")
SHAUTH_BOOTSTRAP_APPS_JSON=$(printf '%s' "$SHAUTH_BOOTSTRAP_APPS_JSON" | prepare_test_app_coordinates)
export SHAUTH_BOOTSTRAP_APPS_JSON
cookie_jar=$(mktemp)
validation_cookie_jar=$(mktemp)
gateway_binary=$(mktemp)
validator_binary=$(mktemp)
validator_coordination_directory=$(mktemp -d)
gateway_pid=
gateway_secondary_pid=
gateway_tertiary_pid=
gateway_test_pid=
validator_pid=
validator_secondary_pid=

cleanup() {
	status=$?
	trap - EXIT INT TERM
	if [ "$status" -ne 0 ]; then
		echo 'Shauth acceptance stack failed; recent service logs follow.' >&2
		compose logs --no-color --tail=20 shauth >&2 || true
		compose logs --no-color --tail=5 hydra >&2 || true
	fi
	if [ -n "$gateway_test_pid" ]; then
		if ! stop_process "$gateway_test_pid" 'gateway browser matrix'; then
			status=1
		fi
	fi
	for child_pid in "$validator_pid" "$validator_secondary_pid" "$gateway_pid" "$gateway_secondary_pid" "$gateway_tertiary_pid"; do
		if [ -n "$child_pid" ]; then
			if ! stop_process "$child_pid" "acceptance child ${child_pid}"; then
				status=1
			fi
		fi
	done
	if [ "$status" -ne 0 ]; then
		compose logs --no-color --tail=20 shauth >&2 || true
		compose logs --no-color --tail=10 hydra >&2 || true
	fi
	compose down --volumes --remove-orphans
	rm -f "$cookie_jar" "$validation_cookie_jar" "$gateway_binary" "$validator_binary"
	rm -rf "$validator_coordination_directory"
	return "$status"
}
# Remove remnants from an interrupted prior run before installing the exit
# trap. Calling cleanup here would intentionally clear that trap and leave the
# new stack running after a successful test.
compose down --volumes --remove-orphans
trap cleanup EXIT INT TERM

chmod 700 "$validator_coordination_directory"
docker build --load --tag shauth-local .
compose up --no-build --detach

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
  compose logs --no-color
  exit 1
fi

SHAUTH_ACCEPTANCE_DATABASE_URL="postgres://shauth:${POSTGRES_PASSWORD}@127.0.0.1:55432/shauth?sslmode=disable" \
	go test -tags acceptance ./internal/identity ./internal/gateway \
	-run '^(TestAppValidationTerminalStateAndLeaseTransitionsAreSerialized|TestLogoutCorrelationGrantIsAtomicAndExpires|TestLogoutCorrelationGrantPersistsEmptyInitiatorProviderSnapshot|TestLogoutSerializationPreservesACompleteOrdering|TestStaleProviderLogoutDoesNotRevokeFreshSessions|TestPausedCallbackCannotCreateSessionAfterProviderLogout)$' -count=1

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
validation_identity=$(compose exec -T postgres psql -U shauth -d shauth -Atc "SELECT concat_ws('|',CASE WHEN is_validation THEN 'validation' ELSE 'regular' END,role,COALESCE(github_id::text,''),COALESCE(entra_object_id::text,''),CASE WHEN password_hash IS NULL THEN 'passwordless' ELSE 'password' END) FROM users WHERE username='shauth-validator'")
[ "$validation_identity" = 'validation|developer|||passwordless' ]
[ "$(compose exec -T postgres psql -U shauth -d shauth -Atc 'SELECT count(*) FROM users WHERE is_validation=TRUE')" = 1 ]

# The validation identity has no reusable login credential. Only the
# validator-token-authenticated Shauth endpoint can mint short-lived browser
# sessions, and each grant is hashed, expires, and can be consumed once.
curl --fail --silent --show-error --cookie-jar "$validation_cookie_jar" http://localhost:8080/login >/dev/null
validation_csrf=$(awk '$6 == "shauth_csrf" { print $7 }' "$validation_cookie_jar")
[ -n "$validation_csrf" ]
curl --fail --silent --show-error --cookie "$validation_cookie_jar" --header 'Origin: http://localhost:8080' \
  --data-urlencode "_csrf=${validation_csrf}" \
  --data-urlencode 'username=shauth-validator' \
  --data-urlencode 'password=not-a-validation-credential' \
  --data-urlencode 'next=/apps' \
  http://localhost:8080/login | grep -q 'Invalid username or password.'
[ "$(curl --silent --output /dev/null --write-out '%{http_code}' --header "Authorization: Bearer ${SHAUTH_VALIDATOR_TOKEN}" --header 'Content-Type: application/json' --data '{"next":["https://attacker.example.test/"]}' http://localhost:8080/internal/validator/browser-bootstraps)" = 400 ]
bootstrap_response=$(curl --fail --silent --show-error --header "Authorization: Bearer ${SHAUTH_VALIDATOR_TOKEN}" --header 'Content-Type: application/json' --data '{"next":["/apps"]}' http://localhost:8080/internal/validator/browser-bootstraps)
bootstrap_token=$(printf '%s' "$bootstrap_response" | sed -n 's|.*validator/bootstrap#\([0-9a-f][0-9a-f]*\)".*|\1|p')
[ "${#bootstrap_token}" -eq 64 ]
bootstrap_headers=$(printf '_csrf=%s&token=%s' "$validation_csrf" "$bootstrap_token" | curl --silent --show-error --dump-header - --output /dev/null --cookie-jar "$validation_cookie_jar" --cookie "$validation_cookie_jar" --header 'Origin: null' --data-binary @- http://localhost:8080/validator/bootstrap)
printf '%s' "$bootstrap_headers" | grep -Eq '^HTTP/[0-9.]+ 303'
printf '%s' "$bootstrap_headers" | grep -Eqi '^location: /apps'
[ "$(printf '_csrf=%s&token=%s' "$validation_csrf" "$bootstrap_token" | curl --silent --output /dev/null --write-out '%{http_code}' --cookie "$validation_cookie_jar" --header 'Origin: null' --data-binary @- http://localhost:8080/validator/bootstrap)" = 410 ]
expired_response=$(curl --fail --silent --show-error --header "Authorization: Bearer ${SHAUTH_VALIDATOR_TOKEN}" --header 'Content-Type: application/json' --data '{"next":["/"]}' http://localhost:8080/internal/validator/browser-bootstraps)
expired_token=$(printf '%s' "$expired_response" | sed -n 's|.*validator/bootstrap#\([0-9a-f][0-9a-f]*\)".*|\1|p')
[ "${#expired_token}" -eq 64 ]
compose exec -T postgres psql -U shauth -d shauth -v ON_ERROR_STOP=1 -c "UPDATE validation_browser_bootstraps SET created_at=now()-interval '11 minutes',expires_at=now()-interval '1 minute' WHERE consumed_at IS NULL" >/dev/null
[ "$(printf '_csrf=%s&token=%s' "$validation_csrf" "$expired_token" | curl --silent --output /dev/null --write-out '%{http_code}' --cookie "$validation_cookie_jar" --header 'Origin: null' --data-binary @- http://localhost:8080/validator/bootstrap)" = 410 ]
[ "$(compose exec -T postgres psql -U shauth -d shauth -Atc 'SELECT count(*) FROM validation_browser_bootstraps WHERE octet_length(token_hash)<>32')" = 0 ]
compose exec -T postgres psql -U shauth -d shauth -c "UPDATE sessions SET revoked_at=now() WHERE user_id=(SELECT id FROM users WHERE is_validation=TRUE) AND revoked_at IS NULL" >/dev/null

curl --fail --silent --show-error --cookie-jar "$cookie_jar" http://localhost:8080/login >/dev/null
csrf_token=$(awk '$6 == "shauth_csrf" { print $7 }' "$cookie_jar")
[ -n "$csrf_token" ]

SHAUTH_GATEWAY_CLIENT_SECRET=$(random_secret)
SHAUTH_GATEWAY_SECONDARY_CLIENT_SECRET=$(random_secret)
SHAUTH_GATEWAY_TERTIARY_CLIENT_SECRET=$(random_secret)
SHAUTH_BOOTSTRAP_APPS_JSON=$(printf '[{"slug":"bootstrap-app","name":"Bootstrap app updated","description":"Updated bootstrap reconciliation coverage.","launch_url":"https://bootstrap.dev.e6qu.dev/apps","oidc_client_id":"bootstrap-app","oidc_client_secret":"%s","redirect_uris":["https://bootstrap.dev.e6qu.dev/oidc/updated"],"post_logout_redirect_uris":["https://bootstrap.dev.e6qu.dev/signed-out"],"frontchannel_logout_uri":"https://bootstrap.dev.e6qu.dev/oidc/frontchannel-logout","health_url":"https://bootstrap.dev.e6qu.dev/ready","monitoring_url":"https://bootstrap.dev.e6qu.dev/monitoring","validation_url":"https://bootstrap.dev.e6qu.dev/apps","signed_out_url":"https://bootstrap.dev.e6qu.dev/signed-out","release_revision":"555555555555"},{"slug":"gateway-integration","name":"Gateway integration","description":"First relying-party acceptance coverage.","launch_url":"http://gateway-integration.localhost:5556/","oidc_client_id":"gateway-integration","oidc_client_secret":"%s","redirect_uris":["http://gateway-integration.localhost:5556/auth/callback"],"post_logout_redirect_uris":["http://gateway-integration.localhost:5556/auth/signed-out"],"frontchannel_logout_uri":"http://gateway-integration.localhost:5556/auth/frontchannel-logout","backchannel_logout_uri":"http://gateway-integration.localhost:5556/auth/backchannel-logout","health_url":"http://gateway-integration.localhost:5556/auth/healthz","monitoring_url":"","validation_url":"http://gateway-integration.localhost:5556/","signed_out_url":"http://gateway-integration.localhost:5556/auth/signed-out","release_revision":"222222222222"},{"slug":"gateway-secondary","name":"Gateway secondary","description":"Second relying-party single sign-on and logout coverage.","launch_url":"http://gateway-secondary.localhost:5558/","oidc_client_id":"gateway-secondary","oidc_client_secret":"%s","redirect_uris":["http://gateway-secondary.localhost:5558/auth/callback"],"post_logout_redirect_uris":["http://gateway-secondary.localhost:5558/auth/signed-out"],"frontchannel_logout_uri":"http://gateway-secondary.localhost:5558/auth/frontchannel-logout","backchannel_logout_uri":"http://gateway-secondary.localhost:5558/auth/backchannel-logout","health_url":"http://gateway-secondary.localhost:5558/auth/healthz","monitoring_url":"","validation_url":"http://gateway-secondary.localhost:5558/","signed_out_url":"http://gateway-secondary.localhost:5558/auth/signed-out","release_revision":"333333333333"},{"slug":"gateway-tertiary","name":"Gateway tertiary","description":"Third relying-party single sign-on and logout coverage.","launch_url":"http://gateway-tertiary.localhost:5560/","oidc_client_id":"gateway-tertiary","oidc_client_secret":"%s","redirect_uris":["http://gateway-tertiary.localhost:5560/auth/callback"],"post_logout_redirect_uris":["http://gateway-tertiary.localhost:5560/auth/signed-out"],"frontchannel_logout_uri":"http://gateway-tertiary.localhost:5560/auth/frontchannel-logout","backchannel_logout_uri":"http://gateway-tertiary.localhost:5560/auth/backchannel-logout","health_url":"http://gateway-tertiary.localhost:5560/auth/healthz","monitoring_url":"","validation_url":"http://gateway-tertiary.localhost:5560/","signed_out_url":"http://gateway-tertiary.localhost:5560/auth/signed-out","release_revision":"444444444444"}]' "$SHAUTH_BOOTSTRAP_APP_CLIENT_SECRET" "$SHAUTH_GATEWAY_CLIENT_SECRET" "$SHAUTH_GATEWAY_SECONDARY_CLIENT_SECRET" "$SHAUTH_GATEWAY_TERTIARY_CLIENT_SECRET")
SHAUTH_BOOTSTRAP_APPS_JSON=$(printf '%s' "$SHAUTH_BOOTSTRAP_APPS_JSON" | prepare_test_app_coordinates)
export SHAUTH_BOOTSTRAP_APPS_JSON
compose up --force-recreate --no-deps --detach shauth
attempt=0
while [ "$attempt" -lt 30 ] && ! curl --fail --silent http://localhost:8080/healthz >/dev/null 2>&1; do
  attempt=$((attempt + 1))
  sleep 1
done
if [ "$attempt" -eq 30 ]; then
  compose logs --no-color
  exit 1
fi
curl --fail --silent --show-error http://localhost:4445/admin/clients/bootstrap-app | grep -q 'https://bootstrap.dev.e6qu.dev/oidc/updated'
for client_id in bootstrap-app gateway-integration gateway-secondary gateway-tertiary; do
	client_registration=$(curl --fail --silent --show-error "http://localhost:4445/admin/clients/${client_id}")
	printf '%s' "$client_registration" | grep -q '"token_endpoint_auth_method":"client_secret_post"'
	printf '%s' "$client_registration" | grep -q '"grant_types":\["authorization_code","refresh_token"\]'
	printf '%s' "$client_registration" | grep -q '"response_types":\["code"\]'
done
for client_port in gateway-integration:5556 gateway-secondary:5558 gateway-tertiary:5560; do
	client_id=${client_port%:*}
	port=${client_port#*:}
	client_registration=$(curl --fail --silent --show-error "http://localhost:4445/admin/clients/${client_id}")
	printf '%s' "$client_registration" | grep -q "\"backchannel_logout_uri\":\"http://${client_id}.localhost:${port}/auth/backchannel-logout\""
done
bootstrap_app=$(compose exec -T postgres psql -U shauth -d shauth -Atc "SELECT concat_ws('|',name,description,launch_url,oidc_client_id,health_url,monitoring_url) FROM managed_apps WHERE slug='bootstrap-app'")
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
  --data-urlencode 'post_logout_redirect_uris=http://localhost:5555/auth/shauth/logout/complete' \
  --data-urlencode 'frontchannel_logout_uri=http://localhost:5555/frontchannel-logout' \
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
rejected_app_location=$(curl --fail --silent --show-error --dump-header - --output /dev/null --cookie "$cookie_jar" --header 'Origin: http://localhost:8080' \
  --data-urlencode "_csrf=${csrf_token}" \
  --data-urlencode 'slug=integration-app' \
  --data-urlencode 'name=Integration app' \
  --data-urlencode 'description=End-to-end managed app catalog coverage.' \
  --data-urlencode 'launch_url=http://localhost:5555/' \
  --data-urlencode 'oidc_client_id=shauth-integration-client' \
  --data-urlencode 'health_url=http://localhost:5555/health' \
  --data-urlencode 'monitoring_url=http://localhost:5555/monitoring' \
  --data-urlencode 'validation_url=http://localhost:5555/' \
  --data-urlencode 'signed_out_url=https://attacker.example/other-signed-out' \
  --data-urlencode 'release_revision=666666666666' \
  http://localhost:8080/admin/apps |
  awk '/^[Ll]ocation:/{sub(/\r$/, "", $2); print $2}')
case "$rejected_app_location" in
	/admin/apps?error=*launch+and+signed-out+URLs+must+use+one+application+origin*) ;;
	*) echo "cross-origin signed-out URL was not rejected: ${rejected_app_location}" >&2; exit 1 ;;
esac
[ "$(compose exec -T postgres psql -U shauth -d shauth -Atc "SELECT count(*) FROM managed_apps WHERE slug='integration-app'")" = 0 ]
curl --fail --silent --show-error --location --cookie-jar "$cookie_jar" --cookie "$cookie_jar" --header 'Origin: http://localhost:8080' \
  --data-urlencode "_csrf=${csrf_token}" \
  --data-urlencode 'slug=integration-app' \
  --data-urlencode 'name=Integration app' \
  --data-urlencode 'description=End-to-end managed app catalog coverage.' \
  --data-urlencode 'launch_url=http://localhost:5555/' \
  --data-urlencode 'oidc_client_id=shauth-integration-client' \
  --data-urlencode 'health_url=http://localhost:5555/health' \
  --data-urlencode 'monitoring_url=http://localhost:5555/monitoring' \
  --data-urlencode 'validation_url=http://localhost:5555/' \
  --data-urlencode 'signed_out_url=http://localhost:5555/signed-out' \
  --data-urlencode 'release_revision=666666666666' \
  http://localhost:8080/admin/apps | grep -q 'Integration app'
SHAUTH_UNVERIFIED_USER_PASSWORD=$(random_secret)
export SHAUTH_UNVERIFIED_USER_PASSWORD
curl --fail --silent --show-error --location --cookie-jar "$cookie_jar" --cookie "$cookie_jar" --header 'Origin: http://localhost:8080' \
  --data-urlencode "_csrf=${csrf_token}" \
  --data-urlencode 'username=unverified-oidc' \
  --data-urlencode 'email=unverified-oidc@localhost.test' \
  --data-urlencode "password=${SHAUTH_UNVERIFIED_USER_PASSWORD}" \
  --data-urlencode 'role=developer' \
  http://localhost:8080/admin/users | grep -q 'unverified-oidc'
compose exec -T postgres psql -U shauth -d shauth -v ON_ERROR_STOP=1 \
  -c "UPDATE users SET email_verified=FALSE WHERE username='unverified-oidc'" >/dev/null
[ "$(compose exec -T postgres psql -U shauth -d shauth -Atc "SELECT email_verified FROM users WHERE username='unverified-oidc'")" = f ]
npm run test:browser
npm run test:oidc-unverified

echo 'Starting the three-relying-party Shauth gateway matrix.'

compose exec -T postgres createdb -U shauth --owner=shauth "$SHAUTH_GATEWAY_PRIMARY_DATABASE"
compose exec -T postgres createdb -U shauth --owner=shauth "$SHAUTH_GATEWAY_SECONDARY_DATABASE"
compose exec -T postgres createdb -U shauth --owner=shauth "$SHAUTH_GATEWAY_TERTIARY_DATABASE"
for gateway_database in "$SHAUTH_GATEWAY_PRIMARY_DATABASE" "$SHAUTH_GATEWAY_SECONDARY_DATABASE" "$SHAUTH_GATEWAY_TERTIARY_DATABASE"; do
	if [ -n "$(compose exec -T postgres psql -U shauth -d "$gateway_database" -Atc "SELECT to_regclass('public.oidc_gateway_sessions')")" ]; then
		echo "fresh relying-party database unexpectedly contained the gateway schema: $gateway_database" >&2
		exit 1
	fi
done

go build -o "$gateway_binary" ./cmd/shauth-gateway
OIDC_GATEWAY_ISSUER=http://localhost:8080 \
OIDC_GATEWAY_CLIENT_ID=gateway-integration \
APPLICATION_RELEASE_REVISION=222222222222 \
OIDC_GATEWAY_CLIENT_SECRET="$SHAUTH_GATEWAY_CLIENT_SECRET" \
OIDC_GATEWAY_PUBLIC_URL=http://gateway-integration.localhost:5556 \
OIDC_GATEWAY_UPSTREAM_URL=http://127.0.0.1:5557 \
OIDC_GATEWAY_POST_LOGOUT_URL=http://gateway-integration.localhost:5556/auth/shauth/logout/complete \
OIDC_GATEWAY_COOKIE_SECRET="$SHAUTH_GATEWAY_COOKIE_SECRET" \
OIDC_GATEWAY_ALLOW_INSECURE_COOKIE=true \
OIDC_GATEWAY_LISTEN_ADDRESS=0.0.0.0:5556 \
DATABASE_URL="postgres://shauth:${POSTGRES_PASSWORD}@127.0.0.1:55432/${SHAUTH_GATEWAY_PRIMARY_DATABASE}?sslmode=disable" \
"$gateway_binary" &
gateway_pid=$!
OIDC_GATEWAY_ISSUER=http://localhost:8080 \
OIDC_GATEWAY_CLIENT_ID=gateway-secondary \
APPLICATION_RELEASE_REVISION=333333333333 \
OIDC_GATEWAY_CLIENT_SECRET="$SHAUTH_GATEWAY_SECONDARY_CLIENT_SECRET" \
OIDC_GATEWAY_PUBLIC_URL='http://gateway-secondary.localhost:5558' \
OIDC_GATEWAY_UPSTREAM_URL=http://127.0.0.1:5559 \
OIDC_GATEWAY_POST_LOGOUT_URL='http://gateway-secondary.localhost:5558/auth/shauth/logout/complete' \
OIDC_GATEWAY_COOKIE_SECRET="$SHAUTH_GATEWAY_SECONDARY_COOKIE_SECRET" \
OIDC_GATEWAY_ALLOW_INSECURE_COOKIE=true \
OIDC_GATEWAY_LISTEN_ADDRESS=0.0.0.0:5558 \
DATABASE_URL="postgres://shauth:${POSTGRES_PASSWORD}@127.0.0.1:55432/${SHAUTH_GATEWAY_SECONDARY_DATABASE}?sslmode=disable" \
"$gateway_binary" &
gateway_secondary_pid=$!
OIDC_GATEWAY_ISSUER=http://localhost:8080 \
OIDC_GATEWAY_CLIENT_ID=gateway-tertiary \
APPLICATION_RELEASE_REVISION=444444444444 \
OIDC_GATEWAY_CLIENT_SECRET="$SHAUTH_GATEWAY_TERTIARY_CLIENT_SECRET" \
OIDC_GATEWAY_PUBLIC_URL='http://gateway-tertiary.localhost:5560' \
OIDC_GATEWAY_UPSTREAM_URL=http://127.0.0.1:5561 \
OIDC_GATEWAY_POST_LOGOUT_URL='http://gateway-tertiary.localhost:5560/auth/shauth/logout/complete' \
OIDC_GATEWAY_COOKIE_SECRET="$SHAUTH_GATEWAY_TERTIARY_COOKIE_SECRET" \
OIDC_GATEWAY_ALLOW_INSECURE_COOKIE=true \
OIDC_GATEWAY_LISTEN_ADDRESS=0.0.0.0:5560 \
DATABASE_URL="postgres://shauth:${POSTGRES_PASSWORD}@127.0.0.1:55432/${SHAUTH_GATEWAY_TERTIARY_DATABASE}?sslmode=disable" \
"$gateway_binary" &
gateway_tertiary_pid=$!
attempt=0
while [ "$attempt" -lt 60 ] && { ! curl --fail --silent --max-time 2 --noproxy '*' http://gateway-integration.localhost:5556/auth/healthz >/dev/null 2>&1 || ! curl --fail --silent --max-time 2 --noproxy '*' 'http://gateway-secondary.localhost:5558/auth/healthz' >/dev/null 2>&1 || ! curl --fail --silent --max-time 2 --noproxy '*' 'http://gateway-tertiary.localhost:5560/auth/healthz' >/dev/null 2>&1; }; do
  attempt=$((attempt + 1))
  sleep 1
done
if [ "$attempt" -eq 60 ]; then
	for relying_party_origin in http://gateway-integration.localhost:5556 'http://gateway-secondary.localhost:5558' 'http://gateway-tertiary.localhost:5560'; do
		status=$(curl --silent --max-time 2 --noproxy '*' --output /dev/null --write-out '%{http_code}' "$relying_party_origin/auth/healthz" || true)
		printf 'Relying-party health check failed: %s returned HTTP %s\n' "$relying_party_origin" "${status:-unreachable}" >&2
	done
	exit 1
fi

echo 'The three Shauth relying parties were healthy.'
for relying_party_pid in "$gateway_pid" "$gateway_secondary_pid" "$gateway_tertiary_pid"; do
	if ps eww -p "$relying_party_pid" -o command= | grep -Eq 'SHAUTH_VALIDATOR_TOKEN='; then
		echo "relying-party process ${relying_party_pid} inherited Shauth validator credentials" >&2
		exit 1
	fi
done
for relying_party_origin in http://gateway-integration.localhost:5556 'http://gateway-secondary.localhost:5558' 'http://gateway-tertiary.localhost:5560'; do
	[ "$(curl --silent --max-time 2 --noproxy '*' --output /dev/null --write-out '%{http_code}' "$relying_party_origin/auth/session")" = 401 ]
done
expected_gateway_tables='oidc_gateway_logout_tokens
oidc_gateway_logout_tombstones
oidc_gateway_sessions
shauth_gateway_schema_migrations'
for gateway_database in "$SHAUTH_GATEWAY_PRIMARY_DATABASE" "$SHAUTH_GATEWAY_SECONDARY_DATABASE" "$SHAUTH_GATEWAY_TERTIARY_DATABASE"; do
	gateway_tables=$(compose exec -T postgres psql -U shauth -d "$gateway_database" -Atc "SELECT tablename FROM pg_tables WHERE schemaname='public' ORDER BY tablename")
	if [ "$gateway_tables" != "$expected_gateway_tables" ]; then
		echo "gateway database contained an unexpected schema: $gateway_database" >&2
		printf '%s\n' "$gateway_tables" >&2
		exit 1
	fi
	migration_count=$(compose exec -T postgres psql -U shauth -d "$gateway_database" -Atc 'SELECT count(*) FROM shauth_gateway_schema_migrations')
	[ "$migration_count" = 2 ]
done
if [ "${SHAUTH_STACK_FOCUS:-}" = browser-global-logout ]; then
	compose restart shauth >/dev/null
	attempt=0
	while [ "$attempt" -lt 30 ] && ! curl --fail --silent http://localhost:8080/healthz >/dev/null 2>&1; do
		attempt=$((attempt + 1))
		sleep 1
	done
	[ "$attempt" -lt 30 ]
	curl --fail --silent --show-error http://localhost:4445/admin/clients/gateway-integration | grep -q '"backchannel_logout_uri":"http://gateway-integration.localhost:5556/auth/backchannel-logout"'
	node scripts/test-browser-global-logout.mjs "$cookie_jar"
	[ "$(compose exec -T postgres psql -U shauth -d "$SHAUTH_GATEWAY_PRIMARY_DATABASE" -Atc "SELECT count(*) FROM oidc_gateway_sessions WHERE revoked_at IS NULL")" = 0 ]
	exit 0
fi
bootstrap_app_id=$(compose exec -T postgres psql -U shauth -d shauth -Atc "SELECT id FROM managed_apps WHERE slug='bootstrap-app'")
[ -n "$bootstrap_app_id" ]
curl --fail --silent --show-error --output /dev/null --cookie "$cookie_jar" \
	--header 'Origin: http://localhost:8080' --header 'Referer: http://localhost:8080/admin/apps' \
	--data-urlencode "_csrf=${csrf_token}" "http://localhost:8080/admin/apps/${bootstrap_app_id}/delete"
[ "$(compose exec -T postgres psql -U shauth -d shauth -Atc "SELECT count(*) FROM managed_apps WHERE slug='bootstrap-app'")" = 0 ]
curl --fail --silent --show-error --output /dev/null --cookie "$cookie_jar" \
	--header 'Origin: http://localhost:8080' --header 'Referer: http://localhost:8080/admin/clients' \
	--data-urlencode "_csrf=${csrf_token}" 'http://localhost:8080/admin/clients/bootstrap-app/delete'
bootstrap_client_status=$(curl --silent --show-error --output /dev/null --write-out '%{http_code}' 'http://localhost:4445/admin/clients/bootstrap-app')
if [ "$bootstrap_client_status" != 404 ]; then
	echo "bootstrap OAuth client deletion returned HTTP ${bootstrap_client_status}; expected 404" >&2
	exit 1
fi
integration_app_id=$(compose exec -T postgres psql -U shauth -d shauth -Atc "SELECT id FROM managed_apps WHERE slug='integration-app'")
[ -n "$integration_app_id" ]
curl --fail --silent --show-error --output /dev/null --cookie "$cookie_jar" \
	--header 'Origin: http://localhost:8080' --header 'Referer: http://localhost:8080/admin/apps' \
	--data-urlencode "_csrf=${csrf_token}" "http://localhost:8080/admin/apps/${integration_app_id}/delete"
[ "$(compose exec -T postgres psql -U shauth -d shauth -Atc "SELECT count(*) FROM managed_apps WHERE slug='integration-app'")" = 0 ]
compose exec -T postgres psql -U shauth -d shauth -v ON_ERROR_STOP=1 <<'SQL' >/dev/null
DELETE FROM app_validation_runs;
UPDATE app_validation_control SET active_run_id=NULL,next_start_at='1970-01-01 00:00:00+00' WHERE singleton=TRUE;
SQL
for validator_app_slug in gateway-integration gateway-secondary gateway-tertiary; do
	validator_app_id=$(compose exec -T postgres psql -U shauth -d shauth -Atc "SELECT id FROM managed_apps WHERE slug='${validator_app_slug}'")
	[ -n "$validator_app_id" ]
	curl --fail --silent --show-error --output /dev/null --cookie "$cookie_jar" \
		--header 'Origin: http://localhost:8080' --header 'Referer: http://localhost:8080/apps' \
		--data-urlencode "_csrf=${csrf_token}" "http://localhost:8080/apps/${validator_app_id}/validate"
done
[ "$(compose exec -T postgres psql -U shauth -d shauth -Atc "SELECT count(*) FROM app_validation_runs WHERE status='queued'")" = 6 ]
[ "$(compose exec -T postgres psql -U shauth -d shauth -Atc "SELECT count(*) FROM app_validation_runs WHERE status='queued' AND witness_managed_app_id IS NOT NULL AND witness_managed_app_id<>managed_app_id AND witness_oidc_client_id<>oidc_client_id")" = 6 ]
validation_witness_ring=$(compose exec -T postgres psql -U shauth -d shauth -Atc "SELECT string_agg(app_slug||':'||direction||'>'||witness_app_slug,',' ORDER BY app_slug,direction) FROM app_validation_runs WHERE status='queued'")
[ "$validation_witness_ring" = 'gateway-integration:from_app>gateway-secondary,gateway-integration:from_shauth>gateway-secondary,gateway-secondary:from_app>gateway-tertiary,gateway-secondary:from_shauth>gateway-tertiary,gateway-tertiary:from_app>gateway-integration,gateway-tertiary:from_shauth>gateway-integration' ]
[ "$(compose exec -T postgres psql -U shauth -d shauth -Atc "SELECT count(*) FROM app_validation_runs WHERE app_slug='gateway-integration' AND validation_url='http://gateway-integration.localhost:5556/auth/validation'")" = 2 ]
compose exec -T postgres psql -U shauth -d shauth -v ON_ERROR_STOP=1 \
	-c "UPDATE managed_apps SET validation_url='http://localhost:5999/drifted-live-row' WHERE slug='gateway-integration'" >/dev/null

go build -o "$validator_binary" ./cmd/shauth-validator
SHAUTH_VALIDATOR_COORDINATION_DIR=$validator_coordination_directory \
	SHAUTH_GATEWAY_TEST_FOCUS=${SHAUTH_STACK_FOCUS:-} \
	node scripts/test-gateway-oidc.mjs &
gateway_test_pid=$!
attempt=0
while [ "$attempt" -lt 120 ] && [ ! -f "$validator_coordination_directory/ready" ]; do
	if ! kill -0 "$gateway_test_pid" 2>/dev/null; then
		wait_for_process "$gateway_test_pid" 'gateway browser matrix startup' 5 || true
		exit 1
	fi
	attempt=$((attempt + 1))
	sleep 1
done
[ -f "$validator_coordination_directory/ready" ]

if [ "${SHAUTH_STACK_FOCUS:-}" = logout-correlation ]; then
	touch "$validator_coordination_directory/run-gateway-matrix"
	if ! wait_for_process "$gateway_test_pid" 'focused logout-correlation browser test' 180; then
		gateway_test_pid=
		exit 1
	fi
	gateway_test_pid=
	exit 0
fi

SHAUTH_URL=http://localhost:8080 \
SHAUTH_VALIDATOR_TOKEN=$SHAUTH_VALIDATOR_TOKEN \
SHAUTH_VALIDATION_USERNAME=shauth-validator \
SHAUTH_VALIDATION_EMAIL=shauth-validator@localhost.test \
SHAUTH_VALIDATOR_SCRIPT=$root/validator/validate.mjs \
	"$validator_binary" &
validator_pid=$!
SHAUTH_URL=http://localhost:8080 \
SHAUTH_VALIDATOR_TOKEN=$SHAUTH_VALIDATOR_TOKEN \
SHAUTH_VALIDATION_USERNAME=shauth-validator \
SHAUTH_VALIDATION_EMAIL=shauth-validator@localhost.test \
SHAUTH_VALIDATOR_SCRIPT=$root/validator/validate.mjs \
	"$validator_binary" &
validator_secondary_pid=$!
attempt=0
while [ "$attempt" -lt 360 ]; do
	passed_count=$(compose exec -T postgres psql -U shauth -d shauth -Atc "SELECT count(*) FROM app_validation_runs WHERE status='passed'")
	failed_count=$(compose exec -T postgres psql -U shauth -d shauth -Atc "SELECT count(*) FROM app_validation_runs WHERE status='failed'")
	[ "$failed_count" = 0 ] || break
	[ "$passed_count" = 6 ] && break
	attempt=$((attempt + 1))
	sleep 1
done
if [ "$failed_count" != 0 ] || [ "$passed_count" != 6 ]; then
	compose exec -T postgres psql -U shauth -d shauth -c "SELECT app_slug,direction,status,failure FROM app_validation_runs ORDER BY requested_at,id" >&2
	for gateway_database in "$SHAUTH_GATEWAY_PRIMARY_DATABASE" "$SHAUTH_GATEWAY_SECONDARY_DATABASE" "$SHAUTH_GATEWAY_TERTIARY_DATABASE"; do
		printf '%s: ' "$gateway_database" >&2
		compose exec -T postgres psql -U shauth -d "$gateway_database" -Atc "SELECT 'active_sessions='||count(*) FILTER (WHERE revoked_at IS NULL)||', logout_tokens='||(SELECT count(*) FROM oidc_gateway_logout_tokens) FROM oidc_gateway_sessions" >&2
	done
	exit 1
fi
queue_timing_violations=$(compose exec -T postgres psql -U shauth -d shauth -Atc "WITH ordered AS (SELECT started_at,completed_at,lag(started_at) OVER (ORDER BY started_at) previous_started,lag(completed_at) OVER (ORDER BY started_at) previous_completed FROM app_validation_runs) SELECT count(*) FROM ordered WHERE previous_started IS NOT NULL AND (started_at-previous_started < interval '30 seconds' OR started_at < previous_completed)")
[ "$queue_timing_violations" = 0 ]
[ "$(compose exec -T postgres psql -U shauth -d shauth -Atc "SELECT count(*) FROM app_validation_runs WHERE status IN ('queued','running')")" = 0 ]
[ "$(compose exec -T postgres psql -U shauth -d shauth -Atc "SELECT count(*) FROM app_validation_runs WHERE status='passed' AND direction='from_app'")" = 3 ]
[ "$(compose exec -T postgres psql -U shauth -d shauth -Atc "SELECT count(*) FROM app_validation_runs WHERE status='passed' AND direction='from_shauth'")" = 3 ]
[ "$(compose exec -T postgres psql -U shauth -d shauth -Atc "SELECT string_agg(app_slug||':'||direction||'>'||witness_app_slug,',' ORDER BY app_slug,direction) FROM app_validation_runs WHERE status='passed'")" = "$validation_witness_ring" ]
[ "$(curl --silent --output /dev/null --write-out '%{http_code}' http://localhost:8080/api/v1/apps/validations)" = 401 ]
[ "$(curl --silent --output /dev/null --write-out '%{http_code}' --header 'Authorization: Bearer wrong' http://localhost:8080/api/v1/apps/validations)" = 401 ]
validation_status_response=$(curl --fail --silent --show-error --header "Authorization: Bearer ${SHAUTH_VALIDATION_STATUS_TOKEN}" http://localhost:8080/api/v1/apps/validations)
printf '%s' "$validation_status_response" | node -e '
let body = "";
process.stdin.on("data", chunk => { body += chunk; });
process.stdin.on("end", () => {
  const response = JSON.parse(body);
  if (response.schema_version !== "shauth.app-validations/v1" || !Date.parse(response.observed_at)) process.exit(1);
  if (!Array.isArray(response.validations) || response.validations.length !== 6) process.exit(1);
  const expected = new Set(["gateway-integration", "gateway-secondary", "gateway-tertiary"].flatMap(slug => [slug + ":from_app", slug + ":from_shauth"]));
  for (const run of response.validations) {
    if (!expected.delete(run.slug + ":" + run.direction) || run.status !== "passed" || !/^[0-9a-f]{64}$/.test(run.validation_contract_hash)) process.exit(1);
    if (!Date.parse(run.requested_at) || !Date.parse(run.started_at) || !Date.parse(run.completed_at) || "failure" in run) process.exit(1);
  }
  if (expected.size !== 0) process.exit(1);
});'
for gateway_database in "$SHAUTH_GATEWAY_PRIMARY_DATABASE" "$SHAUTH_GATEWAY_SECONDARY_DATABASE" "$SHAUTH_GATEWAY_TERTIARY_DATABASE"; do
	[ "$(compose exec -T postgres psql -U shauth -d "$gateway_database" -Atc "SELECT count(*) FROM oidc_gateway_sessions WHERE revoked_at IS NULL")" = 0 ]
done
[ "$(compose exec -T postgres psql -U shauth -d shauth -Atc "SELECT count(*) FROM sessions JOIN users ON users.id=sessions.user_id WHERE users.username='shauth-validator' AND sessions.revoked_at IS NULL")" = 0 ]
compose exec -T postgres psql -U shauth -d shauth -v ON_ERROR_STOP=1 \
	-c "UPDATE managed_apps SET validation_url='http://gateway-integration.localhost:5556/auth/validation' WHERE slug='gateway-integration'" >/dev/null
stop_process "$validator_pid" 'primary application validator'
validator_pid=
stop_process "$validator_secondary_pid" 'secondary application validator'
validator_secondary_pid=
abandoned_validation_id=$(compose exec -T postgres psql -U shauth -d shauth -Atc "SELECT id FROM app_validation_runs WHERE status='passed' ORDER BY requested_at,id LIMIT 1")
[ -n "$abandoned_validation_id" ]
compose exec -T postgres psql -U shauth -d shauth -v ON_ERROR_STOP=1 \
	-c "UPDATE app_validation_runs SET status='running',started_at=now()-interval '2 minutes',completed_at=NULL,lease_expires_at=now()-interval '1 second',duration_milliseconds=NULL,failure='' WHERE id='${abandoned_validation_id}'::uuid; UPDATE app_validation_control SET active_run_id='${abandoned_validation_id}'::uuid WHERE singleton=TRUE" >/dev/null
attempt=0
lease_recovery=
while [ "$attempt" -lt 20 ]; do
	lease_recovery=$(compose exec -T postgres psql -U shauth -d shauth -Atc "SELECT concat_ws('|',run.status,run.failure,COALESCE(control.active_run_id::text,'')) FROM app_validation_runs run CROSS JOIN app_validation_control control WHERE run.id='${abandoned_validation_id}'::uuid AND control.singleton=TRUE")
	[ "$lease_recovery" = 'failed|validator lease expired|' ] && break
	attempt=$((attempt + 1))
	sleep 1
done
[ "$lease_recovery" = 'failed|validator lease expired|' ]

# Production application validation requires both logout channels so Shauth
# can revoke sessions in another browser or device. The focused gateway matrix
# then narrows two registrations to prove current-session front-channel-only
# and back-channel-only delivery independently.
for client_mode in gateway-secondary:front gateway-tertiary:back; do
	client_id=${client_mode%:*}
	mode=${client_mode#*:}
	client_registration=$(curl --fail --silent --show-error "http://localhost:4445/admin/clients/${client_id}")
	if [ "$mode" = front ]; then
		client_registration=$(printf '%s' "$client_registration" | node -e 'let body="";process.stdin.on("data",value=>body+=value);process.stdin.on("end",()=>{const client=JSON.parse(body);delete client.backchannel_logout_uri;delete client.backchannel_logout_session_required;process.stdout.write(JSON.stringify(client))})')
	else
		client_registration=$(printf '%s' "$client_registration" | node -e 'let body="";process.stdin.on("data",value=>body+=value);process.stdin.on("end",()=>{const client=JSON.parse(body);delete client.frontchannel_logout_uri;delete client.frontchannel_logout_session_required;process.stdout.write(JSON.stringify(client))})')
	fi
	curl --fail --silent --show-error --request PUT --header 'Content-Type: application/json' \
		--data "$client_registration" "http://localhost:4445/admin/clients/${client_id}" >/dev/null
done
touch "$validator_coordination_directory/run-gateway-matrix"
if ! wait_for_process "$gateway_test_pid" 'gateway browser matrix' 300; then
	gateway_test_pid=
	compose exec -T postgres psql -U shauth -d shauth -c "SELECT app_slug,direction,status,failure FROM app_validation_runs ORDER BY requested_at,id" >&2 || true
	for gateway_database in "$SHAUTH_GATEWAY_PRIMARY_DATABASE" "$SHAUTH_GATEWAY_SECONDARY_DATABASE" "$SHAUTH_GATEWAY_TERTIARY_DATABASE"; do
		printf '%s: ' "$gateway_database" >&2
		compose exec -T postgres psql -U shauth -d "$gateway_database" -Atc "SELECT 'active_sessions='||count(*) FILTER (WHERE revoked_at IS NULL)||', logout_tokens='||(SELECT count(*) FROM oidc_gateway_logout_tokens) FROM oidc_gateway_sessions" >&2 || true
	done
	exit 1
fi
gateway_test_pid=
# The provider-initiated browser test deliberately signs the administrator out
# of every Shauth device, including this shell's independent cookie jar.
curl --fail --silent --show-error --location --cookie-jar "$cookie_jar" --cookie "$cookie_jar" --header 'Origin: http://localhost:8080' \
  --data-urlencode "_csrf=${csrf_token}" \
  --data-urlencode 'username=admin' \
  --data-urlencode "password=${SHAUTH_BOOTSTRAP_ADMIN_PASSWORD}" \
  --data-urlencode 'next=/' \
  http://localhost:8080/login >/dev/null
auto_consent_client_id=auto-consent-client
auto_consent_client_secret=$(random_secret)
auto_consent_redirect_uri=http://localhost:5570/callback
curl --fail --silent --show-error --location --cookie-jar "$cookie_jar" --cookie "$cookie_jar" --header 'Origin: http://localhost:8080' \
  --data-urlencode "_csrf=${csrf_token}" \
  --data-urlencode "client_id=${auto_consent_client_id}" \
  --data-urlencode 'client_name=Automatic consent integration client' \
  --data-urlencode "client_secret=${auto_consent_client_secret}" \
  --data-urlencode "redirect_uris=${auto_consent_redirect_uri}" \
  --data-urlencode 'post_logout_redirect_uris=http://localhost:5570/auth/shauth/logout/complete' \
  --data-urlencode 'frontchannel_logout_uri=http://localhost:5570/frontchannel-logout' \
  http://localhost:8080/admin/clients | grep -q "$auto_consent_client_id"
curl --fail --silent --show-error --location --cookie-jar "$cookie_jar" --cookie "$cookie_jar" --header 'Origin: http://localhost:8080' \
  --data-urlencode "_csrf=${csrf_token}" \
  --data-urlencode 'slug=auto-consent-app' \
  --data-urlencode 'name=Automatic consent app' \
  --data-urlencode 'description=First-use managed application consent coverage.' \
  --data-urlencode 'launch_url=http://localhost:5570/' \
  --data-urlencode "oidc_client_id=${auto_consent_client_id}" \
  --data-urlencode 'health_url=http://localhost:5570/health' \
  --data-urlencode 'validation_url=http://localhost:5570/' \
  --data-urlencode 'signed_out_url=http://localhost:5570/signed-out' \
  --data-urlencode 'release_revision=999999999999' \
  http://localhost:8080/admin/apps | grep -q 'Automatic consent app'
login_location=$(curl --fail --silent --show-error --dump-header - --output /dev/null --cookie-jar "$cookie_jar" --cookie "$cookie_jar" \
  "http://localhost:8080/oauth2/auth?client_id=${auto_consent_client_id}&response_type=code&scope=openid%20profile%20email%20offline_access&redirect_uri=http%3A%2F%2Flocalhost%3A5570%2Fcallback&state=integration" |
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
	--data-urlencode "redirect_uri=${auto_consent_redirect_uri}" \
	--data-urlencode "client_id=${auto_consent_client_id}" \
	--data-urlencode "client_secret=${auto_consent_client_secret}" \
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
	--data-urlencode "client_id=${auto_consent_client_id}" \
	--data-urlencode "client_secret=${auto_consent_client_secret}" \
	http://localhost:8080/oauth2/token | grep -q '"access_token"'
curl --fail --silent --show-error --cookie "$cookie_jar" http://localhost:8080/admin/users | grep -q 'admin@localhost.test'
curl --fail --silent --show-error --cookie "$cookie_jar" http://localhost:8080/admin | grep -q 'Private administration'
curl --fail --silent --show-error --location --cookie "$cookie_jar" --header 'Origin: http://localhost:8080' \
  --data-urlencode "_csrf=${csrf_token}" \
  --data-urlencode 'kind=user' \
  --data-urlencode 'target=integration-github-user' \
  --data-urlencode 'role=developer' \
  http://localhost:8080/admin/github | grep -q 'integration-github-user'
github_mapping_id=$(compose exec -T postgres psql -U shauth -d shauth -Atc "SELECT id FROM github_role_mappings WHERE kind = 'user' AND target = 'integration-github-user'")
curl --fail --silent --show-error --location --cookie "$cookie_jar" --header 'Origin: http://localhost:8080' --data-urlencode "_csrf=${csrf_token}" "http://localhost:8080/admin/github/${github_mapping_id}/delete" | grep -q 'GitHub access rules'
developer_mapping_id=$(compose exec -T postgres psql -U shauth -d shauth -Atc "SELECT id FROM github_role_mappings WHERE kind = 'team' AND target = 'e6qu-org/e6qu-org-members'")
curl --fail --silent --show-error --location --cookie "$cookie_jar" --header 'Origin: http://localhost:8080' --data-urlencode "_csrf=${csrf_token}" "http://localhost:8080/admin/github/${developer_mapping_id}/delete" >/dev/null
compose restart shauth >/dev/null
attempt=0
while [ "$attempt" -lt 30 ] && ! curl --fail --silent http://localhost:8080/healthz >/dev/null 2>&1; do
  attempt=$((attempt + 1))
  sleep 1
done
remaining_developer_mappings=$(compose exec -T postgres psql -U shauth -d shauth -Atc "SELECT count(*) FROM github_role_mappings WHERE kind = 'team' AND target = 'e6qu-org/e6qu-org-members'")
if [ "$attempt" -eq 30 ] || [ "$remaining_developer_mappings" != 0 ]; then
  compose logs --no-color
  exit 1
fi
curl --fail --silent --show-error http://localhost:4445/admin/clients/gateway-integration | grep -q '"backchannel_logout_uri":"http://gateway-integration.localhost:5556/auth/backchannel-logout"'
curl --fail --silent --show-error --cookie "$cookie_jar" http://localhost:8080/monitoring | grep -q 'Ory Hydra authorization provider'
curl --fail --silent --show-error --cookie "$cookie_jar" http://localhost:8080/monitoring | grep -q 'Active browser sessions'
curl --fail --silent --show-error --cookie "$cookie_jar" http://localhost:8080/monitoring | grep -q 'PostgreSQL session store'
curl --fail --silent --show-error --cookie "$cookie_jar" http://localhost:8080/monitoring | grep -q 'No infrastructure source configured'
attempt=0
while [ "$attempt" -lt 30 ]; do
  if curl --fail --silent http://localhost:8080/.well-known/openid-configuration 2>/dev/null | grep -q 'issuer'; then
    break
  fi
  attempt=$((attempt + 1))
  sleep 1
done
if [ "$attempt" -eq 30 ]; then
  compose logs --no-color
  exit 1
fi

# Browser form posts must remain same-origin. Provider-initiated logout revokes
# the user's correlated Ory Hydra sessions before rendering a durable signed-out
# page; relying applications use Ory Hydra's published logout endpoint. The
# local Shauth session is revoked before the browser leaves the form POST.
[ "$(curl --silent --output /dev/null --write-out '%{http_code}' --cookie "$cookie_jar" --header 'Origin: https://attacker.example.test' --data '' http://localhost:8080/logout)" = 403 ]
[ "$(curl --silent --output /dev/null --write-out '%{http_code}' --cookie "$cookie_jar" --header 'Origin: https://attacker.example.test' --data-urlencode 'challenge=invalid' http://localhost:8080/oauth/logout)" = 403 ]
curl --fail --silent --show-error --cookie "$cookie_jar" http://localhost:8080/logout | grep -q 'Sign out of all apps?'
node scripts/test-browser-global-logout.mjs "$cookie_jar"
curl --fail --silent --show-error --cookie "$cookie_jar" http://localhost:8080/signed-out | grep -q 'Sign in to Shauth'
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
admin_id=$(compose exec -T postgres psql -U shauth -d shauth -Atc "SELECT id FROM users WHERE username = 'admin'")
single_session_setup=$(curl --fail --silent --show-error --dump-header - --output /dev/null --cookie-jar "$cookie_jar" --cookie "$cookie_jar" \
	'http://localhost:8080/oauth2/auth?client_id=gateway-integration&response_type=code&scope=openid%20profile%20email&redirect_uri=http%3A%2F%2Fgateway-integration.localhost%3A5556%2Fauth%2Fcallback&state=single-session-setup&nonce=single-session-setup&code_challenge=6ZPyvBxk3i_6fw7GZ1sKcSmw5Q3e4V1uNQf2JgQJ9bU&code_challenge_method=S256' |
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
current_session_id=$(compose exec -T postgres psql -U shauth -d shauth -Atc "SELECT id FROM sessions WHERE user_id='${admin_id}'::uuid AND revoked_at IS NULL ORDER BY created_at DESC LIMIT 1")
curl --fail --silent --show-error --output /dev/null --cookie "$cookie_jar" --header 'Origin: http://localhost:8080' --header 'Referer: http://localhost:8080/admin/users' --data-urlencode "_csrf=${csrf_token}" "http://localhost:8080/admin/sessions/${current_session_id}/revoke"
[ "$(curl --silent --output /dev/null --write-out '%{http_code}' --cookie "$cookie_jar" http://localhost:8080/apps)" = 303 ]
single_session_login=$(curl --fail --silent --show-error --dump-header - --output /dev/null --cookie-jar "$cookie_jar" --cookie "$cookie_jar" \
	'http://localhost:8080/oauth2/auth?client_id=gateway-integration&response_type=code&scope=openid%20profile%20email&redirect_uri=http%3A%2F%2Fgateway-integration.localhost%3A5556%2Fauth%2Fcallback&state=single-session-revocation&nonce=single-session-revocation&code_challenge=6ZPyvBxk3i_6fw7GZ1sKcSmw5Q3e4V1uNQf2JgQJ9bU&code_challenge_method=S256' |
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
	--data-urlencode "client_id=${auto_consent_client_id}" \
	--data-urlencode "client_secret=${auto_consent_client_secret}" \
	http://localhost:8080/oauth2/token >/dev/null 2>&1; then
	echo 'revoked OIDC refresh token was accepted' >&2
	exit 1
fi

# A managed application has one trusted completion bridge. Registering a
# direct signed-out page alongside it lets an RP bypass Shauth's one-time
# completion correlation, so startup rejects the complete invalid bootstrap
# before it can mutate Ory Hydra or PostgreSQL.
valid_bootstrap_apps_json=$SHAUTH_BOOTSTRAP_APPS_JSON
SHAUTH_BOOTSTRAP_APPS_JSON=$(printf '%s' "$valid_bootstrap_apps_json" | node -e '
let body = "";
process.stdin.on("data", value => body += value);
process.stdin.on("end", () => {
  const apps = JSON.parse(body);
  const target = apps.find(app => app.slug === "gateway-integration");
  if (!target) throw new Error("gateway-integration bootstrap app is unavailable");
  target.post_logout_redirect_uris.push("http://gateway-integration.localhost:5556/auth/signed-out");
  process.stdout.write(JSON.stringify(apps));
});')
export SHAUTH_BOOTSTRAP_APPS_JSON
compose up --force-recreate --no-deps --detach shauth
attempt=0
shauth_status=running
while [ "$attempt" -lt 30 ]; do
	shauth_container=$(compose ps --all --quiet shauth)
	shauth_status=$(docker inspect --format '{{.State.Status}}' "$shauth_container")
	[ "$shauth_status" = exited ] && break
	attempt=$((attempt + 1))
	sleep 1
done
if [ "$shauth_status" != exited ] || [ "$(docker inspect --format '{{.State.ExitCode}}' "$shauth_container")" -eq 0 ]; then
	echo 'Shauth accepted an additional managed-app post-logout redirect' >&2
	exit 1
fi
compose logs --no-color shauth | grep -q 'must register only its exact Shauth logout bridge URI'
client_registration=$(curl --fail --silent --show-error http://localhost:4445/admin/clients/gateway-integration)
printf '%s' "$client_registration" | node -e '
let body = "";
process.stdin.on("data", value => body += value);
process.stdin.on("end", () => {
  const client = JSON.parse(body);
  const expected = ["http://gateway-integration.localhost:5556/auth/shauth/logout/complete"];
  if (JSON.stringify(client.post_logout_redirect_uris) !== JSON.stringify(expected)) {
    throw new Error("invalid bootstrap mutated Ory Hydra: " + JSON.stringify(client.post_logout_redirect_uris));
  }
});'
SHAUTH_BOOTSTRAP_APPS_JSON=$valid_bootstrap_apps_json
export SHAUTH_BOOTSTRAP_APPS_JSON
compose up --force-recreate --no-deps --detach shauth
attempt=0
while [ "$attempt" -lt 30 ] && ! curl --fail --silent http://localhost:8080/healthz >/dev/null 2>&1; do
	attempt=$((attempt + 1))
	sleep 1
done
[ "$attempt" -lt 30 ]

compose exec -T postgres psql -U shauth -d shauth -v ON_ERROR_STOP=1 -c "INSERT INTO managed_apps (id,slug,name,description,launch_url,oidc_client_id,health_url,monitoring_url,validation_url,signed_out_url,release_revision,created_at) VALUES ('00000000-0000-4000-8000-000000000001','protected-app','Protected app','Administrator-owned app.','https://protected.dev.e6qu.dev','protected-client','https://protected.dev.e6qu.dev/health',NULL,'https://protected.dev.e6qu.dev/','https://protected.dev.e6qu.dev/signed-out','777777777777',now())" >/dev/null
protected_client_secret=$(random_secret)
SHAUTH_BOOTSTRAP_APPS_JSON=$(printf '[{"slug":"protected-app","name":"Takeover attempt","description":"Bootstrap must not replace an administrator-owned app.","launch_url":"https://takeover.dev.e6qu.dev","oidc_client_id":"takeover-client","oidc_client_secret":"%s","redirect_uris":["https://takeover.dev.e6qu.dev/oidc/callback"],"post_logout_redirect_uris":["https://takeover.dev.e6qu.dev/"],"backchannel_logout_uri":"https://takeover.dev.e6qu.dev/oidc/backchannel-logout","health_url":"https://takeover.dev.e6qu.dev/health","monitoring_url":"","validation_url":"https://takeover.dev.e6qu.dev/","signed_out_url":"https://takeover.dev.e6qu.dev/signed-out","release_revision":"888888888888"}]' "$protected_client_secret")
SHAUTH_BOOTSTRAP_APPS_JSON=$(printf '%s' "$SHAUTH_BOOTSTRAP_APPS_JSON" | prepare_test_app_coordinates)
export SHAUTH_BOOTSTRAP_APPS_JSON
compose up --force-recreate --no-deps --detach shauth
attempt=0
shauth_status=running
while [ "$attempt" -lt 30 ]; do
	shauth_container=$(compose ps --all --quiet shauth)
	shauth_status=$(docker inspect --format '{{.State.Status}}' "$shauth_container")
	[ "$shauth_status" = exited ] && break
	attempt=$((attempt + 1))
	sleep 1
done
if [ "$shauth_status" != exited ] || [ "$(docker inspect --format '{{.State.ExitCode}}' "$shauth_container")" -eq 0 ]; then
	echo 'Shauth accepted a bootstrap app takeover with another OpenID Connect client' >&2
	exit 1
fi
compose logs --no-color shauth | grep -q 'managed app slug "protected-app" or OpenID Connect client "takeover-client" belongs to another registration'
if curl --fail --silent http://localhost:4445/admin/clients/takeover-client >/dev/null 2>&1; then
	echo 'Shauth mutated Ory Hydra before rejecting a bootstrap ownership conflict' >&2
	exit 1
fi
