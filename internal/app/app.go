// SPDX-License-Identifier: AGPL-3.0-or-later

// Package app provides Shauth's browser login, OAuth broker, and HTMX admin UI.
package app

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"html/template"
	"io"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/e6qu/shauth/internal/config"
	githubapi "github.com/e6qu/shauth/internal/github"
	"github.com/e6qu/shauth/internal/identity"
	"github.com/e6qu/shauth/internal/mailer"
	"github.com/e6qu/shauth/internal/managedapps"
	"github.com/e6qu/shauth/internal/monitoring"
	"github.com/e6qu/shauth/internal/observe"
	"github.com/e6qu/shauth/internal/version"
	"golang.org/x/oauth2"
	oauthgithub "golang.org/x/oauth2/github"
)

const browserSessionCookie = "shauth_session"
const logoutCorrelationCookie = "shauth_logout_correlation"
const logoutCorrelationPath = "/oauth/logout"
const logoutCompletionCookie = "shauth_logout_completion"
const logoutCompletionPath = "/oauth/logout/complete"
const csrfCookie = "shauth_csrf"
const githubStateCookiePrefix = "shauth_github_state_"
const entraStateCookiePrefix = "shauth_entra_state_"
const bootstrapRetryInterval = time.Second
const bootstrapRetryTimeout = 45 * time.Second
const outboundRequestTimeout = 15 * time.Second

const baseContentSecurityPolicy = "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'"
const oidcContentSecurityPolicy = "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; base-uri 'none'; frame-ancestors 'none'; form-action 'self' https: http://localhost:* http://*.localhost:* http://127.0.0.1:*"
const oidcLogoutContentSecurityPolicy = "default-src 'none'; script-src 'unsafe-inline'; style-src 'unsafe-inline'; frame-src https: http://localhost:* http://*.localhost:* http://127.0.0.1:*; base-uri 'none'; frame-ancestors 'none'; form-action 'self'"

var oidcClientIDPattern = regexp.MustCompile(`^[a-z][a-z0-9-]{2,127}$`)

// deletableOIDCClientID accepts any identifier the provider could hold, not
// only ones Shauth would create. The registration pattern is a policy for new
// clients; applying it to deletion would leave a client registered outside
// that policy listed forever with no way to remove it. The identifier is still
// constrained to a single safe path segment and is escaped before use.
func deletableOIDCClientID(clientID string) bool {
	if clientID == "" || len(clientID) > 128 || clientID == "." || clientID == ".." {
		return false
	}
	return !strings.ContainsFunc(clientID, func(character rune) bool {
		return character <= ' ' || character == '' || character == '/' || character == '\\' || character == '?' || character == '#'
	})
}

type oidcClient struct {
	ID                     string   `json:"client_id"`
	Name                   string   `json:"client_name"`
	RedirectURIs           []string `json:"redirect_uris"`
	PostLogoutRedirectURIs []string `json:"post_logout_redirect_uris"`
	FrontChannelLogoutURI  string   `json:"frontchannel_logout_uri"`
	BackChannelLogoutURI   string   `json:"backchannel_logout_uri"`
	GrantTypes             []string `json:"grant_types"`
	ResponseTypes          []string `json:"response_types"`
	TokenEndpointAuth      string   `json:"token_endpoint_auth_method"`
}

type oidcClientInput struct {
	ID                     string
	Name                   string
	Secret                 string
	RedirectURIs           []string
	PostLogoutRedirectURIs []string
	FrontChannelLogoutURI  string
	BackChannelLogoutURI   string
}

func (input oidcClientInput) validate() error {
	if !oidcClientIDPattern.MatchString(input.ID) {
		return identity.Invalid("client ID must contain 3–128 lowercase letters, digits, or hyphens and start with a letter")
	}
	if strings.TrimSpace(input.Name) == "" {
		return identity.Invalid("client name is required")
	}
	if len(input.Secret) < 32 {
		return identity.Invalid("client secret must contain at least 32 characters")
	}
	if len(input.RedirectURIs) == 0 {
		return identity.Invalid("at least one redirect URI is required")
	}
	if len(input.PostLogoutRedirectURIs) == 0 {
		return identity.Invalid("at least one post-logout redirect URI is required")
	}
	if input.FrontChannelLogoutURI == "" && input.BackChannelLogoutURI == "" {
		return identity.Invalid("a front-channel or back-channel logout URI is required")
	}
	if err := validateClientURIs("redirect URI", input.RedirectURIs); err != nil {
		return err
	}
	if err := validateClientURIs("post-logout redirect URI", input.PostLogoutRedirectURIs); err != nil {
		return err
	}
	if err := validateClientURIs("front-channel logout URI", []string{input.FrontChannelLogoutURI}); err != nil {
		return err
	}
	if err := validateClientURIs("back-channel logout URI", []string{input.BackChannelLogoutURI}); err != nil {
		return err
	}
	if _, err := oidcClientOrigin(input.RedirectURIs, input.PostLogoutRedirectURIs, input.FrontChannelLogoutURI, input.BackChannelLogoutURI); err != nil {
		return err
	}
	return nil
}

func oidcClientOrigin(redirectURIs, postLogoutRedirectURIs []string, frontChannelLogoutURI, backChannelLogoutURI string) (*url.URL, error) {
	coordinates := append([]string{}, redirectURIs...)
	coordinates = append(coordinates, postLogoutRedirectURIs...)
	coordinates = append(coordinates, frontChannelLogoutURI, backChannelLogoutURI)
	var origin *url.URL
	for _, raw := range coordinates {
		if raw == "" {
			continue
		}
		coordinate, err := url.Parse(raw)
		if err != nil {
			return nil, identity.Invalid("application coordinate %q is invalid", raw)
		}
		if origin == nil {
			origin = &url.URL{Scheme: strings.ToLower(coordinate.Scheme), Host: strings.ToLower(coordinate.Host)}
			continue
		}
		if !sameOrigin(origin, coordinate) {
			return nil, identity.Invalid("all redirect and logout URIs must use one application origin")
		}
	}
	if origin == nil {
		return nil, identity.Invalid("application origin is unavailable")
	}
	return origin, nil
}

func sameOrigin(left, right *url.URL) bool {
	return left != nil && right != nil && strings.EqualFold(left.Scheme, right.Scheme) && strings.EqualFold(left.Host, right.Host)
}

func validateManagedAppClient(app identity.ManagedApp, client oidcClient) error {
	if app.OIDCClientID != client.ID {
		return identity.Invalid("managed app OpenID Connect client does not match the registered client")
	}
	launchURL, err := url.Parse(app.LaunchURL)
	if err != nil {
		return identity.Invalid("managed app launch URL is invalid")
	}
	bridgeURL, err := managedAppLogoutBridgeURL(app.LaunchURL)
	if err != nil {
		return err
	}
	if len(client.PostLogoutRedirectURIs) != 1 || client.PostLogoutRedirectURIs[0] != bridgeURL {
		return identity.Invalid("managed app must register only its exact Shauth logout bridge URI")
	}
	clientOrigin, err := oidcClientOrigin(client.RedirectURIs, client.PostLogoutRedirectURIs, client.FrontChannelLogoutURI, client.BackChannelLogoutURI)
	if err != nil {
		return err
	}
	if !sameOrigin(clientOrigin, launchURL) {
		return identity.Invalid("managed app and OpenID Connect client must use one application origin")
	}
	return nil
}

func oidcClientContractHash(client oidcClient) string {
	redirectURIs := append([]string(nil), client.RedirectURIs...)
	postLogoutRedirectURIs := append([]string(nil), client.PostLogoutRedirectURIs...)
	grantTypes := append([]string(nil), client.GrantTypes...)
	responseTypes := append([]string(nil), client.ResponseTypes...)
	sort.Strings(redirectURIs)
	sort.Strings(postLogoutRedirectURIs)
	sort.Strings(grantTypes)
	sort.Strings(responseTypes)
	payload, err := json.Marshal(struct {
		ID                     string   `json:"client_id"`
		RedirectURIs           []string `json:"redirect_uris"`
		PostLogoutRedirectURIs []string `json:"post_logout_redirect_uris"`
		FrontChannelLogoutURI  string   `json:"frontchannel_logout_uri"`
		BackChannelLogoutURI   string   `json:"backchannel_logout_uri"`
		GrantTypes             []string `json:"grant_types"`
		ResponseTypes          []string `json:"response_types"`
		TokenEndpointAuth      string   `json:"token_endpoint_auth_method"`
	}{client.ID, redirectURIs, postLogoutRedirectURIs, client.FrontChannelLogoutURI, client.BackChannelLogoutURI, grantTypes, responseTypes, client.TokenEndpointAuth})
	if err != nil {
		panic("marshal OpenID Connect client validation contract: " + err.Error())
	}
	digest := sha256.Sum256(payload)
	return hex.EncodeToString(digest[:])
}

func registeredOIDCClient(input oidcClientInput) oidcClient {
	return oidcClient{
		ID:                     input.ID,
		RedirectURIs:           input.RedirectURIs,
		PostLogoutRedirectURIs: input.PostLogoutRedirectURIs,
		FrontChannelLogoutURI:  input.FrontChannelLogoutURI,
		BackChannelLogoutURI:   input.BackChannelLogoutURI,
		GrantTypes:             []string{"authorization_code", "refresh_token"},
		ResponseTypes:          []string{"code"},
		TokenEndpointAuth:      "client_secret_post",
	}
}

func managedAppLogoutBridgeURL(launchURL string) (string, error) {
	parsed, err := url.Parse(launchURL)
	if err != nil || parsed.Scheme == "" || parsed.Host == "" {
		return "", fmt.Errorf("managed app launch URL is invalid")
	}
	return (&url.URL{Scheme: parsed.Scheme, Host: parsed.Host, Path: "/auth/shauth/logout/complete"}).String(), nil
}

func validateClientURIs(label string, uris []string) error {
	for _, rawURI := range uris {
		if rawURI == "" {
			continue
		}
		uri, err := url.Parse(rawURI)
		if err != nil || uri.Scheme == "" || uri.Host == "" || uri.User != nil || uri.Fragment != "" {
			return identity.Invalid("%s %q must be an absolute URI without user information or a fragment", label, rawURI)
		}
		if uri.Scheme != "https" && !isLoopbackRedirect(uri) {
			return identity.Invalid("%s %q must use HTTPS unless it targets loopback", label, rawURI)
		}
	}
	return nil
}

func isLoopbackRedirect(uri *url.URL) bool {
	host := strings.Trim(strings.ToLower(uri.Hostname()), "[]")
	if host == "localhost" || strings.HasSuffix(host, ".localhost") || host == "::1" {
		return true
	}
	return net.ParseIP(host).IsLoopback()
}

type Server struct {
	config           config.Config
	store            *identity.Store
	github           *githubapi.Client
	oauth            *oauth2.Config
	entraOAuth       *oauth2.Config
	entraVerify      *oidc.IDTokenVerifier
	httpClient       *http.Client
	templates        *template.Template
	hydraPublic      *httputil.ReverseProxy
	mailer           mailer.Invitations
	managedApps      *managedapps.Controller
	monitoringClient *monitoring.Client
	traffic          *traffic
	logs             *observe.Buffer
}

func New(cfg config.Config, store *identity.Store) (*Server, error) {
	outboundClient := &http.Client{Timeout: outboundRequestTimeout}
	client, err := githubapi.NewClient(outboundClient)
	if err != nil {
		return nil, err
	}
	callback := cfg.PublicURL.ResolveReference(&url.URL{Path: "/oauth/github/callback"}).String()
	templates, err := template.New("pages").Funcs(templateHelpers()).Parse(pageTemplates)
	if err != nil {
		return nil, fmt.Errorf("parse templates: %w", err)
	}
	inviter, err := mailer.NewSES(context.Background(), cfg.SESRegion, cfg.InvitationEmailFrom)
	if err != nil {
		return nil, err
	}
	appController := managedapps.New()
	proxy := httputil.NewSingleHostReverseProxy(cfg.HydraPublicURL)
	proxy.ModifyResponse = ensureRedirectBody
	server := &Server{config: cfg, store: store, github: client, httpClient: outboundClient, templates: templates, hydraPublic: proxy, mailer: inviter, managedApps: appController, monitoringClient: monitoring.NewClient(), traffic: newTraffic(), oauth: &oauth2.Config{ClientID: cfg.GitHubClientID, ClientSecret: cfg.GitHubClientSecret, Endpoint: oauthgithub.Endpoint, RedirectURL: callback, Scopes: []string{"read:user", "user:email", "read:org"}}}
	proxy.ErrorHandler = func(w http.ResponseWriter, r *http.Request, err error) {
		observe.Errorf("proxy Hydra public request %s: %v", r.URL.Path, err)
		server.failPage(w, r, http.StatusBadGateway, "The authorization provider is unavailable. Please try signing in again shortly.")
	}
	if cfg.EntraTenantID != "" {
		issuer := "https://login.microsoftonline.com/" + cfg.EntraTenantID + "/v2.0"
		discoveryContext, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		provider, err := oidc.NewProvider(discoveryContext, issuer)
		if err != nil {
			return nil, fmt.Errorf("discover Microsoft Entra ID OpenID Connect provider: %w", err)
		}
		server.entraOAuth = &oauth2.Config{ClientID: cfg.EntraClientID, ClientSecret: cfg.EntraClientSecret, Endpoint: provider.Endpoint(), RedirectURL: cfg.PublicURL.ResolveReference(&url.URL{Path: "/oauth/entra/callback"}).String(), Scopes: []string{oidc.ScopeOpenID, "profile", "email"}}
		server.entraVerify = provider.Verifier(&oidc.Config{ClientID: cfg.EntraClientID})
	}
	if err := server.bootstrapApps(context.Background()); err != nil {
		return nil, err
	}
	return server, nil
}

func ensureRedirectBody(response *http.Response) error {
	if response.StatusCode < http.StatusMultipleChoices || response.StatusCode >= http.StatusBadRequest || response.Header.Get("Location") == "" {
		return nil
	}
	body, err := io.ReadAll(response.Body)
	if err != nil {
		return fmt.Errorf("read OAuth redirect response: %w", err)
	}
	if err := response.Body.Close(); err != nil {
		return fmt.Errorf("close OAuth redirect response: %w", err)
	}
	if len(body) == 0 {
		body = []byte(fmt.Sprintf("<a href=\"%s\">%s</a>.\n", template.HTMLEscapeString(response.Header.Get("Location")), template.HTMLEscapeString(http.StatusText(response.StatusCode))))
		response.Header.Set("Content-Type", "text/html; charset=utf-8")
		observe.Infof("Hydra redirect body injected: status=%d target=%s response_bytes=%d", response.StatusCode, redirectTarget(response.Header.Get("Location")), len(body))
	}
	response.Body = io.NopCloser(bytes.NewReader(body))
	response.ContentLength = int64(len(body))
	response.Header.Set("Content-Length", fmt.Sprintf("%d", len(body)))
	return nil
}

func redirectTarget(location string) string {
	target, err := url.Parse(location)
	if err != nil || target.Host == "" {
		return "invalid"
	}
	return target.Host + target.EscapedPath()
}

func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", s.health)
	mux.HandleFunc("GET /assets/theme.js", serveThemeScript)
	mux.HandleFunc("GET /assets/validator-bootstrap.js", serveValidatorBootstrapScript)
	mux.HandleFunc("GET "+htmxAssetPath, serveHTMX)
	mux.Handle("/.well-known/{path...}", s.hydraPublic)
	mux.HandleFunc("GET /oauth2/sessions/logout", s.providerLogoutStart)
	mux.Handle("/oauth2/{path...}", s.hydraPublic)
	mux.Handle("/userinfo", s.hydraPublic)
	mux.HandleFunc("GET /{$}", s.home)
	mux.HandleFunc("GET /apps", s.apps)
	mux.HandleFunc("GET /apps/{id}/validation", s.appValidationStatus)
	mux.HandleFunc("GET /api/v1/apps", s.applicationsAPI)
	mux.HandleFunc("GET /api/v1/apps/validations", s.applicationValidationStatusAPI)
	mux.HandleFunc("GET /api/v1/apps/validations/history", s.applicationValidationHistoryAPI)
	mux.HandleFunc("GET /api/v1/users", s.usersAPI)
	mux.HandleFunc("GET /api/v1/users/{id}", s.userAPI)
	mux.HandleFunc("GET /api/v1/users/{id}/sessions", s.userSessionsAPI)
	mux.HandleFunc("GET /api/v1/session-policy", s.sessionPolicyAPI)
	mux.HandleFunc("GET /api/v1/oidc-clients", s.oidcClientsAPI)
	mux.HandleFunc("GET /api/v1/github-mappings", s.githubMappingsAPI)
	mux.HandleFunc("GET /api/v1/connectors", s.connectorsAPI)
	mux.HandleFunc("GET /api/v1/monitoring", s.monitoringAPI)
	mux.HandleFunc("GET /api/v1/invitations", s.invitationsAPI)
	mux.HandleFunc("GET /api/v1/audit-events", s.auditEventsAPI)
	mux.HandleFunc("GET /api/v1/users/{id}/audit-events", s.auditEventsAPI)
	mux.HandleFunc("GET /api/v1/metrics", s.metricsAPI)
	mux.HandleFunc("GET /api/v1/metrics/requests", s.requestMetricsAPI)
	mux.HandleFunc("GET /api/v1/logs", s.logsAPI)
	mux.HandleFunc("GET /api/v1/health/deep", s.deepHealthAPI)
	mux.HandleFunc("GET /api/v1/sessions", s.sessionsAPI)
	mux.HandleFunc("GET /api/v1/sessions/{id}", s.sessionAPI)
	mux.HandleFunc("GET /api/v1/logout-grants", s.logoutGrantsAPI)
	mux.HandleFunc("GET /api/v1/apps/{slug}", s.appAPI)
	mux.HandleFunc("GET /api/v1/me/sessions", s.mySessionsAPI)
	mux.HandleFunc("POST /internal/me/sessions/{id}/revoke", s.revokeMySessionAPI)
	mux.HandleFunc("GET /account", s.account)
	mux.HandleFunc("POST /account/sessions/{id}/revoke", s.revokeOwnSession)
	mux.HandleFunc("GET /admin/audit", s.adminAudit)
	mux.HandleFunc("GET /admin/logs", s.adminLogs)
	mux.HandleFunc("POST /internal/users", s.createUserAPI)
	mux.HandleFunc("POST /internal/users/{id}/disable", s.disableUserAPI)
	mux.HandleFunc("POST /internal/users/{id}/enable", s.enableUserAPI)
	mux.HandleFunc("POST /internal/invitations", s.createInvitationAPI)
	mux.HandleFunc("POST /internal/invitations/{id}/revoke", s.revokeInvitationAPI)
	mux.HandleFunc("POST /internal/sessions/{id}/revoke", s.revokeSessionAPI)
	mux.HandleFunc("POST /internal/users/{id}/sessions/revoke", s.revokeUserSessionsAPI)
	mux.HandleFunc("PUT /internal/session-policy", s.updateSessionPolicyAPI)
	mux.HandleFunc("POST /internal/oidc-clients", s.createOIDCClientAPI)
	mux.HandleFunc("DELETE /internal/oidc-clients/{id}", s.deleteOIDCClientAPI)
	mux.HandleFunc("POST /internal/github-mappings", s.createGitHubMappingAPI)
	mux.HandleFunc("DELETE /internal/github-mappings/{id}", s.deleteGitHubMappingAPI)
	mux.HandleFunc("POST /internal/apps", s.createAppAPI)
	mux.HandleFunc("DELETE /internal/apps/{slug}", s.deleteAppAPI)
	mux.HandleFunc("GET /login", s.login)
	mux.HandleFunc("POST /login", s.passwordLogin)
	mux.HandleFunc("GET /logout", s.logoutConfirm)
	mux.HandleFunc("POST /logout", s.logout)
	mux.HandleFunc("GET /signed-out", s.signedOut)
	mux.HandleFunc("GET /oauth/logout/complete", s.logoutComplete)
	mux.HandleFunc("GET /validator/bootstrap", s.validatorBootstrapPage)
	mux.HandleFunc("POST /validator/bootstrap", s.validatorBootstrapConsume)
	mux.HandleFunc("GET /oauth/github", s.githubStart)
	mux.HandleFunc("GET /oauth/github/callback", s.githubCallback)
	mux.HandleFunc("GET /oauth/entra", s.entraStart)
	mux.HandleFunc("GET /oauth/entra/callback", s.entraCallback)
	mux.HandleFunc("GET /oauth/login", s.hydraLogin)
	mux.HandleFunc("GET /oauth/consent", s.hydraConsent)
	mux.HandleFunc("GET /oauth/error", s.hydraError)
	mux.HandleFunc("POST /oauth/consent", s.hydraConsentAccept)
	mux.HandleFunc("GET /oauth/logout", s.hydraLogout)
	mux.HandleFunc("GET /admin", s.admin)
	mux.HandleFunc("GET /admin/apps", s.adminApps)
	mux.HandleFunc("POST /admin/apps", s.adminCreateApp)
	mux.HandleFunc("POST /apps/{id}/validate", s.validateApp)
	mux.HandleFunc("POST /admin/apps/{id}/delete", s.adminDeleteApp)
	mux.HandleFunc("POST /internal/validator/jobs/claim", s.validatorClaim)
	mux.HandleFunc("POST /internal/validator/browser-bootstraps", s.validatorCreateBrowserBootstraps)
	mux.HandleFunc("POST /internal/validator/jobs/{id}/complete", s.validatorComplete)
	mux.HandleFunc("GET /admin/clients", s.adminOIDCClients)
	mux.HandleFunc("POST /admin/clients", s.adminCreateOIDCClient)
	mux.HandleFunc("POST /admin/clients/{id}/delete", s.adminDeleteOIDCClient)
	mux.HandleFunc("GET /admin/session-policy", s.adminSessionPolicy)
	mux.HandleFunc("POST /admin/session-policy", s.adminUpdateSessionPolicy)
	mux.HandleFunc("GET /admin/github", s.adminGitHubMappings)
	mux.HandleFunc("POST /admin/github", s.adminCreateGitHubMapping)
	mux.HandleFunc("POST /admin/github/{id}/delete", s.adminDeleteGitHubMapping)
	mux.HandleFunc("GET /admin/connectors", s.adminConnectors)
	mux.HandleFunc("GET /admin/users", s.adminUsers)
	mux.HandleFunc("POST /admin/users", s.adminCreateUser)
	mux.HandleFunc("POST /admin/invitations", s.adminInvite)
	mux.HandleFunc("GET /admin/invitations", s.adminInvitations)
	mux.HandleFunc("POST /admin/invitations/{id}/revoke", s.adminRevokeInvitation)
	mux.HandleFunc("POST /admin/users/{id}/disable", s.adminDisableUser)
	mux.HandleFunc("POST /admin/users/{id}/enable", s.adminEnableUser)
	mux.HandleFunc("GET /accept-invitation", s.acceptInvitation)
	mux.HandleFunc("POST /accept-invitation", s.acceptInvitationPost)
	mux.HandleFunc("GET /admin/users/{id}", s.adminUserSessions)
	mux.HandleFunc("GET /admin/users/{id}/sessions", s.adminUserSessionsLegacy)
	mux.HandleFunc("GET /admin/apps/{slug}", s.adminApp)
	mux.HandleFunc("POST /admin/users/{id}/sessions/revoke", s.adminRevokeSessions)
	mux.HandleFunc("GET /admin/sessions", s.adminSessions)
	mux.HandleFunc("POST /admin/sessions/{id}/revoke", s.adminRevokeSession)
	mux.HandleFunc("POST /internal/sessions/reset", s.sessionResetAPI)
	// csrfPosts exempts only /oauth2/token and /internal/ paths from browser
	// CSRF enforcement, so this bearer-token POST must live under /internal/.
	mux.HandleFunc("POST /internal/apps/validations/enqueue", s.applicationValidationEnqueueAPI)
	mux.HandleFunc("GET /monitoring", s.monitoring)
	mux.HandleFunc("GET /favicon.svg", serveFavicon)
	mux.HandleFunc("GET /favicon.ico", serveFavicon)
	mux.HandleFunc("/", s.notFound)
	if s.traffic == nil {
		s.traffic = newTraffic()
	}
	// Outermost, so a request refused by CSRF or rejected before routing is
	// still counted: those refusals are exactly what an operator is looking
	// for when something stops working.
	return s.traffic.observe(mux, securityHeaders(csrfPosts(s.config.PublicURL, mux)))
}

func securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		policy := baseContentSecurityPolicy
		if r.URL.Path == "/oauth2/sessions/logout" {
			policy = oidcLogoutContentSecurityPolicy
		} else {
			// CSP frame-ancestors is authoritative in modern browsers; this
			// retains the equivalent protection for older clients.
			w.Header().Set("X-Frame-Options", "DENY")
		}
		w.Header().Set("Content-Security-Policy", policy)
		w.Header().Set("Referrer-Policy", "no-referrer")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Permissions-Policy", "camera=(), geolocation=(), microphone=(), payment=(), usb=()")
		next.ServeHTTP(w, r)
	})
}

func serveThemeScript(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "application/javascript; charset=utf-8")
	w.Header().Set("Cache-Control", "public, max-age=86400")
	// Applied before first paint, so a chosen theme does not flash. The
	// toggle cycles system -> light -> dark and reports the state it is in,
	// rather than claiming "light" while the system renders dark. The three
	// icons are rendered by the server and selected by the theme attribute,
	// so the control shows the right one before this script runs and no
	// markup is assembled in the browser.
	_, _ = w.Write([]byte(`!function(){try{var root=document.documentElement,stored=localStorage.getItem("shauth-theme");if(stored==="light"||stored==="dark"){root.dataset.theme=stored}
function setup(){var button=document.getElementById("theme-toggle");if(!button)return;var order=["system","light","dark"],names={system:"follow the system theme",light:"light mode",dark:"dark mode"};
function label(){var mode=root.dataset.theme||"system",next=order[(order.indexOf(mode)+1)%order.length];button.setAttribute("aria-label","Theme: "+names[mode]+". Switch to "+names[next]+".")}
button.addEventListener("click",function(){var mode=root.dataset.theme||"system",next=order[(order.indexOf(mode)+1)%order.length];root.dataset.theme=next;if(next==="system"){localStorage.removeItem("shauth-theme")}else{localStorage.setItem("shauth-theme",next)}label()});label()}
if(document.readyState==="loading"){document.addEventListener("DOMContentLoaded",setup)}else{setup()}}catch(error){}}();`))
	// A destructive action asks first. The confirmation is attached by
	// attribute so it also covers forms inserted by HTMX.
	_, _ = w.Write([]byte(`document.addEventListener("submit",function(event){var form=event.target;if(!(form instanceof HTMLFormElement))return;var question=form.getAttribute("data-confirm");if(question&&!window.confirm(question)){event.preventDefault();event.stopPropagation()}},true);`))
	// Forms rendered by the server already carry their CSRF token; this
	// covers any form inserted into the page after it loaded.
	_, _ = w.Write([]byte(`document.addEventListener("submit",function(event){var form=event.target;if(!(form instanceof HTMLFormElement)||form.method.toLowerCase()!=="post")return;var input=form.querySelector('input[name="_csrf"]');if(!input){input=document.createElement("input");input.type="hidden";input.name="_csrf";form.appendChild(input)}if(!input.value){var match=document.cookie.match(/(?:^|; )shauth_csrf=([^;]*)/);input.value=match?decodeURIComponent(match[1]):""}},true);`))
	// A newly inserted table row replaces the empty-state row rather than
	// appearing beneath it.
	_, _ = w.Write([]byte(`document.addEventListener("htmx:afterSwap",function(){var empty=document.getElementById("users-empty");if(empty&&empty.parentNode&&empty.parentNode.querySelectorAll("tr").length>1){empty.remove()}});`))
}

func serveValidatorBootstrapScript(w http.ResponseWriter, _ *http.Request) {
	noStore(w)
	w.Header().Set("Content-Type", "application/javascript; charset=utf-8")
	_, _ = w.Write([]byte(`!function(){var status=document.getElementById("validator-bootstrap-status"),form=document.getElementById("validator-bootstrap-form"),input=document.getElementById("validator-bootstrap-token"),token=location.hash.slice(1);history.replaceState(null,"",location.pathname);if(!/^[0-9a-f]{64}$/.test(token)){status.textContent="This validation session link is invalid.";status.setAttribute("role","alert");return}input.value=token;form.requestSubmit()}();`))
}

func noStore(w http.ResponseWriter) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")
	w.Header().Set("Referrer-Policy", "no-referrer")
}

// csrfTokenKey carries the request's CSRF token so every server-rendered
// form can embed it. Injecting the token in the browser would make every
// state change depend on JavaScript.
type csrfTokenKey struct{}

// csrfToken reports the CSRF token for this request, whether it arrived in a
// cookie or was minted by the middleware for this response.
func csrfToken(r *http.Request) string {
	if token, ok := r.Context().Value(csrfTokenKey{}).(string); ok {
		return token
	}
	if cookie, err := r.Cookie(csrfCookie); err == nil {
		return cookie.Value
	}
	return ""
}

func csrfPosts(publicURL *url.URL, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet || r.Method == http.MethodHead {
			if _, err := r.Cookie(csrfCookie); err != nil {
				token, tokenErr := newState()
				if tokenErr != nil {
					http.Error(w, "could not create CSRF token", http.StatusInternalServerError)
					return
				}
				http.SetCookie(w, &http.Cookie{Name: csrfCookie, Value: token, Path: "/", Secure: publicURL.Scheme == "https", SameSite: http.SameSiteLaxMode})
				r = r.WithContext(context.WithValue(r.Context(), csrfTokenKey{}, token))
			}
		}
		if r.Method == http.MethodPost && r.URL.Path != "/oauth2/token" && !strings.HasPrefix(r.URL.Path, "/internal/") {
			if err := r.ParseForm(); err != nil {
				http.Error(w, "invalid form", http.StatusBadRequest)
				return
			}
			cookie, err := r.Cookie(csrfCookie)
			if err != nil || cookie.Value == "" || subtle.ConstantTimeCompare([]byte(cookie.Value), []byte(r.Form.Get("_csrf"))) != 1 {
				http.Error(w, "CSRF token is invalid", http.StatusForbidden)
				return
			}
			origin := r.Header.Get("Origin")
			if origin != "" && origin != "null" {
				parsed, err := url.Parse(origin)
				if err == nil && parsed.Scheme == publicURL.Scheme && parsed.Host == publicURL.Host && parsed.Path == "" && parsed.RawQuery == "" && parsed.Fragment == "" && parsed.User == nil {
					next.ServeHTTP(w, r)
					return
				}
				http.Error(w, "cross-origin request denied", http.StatusForbidden)
				return
			}
		}
		next.ServeHTTP(w, r)
	})
}
func (s *Server) health(w http.ResponseWriter, r *http.Request) {
	noStore(w)
	ctx, cancel := context.WithTimeout(r.Context(), 2*time.Second)
	defer cancel()
	if err := s.store.Ping(ctx); err != nil {
		http.Error(w, "database unavailable", http.StatusServiceUnavailable)
		return
	}
	if !s.hydraReady(ctx) {
		http.Error(w, "OAuth provider unavailable", http.StatusServiceUnavailable)
		return
	}
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	_, _ = fmt.Fprintln(w, "ok")
}

// notFound answers an unrouted path. Machine namespaces receive the JSON
// error shape their clients parse; browsers receive a navigable page.
func (s *Server) notFound(w http.ResponseWriter, r *http.Request) {
	if strings.HasPrefix(r.URL.Path, "/api/") || strings.HasPrefix(r.URL.Path, "/internal/") {
		noStore(w)
		writeAdminAPIError(w, http.StatusNotFound, "no such endpoint")
		return
	}
	s.failPage(w, r, http.StatusNotFound, "That page does not exist.")
}

func (s *Server) home(w http.ResponseWriter, r *http.Request) {
	user, _, err := s.current(r)
	s.render(w, "home", s.view(r, "Home", map[string]any{"User": newUserRecord(user), "SignedIn": err == nil, "IsAdmin": err == nil && user.Role == identity.RoleAdmin}))
}
func (s *Server) login(w http.ResponseWriter, r *http.Request) {
	if _, _, err := s.current(r); err == nil {
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}
	next := relativeNext(r.URL.Query().Get("next"))
	if isOIDCNext(next) {
		allowOIDCFormAction(w)
	}
	s.render(w, "login", s.view(r, "Sign in", map[string]any{"Next": next, "Error": r.URL.Query().Get("error"), "EntraEnabled": s.entraOAuth != nil, "SignedIn": false}))
}
func (s *Server) passwordLogin(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		s.failPage(w, r, http.StatusBadRequest, "invalid form")
		return
	}
	username := r.Form.Get("username")
	user, reason, err := s.store.AuthenticatePassword(r.Context(), username, r.Form.Get("password"))
	if err != nil {
		// The person is told only that the pair did not work; the audit
		// record keeps the reason so an operator can tell a disabled
		// account from a mistyped name.
		event := identity.AuditSignInFailed
		if reason == identity.SignInReasonDisabled {
			event = identity.AuditSignInBlocked
		}
		s.recordSignIn(r, event, "password", username, "", reason)
		s.render(w, "login", s.view(r, "Sign in", map[string]any{
			"Error": "Invalid username or password.", "Next": relativeNext(r.Form.Get("next")),
			"EntraEnabled": s.entraOAuth != nil, "SignedIn": false,
		}))
		return
	}
	if !s.startSession(w, r, user) {
		return
	}
	s.recordSignIn(r, identity.AuditSignInSucceeded, "password", user.Username, user.ID, "")
	http.Redirect(w, r, relativeNext(r.Form.Get("next")), http.StatusSeeOther)
}
func (s *Server) logoutConfirm(w http.ResponseWriter, r *http.Request) {
	user, _, err := s.current(r)
	s.render(w, "logout", s.view(r, "Sign out", map[string]any{"SignedIn": err == nil, "User": newUserRecord(user), "IsAdmin": err == nil && user.Role == identity.RoleAdmin}))
}

func (s *Server) logout(w http.ResponseWriter, r *http.Request) {
	user, session, err := s.current(r)
	if err != nil {
		s.expireCookie(w, browserSessionCookie)
		http.Redirect(w, r, "/signed-out", http.StatusSeeOther)
		return
	}
	correlation, grant, err := s.store.CreateLogoutCorrelationGrant(r.Context(), user.ID, session.ID, "", "", time.Now())
	if err != nil {
		localErr := s.store.RevokeSession(r.Context(), session.ID, time.Now())
		s.expireCookie(w, browserSessionCookie)
		observe.Errorf("logout correlation creation failed after exact local revocation: local=%v correlation=%v", localErr, err)
		s.failPage(w, r, http.StatusBadGateway, "browser session ended but connected application logout could not start")
		return
	}
	s.expireCookie(w, browserSessionCookie)
	if correlation == "" {
		http.Redirect(w, r, "/signed-out", http.StatusSeeOther)
		return
	}
	if len(grant.BrowserHydraSessionIDs) == 0 {
		if err := s.finalizeProviderLogout(r.Context(), grant); err != nil {
			s.scheduleLogoutRecovery(r.Context(), grant, err)
			s.failPage(w, r, http.StatusBadGateway, "local sessions ended but connected application logout did not complete")
			return
		}
		http.Redirect(w, r, "/signed-out", http.StatusSeeOther)
		return
	}
	s.setCookie(w, &http.Cookie{Name: logoutCorrelationCookie, Value: correlation, Path: logoutCorrelationPath, HttpOnly: true, Secure: !s.config.AllowInsecureCookies, SameSite: http.SameSiteLaxMode, Expires: time.Now().Add(identity.LogoutCorrelationLifetime), MaxAge: int(identity.LogoutCorrelationLifetime / time.Second)})
	http.Redirect(w, r, "/oauth2/sessions/logout", http.StatusSeeOther)
}

// providerLogoutStart covers standards-based RP-initiated logout, which enters
// Hydra's end-session endpoint without posting Shauth's portal form first.
// Hydra validates every end-session request before Shauth mutates local state.
func (s *Server) providerLogoutStart(w http.ResponseWriter, r *http.Request) {
	s.hydraPublic.ServeHTTP(w, r)
}

func (s *Server) signedOut(w http.ResponseWriter, r *http.Request) {
	s.render(w, "signed-out", s.view(r, "Signed out", map[string]any{"SignedIn": false}))
}

func (s *Server) logoutComplete(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	destination := "/signed-out"
	if cookie, err := r.Cookie(logoutCompletionCookie); err == nil {
		s.expireCookieAtPath(w, logoutCompletionCookie, logoutCompletionPath)
		grant, claimErr := s.store.ClaimConsumedLogoutCorrelationGrant(r.Context(), cookie.Value, time.Now())
		if claimErr != nil {
			observe.Errorf("claim completed browser logout: %v", claimErr)
		} else if cleanupErr := s.finalizeProviderLogout(r.Context(), *grant); cleanupErr != nil {
			s.scheduleLogoutRecovery(r.Context(), *grant, cleanupErr)
			observe.Errorf("finish provider logout after front-channel delivery: %v", cleanupErr)
		} else if grant.SignedOutURL != "" {
			destination = grant.SignedOutURL
		}
	}
	http.Redirect(w, r, destination, http.StatusSeeOther)
}
func (s *Server) githubStart(w http.ResponseWriter, r *http.Request) {
	state, err := newState()
	if err != nil {
		s.failPage(w, r, http.StatusInternalServerError, "could not begin GitHub login")
		return
	}
	s.setCookie(w, &http.Cookie{Name: githubStateCookieName(state), Value: relativeNext(r.URL.Query().Get("next")), Path: "/oauth/github/callback", HttpOnly: true, Secure: !s.config.AllowInsecureCookies, SameSite: http.SameSiteLaxMode, MaxAge: 600})
	http.Redirect(w, r, s.oauth.AuthCodeURL(state), http.StatusFound)
}
func (s *Server) githubCallback(w http.ResponseWriter, r *http.Request) {
	state := r.URL.Query().Get("state")
	cookieName, validState := validGitHubStateCookieName(state)
	cookie, err := r.Cookie(cookieName)
	if !validState || err != nil {
		s.failPage(w, r, http.StatusBadRequest, "GitHub login state did not match")
		return
	}
	s.expireCookieAtPath(w, cookieName, "/oauth/github/callback")
	token, err := s.oauth.Exchange(r.Context(), r.URL.Query().Get("code"))
	if err != nil {
		s.failPage(w, r, http.StatusBadGateway, "GitHub authorization failed")
		return
	}
	profile, err := s.github.Profile(r.Context(), token.AccessToken)
	if err != nil {
		s.failPage(w, r, http.StatusBadGateway, "could not read GitHub identity")
		return
	}
	role, allowed, err := s.githubRole(r.Context(), token.AccessToken, profile)
	if err != nil {
		s.failPage(w, r, http.StatusBadGateway, "could not verify GitHub organization membership")
		return
	}
	if !allowed {
		s.recordSignIn(r, identity.AuditSignInFailed, "github", profile.Login, "", "no GitHub access rule grants this account a role")
		s.failPage(w, r, http.StatusForbidden, "This GitHub account is not authorized to use this service. Ask an administrator to grant it access.")
		return
	}
	user, err := s.store.FindOrCreateGitHubUser(r.Context(), profile.ID, profile.Login, profile.Email, role)
	if err != nil {
		s.recordSignIn(r, identity.AuditSignInBlocked, "github", profile.Login, "", err.Error())
	}
	if err != nil {
		s.failPage(w, r, http.StatusInternalServerError, "could not establish local account")
		return
	}
	if !s.startSession(w, r, user) {
		return
	}
	s.recordSignIn(r, identity.AuditSignInSucceeded, "github", user.Username, user.ID, "")
	http.Redirect(w, r, relativeNext(cookie.Value), http.StatusSeeOther)
}

func (s *Server) entraStart(w http.ResponseWriter, r *http.Request) {
	if s.entraOAuth == nil {
		http.NotFound(w, r)
		return
	}
	state, err := newState()
	if err != nil {
		s.failPage(w, r, http.StatusInternalServerError, "could not begin Microsoft Entra ID login")
		return
	}
	nonce, err := newState()
	if err != nil {
		s.failPage(w, r, http.StatusInternalServerError, "could not begin Microsoft Entra ID login")
		return
	}
	cookieValue, err := json.Marshal(map[string]string{"next": relativeNext(r.URL.Query().Get("next")), "nonce": nonce})
	if err != nil {
		s.failPage(w, r, http.StatusInternalServerError, "could not begin Microsoft Entra ID login")
		return
	}
	s.setCookie(w, &http.Cookie{Name: entraStateCookieName(state), Value: base64.RawURLEncoding.EncodeToString(cookieValue), Path: "/oauth/entra/callback", HttpOnly: true, Secure: !s.config.AllowInsecureCookies, SameSite: http.SameSiteLaxMode, MaxAge: 600})
	http.Redirect(w, r, s.entraOAuth.AuthCodeURL(state, oauth2.SetAuthURLParam("nonce", nonce)), http.StatusFound)
}

type entraClaims struct {
	Subject           string `json:"sub"`
	ObjectID          string `json:"oid"`
	TenantID          string `json:"tid"`
	Email             string `json:"email"`
	EmailVerified     bool   `json:"email_verified"`
	PreferredUsername string `json:"preferred_username"`
	Nonce             string `json:"nonce"`
}

func (s *Server) entraCallback(w http.ResponseWriter, r *http.Request) {
	if s.entraOAuth == nil || s.entraVerify == nil {
		http.NotFound(w, r)
		return
	}
	state := r.URL.Query().Get("state")
	cookieName, validState := validEntraStateCookieName(state)
	cookie, err := r.Cookie(cookieName)
	if !validState || err != nil {
		s.failPage(w, r, http.StatusBadRequest, "Microsoft Entra ID login state did not match")
		return
	}
	s.expireCookieAtPath(w, cookieName, "/oauth/entra/callback")
	var transaction map[string]string
	transactionJSON, err := base64.RawURLEncoding.DecodeString(cookie.Value)
	if err != nil || json.Unmarshal(transactionJSON, &transaction) != nil || transaction["nonce"] == "" {
		s.failPage(w, r, http.StatusBadRequest, "Microsoft Entra ID login state was invalid")
		return
	}
	token, err := s.entraOAuth.Exchange(r.Context(), r.URL.Query().Get("code"))
	if err != nil {
		s.failPage(w, r, http.StatusBadGateway, "Microsoft Entra ID authorization failed")
		return
	}
	rawIDToken, ok := token.Extra("id_token").(string)
	if !ok || rawIDToken == "" {
		s.failPage(w, r, http.StatusBadGateway, "Microsoft Entra ID authorization omitted the ID token")
		return
	}
	idToken, err := s.entraVerify.Verify(r.Context(), rawIDToken)
	if err != nil {
		s.failPage(w, r, http.StatusBadGateway, "Microsoft Entra ID token verification failed")
		return
	}
	var claims entraClaims
	if err := idToken.Claims(&claims); err != nil {
		s.failPage(w, r, http.StatusBadGateway, "Microsoft Entra ID identity claims were invalid")
		return
	}
	if subtle.ConstantTimeCompare([]byte(claims.Nonce), []byte(transaction["nonce"])) != 1 || !strings.EqualFold(claims.TenantID, s.config.EntraTenantID) || claims.ObjectID == "" || claims.Subject == "" {
		s.failPage(w, r, http.StatusForbidden, "Microsoft Entra ID identity did not match this Shauth tenant")
		return
	}
	email, emailVerified := entraEmail(claims)
	user, err := s.store.FindOrCreateEntraUser(r.Context(), claims.TenantID, claims.ObjectID, entraUsername(claims.PreferredUsername, email, claims.ObjectID), email, emailVerified)
	if err != nil {
		s.recordSignIn(r, identity.AuditSignInBlocked, "entra", email, "", err.Error())
	}
	if err != nil {
		s.failPage(w, r, http.StatusInternalServerError, "could not establish local account")
		return
	}
	if !s.startSession(w, r, user) {
		return
	}
	s.recordSignIn(r, identity.AuditSignInSucceeded, "entra", user.Username, user.ID, "")
	http.Redirect(w, r, relativeNext(transaction["next"]), http.StatusSeeOther)
}

func entraEmail(claims entraClaims) (string, bool) {
	if email := strings.TrimSpace(claims.Email); email != "" {
		return email, claims.EmailVerified
	}
	return strings.TrimSpace(claims.PreferredUsername), false
}

func entraUsername(preferred, email, objectID string) string {
	base := strings.TrimSpace(preferred)
	if index := strings.IndexByte(base, '@'); index >= 0 {
		base = base[:index]
	}
	if base == "" {
		base = strings.SplitN(email, "@", 2)[0]
	}
	base = regexp.MustCompile(`[^a-zA-Z0-9_.-]+`).ReplaceAllString(base, "-")
	suffix := strings.ReplaceAll(objectID, "-", "")
	if len(suffix) > 8 {
		suffix = suffix[:8]
	}
	return strings.Trim(strings.ToLower(base), "-.") + "-" + suffix
}

func entraStateCookieName(state string) string { return entraStateCookiePrefix + state }

func validEntraStateCookieName(state string) (string, bool) {
	if len(state) != 64 {
		return "", false
	}
	if _, err := hex.DecodeString(state); err != nil {
		return "", false
	}
	return entraStateCookieName(state), true
}
func (s *Server) hydraLogin(w http.ResponseWriter, r *http.Request) {
	challenge := r.URL.Query().Get("login_challenge")
	if challenge == "" {
		s.failPage(w, r, http.StatusBadRequest, "missing login_challenge")
		return
	}
	user, session, err := s.current(r)
	if err != nil {
		http.Redirect(w, r, "/login?next="+url.QueryEscape(r.URL.RequestURI()), http.StatusSeeOther)
		return
	}
	policy, err := s.store.SessionPolicy(r.Context())
	if err != nil {
		s.failPage(w, r, http.StatusInternalServerError, "could not load session policy")
		return
	}
	loginRequest, err := s.hydraLoginRequest(r.Context(), challenge)
	if err != nil {
		s.failPage(w, r, http.StatusBadGateway, "could not load OAuth login request")
		return
	}
	if loginRequest.Skip && loginRequest.Subject != user.ID {
		s.failPage(w, r, http.StatusForbidden, "OAuth login request belongs to a different account")
		return
	}
	redirect, err := s.hydraAccept(r.Context(), "/admin/oauth2/auth/requests/login/accept", challenge, map[string]any{"subject": user.ID, "identity_provider_session_id": session.ID, "remember": true, "remember_for": int64(policy.OIDCSessionLifetime / time.Second)})
	if err != nil {
		s.failPage(w, r, http.StatusBadGateway, "could not complete OAuth login")
		return
	}
	if err := s.store.RecordHydraLoginSession(r.Context(), session.ID, loginRequest.SessionID, time.Now()); err != nil {
		if cleanupErr := s.revokeHydraLoginSession(r.Context(), loginRequest.SessionID); cleanupErr != nil {
			observe.Errorf("delete accepted Ory Hydra login after local correlation failed: correlation=%v cleanup=%v", err, cleanupErr)
		} else {
			observe.Errorf("delete accepted Ory Hydra login after local correlation failed: %v", err)
		}
		s.failPage(w, r, http.StatusInternalServerError, "could not correlate OAuth login session")
		return
	}
	http.Redirect(w, r, redirect, http.StatusFound)
}
func (s *Server) hydraConsent(w http.ResponseWriter, r *http.Request) {
	user, session, err := s.current(r)
	if err != nil {
		http.Redirect(w, r, "/login?next="+url.QueryEscape(r.URL.RequestURI()), http.StatusSeeOther)
		return
	}
	challenge := r.URL.Query().Get("consent_challenge")
	if challenge == "" {
		s.failPage(w, r, http.StatusBadRequest, "missing consent_challenge")
		return
	}
	consent, err := s.hydraConsentRequest(r.Context(), challenge)
	if err != nil {
		s.failPage(w, r, http.StatusBadGateway, "could not load OAuth consent request")
		return
	}
	managed, err := s.store.IsManagedOIDCClient(r.Context(), consent.ClientID)
	if err != nil {
		s.failPage(w, r, http.StatusInternalServerError, "could not identify the connected application")
		return
	}
	if managed {
		redirect, err := s.acceptHydraConsent(r.Context(), challenge, consent.Scopes, user)
		if err != nil {
			s.failPage(w, r, http.StatusBadGateway, "could not complete OAuth consent")
			return
		}
		if err := s.store.RevalidateSession(r.Context(), user.ID, session.ID, time.Now()); err != nil {
			if consent.LoginSessionID != "" {
				if cleanupErr := s.revokeHydraLoginSession(r.Context(), consent.LoginSessionID); cleanupErr != nil {
					observe.Errorf("delete accepted Ory Hydra consent after browser logout: revalidate=%v cleanup=%v", err, cleanupErr)
				}
			}
			s.failPage(w, r, http.StatusConflict, "browser session ended before OAuth consent completed")
			return
		}
		http.Redirect(w, r, redirect, http.StatusFound)
		return
	}
	allowOIDCFormAction(w)
	s.render(w, "consent", s.view(r, "Authorize application", map[string]any{"Challenge": challenge, "Scopes": consent.Scopes}))
}

func (s *Server) hydraError(w http.ResponseWriter, r *http.Request) {
	code := strings.TrimSpace(r.URL.Query().Get("error"))
	message := "The authorization request could not be completed. Return to the connected application and try again."
	switch code {
	case "access_denied":
		message = "Authorization was not granted. You can return to the connected application and try again."
	case "invalid_client", "invalid_request", "invalid_scope", "unsupported_response_type", "unauthorized_client":
		message = "The connected application sent an invalid authorization request. Contact its administrator if the problem continues."
	case "server_error", "temporarily_unavailable":
		message = "The authorization service is temporarily unavailable. Please try again shortly."
	}
	w.WriteHeader(http.StatusBadRequest)
	s.render(w, "oauth-error", s.view(r, "Authorization error", map[string]any{"Code": code, "Message": message}))
}
func (s *Server) hydraConsentAccept(w http.ResponseWriter, r *http.Request) {
	user, session, err := s.current(r)
	if err != nil {
		http.Redirect(w, r, "/login", 303)
		return
	}
	if err := r.ParseForm(); err != nil {
		s.failPage(w, r, http.StatusBadRequest, "invalid form")
		return
	}
	challenge := r.Form.Get("challenge")
	consent, err := s.hydraConsentRequest(r.Context(), challenge)
	if err != nil {
		s.failPage(w, r, http.StatusBadGateway, "could not load OAuth consent request")
		return
	}
	redirect, err := s.acceptHydraConsent(r.Context(), challenge, r.Form["scope"], user)
	if err != nil {
		s.failPage(w, r, http.StatusBadGateway, "could not complete OAuth consent")
		return
	}
	if err := s.store.RevalidateSession(r.Context(), user.ID, session.ID, time.Now()); err != nil {
		if consent.LoginSessionID != "" {
			if cleanupErr := s.revokeHydraLoginSession(r.Context(), consent.LoginSessionID); cleanupErr != nil {
				observe.Errorf("delete accepted explicit Ory Hydra consent after browser logout: revalidate=%v cleanup=%v", err, cleanupErr)
			}
		}
		s.failPage(w, r, http.StatusConflict, "browser session ended before OAuth consent completed")
		return
	}
	http.Redirect(w, r, redirect, 302)
}

func (s *Server) acceptHydraConsent(ctx context.Context, challenge string, scopes []string, user identity.User) (string, error) {
	policy, err := s.store.SessionPolicy(ctx)
	if err != nil {
		return "", err
	}
	claims := oidcIdentityClaims(user)
	return s.hydraAccept(ctx, "/admin/oauth2/auth/requests/consent/accept", challenge, map[string]any{"grant_scope": scopes, "remember": true, "remember_for": int64(policy.OIDCSessionLifetime / time.Second), "session": map[string]any{"id_token": claims, "access_token": claims}})
}

func oidcIdentityClaims(user identity.User) map[string]any {
	return map[string]any{"sub": user.ID, "email": user.Email, "email_verified": user.EmailVerified, "preferred_username": user.Username, "role": user.Role}
}

type hydraLogoutRequest struct {
	SessionID   string `json:"sid"`
	Subject     string `json:"subject"`
	RPInitiated bool   `json:"rp_initiated"`
	Client      struct {
		ID string `json:"client_id"`
	} `json:"client"`
}

// hydraLogout obtains the trusted subject for an OIDC logout challenge. The
// challenge comes from Hydra; it is never accepted as a user identifier.
func (s *Server) hydraLogout(w http.ResponseWriter, r *http.Request) {
	challenge := r.URL.Query().Get("logout_challenge")
	request, err := s.hydraLogoutRequest(r.Context(), challenge)
	if err != nil {
		observe.Errorf("load Ory Hydra logout request: %v", err)
		s.failPage(w, r, http.StatusBadGateway, "could not load OAuth logout request")
		return
	}
	correlationCookie, err := r.Cookie(logoutCorrelationCookie)
	if err != nil {
		if !request.RPInitiated {
			if rejectErr := s.hydraRejectLogout(r.Context(), challenge); rejectErr != nil {
				s.failPage(w, r, http.StatusBadGateway, "could not reject unconfirmed OAuth logout")
				return
			}
			s.failPage(w, r, http.StatusBadRequest, "logout confirmation is required")
			return
		}
		s.hydraLogoutWithoutBrowserCookie(w, r, request, challenge)
		return
	}
	grant, err := s.store.ConsumeLogoutCorrelationGrant(r.Context(), correlationCookie.Value, request.Subject, time.Now())
	s.expireCookieAtPath(w, logoutCorrelationCookie, logoutCorrelationPath)
	if err != nil {
		s.failPage(w, r, http.StatusBadRequest, "OAuth logout request cannot be correlated with this browser")
		return
	}
	preservedHydraSessions, err := preservedPublicLogoutSessions(request.SessionID, grant.BrowserHydraSessionIDs)
	if err != nil {
		s.scheduleLogoutRecovery(r.Context(), grant, err)
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	s.completeLogout(w, r, grant, preservedHydraSessions, challenge, correlationCookie.Value)
}

func (s *Server) hydraLogoutWithoutBrowserCookie(w http.ResponseWriter, r *http.Request, request hydraLogoutRequest, challenge string) {
	if request.SessionID == "" {
		s.failPage(w, r, http.StatusBadRequest, "relying-party logout has no provider session")
		return
	}
	if request.Client.ID == "" {
		if rejectErr := s.hydraRejectLogout(r.Context(), challenge); rejectErr != nil {
			s.failPage(w, r, http.StatusBadGateway, "could not reject uncorrelated OAuth logout")
			return
		}
		s.failPage(w, r, http.StatusBadRequest, "relying-party logout has no managed client")
		return
	}
	raw, createdGrant, err := s.store.CreateLogoutCorrelationGrant(r.Context(), request.Subject, "", request.SessionID, request.Client.ID, time.Now())
	if err != nil {
		observe.Errorf("reject uncorrelated provider logout without local session mutation: %v", err)
		if rejectErr := s.hydraRejectLogout(r.Context(), challenge); rejectErr != nil {
			s.failPage(w, r, http.StatusBadGateway, "could not reject uncorrelated OAuth logout")
			return
		}
		s.failPage(w, r, http.StatusBadRequest, "OAuth logout could not be correlated with an exact provider session")
		return
	}
	preservedHydraSessions, err := preservedPublicLogoutSessions(request.SessionID, createdGrant.BrowserHydraSessionIDs)
	if err != nil {
		s.scheduleLogoutRecovery(r.Context(), createdGrant, err)
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	grant, err := s.store.ConsumeLogoutCorrelationGrant(r.Context(), raw, request.Subject, time.Now())
	if err != nil {
		s.failPage(w, r, http.StatusInternalServerError, "could not consume connected application logout")
		return
	}
	if grant.ID != createdGrant.ID {
		s.scheduleLogoutRecovery(r.Context(), grant, fmt.Errorf("logout correlation identifier changed during consumption"))
		s.failPage(w, r, http.StatusInternalServerError, "could not correlate connected application logout")
		return
	}
	s.completeLogout(w, r, grant, preservedHydraSessions, challenge, raw)
}

func preservedPublicLogoutSessions(providerSessionID string, browserSessionIDs []string) ([]string, error) {
	if providerSessionID != "" {
		for _, browserSessionID := range browserSessionIDs {
			if providerSessionID == browserSessionID {
				return []string{providerSessionID}, nil
			}
		}
		return nil, fmt.Errorf("OAuth logout request does not match this browser's connected application session")
	}
	if len(browserSessionIDs) == 0 {
		return nil, fmt.Errorf("OAuth logout request cannot be correlated with a connected application session")
	}
	return append([]string(nil), browserSessionIDs...), nil
}

// completeLogout ends every provider login session except those being
// completed through Hydra's public logout flow. The local Shauth sessions were
// already revoked before the browser left POST /logout.
func (s *Server) completeLogout(w http.ResponseWriter, r *http.Request, grant identity.LogoutCorrelationGrant, preservedHydraSessions []string, challenge, completionToken string) {
	if err := s.revokeOtherHydraSessions(r.Context(), grant.ActiveHydraSessionIDs, preservedHydraSessions...); err != nil {
		observe.Errorf("revoke remote Ory Hydra sessions during public logout: %v", err)
		s.scheduleLogoutRecovery(r.Context(), grant, err)
		s.failPage(w, r, http.StatusBadGateway, "local sessions ended but connected application logout did not complete")
		return
	}
	redirect, err := s.hydraAcceptLogout(r.Context(), challenge)
	if err != nil {
		observe.Errorf("accept Ory Hydra logout request after revoking local session: %v", err)
		s.scheduleLogoutRecovery(r.Context(), grant, err)
		s.failPage(w, r, http.StatusBadGateway, "could not complete OAuth logout")
		return
	}
	s.setCookie(w, &http.Cookie{Name: logoutCompletionCookie, Value: completionToken, Path: logoutCompletionPath, HttpOnly: true, Secure: !s.config.AllowInsecureCookies, SameSite: http.SameSiteLaxMode, Expires: time.Now().Add(identity.LogoutCompletionLifetime), MaxAge: int(identity.LogoutCompletionLifetime / time.Second)})
	http.Redirect(w, r, redirect, http.StatusSeeOther)
}

func (s *Server) finalizeProviderLogout(ctx context.Context, grant identity.LogoutCorrelationGrant) error {
	if err := s.revokeOtherHydraSessions(ctx, grant.ActiveHydraSessionIDs); err != nil {
		return err
	}
	if err := s.store.CompleteLogoutCorrelationGrant(ctx, grant.ID, time.Now()); err != nil {
		return err
	}
	s.record(ctx, logoutActor(grant), identity.AuditLogoutCompleted, grant.SubjectID, map[string]any{
		"grant_id": grant.ID, "provider_sessions": len(grant.ActiveHydraSessionIDs), "attempts": grant.CleanupAttempts,
	})
	return nil
}

func (s *Server) scheduleLogoutRecovery(ctx context.Context, grant identity.LogoutCorrelationGrant, cause error) {
	retryAt := time.Now().Add(logoutRecoveryDelay(grant.CleanupAttempts + 1))
	if err := s.store.FailLogoutCorrelationGrant(ctx, grant.ID, cause.Error(), retryAt); err != nil {
		observe.Errorf("schedule abandoned Ory Hydra logout recovery: %v", err)
	}
	// A logout that does not complete leaves relying-party sessions alive,
	// which is the failure this product exists to prevent. It belongs in the
	// durable record, not only in a log line.
	s.record(ctx, logoutActor(grant), identity.AuditLogoutFailed, grant.SubjectID, map[string]any{
		"grant_id": grant.ID, "attempt": grant.CleanupAttempts + 1, "retry_at": retryAt.UTC(), "error": cause.Error(),
	})
}

// logoutActor names the person whose sessions a logout is ending. A logout
// finished by the background recovery loop has no request behind it, so it
// records no address rather than a misleading one.
func logoutActor(grant identity.LogoutCorrelationGrant) actor {
	return actor{UserID: grant.SubjectID, SessionID: grant.BrowserSessionID}
}

func logoutRecoveryDelay(attempt int) time.Duration {
	if attempt < 1 {
		attempt = 1
	}
	if attempt > 6 {
		attempt = 6
	}
	return time.Duration(1<<(attempt-1)) * 5 * time.Second
}

// RecoverAbandonedLogout leases at most one durable logout record. It is safe
// for every Shauth replica to call: PostgreSQL serializes claims and failed
// provider calls retain their evidence for a later bounded retry.
func (s *Server) RecoverAbandonedLogout(ctx context.Context, now time.Time) error {
	grant, err := s.store.ClaimAbandonedLogoutCorrelationGrant(ctx, now)
	if err != nil || grant == nil {
		return err
	}
	if err := s.store.RevokeSessions(ctx, grant.ActiveBrowserSessionIDs, now); err != nil {
		s.scheduleLogoutRecovery(ctx, *grant, err)
		return fmt.Errorf("revoke abandoned logout's Shauth sessions: %w", err)
	}
	if err := s.finalizeProviderLogout(ctx, *grant); err != nil {
		s.scheduleLogoutRecovery(ctx, *grant, err)
		return fmt.Errorf("finish abandoned provider logout: %w", err)
	}
	return nil
}

func (s *Server) revokeOtherHydraSessions(ctx context.Context, sessionIDs []string, excludedSessionIDs ...string) error {
	excluded := make(map[string]struct{}, len(excludedSessionIDs))
	for _, sessionID := range excludedSessionIDs {
		if sessionID != "" {
			excluded[sessionID] = struct{}{}
		}
	}
	var targets []string
	for _, sessionID := range sessionIDs {
		if _, preservePublicFlow := excluded[sessionID]; preservePublicFlow {
			continue
		}
		targets = append(targets, sessionID)
	}
	if len(targets) == 0 {
		return nil
	}
	revocationContext, cancel := context.WithCancel(ctx)
	defer cancel()
	limit := min(4, len(targets))
	jobs := make(chan string)
	var workers sync.WaitGroup
	var firstError error
	var errorOnce sync.Once
	for range limit {
		workers.Add(1)
		go func() {
			defer workers.Done()
			for sessionID := range jobs {
				if err := s.revokeHydraLoginSession(revocationContext, sessionID); err != nil {
					errorOnce.Do(func() {
						firstError = err
						cancel()
					})
					return
				}
			}
		}()
	}
sendSessions:
	for _, sessionID := range targets {
		select {
		case jobs <- sessionID:
		case <-revocationContext.Done():
			break sendSessions
		}
	}
	close(jobs)
	workers.Wait()
	return firstError
}
func (s *Server) admin(w http.ResponseWriter, r *http.Request) {
	if !s.requireAdmin(w, r) {
		return
	}
	s.render(w, "admin", s.view(r, "Administration", map[string]any{"SignedIn": true, "IsAdmin": true}))
}

func (s *Server) adminConnectors(w http.ResponseWriter, r *http.Request) {
	if !s.requireAdmin(w, r) {
		return
	}
	s.render(w, "connectors", s.view(r, "Connectors", map[string]any{
		"SignedIn": true, "IsAdmin": true, "Connectors": s.connectors(),
	}))
}

type managedAppView struct {
	identity.ManagedApp
	// CSRF lets the re-validation control render inside a component that is
	// also served standalone as an HTMX fragment, where the page root is
	// not in scope.
	CSRF                   string
	DisplayReleaseRevision string
	Healthy                bool
	StatusCode             int
	StatusError            string
	FromShauth             *appValidationRunView
	FromApp                *appValidationRunView
	NeedsPoll              bool
	// MonitoringPageURL is browser navigation granted to the current viewer.
	// MonitoringURL remains the credential-protected machine endpoint that
	// Shauth reads server-side and must never become a catalog link.
	MonitoringPageURL string
}

type appValidationRunView struct {
	identity.AppValidationRun
	DisplayReleaseRevision string
}

func newManagedAppView(app identity.ManagedApp) managedAppView {
	return managedAppView{
		ManagedApp:             app,
		DisplayReleaseRevision: shortReleaseRevision(app.ReleaseRevision),
	}
}

func newAppValidationRunView(run identity.AppValidationRun) *appValidationRunView {
	return &appValidationRunView{
		AppValidationRun:       run,
		DisplayReleaseRevision: shortReleaseRevision(run.ReleaseRevision),
	}
}

func shortReleaseRevision(revision string) string {
	const displayLength = 12
	revision = strings.TrimPrefix(revision, "sha256:")
	if len(revision) <= displayLength {
		return revision
	}
	return revision[:displayLength]
}

func (s *Server) appViews(ctx context.Context) ([]managedAppView, error) {
	apps, err := s.store.ListManagedApps(ctx)
	if err != nil {
		return nil, err
	}
	validations, err := s.store.LatestAppValidationRuns(ctx)
	if err != nil {
		return nil, err
	}
	views := make([]managedAppView, 0, len(apps))
	for _, app := range apps {
		view := newManagedAppView(app)
		if status, err := s.managedApps.Status(ctx, app); err != nil {
			view.StatusError = err.Error()
		} else {
			view.Healthy, view.StatusCode = status.Healthy, status.StatusCode
		}
		if appResults := validations[app.ID]; appResults != nil {
			if run, ok := appResults[identity.ValidationFromShauth]; ok {
				view.FromShauth = newAppValidationRunView(run)
			}
			if run, ok := appResults[identity.ValidationFromApp]; ok {
				view.FromApp = newAppValidationRunView(run)
			}
		}
		view.NeedsPoll = validationNeedsPoll(view.FromShauth) || validationNeedsPoll(view.FromApp)
		views = append(views, view)
	}
	return views, nil
}

func validationNeedsPoll(run *appValidationRunView) bool {
	return run == nil || run.Status == identity.ValidationQueued || run.Status == identity.ValidationRunning
}

func setMonitoringPageURLs(apps []managedAppView, role identity.Role) {
	if role != identity.RoleAdmin {
		return
	}
	for index := range apps {
		if strings.TrimSpace(apps[index].MonitoringURL) != "" {
			apps[index].MonitoringPageURL = "/monitoring"
		}
	}
}

func (s *Server) apps(w http.ResponseWriter, r *http.Request) {
	user, _, err := s.current(r)
	if err != nil {
		http.Redirect(w, r, "/login?next=/apps", http.StatusSeeOther)
		return
	}
	apps, err := s.appViews(r.Context())
	if err != nil {
		observe.Errorf("list applications: %v", err)
		s.failPage(w, r, http.StatusInternalServerError, "The application catalog could not be loaded.")
		return
	}
	token := csrfToken(r)
	for index := range apps {
		apps[index].CSRF = token
	}
	setMonitoringPageURLs(apps, user.Role)
	s.render(w, "apps", s.view(r, "Apps", map[string]any{"SignedIn": true, "User": newUserRecord(user), "Apps": apps, "IsAdmin": user.Role == identity.RoleAdmin}))
}

func (s *Server) appValidationStatus(w http.ResponseWriter, r *http.Request) {
	if _, _, err := s.current(r); err != nil {
		s.failPage(w, r, http.StatusUnauthorized, "sign-in required")
		return
	}
	app, err := s.store.ManagedApp(r.Context(), r.PathValue("id"))
	if err != nil {
		s.failPage(w, r, http.StatusNotFound, "application not found")
		return
	}
	validations, err := s.store.LatestAppValidationRunsForApp(r.Context(), app.ID)
	if err != nil {
		s.failPage(w, r, http.StatusInternalServerError, "could not query application validation")
		return
	}
	view := newManagedAppView(app)
	if run, ok := validations[identity.ValidationFromShauth]; ok {
		view.FromShauth = newAppValidationRunView(run)
	}
	if run, ok := validations[identity.ValidationFromApp]; ok {
		view.FromApp = newAppValidationRunView(run)
	}
	view.NeedsPoll = validationNeedsPoll(view.FromShauth) || validationNeedsPoll(view.FromApp)
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := s.templates.ExecuteTemplate(w, "app-validation-results", view); err != nil {
		observe.Errorf("render application validation status: %v", err)
	}
}

func (s *Server) adminApps(w http.ResponseWriter, r *http.Request) {
	if !s.requireAdmin(w, r) {
		return
	}
	s.renderAdminApps(w, r, http.StatusOK, r.URL.Query().Get("error"), identity.ManagedApp{})
}

func (s *Server) renderAdminApps(w http.ResponseWriter, r *http.Request, status int, message string, form identity.ManagedApp) {
	apps, err := s.appViews(r.Context())
	if err != nil {
		observe.Errorf("list applications: %v", err)
		s.failPage(w, r, http.StatusInternalServerError, "The application catalog could not be loaded.")
		return
	}
	token := csrfToken(r)
	for index := range apps {
		apps[index].CSRF = token
	}
	if status != http.StatusOK {
		w.WriteHeader(status)
	}
	s.render(w, "admin-apps", s.view(r, "Applications", map[string]any{
		"SignedIn": true, "IsAdmin": true, "Apps": apps,
		"Error": message, "Done": r.URL.Query().Get("done"), "Form": form,
	}))
}

func (s *Server) adminCreateApp(w http.ResponseWriter, r *http.Request) {
	if !s.requireAdmin(w, r) {
		return
	}
	if err := r.ParseForm(); err != nil {
		s.failPage(w, r, http.StatusBadRequest, "invalid form")
		return
	}
	app := identity.ManagedApp{
		Slug:            strings.TrimSpace(r.Form.Get("slug")),
		Name:            strings.TrimSpace(r.Form.Get("name")),
		Description:     strings.TrimSpace(r.Form.Get("description")),
		LaunchURL:       strings.TrimSpace(r.Form.Get("launch_url")),
		OIDCClientID:    strings.TrimSpace(r.Form.Get("oidc_client_id")),
		HealthURL:       strings.TrimSpace(r.Form.Get("health_url")),
		MonitoringURL:   strings.TrimSpace(r.Form.Get("monitoring_url")),
		ValidationURL:   strings.TrimSpace(r.Form.Get("validation_url")),
		SignedOutURL:    strings.TrimSpace(r.Form.Get("signed_out_url")),
		ReleaseRevision: strings.TrimSpace(r.Form.Get("release_revision")),
	}
	created, err := s.createApp(r.Context(), app, s.currentActor(r))
	if err != nil {
		status, message := describeOperationFailure("create managed app", err)
		s.renderAdminApps(w, r, status, message, app)
		return
	}
	http.Redirect(w, r, "/admin/apps?done="+url.QueryEscape("Registered the application "+created.Name+"."), http.StatusSeeOther)
}

func (s *Server) validateApp(w http.ResponseWriter, r *http.Request) {
	user, _, err := s.current(r)
	if err != nil {
		s.failPage(w, r, http.StatusUnauthorized, "sign-in required")
		return
	}
	if _, err := s.enqueueAppValidations(r.Context(), identity.ManagedAppRef{ID: r.PathValue("id")}, s.currentActor(r)); err != nil {
		s.failOperation(w, r, "queue application validation", "/apps", err)
		return
	}
	destination := "/apps#validation-" + url.PathEscape(r.PathValue("id"))
	if user.Role == identity.RoleAdmin && strings.HasPrefix(r.Referer(), s.config.PublicURL.ResolveReference(&url.URL{Path: "/admin/apps"}).String()) {
		destination = "/admin/apps#validation-" + url.PathEscape(r.PathValue("id"))
	}
	http.Redirect(w, r, destination, http.StatusSeeOther)
}

type validatorResult struct {
	Status  string `json:"status"`
	Failure string `json:"failure"`
}

type validatorBootstrapRequest struct {
	RunID string   `json:"run_id"`
	Next  []string `json:"next"`
}

type validatorBootstrapResponse struct {
	URLs []string `json:"urls"`
}

func (s *Server) requireValidator(w http.ResponseWriter, r *http.Request) bool {
	if s.config.ValidatorToken == "" {
		writeAdminAPIError(w, http.StatusServiceUnavailable, "application validator is not configured")
		return false
	}
	if !bearerTokenMatches(r, s.config.ValidatorToken) {
		unauthorized(w, "validator authentication failed")
		return false
	}
	return true
}

func bearerTokenMatches(r *http.Request, expected string) bool {
	values := r.Header.Values("Authorization")
	if len(values) != 1 || len(values[0]) < 7 || !strings.EqualFold(values[0][:7], "bearer ") {
		return false
	}
	provided := values[0][7:]
	return len(provided) == len(expected) && subtle.ConstantTimeCompare([]byte(provided), []byte(expected)) == 1
}

// unauthorized answers a missing or wrong credential with the challenge RFC
// 7235 requires, so a standard client can discover the scheme.
func unauthorized(w http.ResponseWriter, message string) {
	w.Header().Set("WWW-Authenticate", "Bearer")
	writeAdminAPIError(w, http.StatusUnauthorized, message)
}

// requireValidationStatusToken authorizes the closed machine-readable
// application API. It is a read-only credential: queuing validations is a
// state change and requires the administration write credential, so a
// dashboard or post-deployment poller given read access cannot start real
// browser logins against every registered relying party.
// requireApplicationReadToken accepts either the application status
// credential or the administration read credential. Both are read-only, and
// an operator holding the administration read token should not be unable to
// list the applications.
func (s *Server) requireApplicationReadToken(w http.ResponseWriter, r *http.Request) bool {
	if s.config.AdminAPIReadToken != "" && bearerTokenMatches(r, s.config.AdminAPIReadToken) {
		return true
	}
	return s.requireValidationStatusToken(w, r)
}

func (s *Server) requireValidationStatusToken(w http.ResponseWriter, r *http.Request) bool {
	if s.config.ValidationStatusToken == "" {
		writeAdminAPIError(w, http.StatusServiceUnavailable, "application validation status is not configured")
		return false
	}
	if !bearerTokenMatches(r, s.config.ValidationStatusToken) {
		unauthorized(w, "validation status authentication failed")
		return false
	}
	return true
}

type validationStatusRecord struct {
	Slug                   string     `json:"slug"`
	ReleaseRevision        string     `json:"release_revision"`
	Direction              string     `json:"direction"`
	Status                 string     `json:"status"`
	RequestedAt            time.Time  `json:"requested_at"`
	ValidationContractHash string     `json:"validation_contract_hash"`
	StartedAt              *time.Time `json:"started_at,omitempty"`
	CompletedAt            *time.Time `json:"completed_at,omitempty"`
	DurationMS             *int64     `json:"duration_ms,omitempty"`
	Failure                string     `json:"failure,omitempty"`
	Witness                string     `json:"witness,omitempty"`
}

func newValidationStatusRecord(run identity.AppValidationRun) validationStatusRecord {
	record := validationStatusRecord{
		Slug: run.AppSlug, ReleaseRevision: run.ReleaseRevision, Direction: run.Direction,
		Status: run.Status, RequestedAt: run.RequestedAt, ValidationContractHash: run.ValidationContractHash,
		StartedAt: run.StartedAt, CompletedAt: run.CompletedAt, Failure: run.Failure,
	}
	if run.Status == identity.ValidationPassed || run.Status == identity.ValidationFailed {
		record.DurationMS = run.DurationMilliseconds
	}
	if run.Witness != nil {
		record.Witness = run.Witness.AppSlug
	}
	return record
}

func (s *Server) applicationValidationStatusAPI(w http.ResponseWriter, r *http.Request) {
	noStore(w)
	if !s.requireApplicationReadToken(w, r) {
		return
	}
	runs, err := s.store.LatestAppValidationRuns(r.Context())
	if err != nil {
		observe.Errorf("list application validation status: %v", err)
		writeAdminAPIError(w, http.StatusInternalServerError, "could not list application validation status")
		return
	}
	records := make([]validationStatusRecord, 0, len(runs)*2)
	for _, directions := range runs {
		for _, run := range directions {
			records = append(records, newValidationStatusRecord(run))
		}
	}
	sort.Slice(records, func(i, j int) bool {
		if records[i].Slug == records[j].Slug {
			return records[i].Direction < records[j].Direction
		}
		return records[i].Slug < records[j].Slug
	})
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"schema_version": "shauth.app-validations/v1",
		"observed_at":    time.Now().UTC(),
		"validations":    records,
	})
}

type appHealthRecord struct {
	Healthy    bool   `json:"healthy"`
	StatusCode int    `json:"status_code,omitempty"`
	Error      string `json:"error,omitempty"`
}

type appValidationsRecord struct {
	FromShauth *validationStatusRecord `json:"from_shauth"`
	FromApp    *validationStatusRecord `json:"from_app"`
}

type appRecord struct {
	Slug            string               `json:"slug"`
	Name            string               `json:"name"`
	Description     string               `json:"description,omitempty"`
	ReleaseRevision string               `json:"release_revision"`
	LaunchURL       string               `json:"launch_url"`
	HealthURL       string               `json:"health_url,omitempty"`
	MonitoringURL   string               `json:"monitoring_url,omitempty"`
	ValidationURL   string               `json:"validation_url"`
	SignedOutURL    string               `json:"signed_out_url"`
	OIDCClientID    string               `json:"oidc_client_id"`
	CreatedAt       time.Time            `json:"created_at"`
	Health          appHealthRecord      `json:"health"`
	Validations     appValidationsRecord `json:"validations"`
}

func newAppRecord(view managedAppView) appRecord {
	record := appRecord{
		Slug: view.Slug, Name: view.Name, Description: view.Description,
		ReleaseRevision: view.ReleaseRevision, LaunchURL: view.LaunchURL,
		HealthURL: view.HealthURL, MonitoringURL: view.MonitoringURL,
		ValidationURL: view.ValidationURL, SignedOutURL: view.SignedOutURL,
		OIDCClientID: view.OIDCClientID, CreatedAt: view.CreatedAt,
		Health: appHealthRecord{Healthy: view.Healthy, StatusCode: view.StatusCode, Error: view.StatusError},
	}
	if view.FromShauth != nil {
		fromShauth := newValidationStatusRecord(view.FromShauth.AppValidationRun)
		record.Validations.FromShauth = &fromShauth
	}
	if view.FromApp != nil {
		fromApp := newValidationStatusRecord(view.FromApp.AppValidationRun)
		record.Validations.FromApp = &fromApp
	}
	return record
}

func (s *Server) applicationsAPI(w http.ResponseWriter, r *http.Request) {
	noStore(w)
	if !s.requireApplicationReadToken(w, r) {
		return
	}
	views, err := s.appViews(r.Context())
	if err != nil {
		observe.Errorf("list applications: %v", err)
		writeAdminAPIError(w, http.StatusInternalServerError, "could not list applications")
		return
	}
	records := make([]appRecord, 0, len(views))
	for _, view := range views {
		records = append(records, newAppRecord(view))
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"schema_version": "shauth.apps/v1",
		"observed_at":    time.Now().UTC(),
		"apps":           records,
	})
}

func parseValidationHistoryLimit(raw string) (int, error) {
	if raw == "" {
		return 50, nil
	}
	limit, err := strconv.Atoi(raw)
	if err != nil || limit < 1 || limit > 500 {
		return 0, fmt.Errorf("limit must be a whole number between 1 and 500")
	}
	return limit, nil
}

func (s *Server) applicationValidationHistoryAPI(w http.ResponseWriter, r *http.Request) {
	noStore(w)
	if !s.requireApplicationReadToken(w, r) {
		return
	}
	limit, err := parseValidationHistoryLimit(r.URL.Query().Get("limit"))
	if err != nil {
		writeAdminAPIError(w, http.StatusBadRequest, err.Error())
		return
	}
	runs, err := s.store.AppValidationRunHistory(r.Context(), strings.TrimSpace(r.URL.Query().Get("slug")), limit)
	if err != nil {
		observe.Errorf("list application validation history: %v", err)
		writeAdminAPIError(w, http.StatusInternalServerError, "could not list application validation history")
		return
	}
	records := make([]validationStatusRecord, 0, len(runs))
	for _, run := range runs {
		records = append(records, newValidationStatusRecord(run))
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"schema_version": "shauth.app-validation-history/v1",
		"observed_at":    time.Now().UTC(),
		"runs":           records,
	})
}

// validationEnqueueRequest selects the app to re-validate. An absent slug
// queues every registered app; a present but empty slug is a caller mistake
// -- typically an unset variable in a deployment script -- and is rejected
// rather than silently starting a real browser check against every relying
// party.
type validationEnqueueRequest struct {
	Slug *string `json:"slug"`
}

func (request validationEnqueueRequest) ref() (identity.ManagedAppRef, error) {
	if request.Slug == nil {
		return identity.ManagedAppRef{}, nil
	}
	slug := strings.TrimSpace(*request.Slug)
	if slug == "" {
		return identity.ManagedAppRef{}, identity.Invalid("slug must name an application, or be omitted to queue every application")
	}
	return identity.ManagedAppRef{Slug: slug}, nil
}

type validationEnqueueRecord struct {
	Slug      string `json:"slug"`
	Direction string `json:"direction"`
}

func decodeValidationEnqueueRequest(reader io.Reader) (validationEnqueueRequest, error) {
	body, err := io.ReadAll(reader)
	if err != nil {
		return validationEnqueueRequest{}, err
	}
	var request validationEnqueueRequest
	if len(bytes.TrimSpace(body)) == 0 {
		return request, nil
	}
	if err := decodeSingleJSONBody(bytes.NewReader(body), &request); err != nil {
		return validationEnqueueRequest{}, err
	}
	return request, nil
}

// applicationValidationEnqueueAPI is the token-authorized twin of the Apps
// page's "Run both checks again" button. An empty or {} body queues both
// browser checks for every app; {"slug":"<slug>"} queues one app. It queues
// real browser sessions and global logouts, so it requires the administration
// write credential rather than the read-only application status credential.
func (s *Server) applicationValidationEnqueueAPI(w http.ResponseWriter, r *http.Request) {
	noStore(w)
	if !s.requireAdminAPIWriteToken(w, r) {
		return
	}
	request, err := decodeValidationEnqueueRequest(http.MaxBytesReader(w, r.Body, 4*1024))
	if err != nil {
		writeAdminAPIError(w, http.StatusBadRequest, "invalid validation enqueue request")
		return
	}
	ref, err := request.ref()
	if err != nil {
		writeOperationFailure(w, "queue application validations", err)
		return
	}
	enqueued, err := s.enqueueAppValidations(r.Context(), ref, tokenActor(r))
	if err != nil {
		writeOperationFailure(w, "queue application validations", err)
		return
	}
	writeAdminAPIJSON(w, http.StatusAccepted, map[string]any{
		"schema_version": "shauth.app-validation-enqueue/v1",
		"observed_at":    time.Now().UTC(),
		"enqueued":       enqueued,
	})
}

func (s *Server) validatorClaim(w http.ResponseWriter, r *http.Request) {
	if !s.requireValidator(w, r) {
		return
	}
	run, err := s.store.ClaimAppValidation(r.Context(), time.Now())
	if err != nil {
		observe.Errorf("claim application validation: %v", err)
		writeAdminAPIError(w, http.StatusInternalServerError, "could not claim application validation")
		return
	}
	if run == nil {
		w.WriteHeader(http.StatusNoContent)
		return
	}
	logoutBridgeURL, err := managedAppLogoutBridgeURL(run.LaunchURL)
	if err != nil {
		writeAdminAPIError(w, http.StatusInternalServerError, "application validation logout bridge is invalid")
		return
	}
	run.LogoutBridgeURL = logoutBridgeURL
	if run.Witness != nil {
		witnessLogoutBridgeURL, err := managedAppLogoutBridgeURL(run.Witness.LaunchURL)
		if err != nil {
			writeAdminAPIError(w, http.StatusInternalServerError, "application validation witness logout bridge is invalid")
			return
		}
		run.Witness.LogoutBridgeURL = witnessLogoutBridgeURL
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"id": run.ID, "managed_app_id": run.ManagedAppID, "app_slug": run.AppSlug, "app_name": run.AppName,
		"oidc_client_id": run.OIDCClientID, "launch_url": run.LaunchURL, "direction": run.Direction,
		"validation_url": run.ValidationURL, "signed_out_url": run.SignedOutURL, "logout_bridge_url": run.LogoutBridgeURL,
		"release_revision": run.ReleaseRevision, "shauth_url": s.config.PublicURL.String(), "witness": run.Witness,
		"validation_username": run.ValidationUsername, "validation_email": run.ValidationEmail,
	})
}

func (s *Server) validatorCreateBrowserBootstraps(w http.ResponseWriter, r *http.Request) {
	noStore(w)
	if !s.requireValidator(w, r) {
		return
	}
	var request validatorBootstrapRequest
	if err := decodeSingleJSONBody(http.MaxBytesReader(w, r.Body, 4*1024), &request); err != nil || strings.TrimSpace(request.RunID) == "" || len(request.Next) == 0 || len(request.Next) > 3 {
		writeAdminAPIError(w, http.StatusBadRequest, "invalid browser bootstrap request")
		return
	}
	for _, next := range request.Next {
		if !strictRelativeNext(next) {
			writeAdminAPIError(w, http.StatusBadRequest, "invalid browser bootstrap destination")
			return
		}
	}
	tokens, err := s.store.CreateValidationBrowserBootstraps(r.Context(), request.RunID, request.Next, time.Now())
	if err != nil {
		writeAdminAPIError(w, http.StatusInternalServerError, "could not create browser bootstraps")
		return
	}
	urls := make([]string, 0, len(tokens))
	for _, token := range tokens {
		coordinate := *s.config.PublicURL
		coordinate.Path = "/validator/bootstrap"
		coordinate.RawPath = ""
		coordinate.RawQuery = ""
		coordinate.Fragment = token
		urls = append(urls, coordinate.String())
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(validatorBootstrapResponse{URLs: urls})
}

func (s *Server) validatorBootstrapPage(w http.ResponseWriter, r *http.Request) {
	noStore(w)
	s.render(w, "validator-bootstrap", s.view(r, "Validation session", map[string]any{"SignedIn": false}))
}

func (s *Server) validatorBootstrapConsume(w http.ResponseWriter, r *http.Request) {
	noStore(w)
	if err := r.ParseForm(); err != nil {
		s.failPage(w, r, http.StatusGone, "validation browser bootstrap is unavailable")
		return
	}
	if len(r.Form) != 2 || len(r.Form["_csrf"]) != 1 || len(r.Form["token"]) != 1 {
		s.failPage(w, r, http.StatusGone, "validation browser bootstrap is unavailable")
		return
	}
	user, next, err := s.store.ConsumeValidationBrowserBootstrap(r.Context(), r.Form.Get("token"), time.Now())
	if err != nil {
		s.failPage(w, r, http.StatusGone, "validation browser bootstrap is unavailable")
		return
	}
	if !strictRelativeNext(next) {
		s.failPage(w, r, http.StatusGone, "validation browser bootstrap is unavailable")
		return
	}
	if !s.startSession(w, r, user) {
		return
	}
	http.Redirect(w, r, next, http.StatusSeeOther)
}

func (s *Server) validatorComplete(w http.ResponseWriter, r *http.Request) {
	if !s.requireValidator(w, r) {
		return
	}
	var result validatorResult
	if err := decodeValidatorResult(http.MaxBytesReader(w, r.Body, 16*1024), &result); err != nil {
		writeAdminAPIError(w, http.StatusBadRequest, "invalid validator result")
		return
	}
	if err := s.store.CompleteAppValidation(r.Context(), r.PathValue("id"), result.Status, result.Failure, time.Now()); err != nil {
		writeAdminAPIError(w, http.StatusBadRequest, "could not record application validation")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func decodeValidatorResult(reader io.Reader, result *validatorResult) error {
	return decodeSingleJSONBody(reader, result)
}

func decodeSingleJSONBody(reader io.Reader, target any) error {
	decoder := json.NewDecoder(reader)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return err
	}
	if err := decoder.Decode(&struct{}{}); err != io.EOF {
		if err == nil {
			return fmt.Errorf("trailing JSON value")
		}
		return fmt.Errorf("trailing JSON data: %w", err)
	}
	return nil
}

func (s *Server) adminDeleteApp(w http.ResponseWriter, r *http.Request) {
	if !s.requireAdmin(w, r) {
		return
	}
	if err := s.deleteApp(r.Context(), identity.ManagedAppRef{ID: r.PathValue("id")}, s.currentActor(r)); err != nil {
		s.failOperation(w, r, "delete managed app", "/admin/apps", err)
		return
	}
	http.Redirect(w, r, "/admin/apps?done="+url.QueryEscape("The application was removed."), http.StatusSeeOther)
}

func (s *Server) adminOIDCClients(w http.ResponseWriter, r *http.Request) {
	if !s.requireAdmin(w, r) {
		return
	}
	s.renderOIDCClients(w, r, http.StatusOK, r.URL.Query().Get("error"), oidcClientInput{})
}

func (s *Server) renderOIDCClients(w http.ResponseWriter, r *http.Request, status int, message string, form oidcClientInput) {
	clients, err := s.listOIDCClients(r.Context())
	if err != nil {
		failureStatus, failureMessage := describeOperationFailure("list OAuth clients", err)
		s.failPage(w, r, failureStatus, failureMessage)
		return
	}
	if status != http.StatusOK {
		w.WriteHeader(status)
	}
	s.render(w, "oidc-clients", s.view(r, "OAuth clients", map[string]any{
		"SignedIn": true, "IsAdmin": true, "Clients": clients,
		"Error": message, "Done": r.URL.Query().Get("done"), "Form": form,
	}))
}

func (s *Server) adminCreateOIDCClient(w http.ResponseWriter, r *http.Request) {
	if !s.requireAdmin(w, r) {
		return
	}
	if err := r.ParseForm(); err != nil {
		s.failPage(w, r, http.StatusBadRequest, "invalid form")
		return
	}
	input := oidcClientInput{
		ID:                    strings.TrimSpace(r.Form.Get("client_id")),
		Name:                  strings.TrimSpace(r.Form.Get("client_name")),
		Secret:                r.Form.Get("client_secret"),
		FrontChannelLogoutURI: strings.TrimSpace(r.Form.Get("frontchannel_logout_uri")),
		BackChannelLogoutURI:  strings.TrimSpace(r.Form.Get("backchannel_logout_uri")),
	}
	for _, rawURI := range strings.Split(r.Form.Get("redirect_uris"), "\n") {
		if uri := strings.TrimSpace(rawURI); uri != "" {
			input.RedirectURIs = append(input.RedirectURIs, uri)
		}
	}
	for _, rawURI := range strings.Split(r.Form.Get("post_logout_redirect_uris"), "\n") {
		if uri := strings.TrimSpace(rawURI); uri != "" {
			input.PostLogoutRedirectURIs = append(input.PostLogoutRedirectURIs, uri)
		}
	}
	if _, err := s.createOIDCClient(r.Context(), input, s.currentActor(r)); err != nil {
		status, message := describeOperationFailure("create OAuth client", err)
		s.renderOIDCClients(w, r, status, message, input)
		return
	}
	http.Redirect(w, r, "/admin/clients?done="+url.QueryEscape("Registered the OAuth client "+input.ID+"."), http.StatusSeeOther)
}

func (s *Server) adminDeleteOIDCClient(w http.ResponseWriter, r *http.Request) {
	if !s.requireAdmin(w, r) {
		return
	}
	clientID := r.PathValue("id")
	if err := s.deleteOIDCClient(r.Context(), clientID, s.currentActor(r)); err != nil {
		s.failOperation(w, r, "delete OAuth client", "/admin/clients", err)
		return
	}
	http.Redirect(w, r, "/admin/clients?done="+url.QueryEscape("Deleted the OAuth client "+clientID+"."), http.StatusSeeOther)
}

// errHydraClientNotFound reports that Ory Hydra has no client with the
// requested identifier.
var errHydraClientNotFound = errors.New("OAuth client not found")

func (s *Server) deleteHydraClient(ctx context.Context, clientID string) error {
	endpoint := s.config.HydraAdminURL.ResolveReference(&url.URL{Path: "/admin/clients/" + url.PathEscape(clientID)})
	request, err := http.NewRequestWithContext(ctx, http.MethodDelete, endpoint.String(), nil)
	if err != nil {
		return err
	}
	response, err := s.httpClient.Do(request)
	if err != nil {
		return err
	}
	defer response.Body.Close()
	if response.StatusCode == http.StatusNotFound {
		return errHydraClientNotFound
	}
	if response.StatusCode != http.StatusNoContent {
		return fmt.Errorf("Hydra delete client returned %s", response.Status)
	}
	return nil
}

func (s *Server) adminSessionPolicy(w http.ResponseWriter, r *http.Request) {
	if !s.requireAdmin(w, r) {
		return
	}
	policy, err := s.store.SessionPolicy(r.Context())
	if err != nil {
		observe.Errorf("read session policy: %v", err)
		s.failPage(w, r, http.StatusInternalServerError, "The session policy could not be loaded.")
		return
	}
	s.renderSessionPolicy(w, r, http.StatusOK, r.URL.Query().Get("error"), newSessionPolicyRecord(policy))
}

// renderSessionPolicy draws the policy form from a record, so a rejected
// submission shows what the operator typed rather than reverting to the
// stored policy and hiding their edit.
func (s *Server) renderSessionPolicy(w http.ResponseWriter, r *http.Request, status int, message string, policy sessionPolicyRecord) {
	if policy.UpdatedAt.IsZero() {
		// A rejected edit carries only what the operator typed, so read
		// the stored change time instead of dropping it from the page.
		if stored, err := s.store.SessionPolicy(r.Context()); err == nil {
			policy.UpdatedAt = stored.UpdatedAt
		}
	}
	if status != http.StatusOK {
		w.WriteHeader(status)
	}
	s.render(w, "session-policy", s.view(r, "Session limits", map[string]any{
		"SignedIn": true, "IsAdmin": true, "Policy": policy,
		"Error": message, "Saved": r.URL.Query().Get("saved") == "true",
	}))
}

func (s *Server) adminUpdateSessionPolicy(w http.ResponseWriter, r *http.Request) {
	if !s.requireAdmin(w, r) {
		return
	}
	if err := r.ParseForm(); err != nil {
		s.failPage(w, r, http.StatusBadRequest, "invalid form")
		return
	}
	request, err := parseSessionPolicyForm(r.Form)
	if err != nil {
		s.renderSessionPolicy(w, r, http.StatusBadRequest, err.Error(), request)
		return
	}
	if _, err := s.updateSessionPolicy(r.Context(), request, s.currentActor(r)); err != nil {
		status, message := describeOperationFailure("update session policy", err)
		s.renderSessionPolicy(w, r, status, message, request)
		return
	}
	http.Redirect(w, r, "/admin/session-policy?saved=true", http.StatusSeeOther)
}

// parseSessionPolicyForm converts the form into the same record the JSON
// transport decodes. Validation belongs to the shared operation, so both
// transports enforce one rule set.
func parseSessionPolicyForm(values url.Values) (sessionPolicyRecord, error) {
	var record sessionPolicyRecord
	// Ordered so a form with several unparseable fields always reports the
	// same one; map iteration would name a different field each submission.
	for _, field := range []struct {
		name   string
		target *int64
	}{
		{"browser_absolute_hours", &record.BrowserAbsoluteHours},
		{"browser_idle_minutes", &record.BrowserIdleMinutes},
		{"oidc_sso_hours", &record.OIDCSSOHours},
		{"access_token_minutes", &record.AccessTokenMinutes},
		{"id_token_minutes", &record.IDTokenMinutes},
		{"refresh_token_hours", &record.RefreshTokenHours},
	} {
		value, err := strconv.ParseInt(strings.TrimSpace(values.Get(field.name)), 10, 64)
		if err != nil {
			return record, fmt.Errorf("%s must be a positive whole number", strings.ReplaceAll(field.name, "_", " "))
		}
		*field.target = value
	}
	return record, nil
}

func hydraClientLifespans(policy identity.SessionPolicy) map[string]string {
	return map[string]string{
		"authorization_code_grant_access_token_lifespan":  policy.AccessTokenLifetime.String(),
		"authorization_code_grant_id_token_lifespan":      policy.IDTokenLifetime.String(),
		"authorization_code_grant_refresh_token_lifespan": policy.RefreshTokenLifetime.String(),
	}
}

func (s *Server) applyHydraSessionPolicy(ctx context.Context, policy identity.SessionPolicy) error {
	clients, err := listHydraClients[oidcClient](ctx, s.httpClient, s.config.HydraAdminURL)
	if err != nil {
		return err
	}
	body, err := json.Marshal(hydraClientLifespans(policy))
	if err != nil {
		return fmt.Errorf("encode Ory Hydra client lifespans: %w", err)
	}
	for _, client := range clients {
		if client.ID == "" {
			return fmt.Errorf("Hydra returned a client without an ID")
		}
		clientEndpoint := s.config.HydraAdminURL.ResolveReference(&url.URL{Path: "/admin/clients/" + url.PathEscape(client.ID) + "/lifespans"})
		update, err := http.NewRequestWithContext(ctx, http.MethodPut, clientEndpoint.String(), bytes.NewReader(body))
		if err != nil {
			return err
		}
		update.Header.Set("Content-Type", "application/json")
		updated, err := s.httpClient.Do(update)
		if err != nil {
			return err
		}
		updated.Body.Close()
		if updated.StatusCode != http.StatusOK {
			return fmt.Errorf("Hydra update client %q lifespans returned %s", client.ID, updated.Status)
		}
	}
	return nil
}

func (s *Server) hydraClients(ctx context.Context) ([]oidcClient, error) {
	return listHydraClients[oidcClient](ctx, s.httpClient, s.config.HydraAdminURL)
}

func listHydraClients[T any](ctx context.Context, client *http.Client, adminURL *url.URL) ([]T, error) {
	endpoint := adminURL.ResolveReference(&url.URL{Path: "/admin/clients"})
	pageToken := ""
	seenTokens := map[string]bool{}
	var clients []T
	for {
		query := endpoint.Query()
		query.Set("page_size", "1000")
		if pageToken != "" {
			query.Set("page_token", pageToken)
		}
		endpoint.RawQuery = query.Encode()
		request, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint.String(), nil)
		if err != nil {
			return nil, err
		}
		response, err := client.Do(request)
		if err != nil {
			return nil, err
		}
		if response.StatusCode != http.StatusOK {
			response.Body.Close()
			return nil, fmt.Errorf("Hydra list clients returned %s", response.Status)
		}
		var page []T
		decodeErr := json.NewDecoder(response.Body).Decode(&page)
		response.Body.Close()
		if decodeErr != nil {
			return nil, fmt.Errorf("decode Hydra clients: %w", decodeErr)
		}
		clients = append(clients, page...)
		pageToken, err = nextHydraPageToken(response.Header.Get("Link"))
		if err != nil {
			return nil, err
		}
		if pageToken == "" {
			return clients, nil
		}
		if seenTokens[pageToken] {
			return nil, fmt.Errorf("Hydra client pagination repeated page token")
		}
		seenTokens[pageToken] = true
	}
}

func nextHydraPageToken(linkHeader string) (string, error) {
	for _, link := range strings.Split(linkHeader, ",") {
		parts := strings.Split(link, ";")
		if len(parts) < 2 {
			continue
		}
		isNext := false
		for _, parameter := range parts[1:] {
			if strings.TrimSpace(parameter) == `rel="next"` || strings.TrimSpace(parameter) == "rel=next" {
				isNext = true
				break
			}
		}
		if !isNext {
			continue
		}
		rawURL := strings.TrimSpace(parts[0])
		if len(rawURL) < 2 || rawURL[0] != '<' || rawURL[len(rawURL)-1] != '>' {
			return "", fmt.Errorf("Hydra client pagination returned a malformed next link")
		}
		nextURL, err := url.Parse(rawURL[1 : len(rawURL)-1])
		if err != nil {
			return "", fmt.Errorf("parse Hydra client pagination link: %w", err)
		}
		token := nextURL.Query().Get("page_token")
		if token == "" {
			return "", fmt.Errorf("Hydra client pagination next link has no page token")
		}
		return token, nil
	}
	return "", nil
}

func (s *Server) createHydraClient(ctx context.Context, input oidcClientInput) error {
	policy, err := s.store.SessionPolicy(ctx)
	if err != nil {
		return err
	}
	body, err := marshalHydraClient(input, policy)
	if err != nil {
		return err
	}
	endpoint := s.config.HydraAdminURL.ResolveReference(&url.URL{Path: "/admin/clients"})
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint.String(), bytes.NewReader(body))
	if err != nil {
		return err
	}
	request.Header.Set("Content-Type", "application/json")
	response, err := s.httpClient.Do(request)
	if err != nil {
		return err
	}
	defer response.Body.Close()
	if response.StatusCode == http.StatusConflict {
		return errHydraClientConflict
	}
	if response.StatusCode != http.StatusCreated {
		return fmt.Errorf("Hydra create client returned %s", response.Status)
	}
	return nil
}

// errHydraClientConflict reports that Ory Hydra already has a client with the
// requested identifier.
var errHydraClientConflict = errors.New("OAuth client already exists")

func marshalHydraClient(input oidcClientInput, policy identity.SessionPolicy) ([]byte, error) {
	payload := map[string]any{
		"client_id":                            input.ID,
		"client_name":                          input.Name,
		"client_secret":                        input.Secret,
		"redirect_uris":                        input.RedirectURIs,
		"grant_types":                          []string{"authorization_code", "refresh_token"},
		"response_types":                       []string{"code"},
		"scope":                                "openid offline_access profile email",
		"token_endpoint_auth_method":           "client_secret_post",
		"frontchannel_logout_uri":              input.FrontChannelLogoutURI,
		"backchannel_logout_uri":               input.BackChannelLogoutURI,
		"frontchannel_logout_session_required": input.FrontChannelLogoutURI != "",
		"backchannel_logout_session_required":  true,
		"authorization_code_grant_access_token_lifespan":  policy.AccessTokenLifetime.String(),
		"authorization_code_grant_id_token_lifespan":      policy.IDTokenLifetime.String(),
		"authorization_code_grant_refresh_token_lifespan": policy.RefreshTokenLifetime.String(),
	}
	if input.Secret == "" {
		delete(payload, "client_secret")
	}
	if input.FrontChannelLogoutURI == "" {
		delete(payload, "frontchannel_logout_uri")
		delete(payload, "frontchannel_logout_session_required")
	}
	if input.BackChannelLogoutURI == "" {
		delete(payload, "backchannel_logout_uri")
		delete(payload, "backchannel_logout_session_required")
	}
	// Only send post_logout_redirect_uris when the client registers some, so
	// existing clients are unchanged. Hydra honours these as the allowlist
	// for RP-initiated logout's post_logout_redirect_uri.
	if len(input.PostLogoutRedirectURIs) > 0 {
		payload["post_logout_redirect_uris"] = input.PostLogoutRedirectURIs
	}
	return json.Marshal(payload)
}

func (s *Server) assertHydraClientReconciled(ctx context.Context, input oidcClientInput) error {
	clients, err := s.hydraClients(ctx)
	if err != nil {
		return err
	}
	for _, client := range clients {
		if client.ID != input.ID {
			continue
		}
		if client.Name != input.Name || !sameStringSet(client.RedirectURIs, input.RedirectURIs) || !sameStringSet(client.PostLogoutRedirectURIs, input.PostLogoutRedirectURIs) || client.FrontChannelLogoutURI != input.FrontChannelLogoutURI || client.BackChannelLogoutURI != input.BackChannelLogoutURI {
			return fmt.Errorf("registered redirect or logout coordinates differ from bootstrap configuration")
		}
		if client.TokenEndpointAuth != "client_secret_post" || !sameStringSet(client.GrantTypes, []string{"authorization_code", "refresh_token"}) || !sameStringSet(client.ResponseTypes, []string{"code"}) {
			return fmt.Errorf("registered token authentication contract differs from bootstrap configuration")
		}
		return nil
	}
	return fmt.Errorf("registered client was not returned by the authorization provider")
}

func sameStringSet(left, right []string) bool {
	if len(left) != len(right) {
		return false
	}
	want := make(map[string]int, len(left))
	for _, value := range left {
		want[value]++
	}
	for _, value := range right {
		want[value]--
		if want[value] < 0 {
			return false
		}
	}
	return true
}

func (s *Server) updateHydraClient(ctx context.Context, input oidcClientInput) error {
	policy, err := s.store.SessionPolicy(ctx)
	if err != nil {
		return err
	}
	body, err := marshalHydraClient(input, policy)
	if err != nil {
		return err
	}
	endpoint := s.config.HydraAdminURL.ResolveReference(&url.URL{Path: "/admin/clients/" + input.ID})
	request, err := http.NewRequestWithContext(ctx, http.MethodPut, endpoint.String(), bytes.NewReader(body))
	if err != nil {
		return err
	}
	request.Header.Set("Content-Type", "application/json")
	response, err := s.httpClient.Do(request)
	if err != nil {
		return err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return fmt.Errorf("Hydra update client returned %s", response.Status)
	}
	return nil
}

func (s *Server) bootstrapApps(ctx context.Context) error {
	type bootstrapRegistration struct {
		input        oidcClientInput
		managedApp   identity.ManagedApp
		owned        bool
		clientExists bool
	}
	registrations := make([]bootstrapRegistration, 0, len(s.config.BootstrapApps))
	seenSlugs := make(map[string]struct{}, len(s.config.BootstrapApps))
	seenClientIDs := make(map[string]struct{}, len(s.config.BootstrapApps))
	for _, bootstrap := range s.config.BootstrapApps {
		input := oidcClientInput{ID: bootstrap.OIDCClientID, Name: bootstrap.Name, Secret: bootstrap.OIDCClientSecret, RedirectURIs: bootstrap.RedirectURIs, PostLogoutRedirectURIs: bootstrap.PostLogoutRedirectURIs, FrontChannelLogoutURI: bootstrap.FrontChannelLogoutURI, BackChannelLogoutURI: bootstrap.BackChannelLogoutURI}
		if err := input.validate(); err != nil {
			return fmt.Errorf("bootstrap app %q OAuth client: %w", bootstrap.Slug, err)
		}
		registeredClient := registeredOIDCClient(input)
		managedApp := identity.ManagedApp{Slug: bootstrap.Slug, Name: bootstrap.Name, Description: bootstrap.Description, LaunchURL: bootstrap.LaunchURL, OIDCClientID: bootstrap.OIDCClientID, OIDCContractHash: oidcClientContractHash(registeredClient), HealthURL: bootstrap.HealthURL, MonitoringURL: bootstrap.MonitoringURL, ValidationURL: bootstrap.ValidationURL, SignedOutURL: bootstrap.SignedOutURL, ReleaseRevision: bootstrap.ReleaseRevision}
		if err := identity.ValidateManagedApp(managedApp); err != nil {
			return fmt.Errorf("bootstrap managed app %q: %w", bootstrap.Slug, err)
		}
		if err := validateManagedAppClient(managedApp, registeredClient); err != nil {
			return fmt.Errorf("bootstrap app %q registration: %w", bootstrap.Slug, err)
		}
		if _, exists := seenSlugs[managedApp.Slug]; exists {
			return fmt.Errorf("bootstrap managed app slug %q is duplicated", managedApp.Slug)
		}
		if _, exists := seenClientIDs[input.ID]; exists {
			return fmt.Errorf("bootstrap OAuth client %q is duplicated", input.ID)
		}
		seenSlugs[managedApp.Slug] = struct{}{}
		seenClientIDs[input.ID] = struct{}{}
		registrations = append(registrations, bootstrapRegistration{input: input, managedApp: managedApp})
	}
	unlock, err := s.store.LockBootstrapManagedApps(ctx)
	if err != nil {
		return err
	}
	defer unlock()
	deadline := time.Now().Add(bootstrapRetryTimeout)
	var clients []oidcClient
	err = nil
	for {
		clients, err = s.hydraClients(ctx)
		if err == nil {
			break
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("list bootstrap OAuth clients: %w", err)
		}
		observe.Warnf("waiting for OAuth provider before bootstrapping managed apps: %v", err)
		time.Sleep(bootstrapRetryInterval)
	}
	byID := make(map[string]oidcClient, len(clients))
	for _, client := range clients {
		byID[client.ID] = client
	}
	for index := range registrations {
		registration := &registrations[index]
		owned, err := s.store.ValidateBootstrapManagedAppOwnership(ctx, registration.managedApp)
		if err != nil {
			return fmt.Errorf("bootstrap managed app %q ownership: %w", registration.managedApp.Slug, err)
		}
		registration.owned = owned
		_, registration.clientExists = byID[registration.input.ID]
		if registration.clientExists && !registration.owned {
			return fmt.Errorf("bootstrap OAuth client %q exists without its matching managed app", registration.input.ID)
		}
	}
	for _, registration := range registrations {
		// The same lock an operator's delete takes, so a client registered
		// here cannot be removed before its catalog row lands.
		err := s.store.WithOIDCClientLock(ctx, registration.input.ID, func(ctx context.Context) error {
			if registration.clientExists {
				if err := s.updateHydraClient(ctx, registration.input); err != nil {
					return fmt.Errorf("update bootstrap OAuth client %q: %w", registration.input.ID, err)
				}
			} else if err := s.createHydraClient(ctx, registration.input); err != nil {
				return fmt.Errorf("create bootstrap OAuth client %q: %w", registration.input.ID, err)
			}
			if _, err := s.store.ReconcileBootstrapManagedApp(ctx, registration.managedApp); err != nil {
				if !registration.clientExists {
					if rollbackErr := s.deleteHydraClient(ctx, registration.input.ID); rollbackErr != nil {
						return fmt.Errorf("reconcile bootstrap managed app %q: %v; remove newly created OAuth client: %w", registration.managedApp.Slug, err, rollbackErr)
					}
				}
				return fmt.Errorf("reconcile bootstrap managed app %q: %w", registration.managedApp.Slug, err)
			}
			if err := s.assertHydraClientReconciled(ctx, registration.input); err != nil {
				return fmt.Errorf("verify bootstrap OAuth client %q: %w", registration.input.ID, err)
			}
			return nil
		})
		if err != nil {
			return err
		}
	}
	return s.assertManagedAppRegistrations(ctx)
}

func (s *Server) assertManagedAppRegistrations(ctx context.Context) error {
	apps, err := s.store.ListManagedApps(ctx)
	if err != nil {
		return fmt.Errorf("list managed apps for registration verification: %w", err)
	}
	clients, err := s.hydraClients(ctx)
	if err != nil {
		return fmt.Errorf("list OAuth clients for registration verification: %w", err)
	}
	byID := make(map[string]oidcClient, len(clients))
	for _, client := range clients {
		byID[client.ID] = client
	}
	for _, app := range apps {
		if err := identity.ValidateManagedApp(app); err != nil {
			return fmt.Errorf("managed app %q registration: %w", app.Slug, err)
		}
		client, exists := byID[app.OIDCClientID]
		if !exists {
			return fmt.Errorf("managed app %q references missing OAuth client %q", app.Slug, app.OIDCClientID)
		}
		if err := validateManagedAppClient(app, client); err != nil {
			return fmt.Errorf("managed app %q registration: %w", app.Slug, err)
		}
		contractHash := oidcClientContractHash(client)
		if app.OIDCContractHash != contractHash {
			if err := s.store.ReconcileManagedAppOIDCContract(ctx, app.ID, contractHash); err != nil {
				return fmt.Errorf("managed app %q OIDC registration contract: %w", app.Slug, err)
			}
		}
	}
	return nil
}

func (s *Server) adminGitHubMappings(w http.ResponseWriter, r *http.Request) {
	if !s.requireAdmin(w, r) {
		return
	}
	s.renderGitHubMappings(w, r, http.StatusOK, r.URL.Query().Get("error"), githubRoleMappingCreateRequest{Kind: "team", Role: string(identity.RoleDeveloper)})
}

func (s *Server) renderGitHubMappings(w http.ResponseWriter, r *http.Request, status int, message string, form githubRoleMappingCreateRequest) {
	mappings, err := s.store.ListGitHubRoleMappings(r.Context())
	if err != nil {
		observe.Errorf("list GitHub role mappings: %v", err)
		s.failPage(w, r, http.StatusInternalServerError, "The GitHub access rules could not be loaded.")
		return
	}
	records := make([]githubRoleMappingRecord, 0, len(mappings))
	for _, mapping := range mappings {
		records = append(records, newGitHubRoleMappingRecord(mapping))
	}
	if status != http.StatusOK {
		w.WriteHeader(status)
	}
	s.render(w, "github-mappings", s.view(r, "GitHub access", map[string]any{
		"SignedIn": true, "IsAdmin": true, "Mappings": records,
		"Error": message, "Done": r.URL.Query().Get("done"), "Form": form,
	}))
}
func (s *Server) adminCreateGitHubMapping(w http.ResponseWriter, r *http.Request) {
	if !s.requireAdmin(w, r) {
		return
	}
	if err := r.ParseForm(); err != nil {
		s.failPage(w, r, http.StatusBadRequest, "invalid form")
		return
	}
	request := githubRoleMappingCreateRequest{Kind: r.Form.Get("kind"), Target: r.Form.Get("target"), Role: r.Form.Get("role")}
	mapping, err := s.createGitHubMapping(r.Context(), request.Kind, request.Target, request.Role, s.currentActor(r))
	if err != nil {
		status, message := describeOperationFailure("create GitHub role mapping", err)
		s.renderGitHubMappings(w, r, status, message, request)
		return
	}
	http.Redirect(w, r, "/admin/github?done="+url.QueryEscape("Added the access rule for "+mapping.Target+"."), http.StatusSeeOther)
}
func (s *Server) adminDeleteGitHubMapping(w http.ResponseWriter, r *http.Request) {
	if !s.requireAdmin(w, r) {
		return
	}
	if err := s.deleteGitHubMapping(r.Context(), r.PathValue("id"), s.currentActor(r)); err != nil {
		s.failOperation(w, r, "delete GitHub role mapping", "/admin/github", err)
		return
	}
	http.Redirect(w, r, "/admin/github?done="+url.QueryEscape("The access rule was removed."), http.StatusSeeOther)
}
func (s *Server) adminUsers(w http.ResponseWriter, r *http.Request) {
	if !s.requireAdmin(w, r) {
		return
	}
	s.renderUsers(w, r, http.StatusOK, r.URL.Query().Get("error"), userCreateRequest{Role: string(identity.RoleDeveloper)})
}

// renderUsers draws the users page from the same records the API publishes,
// carrying any failure message and the operator's unsaved input.
func (s *Server) renderUsers(w http.ResponseWriter, r *http.Request, status int, message string, form userCreateRequest) {
	query := r.URL.Query().Get("q")
	page, err := requestedPage(r)
	if err != nil {
		page = identity.Page{}
	}
	users, total, err := s.store.ListUsers(r.Context(), query, page)
	if err != nil {
		observe.Errorf("list users: %v", err)
		s.failPage(w, r, http.StatusInternalServerError, "The user list could not be loaded.")
		return
	}
	records := make([]userRecord, 0, len(users))
	for _, user := range users {
		records = append(records, newUserRecord(user))
	}
	if status != http.StatusOK {
		w.WriteHeader(status)
	}
	s.render(w, "users", s.view(r, "Users", map[string]any{
		"SignedIn": true, "IsAdmin": true, "Users": records, "Query": query,
		"Error": message, "Done": r.URL.Query().Get("done"), "Form": form,
		"Page": browserPage(r, page, len(records), total),
	}))
}
func (s *Server) adminCreateUser(w http.ResponseWriter, r *http.Request) {
	if !s.requireAdmin(w, r) {
		return
	}
	if err := r.ParseForm(); err != nil {
		s.failPage(w, r, http.StatusBadRequest, "The form could not be read.")
		return
	}
	request := userCreateRequest{
		Username: r.Form.Get("username"), Email: r.Form.Get("email"),
		Password: r.Form.Get("password"), Role: r.Form.Get("role"),
	}
	user, err := s.createUser(r.Context(), request, s.currentActor(r))
	if err != nil {
		// The form posts through HTMX, which does not swap a failed
		// response, so a rejection must re-render the page with the
		// reason and the operator's typed values still in place.
		status, message := describeOperationFailure("create user", err)
		s.renderUsers(w, r, status, message, request)
		return
	}
	if r.Header.Get("HX-Request") == "true" {
		s.render(w, "user-row", newUserRecord(user))
		return
	}
	http.Redirect(w, r, "/admin/users?done="+url.QueryEscape("Created the account "+user.Username+"."), http.StatusSeeOther)
}
func (s *Server) adminInvite(w http.ResponseWriter, r *http.Request) {
	if !s.requireAdmin(w, r) {
		return
	}
	if err := r.ParseForm(); err != nil {
		s.failPage(w, r, http.StatusBadRequest, "invalid form")
		return
	}
	inviter, _, err := s.current(r)
	if err != nil {
		s.failPage(w, r, http.StatusUnauthorized, "Your session has ended. Sign in again to send invitations.")
		return
	}
	invitation, err := s.createInvitation(r.Context(), r.Form.Get("email"), r.Form.Get("role"), actor{UserID: inviter.ID})
	if err != nil {
		s.failOperation(w, r, "create invitation", "/admin/invitations", err)
		return
	}
	http.Redirect(w, r, "/admin/invitations?done="+url.QueryEscape("Invitation sent to "+invitation.Email+"."), http.StatusSeeOther)
}
func (s *Server) adminInvitations(w http.ResponseWriter, r *http.Request) {
	if !s.requireAdmin(w, r) {
		return
	}
	page, err := requestedPage(r)
	if err != nil {
		page = identity.Page{}
	}
	invitations, total, err := s.store.ListInvitations(r.Context(), time.Now(), page)
	if err != nil {
		observe.Errorf("list invitations: %v", err)
		s.failPage(w, r, http.StatusInternalServerError, "The invitations could not be loaded.")
		return
	}
	records := make([]invitationRecord, 0, len(invitations))
	for _, invitation := range invitations {
		records = append(records, newInvitationRecord(invitation))
	}
	s.render(w, "invitations", s.view(r, "Invitations", map[string]any{
		"SignedIn": true, "IsAdmin": true, "Invitations": records,
		"Error": r.URL.Query().Get("error"), "Done": r.URL.Query().Get("done"),
		"Page": browserPage(r, page, len(records), total),
	}))
}

func (s *Server) adminRevokeInvitation(w http.ResponseWriter, r *http.Request) {
	if !s.requireAdmin(w, r) {
		return
	}
	if err := s.revokeInvitation(r.Context(), r.PathValue("id"), s.currentActor(r)); err != nil {
		s.failOperation(w, r, "revoke invitation", "/admin/invitations", err)
		return
	}
	http.Redirect(w, r, "/admin/invitations?done="+url.QueryEscape("The invitation was withdrawn."), http.StatusSeeOther)
}

// adminDisableUser is the browser twin of disableUserAPI: it ends every
// session and disables the account, so a compromised credential cannot sign
// in again.
func (s *Server) adminDisableUser(w http.ResponseWriter, r *http.Request) {
	if !s.requireAdmin(w, r) {
		return
	}
	userID := r.PathValue("id")
	requester := s.currentActor(r)
	if requester.UserID == "" {
		s.failPage(w, r, http.StatusUnauthorized, "Your session has ended. Sign in again to manage accounts.")
		return
	}
	account := "/admin/users/" + url.PathEscape(userID)
	if _, err := s.disableUser(r.Context(), userID, requester); err != nil {
		s.failOperation(w, r, "disable account", account, err)
		return
	}
	http.Redirect(w, r, account+"?done="+url.QueryEscape("The account was disabled and every session ended."), http.StatusSeeOther)
}

func (s *Server) adminEnableUser(w http.ResponseWriter, r *http.Request) {
	if !s.requireAdmin(w, r) {
		return
	}
	userID := r.PathValue("id")
	account := "/admin/users/" + url.PathEscape(userID)
	if _, err := s.enableUser(r.Context(), userID, s.currentActor(r)); err != nil {
		s.failOperation(w, r, "enable account", account, err)
		return
	}
	http.Redirect(w, r, account+"?done="+url.QueryEscape("The account was enabled. It must sign in again."), http.StatusSeeOther)
}
func (s *Server) acceptInvitation(w http.ResponseWriter, r *http.Request) {
	token := r.URL.Query().Get("token")
	if state, err := s.store.InvitationState(r.Context(), token, time.Now()); err != nil || state != identity.InvitationPending {
		s.failPage(w, r, http.StatusGone, invitationRejection(state))
		return
	}
	s.render(w, "accept-invitation", s.view(r, "Accept your invitation", map[string]any{"Token": token, "SignedIn": false}))
}

// invitationRejection explains why a link cannot be used, so the recipient
// knows whether to ask for a new invitation or simply sign in.
func invitationRejection(state string) string {
	switch state {
	case identity.InvitationAccepted:
		return "This invitation has already been used. If the account is yours, sign in instead."
	case identity.InvitationRevoked:
		return "This invitation was withdrawn. Ask an administrator to send a new one."
	case identity.InvitationExpired:
		return "This invitation has expired. Ask an administrator to send a new one."
	default:
		return "This invitation link is not valid. Ask an administrator to send a new one."
	}
}
func (s *Server) acceptInvitationPost(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		s.failPage(w, r, http.StatusBadRequest, "invalid form")
		return
	}
	token := r.Form.Get("token")
	user, err := s.claimInvitation(r.Context(), token, r.Form.Get("username"), r.Form.Get("password"), visitorActor(r))
	if err != nil {
		// The invitation survives a rejected username or password, so keep
		// the recipient on the form with the reason instead of spending
		// their one link on a correctable mistake.
		state, stateErr := s.store.InvitationState(r.Context(), token, time.Now())
		if stateErr != nil || state != identity.InvitationPending || errors.Is(err, identity.ErrInvitationNotAcceptable) {
			s.failPage(w, r, http.StatusGone, invitationRejection(state))
			return
		}
		_, message := describeOperationFailure("accept invitation", err)
		w.WriteHeader(http.StatusBadRequest)
		s.render(w, "accept-invitation", s.view(r, "Accept your invitation", map[string]any{
			"Token": token, "SignedIn": false, "Error": message, "Username": r.Form.Get("username"),
		}))
		return
	}
	if !s.startSession(w, r, user) {
		return
	}
	s.recordSignIn(r, identity.AuditSignInSucceeded, "invitation", user.Username, user.ID, "")
	http.Redirect(w, r, "/", 303)
}

// adminUserSessionsLegacy keeps the older sessions URL working by sending it
// to the account screen that replaced it, so existing links and bookmarks do
// not break.
func (s *Server) adminUserSessionsLegacy(w http.ResponseWriter, r *http.Request) {
	http.Redirect(w, r, "/admin/users/"+url.PathEscape(r.PathValue("id")), http.StatusMovedPermanently)
}

// adminApp is one application's own screen: its coordinates, live health,
// current validation state, and the durable run history that until now was
// only reachable through the machine API.
func (s *Server) adminApp(w http.ResponseWriter, r *http.Request) {
	if !s.requireAdmin(w, r) {
		return
	}
	slug := r.PathValue("slug")
	views, err := s.appViews(r.Context())
	if err != nil {
		observe.Errorf("list applications: %v", err)
		s.failPage(w, r, http.StatusInternalServerError, "The application could not be loaded.")
		return
	}
	token := csrfToken(r)
	for index := range views {
		if views[index].Slug != slug {
			continue
		}
		views[index].CSRF = token
		history, err := s.store.AppValidationRunHistory(r.Context(), slug, 20)
		if err != nil {
			observe.Errorf("read validation history for %s: %v", slug, err)
			s.failPage(w, r, http.StatusInternalServerError, "The validation history could not be loaded.")
			return
		}
		records := make([]validationStatusRecord, 0, len(history))
		for _, run := range history {
			records = append(records, newValidationStatusRecord(run))
		}
		s.render(w, "admin-app", s.view(r, views[index].Name, map[string]any{
			"SignedIn": true, "IsAdmin": true, "App": views[index], "History": records,
			"Done": r.URL.Query().Get("done"), "Error": r.URL.Query().Get("error"),
		}))
		return
	}
	s.failPage(w, r, http.StatusNotFound, "That application is not registered.")
}

func (s *Server) adminUserSessions(w http.ResponseWriter, r *http.Request) {
	if !s.requireAdmin(w, r) {
		return
	}
	userID := r.PathValue("id")
	if err := requireUUID(userID, identity.ErrUserNotFound); err != nil {
		s.failPage(w, r, http.StatusNotFound, "That account does not exist.")
		return
	}
	user, err := s.store.UserByID(r.Context(), userID)
	if err != nil {
		s.failPage(w, r, http.StatusNotFound, "That account does not exist.")
		return
	}
	sessions, err := s.store.ListSessions(r.Context(), userID)
	if err != nil {
		observe.Errorf("list sessions for %s: %v", userID, err)
		s.failPage(w, r, http.StatusInternalServerError, "The sessions for this account could not be loaded.")
		return
	}
	records := make([]sessionRecord, 0, len(sessions))
	for _, session := range sessions {
		records = append(records, newSessionRecord(session))
	}
	s.render(w, "sessions", s.view(r, user.Username+" · sessions", map[string]any{
		"SignedIn": true, "IsAdmin": true, "Sessions": records, "UserID": userID,
		"Account": newUserRecord(user), "Error": r.URL.Query().Get("error"), "Done": r.URL.Query().Get("done"),
	}))
}
func (s *Server) adminRevokeSessions(w http.ResponseWriter, r *http.Request) {
	if !s.requireAdmin(w, r) {
		return
	}
	userID := r.PathValue("id")
	account := "/admin/users/" + url.PathEscape(userID)
	if _, err := s.revokeUserSessions(r.Context(), userID, "", s.currentActor(r)); err != nil {
		s.failOperation(w, r, "revoke account sessions", account, err)
		return
	}
	http.Redirect(w, r, account+"?done="+url.QueryEscape("Every session for this account was ended."), http.StatusSeeOther)
}

// sessionResetAPI is the token-authenticated counterpart of adminRevokeSessions:
// it lets an operator end all of a user's browser sessions and revoke the
// correlated Ory Hydra sessions without an admin browser login. This is how a
// stuck login is cleared -- a stale Hydra session that "could not correlate"
// with the current browser -- programmatically, instead of asking the user to
// clear cookies. Target the account by "user_id" or, more conveniently, "email".
func (s *Server) sessionResetAPI(w http.ResponseWriter, r *http.Request) {
	noStore(w)
	if s.config.SessionResetToken == "" {
		writeAdminAPIError(w, http.StatusServiceUnavailable, "session reset is not configured")
		return
	}
	if !bearerTokenMatches(r, s.config.SessionResetToken) {
		unauthorized(w, "session reset authentication failed")
		return
	}
	userID, err := s.revokeUserSessions(r.Context(),
		strings.TrimSpace(r.URL.Query().Get("user_id")), strings.TrimSpace(r.URL.Query().Get("email")), tokenActor(r))
	if err != nil {
		writeOperationFailure(w, "reset account sessions", err)
		return
	}
	writeAdminAPIJSON(w, http.StatusOK, map[string]any{
		"schema_version": "shauth.session-reset/v1",
		"observed_at":    time.Now().UTC(),
		"reset_user_id":  userID,
	})
}
func (s *Server) adminRevokeSession(w http.ResponseWriter, r *http.Request) {
	if !s.requireAdmin(w, r) {
		return
	}
	// Ending a session from the service-wide listing should return there
	// rather than jumping to the account page the operator was not looking
	// at. Anything but a strictly local path is ignored, so this cannot be
	// turned into an open redirect.
	_ = r.ParseForm()
	destination := ""
	if requested := r.Form.Get("return_to"); strictRelativeNext(requested) {
		destination = requested
	}
	revoked, err := s.revokeSession(r.Context(), r.PathValue("id"), s.currentActor(r))
	if err != nil {
		if destination == "" {
			destination = "/admin/users"
		}
		s.failOperation(w, r, "revoke session", destination, err)
		return
	}
	if destination == "" {
		destination = "/admin/users/" + url.PathEscape(revoked.UserID)
	}
	http.Redirect(w, r, destination+"?done="+url.QueryEscape("The session was ended."), http.StatusSeeOther)
}

func (s *Server) revokeHydraLoginSession(ctx context.Context, sessionID string) error {
	endpoint := s.config.HydraAdminURL.ResolveReference(&url.URL{Path: "/admin/oauth2/auth/sessions/login"})
	query := endpoint.Query()
	query.Set("sid", sessionID)
	endpoint.RawQuery = query.Encode()
	request, err := http.NewRequestWithContext(ctx, http.MethodDelete, endpoint.String(), nil)
	if err != nil {
		return err
	}
	response, err := s.httpClient.Do(request)
	if err != nil {
		return err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusNoContent {
		return fmt.Errorf("Hydra login session deletion returned HTTP %d", response.StatusCode)
	}
	return nil
}

func (s *Server) revokeHydraSessions(ctx context.Context, subject string) error {
	sessionIDs, err := s.store.UserHydraLoginSessionIDs(ctx, subject)
	if err != nil {
		return err
	}
	for _, sessionID := range sessionIDs {
		if err := s.revokeHydraLoginSession(ctx, sessionID); err != nil {
			return err
		}
	}
	return s.revokeHydraSubjectSessions(ctx, subject)
}

func (s *Server) revokeHydraSubjectSessions(ctx context.Context, subject string) error {
	for _, kind := range []string{"login", "consent"} {
		endpoint := s.config.HydraAdminURL.ResolveReference(&url.URL{Path: "/admin/oauth2/auth/sessions/" + kind})
		query := endpoint.Query()
		query.Set("subject", subject)
		if kind == "consent" {
			query.Set("all", "true")
		}
		endpoint.RawQuery = query.Encode()
		request, err := http.NewRequestWithContext(ctx, http.MethodDelete, endpoint.String(), nil)
		if err != nil {
			return err
		}
		response, err := s.httpClient.Do(request)
		if err != nil {
			return err
		}
		response.Body.Close()
		if response.StatusCode != http.StatusNoContent {
			return fmt.Errorf("Hydra %s session deletion returned HTTP %d", kind, response.StatusCode)
		}
	}
	return nil
}

type hydraConsent struct {
	RequestedScope []string `json:"requested_scope"`
	LoginSessionID string   `json:"login_session_id"`
	Client         struct {
		ID string `json:"client_id"`
	} `json:"client"`
}

type hydraConsentRequest struct {
	ClientID       string
	Scopes         []string
	LoginSessionID string
}

func (s *Server) hydraConsentRequest(ctx context.Context, challenge string) (hydraConsentRequest, error) {
	endpoint := s.config.HydraAdminURL.ResolveReference(&url.URL{Path: "/admin/oauth2/auth/requests/consent", RawQuery: "consent_challenge=" + url.QueryEscape(challenge)})
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint.String(), nil)
	if err != nil {
		return hydraConsentRequest{}, err
	}
	response, err := s.httpClient.Do(request)
	if err != nil {
		return hydraConsentRequest{}, err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return hydraConsentRequest{}, fmt.Errorf("Hydra consent request returned HTTP %d", response.StatusCode)
	}
	var consent hydraConsent
	if err := json.NewDecoder(response.Body).Decode(&consent); err != nil {
		return hydraConsentRequest{}, fmt.Errorf("decode Hydra consent request: %w", err)
	}
	if consent.Client.ID == "" || len(consent.RequestedScope) == 0 {
		return hydraConsentRequest{}, fmt.Errorf("Hydra consent request is missing a client or scopes")
	}
	return hydraConsentRequest{ClientID: consent.Client.ID, Scopes: consent.RequestedScope, LoginSessionID: consent.LoginSessionID}, nil
}
func (s *Server) monitoring(w http.ResponseWriter, r *http.Request) {
	if !s.requireAdmin(w, r) {
		return
	}
	snapshot := s.monitoringSnapshot(r.Context())
	// Every panel below is the same operation an endpoint serves, so the
	// page and the machine contracts cannot drift apart. The page showed
	// two dependencies out of nine and none of the durable counts, which
	// meant the answer to "what is wrong" lived only in the API.
	report := s.traffic.report()
	overall, checks := s.deepHealth(r.Context())
	data := map[string]any{
		"SignedIn": true, "IsAdmin": true, "Snapshot": snapshot, "Now": time.Now().UTC(),
		"Traffic": report, "BusiestRoutes": report.Busiest(8),
		"Health": overall, "Checks": checks,
		"LogErrors": s.serviceLog().Counts()[observe.LevelError],
	}
	if metrics, err := s.store.Metrics(r.Context(), time.Now()); err != nil {
		observe.Errorf("read metrics for the monitoring page: %v", err)
		data["MetricsError"] = "The durable counts could not be read."
	} else {
		data["Metrics"] = metrics
	}
	s.render(w, "monitoring", s.view(r, "Monitoring", data))
}
func (s *Server) hydraReady(ctx context.Context) bool {
	ctx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	return hydraEndpointReady(ctx, s.httpClient, s.config.HydraPublicURL) && hydraEndpointReady(ctx, s.httpClient, s.config.HydraAdminURL)
}

func hydraEndpointReady(ctx context.Context, client *http.Client, base *url.URL) bool {
	endpoint := base.ResolveReference(&url.URL{Path: "/health/ready"})
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint.String(), nil)
	if err != nil {
		return false
	}
	response, err := client.Do(request)
	if err != nil {
		return false
	}
	defer response.Body.Close()
	return response.StatusCode == http.StatusOK
}
func (s *Server) githubRole(ctx context.Context, accessToken string, profile githubapi.Profile) (identity.Role, bool, error) {
	mappings, err := s.store.ListGitHubRoleMappings(ctx)
	if err != nil {
		return "", false, err
	}
	var hasTeam, hasOrganization bool
	for _, mapping := range mappings {
		hasTeam = hasTeam || mapping.Kind == "team"
		hasOrganization = hasOrganization || mapping.Kind == "organization"
	}
	teamTargets := map[string]bool{}
	if hasTeam {
		teams, err := s.github.Teams(ctx, accessToken)
		if err != nil {
			return "", false, err
		}
		for _, team := range teams {
			teamTargets[strings.ToLower(team.Organization.Login+"/"+team.Slug)] = true
		}
	}
	organizationTargets := map[string]bool{}
	if hasOrganization {
		organizations, err := s.github.Organizations(ctx, accessToken)
		if err != nil {
			return "", false, err
		}
		for _, organization := range organizations {
			organizationTargets[strings.ToLower(organization)] = true
		}
	}
	role := identity.RoleDeveloper
	allowed := false
	for _, mapping := range mappings {
		matches := (mapping.Kind == "user" && strings.EqualFold(mapping.Target, profile.Login)) ||
			(mapping.Kind == "team" && teamTargets[strings.ToLower(mapping.Target)]) ||
			(mapping.Kind == "organization" && organizationTargets[strings.ToLower(mapping.Target)])
		if !matches {
			continue
		}
		allowed = true
		if mapping.Role == identity.RoleAdmin {
			role = identity.RoleAdmin
		}
	}
	return role, allowed, nil
}
func (s *Server) current(r *http.Request) (identity.User, identity.Session, error) {
	cookie, err := r.Cookie(browserSessionCookie)
	if err != nil {
		return identity.User{}, identity.Session{}, err
	}
	return s.store.CurrentUser(r.Context(), cookie.Value, time.Now())
}

// currentActor identifies the signed-in person performing a browser action,
// so an audit record names them rather than only the address.
func (s *Server) currentActor(r *http.Request) actor {
	user, session, err := s.current(r)
	if err != nil {
		return tokenActor(r)
	}
	return browserActor(r, user, session)
}

func (s *Server) requireAdmin(w http.ResponseWriter, r *http.Request) bool {
	user, _, err := s.current(r)
	if err != nil {
		http.Redirect(w, r, "/login?next="+url.QueryEscape(r.URL.RequestURI()), 303)
		return false
	}
	if user.Role != identity.RoleAdmin {
		s.failPage(w, r, http.StatusForbidden, "This page is limited to administrators. Your account does not have administrator access.")
		return false
	}
	return true
}

// recordSignIn notes an authentication outcome. The attempted identifier is
// recorded because an operator investigating a lockout needs to know which
// name was used; no credential material is ever recorded.
func (s *Server) recordSignIn(r *http.Request, eventType, method, username, subjectUserID, reason string) {
	details := map[string]any{"method": method, "username": username}
	if reason != "" {
		details["reason"] = reason
	}
	s.record(r.Context(), actor{Address: clientIP(r)}, eventType, subjectUserID, details)
}

func (s *Server) startSession(w http.ResponseWriter, r *http.Request, user identity.User) bool {
	raw, session, err := s.store.CreateSession(r.Context(), user.ID, r.UserAgent(), clientIP(r), time.Now())
	if err != nil {
		s.failPage(w, r, http.StatusInternalServerError, "could not create session")
		return false
	}
	s.setCookie(w, &http.Cookie{Name: browserSessionCookie, Value: raw, Path: "/", HttpOnly: true, Secure: !s.config.AllowInsecureCookies, SameSite: http.SameSiteLaxMode, Expires: session.ExpiresAt, MaxAge: int(time.Until(session.ExpiresAt).Seconds())})
	return true
}
func jsonBody(value any) (*bytes.Reader, error) {
	encoded, err := json.Marshal(value)
	if err != nil {
		return nil, err
	}
	return bytes.NewReader(encoded), nil
}
func (s *Server) setCookie(w http.ResponseWriter, cookie *http.Cookie) { http.SetCookie(w, cookie) }
func (s *Server) expireCookie(w http.ResponseWriter, name string) {
	s.expireCookieAtPath(w, name, "/")
}
func (s *Server) expireCookieAtPath(w http.ResponseWriter, name, path string) {
	s.setCookie(w, &http.Cookie{Name: name, Value: "", Path: path, HttpOnly: true, Secure: !s.config.AllowInsecureCookies, MaxAge: -1, Expires: time.Unix(0, 0)})
}

// view completes a page's template data. Every page receives its own title,
// the CSRF token its forms must carry, and the sign-in state the header
// renders from, so no page can accidentally present a signed-in
// administrator as anonymous or ship a form the browser cannot submit.
func (s *Server) view(r *http.Request, title string, data map[string]any) map[string]any {
	if data == nil {
		data = map[string]any{}
	}
	data["Title"] = title
	data["CSRF"] = csrfToken(r)
	data["Path"] = r.URL.Path
	data["Revision"] = version.Short()
	data["StartedAt"] = version.StartedAt()
	if _, ok := data["SignedIn"]; !ok {
		user, _, err := s.current(r)
		data["SignedIn"] = err == nil
		data["IsAdmin"] = err == nil && user.Role == identity.RoleAdmin
	}
	if _, ok := data["IsAdmin"]; !ok {
		data["IsAdmin"] = false
	}
	return data
}

// pageView describes a listing window for a page that renders navigation.
type pageView struct {
	First    int
	Last     int
	Total    int
	Previous string
	Next     string
}

func browserPage(r *http.Request, page identity.Page, returned, total int) pageView {
	limit := page.Limit
	if limit <= 0 {
		limit = 100
	}
	view := pageView{Total: total}
	if returned > 0 {
		view.First, view.Last = page.Offset+1, page.Offset+returned
	}
	link := func(offset int) string {
		query := r.URL.Query()
		query.Del("done")
		query.Del("error")
		if offset <= 0 {
			query.Del("offset")
		} else {
			query.Set("offset", strconv.Itoa(offset))
		}
		return r.URL.Path + "?" + query.Encode()
	}
	if page.Offset > 0 {
		view.Previous = link(max(0, page.Offset-limit))
	}
	if page.Offset+returned < total {
		view.Next = link(page.Offset + limit)
	}
	return view
}

func templateHelpers() template.FuncMap {
	return template.FuncMap{
		// Both accept any value so a page whose data omits a timestamp
		// renders a blank rather than failing to render at all.
		"moment": func(value any) string {
			moment, ok := value.(time.Time)
			if !ok || moment.IsZero() {
				return "unknown"
			}
			return moment.UTC().Format("2 Jan 2006 15:04 MST")
		},
		"iso": func(value any) string {
			moment, ok := value.(time.Time)
			if !ok || moment.IsZero() {
				return ""
			}
			return moment.UTC().Format(time.RFC3339)
		},
		// A log is read by scanning down a column of times on one day, so
		// it shows the time to the second and leaves the date to the
		// machine-readable attribute beside it.
		"clock": func(value any) string {
			moment, ok := value.(time.Time)
			if !ok || moment.IsZero() {
				return "--:--:--"
			}
			return moment.UTC().Format("15:04:05")
		},
		"shortRevision": shortReleaseRevision,
		"identityLabel": func(source, githubLogin string) string {
			switch source {
			case identity.IdentitySourceGitHub:
				return "GitHub: " + githubLogin
			case identity.IdentitySourceEntra:
				return "Microsoft Entra ID"
			default:
				return "Local account"
			}
		},
	}
}

func (s *Server) render(w http.ResponseWriter, name string, data any) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	var page bytes.Buffer
	if err := s.templates.ExecuteTemplate(&page, name, data); err != nil {
		observe.Errorf("render %s: %v", name, err)
		http.Error(w, "page rendering failed", http.StatusInternalServerError)
		return
	}
	_, _ = page.WriteTo(w)
}

// failPage answers a browser navigation with a styled, navigable error page
// instead of unstyled plain text, so a person who hits a failure keeps the
// header, the theme, and a way back.
func (s *Server) failPage(w http.ResponseWriter, r *http.Request, status int, message string) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	var page bytes.Buffer
	data := s.view(r, http.StatusText(status), map[string]any{"Status": status, "StatusText": http.StatusText(status), "Message": message})
	if err := s.templates.ExecuteTemplate(&page, "error", data); err != nil {
		observe.Errorf("render error page: %v", err)
		http.Error(w, message, status)
		return
	}
	w.WriteHeader(status)
	_, _ = page.WriteTo(w)
}

// failOperation reports a failed administration operation to a browser
// caller, using the same classification the JSON transport uses. Rejections
// return the operator to the form with an explanation; failures render a
// styled error page.
func (s *Server) failOperation(w http.ResponseWriter, r *http.Request, action, back string, err error) {
	status, message := describeOperationFailure(action, err)
	if back != "" && status < http.StatusInternalServerError {
		http.Redirect(w, r, back+"?error="+url.QueryEscape(message), http.StatusSeeOther)
		return
	}
	s.failPage(w, r, status, message)
}
func (s *Server) hydraAccept(ctx context.Context, path, challenge string, payload any) (string, error) {
	if challenge == "" {
		return "", fmt.Errorf("missing OAuth challenge")
	}
	endpoint := s.config.HydraAdminURL.ResolveReference(&url.URL{Path: path})
	q := endpoint.Query()
	if strings.Contains(path, "login/") {
		q.Set("login_challenge", challenge)
	} else {
		q.Set("consent_challenge", challenge)
	}
	endpoint.RawQuery = q.Encode()
	body, err := jsonBody(payload)
	if err != nil {
		return "", err
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodPut, endpoint.String(), body)
	if err != nil {
		return "", err
	}
	request.Header.Set("Content-Type", "application/json")
	response, err := s.httpClient.Do(request)
	if err != nil {
		return "", err
	}
	defer response.Body.Close()
	var result struct {
		RedirectTo string `json:"redirect_to"`
	}
	if response.StatusCode != 200 {
		return "", fmt.Errorf("Hydra returned HTTP %d", response.StatusCode)
	}
	if err := json.NewDecoder(response.Body).Decode(&result); err != nil {
		return "", err
	}
	if result.RedirectTo == "" {
		return "", fmt.Errorf("Hydra did not return redirect_to")
	}
	return result.RedirectTo, nil
}

type hydraLoginRequest struct {
	SessionID string `json:"session_id"`
	Subject   string `json:"subject"`
	Skip      bool   `json:"skip"`
}

func (s *Server) hydraLoginRequest(ctx context.Context, challenge string) (hydraLoginRequest, error) {
	if challenge == "" {
		return hydraLoginRequest{}, fmt.Errorf("missing OAuth login challenge")
	}
	endpoint := s.config.HydraAdminURL.ResolveReference(&url.URL{Path: "/admin/oauth2/auth/requests/login"})
	query := endpoint.Query()
	query.Set("login_challenge", challenge)
	endpoint.RawQuery = query.Encode()
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint.String(), nil)
	if err != nil {
		return hydraLoginRequest{}, err
	}
	response, err := s.httpClient.Do(request)
	if err != nil {
		return hydraLoginRequest{}, err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return hydraLoginRequest{}, fmt.Errorf("Ory Hydra login request returned HTTP %d", response.StatusCode)
	}
	var result hydraLoginRequest
	if err := json.NewDecoder(response.Body).Decode(&result); err != nil {
		return hydraLoginRequest{}, fmt.Errorf("decode Ory Hydra login request: %w", err)
	}
	if result.SessionID == "" {
		return hydraLoginRequest{}, fmt.Errorf("Ory Hydra login request has no session ID")
	}
	return result, nil
}

func (s *Server) hydraLogoutRequest(ctx context.Context, challenge string) (hydraLogoutRequest, error) {
	if challenge == "" {
		return hydraLogoutRequest{}, fmt.Errorf("missing OAuth logout challenge")
	}
	endpoint := s.config.HydraAdminURL.ResolveReference(&url.URL{Path: "/admin/oauth2/auth/requests/logout"})
	query := endpoint.Query()
	query.Set("logout_challenge", challenge)
	endpoint.RawQuery = query.Encode()
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint.String(), nil)
	if err != nil {
		return hydraLogoutRequest{}, err
	}
	response, err := s.httpClient.Do(request)
	if err != nil {
		return hydraLogoutRequest{}, err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return hydraLogoutRequest{}, fmt.Errorf("Hydra logout request returned HTTP %d", response.StatusCode)
	}
	var result hydraLogoutRequest
	if err := json.NewDecoder(response.Body).Decode(&result); err != nil {
		return hydraLogoutRequest{}, fmt.Errorf("decode Hydra logout request: %w", err)
	}
	if result.Subject == "" {
		return hydraLogoutRequest{}, fmt.Errorf("Hydra logout request has no subject")
	}
	return result, nil
}

func (s *Server) hydraAcceptLogout(ctx context.Context, challenge string) (string, error) {
	if challenge == "" {
		return "", fmt.Errorf("missing OAuth logout challenge")
	}
	endpoint := s.config.HydraAdminURL.ResolveReference(&url.URL{Path: "/admin/oauth2/auth/requests/logout/accept"})
	query := endpoint.Query()
	query.Set("logout_challenge", challenge)
	endpoint.RawQuery = query.Encode()
	request, err := http.NewRequestWithContext(ctx, http.MethodPut, endpoint.String(), nil)
	if err != nil {
		return "", err
	}
	response, err := s.httpClient.Do(request)
	if err != nil {
		return "", err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return "", fmt.Errorf("Hydra logout acceptance returned HTTP %d", response.StatusCode)
	}
	var result struct {
		RedirectTo string `json:"redirect_to"`
	}
	if err := json.NewDecoder(response.Body).Decode(&result); err != nil {
		return "", fmt.Errorf("decode Hydra logout acceptance: %w", err)
	}
	if result.RedirectTo == "" {
		return "", fmt.Errorf("Hydra logout acceptance did not return redirect_to")
	}
	return result.RedirectTo, nil
}

func (s *Server) hydraRejectLogout(ctx context.Context, challenge string) error {
	if challenge == "" {
		return fmt.Errorf("missing OAuth logout challenge")
	}
	endpoint := s.config.HydraAdminURL.ResolveReference(&url.URL{Path: "/admin/oauth2/auth/requests/logout/reject"})
	query := endpoint.Query()
	query.Set("logout_challenge", challenge)
	endpoint.RawQuery = query.Encode()
	body, err := jsonBody(map[string]any{
		"error":             "request_denied",
		"error_description": "logout confirmation is required",
	})
	if err != nil {
		return err
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodPut, endpoint.String(), body)
	if err != nil {
		return err
	}
	request.Header.Set("Content-Type", "application/json")
	response, err := s.httpClient.Do(request)
	if err != nil {
		return err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusNoContent {
		return fmt.Errorf("Hydra logout rejection returned HTTP %d", response.StatusCode)
	}
	return nil
}
func newState() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

// clientIP reports the address the request came from. Shauth is reached only
// through a gateway inside the private network, so the peer address is that
// gateway rather than the person signing in. When the peer is a private or
// loopback address the rightmost X-Forwarded-For entry is used instead: that
// entry is the one the nearest proxy observed and appended, so it cannot be
// forged by the caller, unlike the leftmost entry. A public peer is trusted
// as-is and any forwarded header is ignored, so a direct caller cannot
// choose the address recorded against their session.
func clientIP(r *http.Request) net.IP {
	peer := peerIP(r)
	if peer == nil || !isPrivatePeer(peer) {
		return peer
	}
	forwarded := r.Header.Get("X-Forwarded-For")
	if forwarded == "" {
		return peer
	}
	entries := strings.Split(forwarded, ",")
	nearest := net.ParseIP(strings.TrimSpace(entries[len(entries)-1]))
	if nearest == nil {
		return peer
	}
	return nearest
}

func peerIP(r *http.Request) net.IP {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err == nil {
		return net.ParseIP(host)
	}
	return net.ParseIP(r.RemoteAddr)
}

func isPrivatePeer(address net.IP) bool {
	return address.IsLoopback() || address.IsPrivate() || address.IsLinkLocalUnicast()
}
func relativeNext(value string) string {
	if value == "" {
		return "/"
	}
	parsed, err := url.Parse(value)
	if err != nil || parsed.IsAbs() || parsed.Host != "" || !strings.HasPrefix(parsed.Path, "/") || strings.HasPrefix(parsed.Path, "//") || strings.Contains(parsed.Path, "\\") {
		return "/"
	}
	return parsed.RequestURI()
}

func strictRelativeNext(value string) bool {
	if value == "" {
		return false
	}
	parsed, err := url.ParseRequestURI(value)
	return err == nil && parsed.IsAbs() == false && parsed.Host == "" && parsed.User == nil && parsed.Fragment == "" && strings.HasPrefix(parsed.Path, "/") && !strings.HasPrefix(parsed.Path, "//") && !strings.Contains(parsed.Path, "\\") && parsed.RequestURI() == value
}

func isOIDCNext(value string) bool {
	target, err := url.Parse(value)
	if err != nil {
		return false
	}
	return target.Path == "/oauth/login" || target.Path == "/oauth/consent"
}

func allowOIDCFormAction(w http.ResponseWriter) {
	w.Header().Set("Content-Security-Policy", oidcContentSecurityPolicy)
}

func githubStateCookieName(state string) string {
	return githubStateCookiePrefix + state
}

func validGitHubStateCookieName(state string) (string, bool) {
	decoded, err := hex.DecodeString(state)
	if err != nil || len(decoded) != 32 {
		return "", false
	}
	return githubStateCookieName(state), true
}
