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
	"slices"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode"
	"unicode/utf8"

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
const noticeCookie = "shauth_notice"
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
	// DeploymentOwned marks the client of an app the bootstrap
	// configuration declares, which the interface does not offer to delete.
	DeploymentOwned bool `json:"-"`
	// UsedBy names the catalog app that depends on this client, which must
	// be removed before the client can be deleted.
	UsedBy string `json:"-"`
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

// validateManagedAppClient checks that a client registered in Ory Hydra is
// one Shauth can stand behind for a catalog app: a confidential
// authorization-code client on the app's own origin, with HTTPS (or
// loopback) coordinates, a way to receive logout, and only the exact logout
// bridge as its post-logout destination. A client registered directly in
// Hydra with weaker settings is refused rather than listed.
func validateManagedAppClient(app identity.ManagedApp, client oidcClient) error {
	if app.OIDCClientID != client.ID {
		return identity.Invalid("managed app OpenID Connect client does not match the registered client")
	}
	if client.TokenEndpointAuth != "client_secret_post" && client.TokenEndpointAuth != "client_secret_basic" {
		return identity.Invalid("managed app OpenID Connect client must authenticate with its client secret")
	}
	if !slices.Contains(client.GrantTypes, "authorization_code") || slices.ContainsFunc(client.GrantTypes, func(grant string) bool {
		return grant != "authorization_code" && grant != "refresh_token"
	}) {
		return identity.Invalid("managed app OpenID Connect client may use only the authorization code and refresh token grants")
	}
	if len(client.ResponseTypes) != 1 || client.ResponseTypes[0] != "code" {
		return identity.Invalid("managed app OpenID Connect client must use only the code response type")
	}
	if len(client.RedirectURIs) == 0 {
		return identity.Invalid("managed app OpenID Connect client must register a redirect URI")
	}
	if client.FrontChannelLogoutURI == "" && client.BackChannelLogoutURI == "" {
		return identity.Invalid("managed app OpenID Connect client must register a front-channel or back-channel logout URI")
	}
	for _, check := range []struct {
		label string
		uris  []string
	}{
		{"redirect URI", client.RedirectURIs},
		{"post-logout redirect URI", client.PostLogoutRedirectURIs},
		{"front-channel logout URI", []string{client.FrontChannelLogoutURI}},
		{"back-channel logout URI", []string{client.BackChannelLogoutURI}},
	} {
		if err := validateClientURIs(check.label, check.uris); err != nil {
			return err
		}
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
	proxy := newHydraPublicProxy(cfg.HydraPublicURL)
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

// newHydraPublicProxy serves Ory Hydra's public endpoints from Shauth's own
// origin. Discovery is read uncompressed so the response modes Shauth
// cannot serve are withdrawn from it before a client sees them.
func newHydraPublicProxy(target *url.URL) *httputil.ReverseProxy {
	proxy := httputil.NewSingleHostReverseProxy(target)
	director := proxy.Director
	proxy.Director = func(request *http.Request) {
		director(request)
		if request.URL.Path == discoveryPath {
			request.Header.Del("Accept-Encoding")
		}
	}
	proxy.ModifyResponse = func(response *http.Response) error {
		if response.Request != nil && response.Request.URL.Path == discoveryPath {
			return withdrawFormPostResponseMode(response)
		}
		return ensureRedirectBody(response)
	}
	return proxy
}

const discoveryPath = "/.well-known/openid-configuration"

// withdrawFormPostResponseMode removes form_post from the advertised response
// modes. Hydra answers it with a page that submits itself through an inline
// script to the application's origin, which Shauth's content security policy
// rightly forbids, so a client choosing it from discovery would stall.
func withdrawFormPostResponseMode(response *http.Response) error {
	if response.StatusCode != http.StatusOK || response.Header.Get("Content-Encoding") != "" {
		return nil
	}
	body, err := io.ReadAll(io.LimitReader(response.Body, 1<<20))
	if err != nil {
		return fmt.Errorf("read OpenID Connect discovery: %w", err)
	}
	if err := response.Body.Close(); err != nil {
		return fmt.Errorf("close OpenID Connect discovery: %w", err)
	}
	var document map[string]json.RawMessage
	if err := json.Unmarshal(body, &document); err != nil {
		return fmt.Errorf("decode OpenID Connect discovery: %w", err)
	}
	var modes []string
	if raw, ok := document["response_modes_supported"]; ok {
		if err := json.Unmarshal(raw, &modes); err != nil {
			return fmt.Errorf("decode advertised response modes: %w", err)
		}
		modes = slices.DeleteFunc(modes, func(mode string) bool { return mode == "form_post" })
		encoded, err := json.Marshal(modes)
		if err != nil {
			return err
		}
		document["response_modes_supported"] = encoded
		if body, err = json.Marshal(document); err != nil {
			return err
		}
	}
	response.Body = io.NopCloser(bytes.NewReader(body))
	response.ContentLength = int64(len(body))
	response.Header.Set("Content-Length", fmt.Sprintf("%d", len(body)))
	return nil
}

// providerAuthorize refuses the form_post response mode before Hydra sees the
// request, with a page saying why, rather than letting Hydra answer with a
// self-submitting page the browser will not run. Every other authorization
// request goes to Hydra unchanged.
func (s *Server) providerAuthorize(w http.ResponseWriter, r *http.Request) {
	mode := r.URL.Query().Get("response_mode")
	if r.Method == http.MethodPost {
		if err := r.ParseForm(); err != nil {
			s.failPage(w, r, http.StatusBadRequest, "The sign-in request could not be read.")
			return
		}
		mode = r.Form.Get("response_mode")
		// ParseForm consumed the body; Hydra reads the same parameters.
		r.Body = io.NopCloser(strings.NewReader(r.PostForm.Encode()))
		r.ContentLength = int64(len(r.PostForm.Encode()))
	}
	if mode == "form_post" {
		s.failPage(w, r, http.StatusBadRequest, "This application asked for the form_post response mode, which Shauth does not support. The application must use the default query response mode.")
		return
	}
	s.hydraPublic.ServeHTTP(w, r)
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
	mux.HandleFunc("/oauth2/auth", s.providerAuthorize)
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
	mux.HandleFunc("POST /internal/hydra/token-hook", s.hydraTokenHook)
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
	return s.traffic.observe(mux, securityHeaders(s.config.PublicURL, csrfPosts(s.config.PublicURL, s.notices(mux))))
}

func securityHeaders(publicURL *url.URL, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if publicURL.Scheme == "https" {
			// Every credential this service handles travels over this
			// origin; a browser must never be talked down to plain HTTP.
			w.Header().Set("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
		}
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
	// A page that arrives with an error moves focus to it, so a screen
	// reader announces why the submission was refused and keyboard users
	// start from the explanation.
	_, _ = w.Write([]byte(`document.addEventListener("DOMContentLoaded",function(){var notice=document.querySelector("main .notice[role=alert]");if(notice){notice.setAttribute("tabindex","-1");notice.focus()}});`))
	// A form that adds a row in place starts empty again once the server
	// accepted it. A rejection is retargeted to the form's message area and
	// keeps what was typed, so it can be corrected.
	_, _ = w.Write([]byte(`document.addEventListener("htmx:afterRequest",function(event){var form=event.detail.elt;if(form instanceof HTMLFormElement&&form.hasAttribute("data-reset-on-success")&&event.detail.successful&&!event.detail.xhr.getResponseHeader("HX-Retarget")){form.reset()}});`))
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
		if r.Method != http.MethodGet && r.Method != http.MethodHead && strings.HasPrefix(r.URL.Path, "/internal/") && r.Header.Get("Authorization") == "" {
			// The machine namespace authenticates with bearer tokens, which
			// a browser never attaches on its own. A request without one is
			// a cookie-authenticated call, and only this origin may make it.
			if origin := r.Header.Get("Origin"); origin != "" && !isPublicOrigin(publicURL, origin) {
				http.Error(w, "cross-origin request denied", http.StatusForbidden)
				return
			}
		}
		if r.Method == http.MethodPost && !providerOwnedPath(r.URL.Path) && !strings.HasPrefix(r.URL.Path, "/internal/") {
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
				if isPublicOrigin(publicURL, origin) {
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

// providerOwnedPath reports the Ory Hydra public endpoints Shauth proxies.
// Relying parties call them server to server or through standard OAuth
// browser flows; they carry no Shauth cookie and Hydra applies its own
// protections, so Shauth's form CSRF token does not apply to them.
func providerOwnedPath(path string) bool {
	return strings.HasPrefix(path, "/oauth2/") || path == "/userinfo" || strings.HasPrefix(path, "/.well-known/")
}

// isPublicOrigin reports whether an Origin header names exactly this
// service's public origin.
func isPublicOrigin(publicURL *url.URL, origin string) bool {
	parsed, err := url.Parse(origin)
	return err == nil && parsed.Scheme == publicURL.Scheme && parsed.Host == publicURL.Host && parsed.Path == "" && parsed.RawQuery == "" && parsed.Fragment == "" && parsed.User == nil
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
	next := relativeNext(r.URL.Query().Get("next"))
	// An application may ask for a fresh sign-in (OIDC prompt=login or
	// max_age). Only then does a signed-in person see this page; otherwise
	// they are already where signing in would take them.
	reauthenticate := r.URL.Query().Get("reauthenticate") == "1" && isOIDCNext(next)
	if user, _, err := s.current(r); err == nil {
		if !reauthenticate {
			http.Redirect(w, r, "/", http.StatusSeeOther)
			return
		}
		if isOIDCNext(next) {
			allowOIDCFormAction(w)
		}
		s.render(w, "login", s.view(r, "Sign in again", map[string]any{"Next": next, "Reauthenticate": true, "Username": user.Username, "EntraEnabled": s.entraOAuth != nil, "SignedIn": false}))
		return
	}
	if isOIDCNext(next) {
		allowOIDCFormAction(w)
	}
	s.render(w, "login", s.view(r, "Sign in", map[string]any{"Next": next, "Error": noticeError(r), "EntraEnabled": s.entraOAuth != nil, "SignedIn": false}))
}
func (s *Server) passwordLogin(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		s.failPage(w, r, http.StatusBadRequest, "invalid form")
		return
	}
	username := strings.TrimSpace(r.Form.Get("username"))
	next := relativeNext(r.Form.Get("next"))
	throttled, err := s.store.PasswordSignInThrottled(r.Context(), username, clientIP(r), time.Now())
	if err != nil {
		// Without the count, a password cannot safely be checked.
		observe.Errorf("check password sign-in throttle: %v", err)
		s.failPage(w, r, http.StatusServiceUnavailable, "Password sign-in is temporarily unavailable. Try again shortly, or use another sign-in method.")
		return
	}
	if throttled {
		// Refused before the password is checked, so guessing gains nothing.
		// The failure is not counted again: the limit lifts on its own once
		// the earlier failures leave the window.
		s.recordSignIn(r, identity.AuditSignInBlocked, "password", username, "", "too many recent failures")
		if isOIDCNext(next) {
			allowOIDCFormAction(w)
		}
		w.WriteHeader(http.StatusTooManyRequests)
		s.render(w, "login", s.view(r, "Sign in", map[string]any{
			"Error": fmt.Sprintf("Too many unsuccessful sign-in attempts. Wait up to %d minutes and try again, or use another sign-in method.", int(identity.PasswordFailureWindow/time.Minute)),
			"Next":  next, "Username": username, "EntraEnabled": s.entraOAuth != nil, "SignedIn": false,
		}))
		return
	}
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
		if isOIDCNext(next) {
			allowOIDCFormAction(w)
		}
		s.render(w, "login", s.view(r, "Sign in", map[string]any{
			"Error": "Invalid username or password.", "CredentialError": true, "Next": next, "Username": username,
			"EntraEnabled": s.entraOAuth != nil, "SignedIn": false,
		}))
		return
	}
	if !s.startSession(w, r, user) {
		return
	}
	s.recordSignIn(r, identity.AuditSignInSucceeded, "password", user.Username, user.ID, "")
	http.Redirect(w, r, next, http.StatusSeeOther)
}

// logoutApplication names the connected application a sign-out started from,
// when it passed its OpenID Connect client identifier, and where the person
// returns afterwards: that application's registered signed-out page, or
// Shauth's own. An identifier that names no catalog app is ignored; it only
// ever chooses between registered destinations.
func (s *Server) logoutApplication(r *http.Request) (identity.ManagedApp, string) {
	clientID := strings.TrimSpace(r.FormValue("client_id"))
	if clientID == "" || !oidcClientIDPattern.MatchString(clientID) {
		return identity.ManagedApp{}, "/signed-out"
	}
	app, err := s.store.ManagedAppByClientID(r.Context(), clientID)
	if err != nil {
		if !errors.Is(err, identity.ErrManagedAppNotFound) {
			observe.Errorf("resolve signing-out application %s: %v", clientID, err)
		}
		return identity.ManagedApp{}, "/signed-out"
	}
	return app, app.SignedOutURL
}

// logoutConfirm asks before ending every session. An application whose own
// session has already ended sends the person here with its client_id, so a
// sign-out from that application still ends the Shauth session and every
// other application's, then returns to its signed-out page.
func (s *Server) logoutConfirm(w http.ResponseWriter, r *http.Request) {
	user, _, err := s.current(r)
	app, destination := s.logoutApplication(r)
	if err != nil && app.OIDCClientID != "" {
		http.Redirect(w, r, destination, http.StatusSeeOther)
		return
	}
	if app.OIDCClientID != "" {
		// The sign-out form's redirects end on the application's origin,
		// and browsers apply form-action to every redirect a form starts.
		if target, parseErr := url.Parse(destination); parseErr == nil && target.Scheme != "" && target.Host != "" {
			w.Header().Set("Content-Security-Policy", strings.Replace(baseContentSecurityPolicy, "form-action 'self'", "form-action 'self' "+target.Scheme+"://"+target.Host, 1))
		}
	}
	s.render(w, "logout", s.view(r, "Sign out", map[string]any{"SignedIn": err == nil, "User": newUserRecord(user), "IsAdmin": err == nil && user.Role == identity.RoleAdmin, "App": app}))
}

func (s *Server) logout(w http.ResponseWriter, r *http.Request) {
	app, destination := s.logoutApplication(r)
	user, session, err := s.current(r)
	if err != nil {
		s.expireCookie(w, browserSessionCookie)
		http.Redirect(w, r, destination, http.StatusSeeOther)
		return
	}
	correlation, grant, err := s.store.CreateLogoutCorrelationGrant(r.Context(), user.ID, session.ID, "", app.OIDCClientID, time.Now())
	if errors.Is(err, identity.ErrLogoutSessionInactive) {
		// A repeated submission: the first request is already signing this
		// browser out, so this one shows the same outcome.
		s.expireCookie(w, browserSessionCookie)
		http.Redirect(w, r, destination, http.StatusSeeOther)
		return
	}
	if err != nil {
		// Without a correlation grant the connected applications cannot be
		// told which sessions ended, so the account's sessions all end here
		// instead: failing closed, not leaving them alive.
		s.expireCookie(w, browserSessionCookie)
		_, revokeErr := s.revokeUserSessions(r.Context(), user.ID, "", browserActor(r, user, session))
		observe.Errorf("logout correlation creation failed; ended every session for the account instead: correlation=%v revoke=%v", err, revokeErr)
		if revokeErr != nil {
			s.failPage(w, r, http.StatusBadGateway, "Your Shauth session ended, but signing out of connected applications did not finish. Sign out again from each application, or ask an administrator to end your sessions.")
			return
		}
		http.Redirect(w, r, destination, http.StatusSeeOther)
		return
	}
	s.expireCookie(w, browserSessionCookie)
	if correlation == "" {
		http.Redirect(w, r, destination, http.StatusSeeOther)
		return
	}
	if len(grant.BrowserHydraSessionIDs) == 0 {
		if err := s.finalizeProviderLogout(r.Context(), grant); err != nil {
			s.scheduleLogoutRecovery(r.Context(), grant, err)
			s.failPage(w, r, http.StatusBadGateway, "local sessions ended but connected application logout did not complete")
			return
		}
		http.Redirect(w, r, destination, http.StatusSeeOther)
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
	verifier := oauth2.GenerateVerifier()
	transaction, err := encodeUpstreamTransaction(upstreamTransaction{Next: relativeNext(r.URL.Query().Get("next")), Verifier: verifier})
	if err != nil {
		s.failPage(w, r, http.StatusInternalServerError, "GitHub sign-in could not start. Try again.")
		return
	}
	s.setCookie(w, &http.Cookie{Name: githubStateCookieName(state), Value: transaction, Path: "/oauth/github/callback", HttpOnly: true, Secure: !s.config.AllowInsecureCookies, SameSite: http.SameSiteLaxMode, MaxAge: 600})
	http.Redirect(w, r, s.oauth.AuthCodeURL(state, oauth2.S256ChallengeOption(verifier)), http.StatusFound)
}

// upstreamTransaction is what a browser carries, in a state-named,
// callback-scoped HttpOnly cookie, between leaving for an upstream identity
// provider and returning: where to go afterwards and the PKCE verifier (and,
// for OpenID Connect providers, the nonce) bound to this one attempt.
type upstreamTransaction struct {
	Next     string `json:"next"`
	Verifier string `json:"verifier"`
	Nonce    string `json:"nonce,omitempty"`
}

func encodeUpstreamTransaction(transaction upstreamTransaction) (string, error) {
	encoded, err := json.Marshal(transaction)
	if err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(encoded), nil
}

func decodeUpstreamTransaction(value string) (upstreamTransaction, bool) {
	var transaction upstreamTransaction
	decoded, err := base64.RawURLEncoding.DecodeString(value)
	if err != nil || json.Unmarshal(decoded, &transaction) != nil || transaction.Verifier == "" {
		return upstreamTransaction{}, false
	}
	return transaction, true
}

// upstreamSignInCancelled answers a provider that returned an OAuth error
// instead of a code, which is usually the person choosing not to continue.
// They return to the sign-in page, with their destination intact, rather
// than to a gateway error.
func (s *Server) upstreamSignInCancelled(w http.ResponseWriter, r *http.Request, provider, next string) {
	message := provider + " sign-in did not complete. Choose a sign-in method to try again."
	if r.URL.Query().Get("error") == "access_denied" {
		message = provider + " sign-in was cancelled. Choose a sign-in method to try again."
	}
	if isOIDCNext(next) {
		allowOIDCFormAction(w)
	}
	w.WriteHeader(http.StatusUnauthorized)
	s.render(w, "login", s.view(r, "Sign in", map[string]any{"Next": next, "Error": message, "EntraEnabled": s.entraOAuth != nil, "SignedIn": false}))
}
func (s *Server) githubCallback(w http.ResponseWriter, r *http.Request) {
	state := r.URL.Query().Get("state")
	cookieName, validState := validGitHubStateCookieName(state)
	cookie, err := r.Cookie(cookieName)
	if !validState || err != nil {
		s.failPage(w, r, http.StatusBadRequest, "This GitHub sign-in link has expired or was already used. Sign in again.")
		return
	}
	s.expireCookieAtPath(w, cookieName, "/oauth/github/callback")
	transaction, ok := decodeUpstreamTransaction(cookie.Value)
	if !ok {
		s.failPage(w, r, http.StatusBadRequest, "This GitHub sign-in link has expired or was already used. Sign in again.")
		return
	}
	if r.URL.Query().Get("error") != "" {
		s.recordSignIn(r, identity.AuditSignInFailed, "github", "", "", "GitHub returned "+r.URL.Query().Get("error"))
		s.upstreamSignInCancelled(w, r, "GitHub", relativeNext(transaction.Next))
		return
	}
	token, err := s.oauth.Exchange(r.Context(), r.URL.Query().Get("code"), oauth2.VerifierOption(transaction.Verifier))
	if err != nil {
		observe.Errorf("exchange GitHub authorization code: %v", err)
		s.recordSignIn(r, identity.AuditSignInFailed, "github", "", "", err.Error())
		s.failPage(w, r, http.StatusBadGateway, "GitHub authorization failed")
		return
	}
	profile, err := s.github.Profile(r.Context(), token.AccessToken)
	if err != nil {
		observe.Errorf("read GitHub identity: %v", err)
		s.recordSignIn(r, identity.AuditSignInFailed, "github", "", "", err.Error())
		s.failPage(w, r, http.StatusBadGateway, "could not read GitHub identity")
		return
	}
	role, allowed, err := s.githubRole(r.Context(), token.AccessToken, profile)
	if err != nil {
		observe.Errorf("verify GitHub organization membership for %s: %v", profile.Login, err)
		s.recordSignIn(r, identity.AuditSignInFailed, "github", profile.Login, "", err.Error())
		s.failPage(w, r, http.StatusBadGateway, "could not verify GitHub organization membership")
		return
	}
	if !allowed {
		s.recordSignIn(r, identity.AuditSignInFailed, "github", profile.Login, "", "no GitHub access rule grants this account a role")
		// The account may still hold sessions and tokens from when a rule
		// admitted it. GitHub has just said no rule does any longer, so
		// those end now rather than when they expire.
		if userID, err := s.store.GitHubUserID(r.Context(), profile.ID); err == nil {
			if _, err := s.revokeUserSessions(r.Context(), userID, "", actor{}); err != nil {
				observe.Errorf("end the sessions of deauthorized GitHub account %s: %v", profile.Login, err)
				s.failPage(w, r, http.StatusBadGateway, "This GitHub account no longer has access, but its existing sessions could not all be ended. Try again, or ask an administrator to end them.")
				return
			}
		} else if !errors.Is(err, identity.ErrUserNotFound) {
			observe.Errorf("look up deauthorized GitHub account %s: %v", profile.Login, err)
			s.failPage(w, r, http.StatusBadGateway, "This GitHub account no longer has access, and its existing sessions could not be checked. Try again shortly.")
			return
		}
		s.failPage(w, r, http.StatusForbidden, "This GitHub account is not authorized to use this service. Ask an administrator to grant it access.")
		return
	}
	user, demoted, err := s.store.FindOrCreateGitHubUser(r.Context(), profile.ID, profile.Login, profile.Email, role)
	if errors.Is(err, identity.ErrUserInactive) {
		s.recordSignIn(r, identity.AuditSignInBlocked, "github", profile.Login, "", identity.SignInReasonDisabled)
		s.failPage(w, r, http.StatusForbidden, "This account is disabled. Ask an administrator to enable it.")
		return
	}
	if err != nil {
		s.recordSignIn(r, identity.AuditSignInBlocked, "github", profile.Login, "", err.Error())
		s.failPage(w, r, http.StatusInternalServerError, "could not establish local account")
		return
	}
	if demoted {
		// Sessions and tokens issued while the account was an administrator
		// still carry that role; they end before the new session begins.
		if _, err := s.revokeUserSessions(r.Context(), user.ID, "", actor{}); err != nil {
			observe.Errorf("end the administrator sessions of demoted GitHub account %s: %v", profile.Login, err)
			s.recordSignIn(r, identity.AuditSignInFailed, "github", user.Username, user.ID, "the account's administrator sessions could not be ended")
			s.failPage(w, r, http.StatusBadGateway, "Your access changed and your previous sessions could not be ended. Try again.")
			return
		}
	}
	if !s.startSession(w, r, user) {
		return
	}
	s.recordSignIn(r, identity.AuditSignInSucceeded, "github", user.Username, user.ID, "")
	http.Redirect(w, r, relativeNext(transaction.Next), http.StatusSeeOther)
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
	verifier := oauth2.GenerateVerifier()
	cookieValue, err := encodeUpstreamTransaction(upstreamTransaction{Next: relativeNext(r.URL.Query().Get("next")), Verifier: verifier, Nonce: nonce})
	if err != nil {
		s.failPage(w, r, http.StatusInternalServerError, "Microsoft Entra ID sign-in could not start. Try again.")
		return
	}
	s.setCookie(w, &http.Cookie{Name: entraStateCookieName(state), Value: cookieValue, Path: "/oauth/entra/callback", HttpOnly: true, Secure: !s.config.AllowInsecureCookies, SameSite: http.SameSiteLaxMode, MaxAge: 600})
	http.Redirect(w, r, s.entraOAuth.AuthCodeURL(state, oauth2.SetAuthURLParam("nonce", nonce), oauth2.S256ChallengeOption(verifier)), http.StatusFound)
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
		s.failPage(w, r, http.StatusBadRequest, "This Microsoft Entra ID sign-in link has expired or was already used. Sign in again.")
		return
	}
	s.expireCookieAtPath(w, cookieName, "/oauth/entra/callback")
	transaction, ok := decodeUpstreamTransaction(cookie.Value)
	if !ok || transaction.Nonce == "" {
		s.failPage(w, r, http.StatusBadRequest, "This Microsoft Entra ID sign-in link has expired or was already used. Sign in again.")
		return
	}
	if r.URL.Query().Get("error") != "" {
		s.recordSignIn(r, identity.AuditSignInFailed, "entra", "", "", "Microsoft Entra ID returned "+r.URL.Query().Get("error"))
		s.upstreamSignInCancelled(w, r, "Microsoft Entra ID", relativeNext(transaction.Next))
		return
	}
	token, err := s.entraOAuth.Exchange(r.Context(), r.URL.Query().Get("code"), oauth2.VerifierOption(transaction.Verifier))
	if err != nil {
		observe.Errorf("exchange Microsoft Entra ID authorization code: %v", err)
		s.recordSignIn(r, identity.AuditSignInFailed, "entra", "", "", "authorization code exchange failed")
		s.failPage(w, r, http.StatusBadGateway, "Microsoft Entra ID authorization failed")
		return
	}
	rawIDToken, ok := token.Extra("id_token").(string)
	if !ok || rawIDToken == "" {
		s.recordSignIn(r, identity.AuditSignInFailed, "entra", "", "", "token response omitted the ID token")
		s.failPage(w, r, http.StatusBadGateway, "Microsoft Entra ID authorization omitted the ID token")
		return
	}
	idToken, err := s.entraVerify.Verify(r.Context(), rawIDToken)
	if err != nil {
		observe.Warnf("verify Microsoft Entra ID token: %v", err)
		s.recordSignIn(r, identity.AuditSignInFailed, "entra", "", "", "ID token verification failed")
		s.failPage(w, r, http.StatusBadGateway, "Microsoft Entra ID token verification failed")
		return
	}
	var claims entraClaims
	if err := idToken.Claims(&claims); err != nil {
		s.recordSignIn(r, identity.AuditSignInFailed, "entra", "", "", "ID token claims could not be read")
		s.failPage(w, r, http.StatusBadGateway, "Microsoft Entra ID identity claims were invalid")
		return
	}
	if subtle.ConstantTimeCompare([]byte(claims.Nonce), []byte(transaction.Nonce)) != 1 || !strings.EqualFold(claims.TenantID, s.config.EntraTenantID) || claims.ObjectID == "" || claims.Subject == "" {
		s.recordSignIn(r, identity.AuditSignInFailed, "entra", claims.PreferredUsername, "", "nonce, tenant or identity claims did not match")
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
	http.Redirect(w, r, relativeNext(transaction.Next), http.StatusSeeOther)
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
		s.failPage(w, r, http.StatusForbidden, "This sign-in request belongs to a different account. Return to the application and sign in again.")
		return
	}
	if !loginRequest.Skip {
		promptLogin, maxAge := reauthenticationDemand(loginRequest.RequestURL)
		satisfied := true
		if promptLogin {
			cookie, cookieErr := r.Cookie(reauthenticationCookie)
			satisfied = cookieErr == nil && reauthenticatedSince(cookie.Value, challenge, session.CreatedAt)
		}
		if maxAge >= 0 && time.Since(session.CreatedAt) > maxAge {
			satisfied = false
		}
		if !satisfied {
			s.setCookie(w, &http.Cookie{Name: reauthenticationCookie, Value: reauthenticationMarker(challenge, time.Now()), Path: "/oauth/login", HttpOnly: true, Secure: !s.config.AllowInsecureCookies, SameSite: http.SameSiteLaxMode, MaxAge: 600})
			http.Redirect(w, r, "/login?reauthenticate=1&next="+url.QueryEscape(r.URL.RequestURI()), http.StatusSeeOther)
			return
		}
		s.expireCookieAtPath(w, reauthenticationCookie, "/oauth/login")
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
		s.failPage(w, r, http.StatusBadGateway, "The application's authorization request could not be loaded. Return to the application and try again.")
		return
	}
	if consent.Subject != user.ID {
		s.failPage(w, r, http.StatusForbidden, consentSubjectMismatch)
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
	application := consent.ClientName
	if application == "" {
		application = consent.ClientID
	}
	s.render(w, "consent", s.view(r, "Authorize application", map[string]any{"Challenge": challenge, "Scopes": describeScopes(consent.Scopes), "Application": application, "ClientID": consent.ClientID, "SignedIn": true, "User": newUserRecord(user), "IsAdmin": user.Role == identity.RoleAdmin}))
}

// consentSubjectMismatch explains a consent challenge that belongs to a
// different account than the one signed in to this browser, for example
// after switching accounts in another tab.
const consentSubjectMismatch = "This authorization request was started by a different account than the one signed in now. Return to the application and sign in again."

type scopeDescription struct{ Code, Description string }

// describeScopes states what each requested scope releases in plain words,
// keeping the protocol name visible for people who need it.
func describeScopes(scopes []string) []scopeDescription {
	descriptions := map[string]string{
		"openid":         "Confirm who you are with your Shauth account.",
		"profile":        "See your username.",
		"email":          "See your email address and whether it is verified.",
		"offline_access": "Stay connected after you close the application, until you sign out.",
	}
	described := make([]scopeDescription, 0, len(scopes))
	for _, scope := range scopes {
		description, ok := descriptions[scope]
		if !ok {
			description = "An application-specific permission."
		}
		described = append(described, scopeDescription{Code: scope, Description: description})
	}
	return described
}

// grantableScopes keeps only the submitted scopes the request actually asked
// for, so a crafted form cannot widen the grant.
func grantableScopes(requested, submitted []string) []string {
	allowed := make(map[string]bool, len(requested))
	for _, scope := range requested {
		allowed[scope] = true
	}
	granted := make([]string, 0, len(submitted))
	seen := make(map[string]bool, len(submitted))
	for _, scope := range submitted {
		if allowed[scope] && !seen[scope] {
			seen[scope] = true
			granted = append(granted, scope)
		}
	}
	return granted
}

var oauthErrorCodePattern = regexp.MustCompile(`^[a-z_]{1,64}$`)

func (s *Server) hydraError(w http.ResponseWriter, r *http.Request) {
	code := strings.TrimSpace(r.URL.Query().Get("error"))
	// The code is shown to help support; anything that is not an OAuth
	// error code is a crafted link and is not repeated on the page.
	if !oauthErrorCodePattern.MatchString(code) {
		code = ""
	}
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
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}
	if err := r.ParseForm(); err != nil {
		s.failPage(w, r, http.StatusBadRequest, "The form could not be read. Go back and try again.")
		return
	}
	challenge := r.Form.Get("challenge")
	consent, err := s.hydraConsentRequest(r.Context(), challenge)
	if err != nil {
		s.failPage(w, r, http.StatusBadGateway, "The application's authorization request could not be loaded. Return to the application and try again.")
		return
	}
	if consent.Subject != user.ID {
		s.failPage(w, r, http.StatusForbidden, consentSubjectMismatch)
		return
	}
	if r.Form.Get("decision") == "deny" {
		redirect, err := s.hydraAccept(r.Context(), "/admin/oauth2/auth/requests/consent/reject", challenge, map[string]any{"error": "access_denied", "error_description": "The user denied the request."})
		if err != nil {
			s.failPage(w, r, http.StatusBadGateway, "Your refusal could not be sent to the application. Close this page; no access was granted.")
			return
		}
		http.Redirect(w, r, redirect, http.StatusFound)
		return
	}
	scopes := grantableScopes(consent.Scopes, r.Form["scope"])
	if len(scopes) == 0 {
		s.failPage(w, r, http.StatusBadRequest, "No requested permission was granted. Return to the application and try again.")
		return
	}
	redirect, err := s.acceptHydraConsent(r.Context(), challenge, scopes, user)
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
	http.Redirect(w, r, redirect, http.StatusFound)
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
		s.rejectMismatchedLogout(w, r, challenge, err)
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
		s.rejectMismatchedLogout(w, r, challenge, err)
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

// rejectMismatchedLogout ends a logout request that names a different
// provider session than this browser's. The correlated sessions are already
// scheduled for revocation; Hydra's request is refused so it does not wait
// on an answer, and the person sees a navigable page.
func (s *Server) rejectMismatchedLogout(w http.ResponseWriter, r *http.Request, challenge string, cause error) {
	observe.Warnf("refuse mismatched OAuth logout: %v", cause)
	if err := s.hydraRejectLogout(r.Context(), challenge); err != nil {
		observe.Errorf("reject mismatched OAuth logout: %v", err)
	}
	s.failPage(w, r, http.StatusBadRequest, "This sign-out request belongs to a different browser session. Your sessions here are being ended; sign out again from the application if it still shows you as signed in.")
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
	// The configured teams only seed the first rules; what admits people
	// is the rule list as it stands now.
	mappings, err := s.store.ListGitHubRoleMappings(r.Context())
	if err != nil {
		observe.Errorf("count GitHub access rules: %v", err)
		s.failPage(w, r, http.StatusInternalServerError, "The identity sources could not be loaded.")
		return
	}
	s.render(w, "connectors", s.view(r, "Identity sources", map[string]any{
		"SignedIn": true, "IsAdmin": true, "Connectors": s.connectors(), "GitHubRuleCount": len(mappings),
	}))
}

type managedAppView struct {
	identity.ManagedApp
	// CSRF lets the re-validation control render inside a component that is
	// also served standalone as an HTMX fragment, where the page root is
	// not in scope.
	CSRF string
	// ReturnTo is the page the re-validation control returns to, so an
	// operator stays where they started.
	ReturnTo string
	// DeploymentOwned marks an app the bootstrap configuration declares;
	// it is changed there, not removed from the catalog.
	DeploymentOwned bool
	// Operator is set for administrators, who may re-run the checks;
	// everyone else sees their results only.
	Operator               bool
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
	return s.viewsWithStatus(ctx, apps, validations), nil
}

// appViewBySlug describes one application, probing only its own health
// endpoint.
func (s *Server) appViewBySlug(ctx context.Context, slug string) (managedAppView, error) {
	apps, err := s.store.ListManagedApps(ctx)
	if err != nil {
		return managedAppView{}, err
	}
	for _, app := range apps {
		if app.Slug != slug {
			continue
		}
		runs, err := s.store.LatestAppValidationRunsForApp(ctx, app.ID)
		if err != nil {
			return managedAppView{}, err
		}
		return s.viewsWithStatus(ctx, []identity.ManagedApp{app}, map[string]map[string]identity.AppValidationRun{app.ID: runs})[0], nil
	}
	return managedAppView{}, identity.ErrManagedAppNotFound
}

// viewsWithStatus probes each application's health endpoint concurrently,
// a few at a time: probed one after another, a handful of unreachable
// applications would outlast the server's response deadline.
func (s *Server) viewsWithStatus(ctx context.Context, apps []identity.ManagedApp, validations map[string]map[string]identity.AppValidationRun) []managedAppView {
	views := make([]managedAppView, len(apps))
	limit := make(chan struct{}, 8)
	var probes sync.WaitGroup
	for index, app := range apps {
		views[index] = newManagedAppView(app)
		probes.Add(1)
		limit <- struct{}{}
		go func(view *managedAppView, app identity.ManagedApp) {
			defer probes.Done()
			defer func() { <-limit }()
			if status, err := s.managedApps.Status(ctx, app); err != nil {
				view.StatusError = err.Error()
			} else {
				view.Healthy, view.StatusCode = status.Healthy, status.StatusCode
			}
		}(&views[index], app)
		if appResults := validations[app.ID]; appResults != nil {
			if run, ok := appResults[identity.ValidationFromShauth]; ok {
				views[index].FromShauth = newAppValidationRunView(run)
			}
			if run, ok := appResults[identity.ValidationFromApp]; ok {
				views[index].FromApp = newAppValidationRunView(run)
			}
		}
		views[index].NeedsPoll = validationNeedsPoll(views[index].FromShauth) || validationNeedsPoll(views[index].FromApp)
	}
	probes.Wait()
	return views
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
		apps[index].ReturnTo = "/apps"
		apps[index].Operator = user.Role == identity.RoleAdmin
	}
	setMonitoringPageURLs(apps, user.Role)
	s.render(w, "apps", s.view(r, "Apps", map[string]any{"SignedIn": true, "User": newUserRecord(user), "Apps": apps, "IsAdmin": user.Role == identity.RoleAdmin, "Error": noticeError(r), "Done": noticeDone(r)}))
}

func (s *Server) appValidationStatus(w http.ResponseWriter, r *http.Request) {
	// The page polls this every few seconds on its own. Polling must not
	// count as the person being active, or an unattended tab would keep the
	// session alive forever; once the session has ended the page is sent to
	// sign in instead of polling a refusal it never shows.
	if _, _, err := s.peekCurrent(r); err != nil {
		if r.Header.Get("HX-Request") == "true" {
			w.Header().Set("HX-Redirect", "/login?next="+url.QueryEscape("/apps"))
		}
		s.failPage(w, r, http.StatusUnauthorized, "Your session has ended. Sign in again to continue.")
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
	s.renderAdminApps(w, r, http.StatusOK, noticeError(r), identity.ManagedApp{})
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
		apps[index].ReturnTo = "/admin/apps"
		apps[index].Operator = true
		apps[index].DeploymentOwned = s.isBootstrapSlug(apps[index].Slug)
	}
	if status != http.StatusOK {
		w.WriteHeader(status)
	}
	s.render(w, "admin-apps", s.view(r, "Connected apps", map[string]any{
		"SignedIn": true, "IsAdmin": true, "Apps": apps,
		"Error": message, "Done": noticeDone(r), "Form": form,
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
	s.redirectWithNotice(w, r, "/admin/apps", false, "Registered the application "+created.Name+".")
}

func (s *Server) validateApp(w http.ResponseWriter, r *http.Request) {
	user, _, err := s.current(r)
	if err != nil {
		s.failPage(w, r, http.StatusUnauthorized, "sign-in required")
		return
	}
	if user.Role != identity.RoleAdmin {
		// Each run signs a dedicated identity in and out of two
		// applications; starting them is an operator's decision.
		s.failPage(w, r, http.StatusForbidden, "Only administrators can run the sign-in checks again.")
		return
	}
	// The control names the page it sits on; Shauth sends no Referer, so
	// that cannot be inferred. Only the catalog and, for administrators,
	// the application pages are accepted, for success and failure alike.
	destination := "/apps"
	if requested := r.FormValue("return_to"); strictRelativeNext(requested) && user.Role == identity.RoleAdmin && (requested == "/admin/apps" || strings.HasPrefix(requested, "/admin/apps/")) {
		destination = requested
	}
	if _, err := s.enqueueAppValidations(r.Context(), identity.ManagedAppRef{ID: r.PathValue("id")}, s.currentActor(r)); err != nil {
		s.failOperation(w, r, "queue application validation", destination, err)
		return
	}
	s.redirectWithNotice(w, r, destination+"#validation-"+url.PathEscape(r.PathValue("id")), false, "Both checks were queued. Their results appear here as they finish.")
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
		OIDCClientID: view.OIDCClientID, CreatedAt: view.CreatedAt.UTC(),
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
	// These links sign a browser in; who minted them, and for which run, is
	// part of the sign-in record.
	s.record(r.Context(), tokenActor(r), identity.AuditValidationBootstrapsIssued, "", map[string]any{"run_id": request.RunID, "count": len(tokens)})
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
		s.recordSignIn(r, identity.AuditSignInFailed, "validator_bootstrap", "", "", "bootstrap link unavailable")
		s.failPage(w, r, http.StatusGone, "validation browser bootstrap is unavailable")
		return
	}
	if !strictRelativeNext(next) {
		s.recordSignIn(r, identity.AuditSignInFailed, "validator_bootstrap", user.Username, user.ID, "bootstrap destination is not local")
		s.failPage(w, r, http.StatusGone, "validation browser bootstrap is unavailable")
		return
	}
	if !s.startSession(w, r, user) {
		return
	}
	s.recordSignIn(r, identity.AuditSignInSucceeded, "validator_bootstrap", user.Username, user.ID, "")
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
	s.redirectWithNotice(w, r, "/admin/apps", false, "The application was removed.")
}

func (s *Server) adminOIDCClients(w http.ResponseWriter, r *http.Request) {
	if !s.requireAdmin(w, r) {
		return
	}
	s.renderOIDCClients(w, r, http.StatusOK, noticeError(r), oidcClientInput{})
}

func (s *Server) renderOIDCClients(w http.ResponseWriter, r *http.Request, status int, message string, form oidcClientInput) {
	clients, err := s.listOIDCClients(r.Context())
	if err != nil {
		failureStatus, failureMessage := describeOperationFailure("list OAuth clients", err)
		s.failPage(w, r, failureStatus, failureMessage)
		return
	}
	apps, err := s.store.ListManagedApps(r.Context())
	if err != nil {
		observe.Errorf("list applications for the OAuth client page: %v", err)
		s.failPage(w, r, http.StatusInternalServerError, "The OAuth clients could not be loaded.")
		return
	}
	usedBy := make(map[string]string, len(apps))
	for _, app := range apps {
		usedBy[app.OIDCClientID] = app.Name
	}
	for index := range clients {
		clients[index].DeploymentOwned = s.isBootstrapClient(clients[index].ID)
		clients[index].UsedBy = usedBy[clients[index].ID]
	}
	if status != http.StatusOK {
		w.WriteHeader(status)
	}
	s.render(w, "oidc-clients", s.view(r, "OAuth clients", map[string]any{
		"SignedIn": true, "IsAdmin": true, "Clients": clients,
		"Error": message, "Done": noticeDone(r), "Form": form,
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
	s.redirectWithNotice(w, r, "/admin/clients", false, "Registered the OAuth client "+input.ID+".")
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
	s.redirectWithNotice(w, r, "/admin/clients", false, "Deleted the OAuth client "+clientID+".")
}

// errHydraClientNotFound reports that Ory Hydra has no client with the
// requested identifier.
var errHydraClientNotFound = errors.New("OAuth client not found")

func (s *Server) deleteHydraClient(ctx context.Context, clientID string) error {
	endpoint := s.hydraClientURL(clientID, "")
	request, err := http.NewRequestWithContext(ctx, http.MethodDelete, endpoint.String(), nil)
	if err != nil {
		return err
	}
	response, err := s.doProvider(request)
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
	s.renderSessionPolicy(w, r, http.StatusOK, noticeError(r), newSessionPolicyRecord(policy))
}

// renderSessionPolicy draws the policy form from a record, so a rejected
// submission shows what the operator typed rather than reverting to the
// stored policy and hiding their edit.
func (s *Server) renderSessionPolicy(w http.ResponseWriter, r *http.Request, status int, message string, policy sessionPolicyRecord) {
	s.renderSessionPolicyForm(w, r, status, message, policy, nil)
}

// renderSessionPolicyForm also redraws exactly what was submitted, including
// a value that could not be read as a number.
func (s *Server) renderSessionPolicyForm(w http.ResponseWriter, r *http.Request, status int, message string, policy sessionPolicyRecord, submitted url.Values) {
	values := map[string]string{}
	for _, field := range sessionPolicyFields(&policy) {
		if submitted != nil {
			values[field.name] = submitted.Get(field.name)
		} else {
			values[field.name] = strconv.FormatInt(*field.target, 10)
		}
	}
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
	s.render(w, "session-policy", s.view(r, "Session time limits", map[string]any{
		"SignedIn": true, "IsAdmin": true, "Policy": policy, "Values": values,
		"Error": message, "Done": noticeDone(r),
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
		s.renderSessionPolicyForm(w, r, http.StatusBadRequest, err.Error(), request, r.Form)
		return
	}
	if _, err := s.updateSessionPolicy(r.Context(), request, s.currentActor(r)); err != nil {
		status, message := describeOperationFailure("update session policy", err)
		s.renderSessionPolicyForm(w, r, status, message, request, r.Form)
		return
	}
	s.redirectWithNotice(w, r, "/admin/session-policy", false, "Session time limits were saved and applied to every OAuth client.")
}

// parseSessionPolicyForm converts the form into the same record the JSON
// transport decodes. Validation belongs to the shared operation, so both
// transports enforce one rule set.
func parseSessionPolicyForm(values url.Values) (sessionPolicyRecord, error) {
	var record sessionPolicyRecord
	var problems []string
	// Every field is read, so one rejected value does not hide another, and
	// each is named as its label reads.
	for _, field := range sessionPolicyFields(&record) {
		value, err := strconv.ParseInt(strings.TrimSpace(values.Get(field.name)), 10, 64)
		if err != nil || value <= 0 {
			problems = append(problems, field.label)
			continue
		}
		*field.target = value
	}
	if len(problems) > 0 {
		return record, identity.Invalid("%s must be a positive whole number", strings.Join(problems, ", "))
	}
	return record, nil
}

// sessionPolicyFields names each form field with the label the form shows.
func sessionPolicyFields(record *sessionPolicyRecord) []struct {
	name, label string
	target      *int64
} {
	return []struct {
		name, label string
		target      *int64
	}{
		{"browser_absolute_hours", "Browser absolute lifetime (hours)", &record.BrowserAbsoluteHours},
		{"browser_idle_minutes", "Browser idle timeout (minutes)", &record.BrowserIdleMinutes},
		{"oidc_sso_hours", "OIDC SSO lifetime (hours)", &record.OIDCSSOHours},
		{"access_token_minutes", "Access token lifetime (minutes)", &record.AccessTokenMinutes},
		{"id_token_minutes", "ID token lifetime (minutes)", &record.IDTokenMinutes},
		{"refresh_token_hours", "Refresh token lifetime (hours)", &record.RefreshTokenHours},
	}
}

// hydraClientURL addresses one client in Hydra's administration API. The
// identifier is one escaped path segment: escaping it into Path alone would
// be escaped a second time, and leaving it raw would let a "/" or ".." in a
// client registered directly in Hydra address a different resource.
func (s *Server) hydraClientURL(clientID, suffix string) *url.URL {
	return s.config.HydraAdminURL.ResolveReference(&url.URL{
		Path:    "/admin/clients/" + clientID + suffix,
		RawPath: "/admin/clients/" + url.PathEscape(clientID) + suffix,
	})
}

// hydraClientLifespans sets the policy's token lifetimes for both grants an
// application uses. Hydra applies a client's authorization-code lifespans only
// to the first tokens; every refresh uses the refresh-token-grant lifespans and
// otherwise falls back to Hydra's global defaults, which would quietly undo
// the policy from the first refresh on.
func hydraClientLifespans(policy identity.SessionPolicy) map[string]string {
	lifespans := map[string]string{}
	for _, grant := range []string{"authorization_code_grant", "refresh_token_grant"} {
		lifespans[grant+"_access_token_lifespan"] = policy.AccessTokenLifetime.String()
		lifespans[grant+"_id_token_lifespan"] = policy.IDTokenLifetime.String()
		lifespans[grant+"_refresh_token_lifespan"] = policy.RefreshTokenLifetime.String()
	}
	return lifespans
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
		clientEndpoint := s.hydraClientURL(client.ID, "/lifespans")
		update, err := http.NewRequestWithContext(ctx, http.MethodPut, clientEndpoint.String(), bytes.NewReader(body))
		if err != nil {
			return err
		}
		update.Header.Set("Content-Type", "application/json")
		updated, err := s.doProvider(update)
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

// createHydraClient registers a client with the lifetimes of the current
// session policy. The policy lock keeps a concurrent policy change from
// updating every existing client while this one is created with the old
// lifetimes.
func (s *Server) createHydraClient(ctx context.Context, input oidcClientInput) error {
	return s.store.WithSessionPolicyLock(ctx, func(ctx context.Context) error {
		return s.writeHydraClient(ctx, input)
	})
}

func (s *Server) writeHydraClient(ctx context.Context, input oidcClientInput) error {
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
	response, err := s.doProvider(request)
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
	}
	for name, lifespan := range hydraClientLifespans(policy) {
		payload[name] = lifespan
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

// updateHydraClient replaces a client's registration, under the same policy
// lock as createHydraClient.
func (s *Server) updateHydraClient(ctx context.Context, input oidcClientInput) error {
	return s.store.WithSessionPolicyLock(ctx, func(ctx context.Context) error {
		return s.rewriteHydraClient(ctx, input)
	})
}

func (s *Server) rewriteHydraClient(ctx context.Context, input oidcClientInput) error {
	policy, err := s.store.SessionPolicy(ctx)
	if err != nil {
		return err
	}
	body, err := marshalHydraClient(input, policy)
	if err != nil {
		return err
	}
	endpoint := s.hydraClientURL(input.ID, "")
	request, err := http.NewRequestWithContext(ctx, http.MethodPut, endpoint.String(), bytes.NewReader(body))
	if err != nil {
		return err
	}
	request.Header.Set("Content-Type", "application/json")
	response, err := s.doProvider(request)
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
	s.renderGitHubMappings(w, r, http.StatusOK, noticeError(r), githubRoleMappingCreateRequest{Kind: "team", Role: string(identity.RoleDeveloper)})
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
	s.render(w, "github-mappings", s.view(r, "GitHub access rules", map[string]any{
		"SignedIn": true, "IsAdmin": true, "Mappings": records,
		"Error": message, "Done": noticeDone(r), "Form": form,
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
	notice := "Added the access rule for " + mapping.Target + "."
	if mapping.GitHubUserID > 0 {
		notice = fmt.Sprintf("Added the access rule for %s, bound to GitHub ID %d.", mapping.Target, mapping.GitHubUserID)
	}
	s.redirectWithNotice(w, r, "/admin/github", false, notice)
}
func (s *Server) adminDeleteGitHubMapping(w http.ResponseWriter, r *http.Request) {
	if !s.requireAdmin(w, r) {
		return
	}
	if err := s.deleteGitHubMapping(r.Context(), r.PathValue("id"), s.currentActor(r)); err != nil {
		s.failOperation(w, r, "delete GitHub role mapping", "/admin/github", err)
		return
	}
	s.redirectWithNotice(w, r, "/admin/github", false, "The access rule was removed. Accounts it may have admitted were signed out and are checked again at their next sign-in.")
}
func (s *Server) adminUsers(w http.ResponseWriter, r *http.Request) {
	if !s.requireAdmin(w, r) {
		return
	}
	s.renderUsers(w, r, http.StatusOK, noticeError(r), userCreateRequest{Role: string(identity.RoleDeveloper)})
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
	s.render(w, "users", s.view(r, "Users and local accounts", map[string]any{
		"SignedIn": true, "IsAdmin": true, "Users": records, "Query": query,
		"Error": message, "Done": noticeDone(r), "Form": form,
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
		status, message := describeOperationFailure("create user", err)
		if r.Header.Get("HX-Request") == "true" && status < http.StatusInternalServerError {
			// HTMX does not swap an error status, so a rejection is
			// answered with 200 and redirected into the form's live
			// region; the operator's typed values stay where they are.
			w.Header().Set("HX-Retarget", "#user-create-feedback")
			w.Header().Set("HX-Reswap", "innerHTML")
			s.render(w, "user-create-rejected", message)
			return
		}
		// Without HTMX, the page is drawn again with the reason and the
		// operator's typed values still in place.
		s.renderUsers(w, r, status, message, request)
		return
	}
	if r.Header.Get("HX-Request") == "true" {
		s.render(w, "user-created", newUserRecord(user))
		return
	}
	s.redirectWithNotice(w, r, "/admin/users", false, "Created the account "+user.Username+".")
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
	form := invitationForm{Email: r.Form.Get("email"), Role: r.Form.Get("role")}
	invitation, err := s.createInvitation(r.Context(), form.Email, form.Role, actor{UserID: inviter.ID})
	if err != nil {
		// A rejected invitation is shown on the same page with what was
		// typed, so a mistyped address is corrected rather than retyped.
		status, message := describeOperationFailure("create invitation", err)
		if status >= http.StatusInternalServerError {
			s.failPage(w, r, status, message)
			return
		}
		s.renderInvitations(w, r, status, message, form)
		return
	}
	s.redirectWithNotice(w, r, "/admin/invitations", false, "Invitation sent to "+invitation.Email+".")
}

// invitationForm is what the invitation form submitted.
type invitationForm struct {
	Email string
	Role  string
}

func (s *Server) adminInvitations(w http.ResponseWriter, r *http.Request) {
	if !s.requireAdmin(w, r) {
		return
	}
	s.renderInvitations(w, r, http.StatusOK, noticeError(r), invitationForm{Role: string(identity.RoleDeveloper)})
}

func (s *Server) renderInvitations(w http.ResponseWriter, r *http.Request, status int, message string, form invitationForm) {
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
	if status != http.StatusOK {
		w.WriteHeader(status)
	}
	s.render(w, "invitations", s.view(r, "Invitations", map[string]any{
		"SignedIn": true, "IsAdmin": true, "Invitations": records, "Form": form,
		"Error": message, "Done": noticeDone(r),
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
	s.redirectWithNotice(w, r, "/admin/invitations", false, "The invitation was withdrawn.")
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
	s.redirectWithNotice(w, r, account, false, "The account was disabled and every session ended.")
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
	s.redirectWithNotice(w, r, account, false, "The account was enabled. It must sign in again.")
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
		views[index].ReturnTo = "/admin/apps/" + url.PathEscape(r.PathValue("slug"))
		views[index].Operator = true
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
			"Done": noticeDone(r), "Error": noticeError(r),
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
	page, err := requestedPage(r)
	if err != nil {
		page = identity.Page{}
	}
	sessions, total, err := s.store.ListSessions(r.Context(), userID, page)
	if err != nil {
		observe.Errorf("list sessions for %s: %v", userID, err)
		s.failPage(w, r, http.StatusInternalServerError, "The sessions for this account could not be loaded.")
		return
	}
	records := make([]sessionRecord, 0, len(sessions))
	hasActive := total > len(sessions)
	for _, session := range sessions {
		records = append(records, newSessionRecord(session))
		hasActive = hasActive || session.Active
	}
	s.render(w, "sessions", s.view(r, user.Username+" · sessions", map[string]any{
		"SignedIn": true, "IsAdmin": true, "Sessions": records, "UserID": userID, "HasActive": hasActive,
		"Account": newUserRecord(user), "Error": noticeError(r), "Done": noticeDone(r),
		"Page": browserPage(r, page, len(records), total),
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
	s.redirectWithNotice(w, r, account, false, "Every session for this account was ended.")
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
	// The account is named in the request body (JSON or a form), which keeps
	// an email address out of URLs and therefore out of access logs. The
	// query string is still read for existing callers.
	var target struct {
		UserID string `json:"user_id"`
		Email  string `json:"email"`
	}
	if strings.HasPrefix(r.Header.Get("Content-Type"), "application/json") {
		if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4096)).Decode(&target); err != nil {
			writeOperationFailure(w, "reset account sessions", identity.Invalid("the request body must be a JSON object with user_id or email"))
			return
		}
	} else {
		target.UserID, target.Email = r.FormValue("user_id"), r.FormValue("email")
	}
	userID, err := s.revokeUserSessions(r.Context(),
		strings.TrimSpace(target.UserID), strings.TrimSpace(target.Email), tokenActor(r))
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
	s.redirectWithNotice(w, r, destination, false, "The session was ended.")
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
	response, err := s.doProvider(request)
	if err != nil {
		return err
	}
	defer response.Body.Close()
	// A login session Hydra no longer holds is already revoked.
	if response.StatusCode != http.StatusNoContent && response.StatusCode != http.StatusNotFound {
		return fmt.Errorf("Hydra login session deletion returned HTTP %d", response.StatusCode)
	}
	return nil
}

func (s *Server) revokeHydraSessions(ctx context.Context, subject string) error {
	sessionIDs, err := s.store.UserHydraLoginSessionIDs(ctx, subject)
	if err != nil {
		return err
	}
	// Each session is revoked by sid, because only that delivers back-channel
	// logout to the applications; a long-lived account can have many, so
	// they are revoked through the same bounded pool as browser logout.
	if err := s.revokeOtherHydraSessions(ctx, sessionIDs); err != nil {
		return err
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
		response, err := s.doProvider(request)
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
	Subject        string   `json:"subject"`
	Client         struct {
		ID   string `json:"client_id"`
		Name string `json:"client_name"`
	} `json:"client"`
}

type hydraConsentRequest struct {
	ClientID       string
	ClientName     string
	Subject        string
	Scopes         []string
	LoginSessionID string
}

func (s *Server) hydraConsentRequest(ctx context.Context, challenge string) (hydraConsentRequest, error) {
	endpoint := s.config.HydraAdminURL.ResolveReference(&url.URL{Path: "/admin/oauth2/auth/requests/consent", RawQuery: "consent_challenge=" + url.QueryEscape(challenge)})
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint.String(), nil)
	if err != nil {
		return hydraConsentRequest{}, err
	}
	response, err := s.doProvider(request)
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
	return hydraConsentRequest{ClientID: consent.Client.ID, ClientName: consent.Client.Name, Subject: consent.Subject, Scopes: consent.RequestedScope, LoginSessionID: consent.LoginSessionID}, nil
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

// githubUserRuleMatches reports whether a user access rule names the signed-in
// account. A bound rule matches only its numeric account ID, so a login that
// is renamed and later claimed by someone else gains nothing. A rule recorded
// before IDs were kept matches its login once, and is bound to that account.
func (s *Server) githubUserRuleMatches(ctx context.Context, mapping identity.GitHubRoleMapping, profile githubapi.Profile) bool {
	if mapping.GitHubUserID > 0 {
		return mapping.GitHubUserID == profile.ID
	}
	if profile.ID <= 0 || !strings.EqualFold(mapping.Target, profile.Login) {
		return false
	}
	bound, err := s.store.BindGitHubUserMapping(ctx, mapping.ID, profile.ID)
	if err != nil {
		observe.Errorf("bind GitHub user rule %s: %v", mapping.ID, err)
		return false
	}
	if !bound {
		// Another rule already names this account, or a concurrent sign-in
		// bound this one; either way the other rule decides.
		return false
	}
	s.record(ctx, actor{}, identity.AuditGitHubMappingBound, "", map[string]any{
		"mapping_id": mapping.ID, "target": mapping.Target, "github_user_id": profile.ID,
	})
	return true
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
		matches := (mapping.Kind == "user" && s.githubUserRuleMatches(ctx, mapping, profile)) ||
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

// doProvider sends a request to Ory Hydra or another dependency. A transport
// failure names the endpoint without its query string: those carry login,
// consent and logout challenges, and failures are written to the service
// log, which administrators and the logs API can read.
func (s *Server) doProvider(request *http.Request) (*http.Response, error) {
	response, err := s.httpClient.Do(request)
	var failure *url.Error
	if errors.As(err, &failure) {
		if target, parseErr := url.Parse(failure.URL); parseErr == nil {
			target.RawQuery = ""
			target.Fragment = ""
			failure.URL = target.String()
		} else {
			failure.URL = "(unparseable URL)"
		}
	}
	return response, err
}

// peekCurrent identifies the signed-in person without recording activity.
func (s *Server) peekCurrent(r *http.Request) (identity.User, identity.Session, error) {
	cookie, err := r.Cookie(browserSessionCookie)
	if err != nil {
		return identity.User{}, identity.Session{}, err
	}
	return s.store.PeekCurrentUser(r.Context(), cookie.Value, time.Now())
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
	s.record(r.Context(), visitorActor(r), eventType, subjectUserID, details)
}

func (s *Server) startSession(w http.ResponseWriter, r *http.Request, user identity.User) bool {
	// A browser holds one Shauth session. Signing in again replaces the
	// previous one instead of leaving it alive, unseen, behind an
	// overwritten cookie. Switching to another account also ends the
	// previous person's application sessions. Re-authenticating as the same
	// person (for an application's prompt=login) keeps them: Ory Hydra's
	// login session for this browser is rebound to the new browser session
	// the next time an application signs in.
	if previousUser, previousSession, err := s.current(r); err == nil {
		if previousUser.ID != user.ID {
			if _, err := s.revokeSession(r.Context(), previousSession.ID, browserActor(r, previousUser, previousSession)); err != nil && !errors.Is(err, identity.ErrActiveSessionNotFound) {
				observe.Errorf("end the previous account's session while switching accounts: %v", err)
			}
		} else if err := s.store.RevokeSession(r.Context(), previousSession.ID, time.Now()); err != nil && !errors.Is(err, identity.ErrActiveSessionNotFound) {
			observe.Errorf("replace the browser session on a repeated sign-in: %v", err)
		}
	}
	raw, session, err := s.store.CreateSession(r.Context(), user.ID, r.UserAgent(), clientIP(r), time.Now())
	if err != nil {
		s.failPage(w, r, http.StatusInternalServerError, "Your session could not be started. Try signing in again.")
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

// A notice is the one-line outcome of a form submission ("Created the account
// ada."), shown once on the page the submission redirects to. It travels in a
// short-lived HttpOnly cookie that only this server sets, bound to the
// destination path, rather than in the URL: a query string would let anyone
// put their own words on a Shauth page with a crafted link.
type notice struct {
	Path    string `json:"path"`
	Failure bool   `json:"failure,omitempty"`
	Message string `json:"message"`
}

type noticeKey struct{}

// redirectWithNotice ends a form submission by redirecting to destination,
// which then shows message once.
func (s *Server) redirectWithNotice(w http.ResponseWriter, r *http.Request, destination string, failure bool, message string) {
	target, err := url.Parse(destination)
	if err == nil {
		encoded, encodeErr := json.Marshal(notice{Path: target.Path, Failure: failure, Message: message})
		if encodeErr == nil {
			s.setCookie(w, &http.Cookie{Name: noticeCookie, Value: base64.RawURLEncoding.EncodeToString(encoded), Path: "/", HttpOnly: true, Secure: !s.config.AllowInsecureCookies, SameSite: http.SameSiteLaxMode, MaxAge: 60})
		}
	}
	http.Redirect(w, r, destination, http.StatusSeeOther)
}

// notices consumes a pending notice when the browser arrives at the page it
// was written for, so it is shown exactly once.
func (s *Server) notices(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		cookie, err := r.Cookie(noticeCookie)
		if err != nil || r.Method != http.MethodGet || r.Header.Get("HX-Request") != "" {
			next.ServeHTTP(w, r)
			return
		}
		var pending notice
		decoded, decodeErr := base64.RawURLEncoding.DecodeString(cookie.Value)
		if decodeErr != nil || json.Unmarshal(decoded, &pending) != nil {
			s.expireCookie(w, noticeCookie)
			next.ServeHTTP(w, r)
			return
		}
		if pending.Path != r.URL.Path {
			next.ServeHTTP(w, r)
			return
		}
		s.expireCookie(w, noticeCookie)
		next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), noticeKey{}, pending)))
	})
}

// noticeDone and noticeError report the notice this request consumed.
func noticeDone(r *http.Request) string {
	if pending, ok := r.Context().Value(noticeKey{}).(notice); ok && !pending.Failure {
		return pending.Message
	}
	return ""
}

func noticeError(r *http.Request) string {
	if pending, ok := r.Context().Value(noticeKey{}).(notice); ok && pending.Failure {
		return pending.Message
	}
	return ""
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
	// Outcome messages come from many code paths, some phrased as fragments
	// ("could not complete the request"); every banner reads as a sentence.
	for _, key := range []string{"Error", "Done"} {
		if message, ok := data[key].(string); ok {
			data[key] = asSentence(message)
		}
	}
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
	// Every signed-in page names who is signed in, so a shared or
	// forgotten browser is recognised before anything is done with it.
	if signedIn, _ := data["SignedIn"].(bool); signedIn {
		if user, _, err := s.peekCurrent(r); err == nil {
			data["Viewer"] = user.Username
		}
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
		// Stored values shown as the interface names them everywhere.
		"roleLabel": func(role any) string {
			switch fmt.Sprint(role) {
			case string(identity.RoleAdmin):
				return "Administrator"
			case string(identity.RoleDeveloper):
				return "Developer"
			default:
				return fmt.Sprint(role)
			}
		},
		"ruleKindLabel": func(kind string) string {
			switch kind {
			case "user":
				return "GitHub user"
			case "organization":
				return "GitHub organization"
			case "team":
				return "GitHub team"
			default:
				return kind
			}
		},
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
		// navCurrent marks a navigation link: "page" on the page itself,
		// "true" anywhere inside its section, so a person on
		// /admin/users/{id} still sees where they are.
		"navCurrent": func(value any, section string) string {
			path, _ := value.(string)
			switch {
			case path == section:
				return "page"
			case section != "/" && strings.HasPrefix(path, section+"/"):
				return "true"
			}
			return ""
		},
		// lines writes a list back into the textarea it was typed into,
		// one entry per line.
		"lines": func(value any) string {
			values, _ := value.([]string)
			return strings.Join(values, "\n")
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
	heading := errorHeading(status)
	data := s.view(r, heading, map[string]any{"Status": status, "StatusText": heading, "Message": asSentence(message)})
	if err := s.templates.ExecuteTemplate(&page, "error", data); err != nil {
		observe.Errorf("render error page: %v", err)
		http.Error(w, message, status)
		return
	}
	w.WriteHeader(status)
	_, _ = page.WriteTo(w)
}

// errorHeading names a failure the way a person experiences it, rather than
// by its HTTP status text.
func errorHeading(status int) string {
	switch {
	case status == http.StatusNotFound:
		return "Page not found"
	case status == http.StatusUnauthorized:
		return "Sign in to continue"
	case status == http.StatusForbidden:
		return "You don't have access to this"
	case status == http.StatusConflict:
		return "This changed before it could finish"
	case status == http.StatusGone:
		return "This link is no longer valid"
	case status == http.StatusTooManyRequests:
		return "Too many attempts"
	case status >= 400 && status < 500:
		return "This request couldn't be completed"
	case status == http.StatusBadGateway || status == http.StatusServiceUnavailable || status == http.StatusGatewayTimeout:
		return "A connected service didn't respond"
	default:
		return "Something went wrong on our side"
	}
}

// asSentence presents an error message as a sentence: capitalised and
// closed with punctuation, whichever code path produced it.
func asSentence(message string) string {
	message = strings.TrimSpace(message)
	if message == "" {
		return message
	}
	first, size := utf8.DecodeRuneInString(message)
	message = string(unicode.ToUpper(first)) + message[size:]
	if last, _ := utf8.DecodeLastRuneInString(message); !strings.ContainsRune(".!?", last) {
		message += "."
	}
	return message
}

// failOperation reports a failed administration operation to a browser
// caller, using the same classification the JSON transport uses. Rejections
// return the operator to the form with an explanation; failures render a
// styled error page.
func (s *Server) failOperation(w http.ResponseWriter, r *http.Request, action, back string, err error) {
	status, message := describeOperationFailure(action, err)
	if back != "" && status < http.StatusInternalServerError {
		s.redirectWithNotice(w, r, back, true, message)
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
	response, err := s.doProvider(request)
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
	SessionID  string `json:"session_id"`
	Subject    string `json:"subject"`
	Skip       bool   `json:"skip"`
	RequestURL string `json:"request_url"`
}

// reauthenticationDemand reads what the relying party asked for in its
// authorization request: prompt=login demands a credential presented for
// this request, and max_age bounds how long ago the person last presented
// one. A negative maxAge means the request set no bound.
func reauthenticationDemand(requestURL string) (promptLogin bool, maxAge time.Duration) {
	maxAge = -1
	parsed, err := url.Parse(requestURL)
	if err != nil {
		return false, maxAge
	}
	query := parsed.Query()
	for _, prompt := range strings.Fields(query.Get("prompt")) {
		if prompt == "login" {
			promptLogin = true
		}
	}
	if raw := query.Get("max_age"); raw != "" {
		if seconds, err := strconv.ParseInt(raw, 10, 64); err == nil && seconds >= 0 {
			maxAge = time.Duration(seconds) * time.Second
		}
	}
	return promptLogin, maxAge
}

// reauthenticationCookie names the attempt that sent a person back to sign
// in for one login challenge, and when; only a browser session created
// after that moment satisfies prompt=login for that challenge.
const reauthenticationCookie = "shauth_reauthentication"

func reauthenticationMarker(challenge string, at time.Time) string {
	digest := sha256.Sum256([]byte(challenge))
	return hex.EncodeToString(digest[:]) + "." + strconv.FormatInt(at.UnixNano(), 10)
}

func reauthenticatedSince(cookieValue, challenge string, sessionCreated time.Time) bool {
	digest := sha256.Sum256([]byte(challenge))
	prefix, nanos, found := strings.Cut(cookieValue, ".")
	if !found || subtle.ConstantTimeCompare([]byte(prefix), []byte(hex.EncodeToString(digest[:]))) != 1 {
		return false
	}
	issued, err := strconv.ParseInt(nanos, 10, 64)
	return err == nil && sessionCreated.After(time.Unix(0, issued))
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
	response, err := s.doProvider(request)
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
	response, err := s.doProvider(request)
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
	response, err := s.doProvider(request)
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
	response, err := s.doProvider(request)
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
