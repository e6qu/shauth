// SPDX-License-Identifier: AGPL-3.0-or-later

// Package app provides Shauth's browser login, OAuth broker, and HTMX admin UI.
package app

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"html/template"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/e6qu/shauth/internal/config"
	githubapi "github.com/e6qu/shauth/internal/github"
	"github.com/e6qu/shauth/internal/identity"
	"github.com/e6qu/shauth/internal/mailer"
	"github.com/e6qu/shauth/internal/managedapps"
	"golang.org/x/oauth2"
	oauthgithub "golang.org/x/oauth2/github"
)

const browserSessionCookie = "shauth_session"
const csrfCookie = "shauth_csrf"
const githubStateCookiePrefix = "shauth_github_state_"
const entraStateCookiePrefix = "shauth_entra_state_"
const bootstrapRetryInterval = time.Second
const bootstrapRetryTimeout = 45 * time.Second
const outboundRequestTimeout = 15 * time.Second

const baseContentSecurityPolicy = "default-src 'self'; script-src 'self' https://unpkg.com; style-src 'self' 'unsafe-inline'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'"
const oidcContentSecurityPolicy = "default-src 'self'; script-src 'self' https://unpkg.com; style-src 'self' 'unsafe-inline'; base-uri 'none'; frame-ancestors 'none'; form-action 'self' https: http://localhost:* http://127.0.0.1:*"
const oidcLogoutContentSecurityPolicy = "default-src 'none'; script-src 'unsafe-inline'; style-src 'unsafe-inline'; frame-src https: http://localhost:* http://127.0.0.1:*; base-uri 'none'; frame-ancestors 'none'; form-action 'self'"

var oidcClientIDPattern = regexp.MustCompile(`^[a-z][a-z0-9-]{2,127}$`)

type oidcClient struct {
	ID                     string   `json:"client_id"`
	Name                   string   `json:"client_name"`
	RedirectURIs           []string `json:"redirect_uris"`
	PostLogoutRedirectURIs []string `json:"post_logout_redirect_uris"`
	FrontChannelLogoutURI  string   `json:"frontchannel_logout_uri"`
	BackChannelLogoutURI   string   `json:"backchannel_logout_uri"`
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
		return fmt.Errorf("client ID must contain 3–128 lowercase letters, digits, or hyphens and start with a letter")
	}
	if strings.TrimSpace(input.Name) == "" {
		return fmt.Errorf("client name is required")
	}
	if len(input.Secret) < 32 {
		return fmt.Errorf("client secret must contain at least 32 characters")
	}
	if len(input.RedirectURIs) == 0 {
		return fmt.Errorf("at least one redirect URI is required")
	}
	if len(input.PostLogoutRedirectURIs) == 0 {
		return fmt.Errorf("at least one post-logout redirect URI is required")
	}
	if input.FrontChannelLogoutURI == "" && input.BackChannelLogoutURI == "" {
		return fmt.Errorf("a front-channel or back-channel logout URI is required")
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
	return validateClientURIs("back-channel logout URI", []string{input.BackChannelLogoutURI})
}

func validateClientURIs(label string, uris []string) error {
	for _, rawURI := range uris {
		if rawURI == "" {
			continue
		}
		uri, err := url.Parse(rawURI)
		if err != nil || uri.Scheme == "" || uri.Host == "" || uri.User != nil || uri.Fragment != "" {
			return fmt.Errorf("%s %q must be an absolute URI without a fragment", label, rawURI)
		}
		if uri.Scheme != "https" && !isLoopbackRedirect(uri) {
			return fmt.Errorf("%s %q must use HTTPS unless it targets loopback", label, rawURI)
		}
	}
	if input.FrontChannelLogoutURI != "" {
		frontchannel, _ := url.Parse(input.FrontChannelLogoutURI)
		matchedRedirectOrigin := false
		for _, rawRedirect := range input.RedirectURIs {
			redirect, _ := url.Parse(rawRedirect)
			if strings.EqualFold(frontchannel.Scheme, redirect.Scheme) && strings.EqualFold(frontchannel.Host, redirect.Host) {
				matchedRedirectOrigin = true
				break
			}
		}
		if !matchedRedirectOrigin {
			return fmt.Errorf("front-channel logout URI must use the scheme, host, and port of a redirect URI")
		}
	}
	return nil
}

func isLoopbackRedirect(uri *url.URL) bool {
	host := strings.Trim(strings.ToLower(uri.Hostname()), "[]")
	if host == "localhost" || host == "::1" {
		return true
	}
	return net.ParseIP(host).IsLoopback()
}

type Server struct {
	config      config.Config
	store       *identity.Store
	github      *githubapi.Client
	oauth       *oauth2.Config
	entraOAuth  *oauth2.Config
	entraVerify *oidc.IDTokenVerifier
	httpClient  *http.Client
	templates   *template.Template
	hydraPublic *httputil.ReverseProxy
	mailer      mailer.Invitations
	managedApps *managedapps.Controller
}

func New(cfg config.Config, store *identity.Store) (*Server, error) {
	outboundClient := &http.Client{Timeout: outboundRequestTimeout}
	client, err := githubapi.NewClient(outboundClient)
	if err != nil {
		return nil, err
	}
	callback := cfg.PublicURL.ResolveReference(&url.URL{Path: "/oauth/github/callback"}).String()
	templates, err := template.New("pages").Parse(pageTemplates)
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
	proxy.ErrorHandler = func(w http.ResponseWriter, r *http.Request, err error) {
		log.Printf("proxy Hydra public request %s: %v", r.URL.Path, err)
		http.Error(w, "OAuth provider unavailable", http.StatusBadGateway)
	}
	server := &Server{config: cfg, store: store, github: client, httpClient: outboundClient, templates: templates, hydraPublic: proxy, mailer: inviter, managedApps: appController, oauth: &oauth2.Config{ClientID: cfg.GitHubClientID, ClientSecret: cfg.GitHubClientSecret, Endpoint: oauthgithub.Endpoint, RedirectURL: callback, Scopes: []string{"read:user", "user:email", "read:org"}}}
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
		log.Printf("Hydra redirect body injected: status=%d target=%s response_bytes=%d", response.StatusCode, redirectTarget(response.Header.Get("Location")), len(body))
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
	mux.Handle("/.well-known/{path...}", s.hydraPublic)
	mux.Handle("/oauth2/{path...}", s.hydraPublic)
	mux.Handle("/userinfo", s.hydraPublic)
	mux.HandleFunc("GET /{$}", s.home)
	mux.HandleFunc("GET /apps", s.apps)
	mux.HandleFunc("GET /login", s.login)
	mux.HandleFunc("POST /login", s.passwordLogin)
	mux.HandleFunc("GET /logout", s.logoutConfirm)
	mux.HandleFunc("POST /logout", s.logout)
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
	mux.HandleFunc("POST /admin/apps/{id}/delete", s.adminDeleteApp)
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
	mux.HandleFunc("GET /accept-invitation", s.acceptInvitation)
	mux.HandleFunc("POST /accept-invitation", s.acceptInvitationPost)
	mux.HandleFunc("GET /admin/users/{id}/sessions", s.adminUserSessions)
	mux.HandleFunc("POST /admin/users/{id}/sessions/revoke", s.adminRevokeSessions)
	mux.HandleFunc("POST /admin/sessions/{id}/revoke", s.adminRevokeSession)
	mux.HandleFunc("GET /monitoring", s.monitoring)
	return securityHeaders(csrfPosts(s.config.PublicURL, mux))
}

func securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		policy := baseContentSecurityPolicy
		if r.URL.Path == "/oauth2/sessions/logout" {
			policy = oidcLogoutContentSecurityPolicy
		}
		w.Header().Set("Content-Security-Policy", policy)
		w.Header().Set("Referrer-Policy", "no-referrer")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		next.ServeHTTP(w, r)
	})
}

func serveThemeScript(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "application/javascript; charset=utf-8")
	w.Header().Set("Cache-Control", "public, max-age=86400")
	_, _ = w.Write([]byte(`!function(){try{var root=document.documentElement,theme=localStorage.getItem("shauth-theme");if(theme){root.dataset.theme=theme}function setup(){var button=document.getElementById("theme-toggle");if(!button)return;function label(){var dark=root.dataset.theme==="dark";button.setAttribute("aria-pressed",String(dark));button.setAttribute("aria-label",dark?"Switch to light mode":"Switch to dark mode");button.innerHTML="<span aria-hidden=\"true\">"+(dark?"☀":"☾")+"</span>"}button.addEventListener("click",function(){root.dataset.theme=root.dataset.theme==="dark"?"light":"dark";localStorage.setItem("shauth-theme",root.dataset.theme);label()});label()}if(document.readyState==="loading"){document.addEventListener("DOMContentLoaded",setup)}else{setup()}}catch(error){}}();`))
	_, _ = w.Write([]byte(`document.addEventListener("submit",function(event){var form=event.target;if(!(form instanceof HTMLFormElement)||form.method.toLowerCase()!=="post")return;var input=form.querySelector('input[name="_csrf"]');if(!input){input=document.createElement("input");input.type="hidden";input.name="_csrf";form.appendChild(input)}var match=document.cookie.match(/(?:^|; )shauth_csrf=([^;]*)/);input.value=match?decodeURIComponent(match[1]):""},true);`))
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
			}
		}
		if r.Method == http.MethodPost && r.URL.Path != "/oauth2/token" {
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
func (s *Server) home(w http.ResponseWriter, r *http.Request) {
	user, _, err := s.current(r)
	s.render(w, "home", map[string]any{"User": user, "SignedIn": err == nil, "IsAdmin": err == nil && user.Role == identity.RoleAdmin})
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
	s.render(w, "login", map[string]any{"Next": next, "Error": r.URL.Query().Get("error"), "EntraEnabled": s.entraOAuth != nil})
}
func (s *Server) passwordLogin(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "invalid form", 400)
		return
	}
	user, err := s.store.AuthenticatePassword(r.Context(), r.Form.Get("username"), r.Form.Get("password"))
	if err != nil {
		s.render(w, "login", map[string]any{"Error": "Invalid username or password.", "Next": relativeNext(r.Form.Get("next")), "EntraEnabled": s.entraOAuth != nil})
		return
	}
	if !s.startSession(w, r, user) {
		return
	}
	http.Redirect(w, r, relativeNext(r.Form.Get("next")), http.StatusSeeOther)
}
func (s *Server) logoutConfirm(w http.ResponseWriter, r *http.Request) {
	user, _, err := s.current(r)
	s.render(w, "logout", map[string]any{"SignedIn": err == nil, "User": user, "IsAdmin": err == nil && user.Role == identity.RoleAdmin})
}

func (s *Server) logout(w http.ResponseWriter, r *http.Request) {
	if _, _, err := s.current(r); err != nil {
		s.expireCookie(w, browserSessionCookie)
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}
	// The browser must visit Ory Hydra so it can remove its own authentication
	// cookie and propagate logout to every correlated relying application.
	http.Redirect(w, r, "/oauth2/sessions/logout", http.StatusSeeOther)
}
func (s *Server) githubStart(w http.ResponseWriter, r *http.Request) {
	state, err := newState()
	if err != nil {
		http.Error(w, "could not begin GitHub login", 500)
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
		http.Error(w, "GitHub login state did not match", http.StatusBadRequest)
		return
	}
	s.expireCookieAtPath(w, cookieName, "/oauth/github/callback")
	token, err := s.oauth.Exchange(r.Context(), r.URL.Query().Get("code"))
	if err != nil {
		http.Error(w, "GitHub authorization failed", http.StatusBadGateway)
		return
	}
	profile, err := s.github.Profile(r.Context(), token.AccessToken)
	if err != nil {
		http.Error(w, "could not read GitHub identity", http.StatusBadGateway)
		return
	}
	role, allowed, err := s.githubRole(r.Context(), token.AccessToken, profile)
	if err != nil {
		http.Error(w, "could not verify GitHub organization membership", http.StatusBadGateway)
		return
	}
	if !allowed {
		http.Error(w, "GitHub account is not authorized for e6qu", http.StatusForbidden)
		return
	}
	user, err := s.store.FindOrCreateGitHubUser(r.Context(), profile.ID, profile.Login, profile.Email, role)
	if err != nil {
		http.Error(w, "could not establish local account", 500)
		return
	}
	if !s.startSession(w, r, user) {
		return
	}
	http.Redirect(w, r, relativeNext(cookie.Value), http.StatusSeeOther)
}

func (s *Server) entraStart(w http.ResponseWriter, r *http.Request) {
	if s.entraOAuth == nil {
		http.NotFound(w, r)
		return
	}
	state, err := newState()
	if err != nil {
		http.Error(w, "could not begin Microsoft Entra ID login", http.StatusInternalServerError)
		return
	}
	nonce, err := newState()
	if err != nil {
		http.Error(w, "could not begin Microsoft Entra ID login", http.StatusInternalServerError)
		return
	}
	cookieValue, err := json.Marshal(map[string]string{"next": relativeNext(r.URL.Query().Get("next")), "nonce": nonce})
	if err != nil {
		http.Error(w, "could not begin Microsoft Entra ID login", http.StatusInternalServerError)
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
		http.Error(w, "Microsoft Entra ID login state did not match", http.StatusBadRequest)
		return
	}
	s.expireCookieAtPath(w, cookieName, "/oauth/entra/callback")
	var transaction map[string]string
	transactionJSON, err := base64.RawURLEncoding.DecodeString(cookie.Value)
	if err != nil || json.Unmarshal(transactionJSON, &transaction) != nil || transaction["nonce"] == "" {
		http.Error(w, "Microsoft Entra ID login state was invalid", http.StatusBadRequest)
		return
	}
	token, err := s.entraOAuth.Exchange(r.Context(), r.URL.Query().Get("code"))
	if err != nil {
		http.Error(w, "Microsoft Entra ID authorization failed", http.StatusBadGateway)
		return
	}
	rawIDToken, ok := token.Extra("id_token").(string)
	if !ok || rawIDToken == "" {
		http.Error(w, "Microsoft Entra ID authorization omitted the ID token", http.StatusBadGateway)
		return
	}
	idToken, err := s.entraVerify.Verify(r.Context(), rawIDToken)
	if err != nil {
		http.Error(w, "Microsoft Entra ID token verification failed", http.StatusBadGateway)
		return
	}
	var claims entraClaims
	if err := idToken.Claims(&claims); err != nil {
		http.Error(w, "Microsoft Entra ID identity claims were invalid", http.StatusBadGateway)
		return
	}
	if subtle.ConstantTimeCompare([]byte(claims.Nonce), []byte(transaction["nonce"])) != 1 || !strings.EqualFold(claims.TenantID, s.config.EntraTenantID) || claims.ObjectID == "" || claims.Subject == "" {
		http.Error(w, "Microsoft Entra ID identity did not match this Shauth tenant", http.StatusForbidden)
		return
	}
	email := strings.TrimSpace(claims.Email)
	if email == "" {
		email = strings.TrimSpace(claims.PreferredUsername)
	}
	user, err := s.store.FindOrCreateEntraUser(r.Context(), claims.TenantID, claims.ObjectID, entraUsername(claims.PreferredUsername, email, claims.ObjectID), email)
	if err != nil {
		http.Error(w, "could not establish local account", http.StatusInternalServerError)
		return
	}
	if !s.startSession(w, r, user) {
		return
	}
	http.Redirect(w, r, relativeNext(transaction["next"]), http.StatusSeeOther)
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
	if challenge := r.URL.Query().Get("login_challenge"); challenge == "" {
		http.Error(w, "missing login_challenge", 400)
		return
	}
	user, session, err := s.current(r)
	if err != nil {
		http.Redirect(w, r, "/login?next="+url.QueryEscape(r.URL.RequestURI()), http.StatusSeeOther)
		return
	}
	policy, err := s.store.SessionPolicy(r.Context())
	if err != nil {
		http.Error(w, "could not load session policy", http.StatusInternalServerError)
		return
	}
	redirect, err := s.hydraAccept(r.Context(), "/admin/oauth2/auth/requests/login/accept", r.URL.Query().Get("login_challenge"), map[string]any{"subject": user.ID, "identity_provider_session_id": session.ID, "remember": true, "remember_for": int64(policy.OIDCSessionLifetime / time.Second)})
	if err != nil {
		http.Error(w, "could not complete OAuth login", http.StatusBadGateway)
		return
	}
	http.Redirect(w, r, redirect, http.StatusFound)
}
func (s *Server) hydraConsent(w http.ResponseWriter, r *http.Request) {
	user, _, err := s.current(r)
	if err != nil {
		http.Redirect(w, r, "/login?next="+url.QueryEscape(r.URL.RequestURI()), http.StatusSeeOther)
		return
	}
	challenge := r.URL.Query().Get("consent_challenge")
	if challenge == "" {
		http.Error(w, "missing consent_challenge", http.StatusBadRequest)
		return
	}
	consent, err := s.hydraConsentRequest(r.Context(), challenge)
	if err != nil {
		http.Error(w, "could not load OAuth consent request", http.StatusBadGateway)
		return
	}
	managed, err := s.store.IsManagedOIDCClient(r.Context(), consent.ClientID)
	if err != nil {
		http.Error(w, "could not identify the connected application", http.StatusInternalServerError)
		return
	}
	if managed {
		redirect, err := s.acceptHydraConsent(r.Context(), challenge, consent.Scopes, user)
		if err != nil {
			http.Error(w, "could not complete OAuth consent", http.StatusBadGateway)
			return
		}
		http.Redirect(w, r, redirect, http.StatusFound)
		return
	}
	allowOIDCFormAction(w)
	s.render(w, "consent", map[string]any{"Challenge": challenge, "Scopes": consent.Scopes})
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
	s.render(w, "oauth-error", map[string]any{"Code": code, "Message": message})
}
func (s *Server) hydraConsentAccept(w http.ResponseWriter, r *http.Request) {
	user, _, err := s.current(r)
	if err != nil {
		http.Redirect(w, r, "/login", 303)
		return
	}
	if err := r.ParseForm(); err != nil {
		http.Error(w, "invalid form", 400)
		return
	}
	redirect, err := s.acceptHydraConsent(r.Context(), r.Form.Get("challenge"), r.Form["scope"], user)
	if err != nil {
		http.Error(w, "could not complete OAuth consent", 502)
		return
	}
	http.Redirect(w, r, redirect, 302)
}

func (s *Server) acceptHydraConsent(ctx context.Context, challenge string, scopes []string, user identity.User) (string, error) {
	policy, err := s.store.SessionPolicy(ctx)
	if err != nil {
		return "", err
	}
	claims := map[string]any{"sub": user.ID, "email": user.Email, "preferred_username": user.Username, "role": user.Role}
	return s.hydraAccept(ctx, "/admin/oauth2/auth/requests/consent/accept", challenge, map[string]any{"grant_scope": scopes, "remember": true, "remember_for": int64(policy.OIDCSessionLifetime / time.Second), "session": map[string]any{"id_token": claims, "access_token": claims}})
}

type hydraLogoutRequest struct {
	Subject string `json:"subject"`
}

// hydraLogout obtains the trusted subject for an OIDC logout challenge. The
// challenge comes from Hydra; it is never accepted as a user identifier.
func (s *Server) hydraLogout(w http.ResponseWriter, r *http.Request) {
	challenge := r.URL.Query().Get("logout_challenge")
	request, err := s.hydraLogoutRequest(r.Context(), challenge)
	if err != nil {
		log.Printf("load Ory Hydra logout request: %v", err)
		http.Error(w, "could not load OAuth logout request", http.StatusBadGateway)
		return
	}
	user, session, currentErr := s.current(r)
	if currentErr == nil && user.ID != request.Subject {
		http.Error(w, "OAuth logout request belongs to a different account", http.StatusForbidden)
		return
	}
	if currentErr == nil {
		s.completeLogout(w, r, session, challenge)
		return
	}
	redirect, err := s.hydraAcceptLogout(r.Context(), challenge)
	if err != nil {
		log.Printf("accept Ory Hydra logout request without local session: %v", err)
		http.Error(w, "could not complete OAuth logout", http.StatusBadGateway)
		return
	}
	s.expireCookie(w, browserSessionCookie)
	http.Redirect(w, r, redirect, http.StatusSeeOther)
}

// completeLogout ends the local browser session before accepting Hydra's
// logout. A failure therefore never leaves the local account
// authenticated after the user has confirmed sign-out.
func (s *Server) completeLogout(w http.ResponseWriter, r *http.Request, session identity.Session, challenge string) {
	if err := s.store.RevokeSession(r.Context(), session.ID, time.Now()); err != nil {
		http.Error(w, "could not end local session", http.StatusInternalServerError)
		return
	}
	s.expireCookie(w, browserSessionCookie)
	redirect, err := s.hydraAcceptLogout(r.Context(), challenge)
	if err != nil {
		log.Printf("accept Ory Hydra logout request after revoking local session: %v", err)
		http.Error(w, "could not complete OAuth logout", http.StatusBadGateway)
		return
	}
	http.Redirect(w, r, redirect, http.StatusSeeOther)
}
func (s *Server) admin(w http.ResponseWriter, r *http.Request) {
	if !s.requireAdmin(w, r) {
		return
	}
	s.render(w, "admin", map[string]any{"SignedIn": true, "IsAdmin": true})
}

func (s *Server) adminConnectors(w http.ResponseWriter, r *http.Request) {
	if !s.requireAdmin(w, r) {
		return
	}
	s.render(w, "connectors", map[string]any{
		"SignedIn":         true,
		"IsAdmin":          true,
		"GitHubEnabled":    s.oauth != nil,
		"EntraEnabled":     s.entraOAuth != nil,
		"EntraTenantID":    s.config.EntraTenantID,
		"GitHubAdminTeam":  s.config.GitHubAdminTeam,
		"GitHubMemberTeam": s.config.GitHubDeveloperTeam,
	})
}

type managedAppView struct {
	identity.ManagedApp
	Healthy     bool
	StatusCode  int
	StatusError string
}

func (s *Server) appViews(ctx context.Context) ([]managedAppView, error) {
	apps, err := s.store.ListManagedApps(ctx)
	if err != nil {
		return nil, err
	}
	views := make([]managedAppView, 0, len(apps))
	for _, app := range apps {
		view := managedAppView{ManagedApp: app}
		if status, err := s.managedApps.Status(ctx, app); err != nil {
			view.StatusError = err.Error()
		} else {
			view.Healthy, view.StatusCode = status.Healthy, status.StatusCode
		}
		views = append(views, view)
	}
	return views, nil
}

func (s *Server) apps(w http.ResponseWriter, r *http.Request) {
	user, _, err := s.current(r)
	if err != nil {
		http.Redirect(w, r, "/login?next=/apps", http.StatusSeeOther)
		return
	}
	apps, err := s.appViews(r.Context())
	if err != nil {
		http.Error(w, "could not query apps", http.StatusInternalServerError)
		return
	}
	s.render(w, "apps", map[string]any{"SignedIn": true, "User": user, "Apps": apps, "IsAdmin": user.Role == identity.RoleAdmin})
}

func (s *Server) adminApps(w http.ResponseWriter, r *http.Request) {
	if !s.requireAdmin(w, r) {
		return
	}
	apps, err := s.appViews(r.Context())
	if err != nil {
		http.Error(w, "could not query apps", http.StatusInternalServerError)
		return
	}
	s.render(w, "admin-apps", map[string]any{"SignedIn": true, "IsAdmin": true, "Apps": apps, "Error": r.URL.Query().Get("error")})
}

func (s *Server) adminCreateApp(w http.ResponseWriter, r *http.Request) {
	if !s.requireAdmin(w, r) {
		return
	}
	if err := r.ParseForm(); err != nil {
		http.Error(w, "invalid form", http.StatusBadRequest)
		return
	}
	app := identity.ManagedApp{
		Slug:          strings.TrimSpace(r.Form.Get("slug")),
		Name:          strings.TrimSpace(r.Form.Get("name")),
		Description:   strings.TrimSpace(r.Form.Get("description")),
		LaunchURL:     strings.TrimSpace(r.Form.Get("launch_url")),
		OIDCClientID:  strings.TrimSpace(r.Form.Get("oidc_client_id")),
		HealthURL:     strings.TrimSpace(r.Form.Get("health_url")),
		MonitoringURL: strings.TrimSpace(r.Form.Get("monitoring_url")),
	}
	clients, err := s.hydraClients(r.Context())
	if err != nil {
		http.Error(w, "could not verify OAuth client", http.StatusBadGateway)
		return
	}
	clientFound := false
	for _, client := range clients {
		clientFound = clientFound || client.ID == app.OIDCClientID
	}
	if !clientFound {
		http.Redirect(w, r, "/admin/apps?error="+url.QueryEscape("register the OIDC client before adding its app"), http.StatusSeeOther)
		return
	}
	if _, err := s.store.CreateManagedApp(r.Context(), app); err != nil {
		http.Redirect(w, r, "/admin/apps?error="+url.QueryEscape(err.Error()), http.StatusSeeOther)
		return
	}
	http.Redirect(w, r, "/admin/apps", http.StatusSeeOther)
}

func (s *Server) adminDeleteApp(w http.ResponseWriter, r *http.Request) {
	if !s.requireAdmin(w, r) {
		return
	}
	if err := s.store.DeleteManagedApp(r.Context(), r.PathValue("id")); err != nil {
		http.Error(w, "app not found", http.StatusNotFound)
		return
	}
	http.Redirect(w, r, "/admin/apps", http.StatusSeeOther)
}

func (s *Server) adminOIDCClients(w http.ResponseWriter, r *http.Request) {
	if !s.requireAdmin(w, r) {
		return
	}
	clients, err := s.hydraClients(r.Context())
	if err != nil {
		http.Error(w, "could not query OAuth clients", http.StatusBadGateway)
		return
	}
	s.render(w, "oidc-clients", map[string]any{"SignedIn": true, "IsAdmin": true, "Clients": clients, "Error": r.URL.Query().Get("error")})
}

func (s *Server) adminCreateOIDCClient(w http.ResponseWriter, r *http.Request) {
	if !s.requireAdmin(w, r) {
		return
	}
	if err := r.ParseForm(); err != nil {
		http.Error(w, "invalid form", http.StatusBadRequest)
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
	if err := input.validate(); err != nil {
		http.Redirect(w, r, "/admin/clients?error="+url.QueryEscape(err.Error()), http.StatusSeeOther)
		return
	}
	if err := s.createHydraClient(r.Context(), input); err != nil {
		http.Error(w, "could not create OAuth client", http.StatusBadGateway)
		return
	}
	http.Redirect(w, r, "/admin/clients", http.StatusSeeOther)
}

func (s *Server) adminDeleteOIDCClient(w http.ResponseWriter, r *http.Request) {
	if !s.requireAdmin(w, r) {
		return
	}
	clientID := r.PathValue("id")
	if !oidcClientIDPattern.MatchString(clientID) {
		http.Error(w, "invalid client ID", http.StatusBadRequest)
		return
	}
	endpoint := s.config.HydraAdminURL.ResolveReference(&url.URL{Path: "/admin/clients/" + url.PathEscape(clientID)})
	request, err := http.NewRequestWithContext(r.Context(), http.MethodDelete, endpoint.String(), nil)
	if err != nil {
		http.Error(w, "could not build OAuth client request", http.StatusInternalServerError)
		return
	}
	response, err := s.httpClient.Do(request)
	if err != nil {
		http.Error(w, "OAuth provider unavailable", http.StatusBadGateway)
		return
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusNoContent {
		http.Error(w, "could not delete OAuth client", http.StatusBadGateway)
		return
	}
	http.Redirect(w, r, "/admin/clients", http.StatusSeeOther)
}

type sessionPolicyView struct {
	BrowserAbsoluteHours int64
	BrowserIdleMinutes   int64
	OIDCSSOHours         int64
	AccessTokenMinutes   int64
	IDTokenMinutes       int64
	RefreshTokenHours    int64
}

func newSessionPolicyView(policy identity.SessionPolicy) sessionPolicyView {
	return sessionPolicyView{
		BrowserAbsoluteHours: int64(policy.BrowserAbsoluteLifetime / time.Hour),
		BrowserIdleMinutes:   int64(policy.BrowserIdleTimeout / time.Minute),
		OIDCSSOHours:         int64(policy.OIDCSessionLifetime / time.Hour),
		AccessTokenMinutes:   int64(policy.AccessTokenLifetime / time.Minute),
		IDTokenMinutes:       int64(policy.IDTokenLifetime / time.Minute),
		RefreshTokenHours:    int64(policy.RefreshTokenLifetime / time.Hour),
	}
}

func (s *Server) adminSessionPolicy(w http.ResponseWriter, r *http.Request) {
	if !s.requireAdmin(w, r) {
		return
	}
	policy, err := s.store.SessionPolicy(r.Context())
	if err != nil {
		http.Error(w, "could not load session policy", http.StatusInternalServerError)
		return
	}
	s.render(w, "session-policy", map[string]any{"SignedIn": true, "IsAdmin": true, "Policy": newSessionPolicyView(policy), "Error": r.URL.Query().Get("error"), "Saved": r.URL.Query().Get("saved") == "true"})
}

func (s *Server) adminUpdateSessionPolicy(w http.ResponseWriter, r *http.Request) {
	if !s.requireAdmin(w, r) {
		return
	}
	if err := r.ParseForm(); err != nil {
		http.Error(w, "invalid form", http.StatusBadRequest)
		return
	}
	policy, err := parseSessionPolicyForm(r.Form)
	if err != nil {
		http.Redirect(w, r, "/admin/session-policy?error="+url.QueryEscape(err.Error()), http.StatusSeeOther)
		return
	}
	previous, err := s.store.SessionPolicy(r.Context())
	if err != nil {
		http.Error(w, "could not load current session policy", http.StatusInternalServerError)
		return
	}
	if err := s.applyHydraSessionPolicy(r.Context(), policy); err != nil {
		if rollbackErr := s.applyHydraSessionPolicy(r.Context(), previous); rollbackErr != nil {
			log.Printf("restore Ory Hydra session policy after client update failed: %v", rollbackErr)
		}
		http.Error(w, "could not update OAuth client lifetimes", http.StatusBadGateway)
		return
	}
	if err := s.store.UpdateSessionPolicy(r.Context(), policy, time.Now()); err != nil {
		if rollbackErr := s.applyHydraSessionPolicy(r.Context(), previous); rollbackErr != nil {
			log.Printf("restore Ory Hydra session policy after PostgreSQL update failed: %v", rollbackErr)
		}
		http.Error(w, "could not save session policy", http.StatusInternalServerError)
		return
	}
	http.Redirect(w, r, "/admin/session-policy?saved=true", http.StatusSeeOther)
}

func parseSessionPolicyForm(values url.Values) (identity.SessionPolicy, error) {
	parse := func(name string, unit time.Duration) (time.Duration, error) {
		value, err := strconv.ParseInt(strings.TrimSpace(values.Get(name)), 10, 64)
		if err != nil || value <= 0 {
			return 0, fmt.Errorf("%s must be a positive whole number", strings.ReplaceAll(name, "_", " "))
		}
		if value > int64((90*24*time.Hour)/unit) {
			return 0, fmt.Errorf("%s exceeds the maximum supported duration", strings.ReplaceAll(name, "_", " "))
		}
		return time.Duration(value) * unit, nil
	}
	var policy identity.SessionPolicy
	var err error
	if policy.BrowserAbsoluteLifetime, err = parse("browser_absolute_hours", time.Hour); err != nil {
		return identity.SessionPolicy{}, err
	}
	if policy.BrowserIdleTimeout, err = parse("browser_idle_minutes", time.Minute); err != nil {
		return identity.SessionPolicy{}, err
	}
	if policy.OIDCSessionLifetime, err = parse("oidc_sso_hours", time.Hour); err != nil {
		return identity.SessionPolicy{}, err
	}
	if policy.AccessTokenLifetime, err = parse("access_token_minutes", time.Minute); err != nil {
		return identity.SessionPolicy{}, err
	}
	if policy.IDTokenLifetime, err = parse("id_token_minutes", time.Minute); err != nil {
		return identity.SessionPolicy{}, err
	}
	if policy.RefreshTokenLifetime, err = parse("refresh_token_hours", time.Hour); err != nil {
		return identity.SessionPolicy{}, err
	}
	if err := policy.Validate(); err != nil {
		return identity.SessionPolicy{}, err
	}
	return policy, nil
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
	if response.StatusCode != http.StatusCreated {
		return fmt.Errorf("Hydra create client returned %s", response.Status)
	}
	return nil
}

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
		"post_logout_redirect_uris":            input.PostLogoutRedirectURIs,
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
	if len(s.config.BootstrapApps) == 0 {
		return nil
	}
	deadline := time.Now().Add(bootstrapRetryTimeout)
	var clients []oidcClient
	var err error
	for {
		clients, err = s.hydraClients(ctx)
		if err == nil {
			break
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("list bootstrap OAuth clients: %w", err)
		}
		log.Printf("waiting for OAuth provider before bootstrapping managed apps: %v", err)
		time.Sleep(bootstrapRetryInterval)
	}
	byID := make(map[string]oidcClient, len(clients))
	for _, client := range clients {
		byID[client.ID] = client
	}
	for _, bootstrap := range s.config.BootstrapApps {
		input := oidcClientInput{ID: bootstrap.OIDCClientID, Name: bootstrap.Name, Secret: bootstrap.OIDCClientSecret, RedirectURIs: bootstrap.RedirectURIs, PostLogoutRedirectURIs: bootstrap.PostLogoutRedirectURIs, FrontChannelLogoutURI: bootstrap.FrontChannelLogoutURI, BackChannelLogoutURI: bootstrap.BackChannelLogoutURI}
		if err := input.validate(); err != nil {
			return fmt.Errorf("bootstrap app %q OAuth client: %w", bootstrap.Slug, err)
		}
		managedApp := identity.ManagedApp{Slug: bootstrap.Slug, Name: bootstrap.Name, Description: bootstrap.Description, LaunchURL: bootstrap.LaunchURL, OIDCClientID: bootstrap.OIDCClientID, HealthURL: bootstrap.HealthURL, MonitoringURL: bootstrap.MonitoringURL}
		if err := identity.ValidateManagedApp(managedApp); err != nil {
			return fmt.Errorf("bootstrap managed app %q: %w", bootstrap.Slug, err)
		}
		if _, ok := byID[input.ID]; ok {
			if err := s.updateHydraClient(ctx, input); err != nil {
				return fmt.Errorf("update bootstrap OAuth client %q: %w", input.ID, err)
			}
		} else if err := s.createHydraClient(ctx, input); err != nil {
			return fmt.Errorf("create bootstrap OAuth client %q: %w", input.ID, err)
		}
		if _, err := s.store.ReconcileBootstrapManagedApp(ctx, managedApp); err != nil {
			return fmt.Errorf("reconcile bootstrap managed app %q: %w", managedApp.Slug, err)
		}
	}
	return nil
}

func (s *Server) adminGitHubMappings(w http.ResponseWriter, r *http.Request) {
	if !s.requireAdmin(w, r) {
		return
	}
	mappings, err := s.store.ListGitHubRoleMappings(r.Context())
	if err != nil {
		http.Error(w, "could not query GitHub role mappings", http.StatusInternalServerError)
		return
	}
	s.render(w, "github-mappings", map[string]any{"SignedIn": true, "IsAdmin": true, "Mappings": mappings})
}
func (s *Server) adminCreateGitHubMapping(w http.ResponseWriter, r *http.Request) {
	if !s.requireAdmin(w, r) {
		return
	}
	if err := r.ParseForm(); err != nil {
		http.Error(w, "invalid form", http.StatusBadRequest)
		return
	}
	_, err := s.store.CreateGitHubRoleMapping(r.Context(), r.Form.Get("kind"), r.Form.Get("target"), identity.Role(r.Form.Get("role")))
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	http.Redirect(w, r, "/admin/github", http.StatusSeeOther)
}
func (s *Server) adminDeleteGitHubMapping(w http.ResponseWriter, r *http.Request) {
	if !s.requireAdmin(w, r) {
		return
	}
	if err := s.store.DeleteGitHubRoleMapping(r.Context(), r.PathValue("id")); err != nil {
		http.Error(w, err.Error(), http.StatusNotFound)
		return
	}
	http.Redirect(w, r, "/admin/github", http.StatusSeeOther)
}
func (s *Server) adminUsers(w http.ResponseWriter, r *http.Request) {
	if !s.requireAdmin(w, r) {
		return
	}
	users, err := s.store.ListUsers(r.Context(), r.URL.Query().Get("q"))
	if err != nil {
		http.Error(w, "could not query users", 500)
		return
	}
	s.render(w, "users", map[string]any{"SignedIn": true, "IsAdmin": true, "Users": users, "Query": r.URL.Query().Get("q")})
}
func (s *Server) adminCreateUser(w http.ResponseWriter, r *http.Request) {
	if !s.requireAdmin(w, r) {
		return
	}
	if err := r.ParseForm(); err != nil {
		http.Error(w, "invalid form", http.StatusBadRequest)
		return
	}
	role := identity.Role(r.Form.Get("role"))
	user, err := s.store.CreatePasswordUser(r.Context(), r.Form.Get("username"), r.Form.Get("email"), r.Form.Get("password"), role)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if r.Header.Get("HX-Request") == "true" {
		s.render(w, "user-row", user)
		return
	}
	http.Redirect(w, r, "/admin/users", http.StatusSeeOther)
}
func (s *Server) adminInvite(w http.ResponseWriter, r *http.Request) {
	if !s.requireAdmin(w, r) {
		return
	}
	if err := r.ParseForm(); err != nil {
		http.Error(w, "invalid form", 400)
		return
	}
	actor, _, _ := s.current(r)
	raw, invitation, err := s.store.CreateInvitation(r.Context(), r.Form.Get("email"), identity.Role(r.Form.Get("role")), actor.ID, time.Now())
	if err != nil {
		http.Error(w, err.Error(), 400)
		return
	}
	link := s.config.PublicURL.ResolveReference(&url.URL{Path: "/accept-invitation", RawQuery: "token=" + url.QueryEscape(raw)}).String()
	if err := s.mailer.SendInvitation(r.Context(), invitation.Email, link); err != nil {
		if revokeErr := s.store.RevokeInvitation(r.Context(), invitation.ID, time.Now()); revokeErr != nil {
			log.Printf("revoke unsent invitation %s: %v", invitation.ID, revokeErr)
		}
		http.Error(w, "invitation email could not be sent", 502)
		return
	}
	http.Redirect(w, r, "/admin/users", 303)
}
func (s *Server) adminInvitations(w http.ResponseWriter, r *http.Request) {
	if !s.requireAdmin(w, r) {
		return
	}
	s.render(w, "invitations", map[string]any{"SignedIn": true, "IsAdmin": true})
}
func (s *Server) acceptInvitation(w http.ResponseWriter, r *http.Request) {
	s.render(w, "accept-invitation", map[string]any{"Token": r.URL.Query().Get("token")})
}
func (s *Server) acceptInvitationPost(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "invalid form", 400)
		return
	}
	user, err := s.store.AcceptInvitation(r.Context(), r.Form.Get("token"), r.Form.Get("username"), r.Form.Get("password"), time.Now())
	if err != nil {
		http.Error(w, "invitation cannot be accepted", 400)
		return
	}
	if !s.startSession(w, r, user) {
		return
	}
	http.Redirect(w, r, "/", 303)
}
func (s *Server) adminUserSessions(w http.ResponseWriter, r *http.Request) {
	if !s.requireAdmin(w, r) {
		return
	}
	sessions, err := s.store.ListSessions(r.Context(), r.PathValue("id"))
	if err != nil {
		http.Error(w, "could not query sessions", 500)
		return
	}
	s.render(w, "sessions", map[string]any{"SignedIn": true, "IsAdmin": true, "Sessions": sessions, "UserID": r.PathValue("id")})
}
func (s *Server) adminRevokeSessions(w http.ResponseWriter, r *http.Request) {
	if !s.requireAdmin(w, r) {
		return
	}
	userID := r.PathValue("id")
	if err := s.revokeHydraSessions(r.Context(), userID); err != nil {
		http.Error(w, "could not revoke OAuth sessions", http.StatusBadGateway)
		return
	}
	if err := s.store.RevokeUserSessions(r.Context(), userID, time.Now()); err != nil {
		http.Error(w, "could not revoke sessions", 500)
		return
	}
	http.Redirect(w, r, "/admin/users/"+r.PathValue("id")+"/sessions", 303)
}
func (s *Server) adminRevokeSession(w http.ResponseWriter, r *http.Request) {
	if !s.requireAdmin(w, r) {
		return
	}
	sessionID := r.PathValue("id")
	userID, err := s.store.SessionUserID(r.Context(), sessionID)
	if err != nil {
		http.Error(w, "session not found", http.StatusNotFound)
		return
	}
	if err := s.revokeHydraLoginSession(r.Context(), sessionID); err != nil {
		http.Error(w, "could not revoke OAuth session", http.StatusBadGateway)
		return
	}
	if err := s.store.RevokeSession(r.Context(), sessionID, time.Now()); err != nil {
		http.Error(w, "could not revoke session", 500)
		return
	}
	http.Redirect(w, r, "/admin/users/"+userID+"/sessions", http.StatusSeeOther)
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
	sessions, err := s.store.ListSessions(ctx, subject)
	if err != nil {
		return err
	}
	for _, session := range sessions {
		if session.Active {
			if err := s.revokeHydraLoginSession(ctx, session.ID); err != nil {
				return err
			}
		}
	}
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
	Client         struct {
		ID string `json:"client_id"`
	} `json:"client"`
}

type hydraConsentRequest struct {
	ClientID string
	Scopes   []string
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
	return hydraConsentRequest{ClientID: consent.Client.ID, Scopes: consent.RequestedScope}, nil
}
func (s *Server) monitoring(w http.ResponseWriter, r *http.Request) {
	if !s.requireAdmin(w, r) {
		return
	}
	active, err := s.store.CountActiveSessions(r.Context(), time.Now())
	if err != nil {
		http.Error(w, "could not inspect sessions", 500)
		return
	}
	s.render(w, "monitoring", map[string]any{"SignedIn": true, "IsAdmin": true, "ActiveSessions": active, "HydraHealthy": s.hydraReady(r.Context()), "Now": time.Now().UTC()})
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
func (s *Server) requireAdmin(w http.ResponseWriter, r *http.Request) bool {
	user, _, err := s.current(r)
	if err != nil {
		http.Redirect(w, r, "/login?next="+url.QueryEscape(r.URL.RequestURI()), 303)
		return false
	}
	if user.Role != identity.RoleAdmin {
		http.Error(w, "administrator access required", 403)
		return false
	}
	return true
}
func (s *Server) startSession(w http.ResponseWriter, r *http.Request, user identity.User) bool {
	raw, session, err := s.store.CreateSession(r.Context(), user.ID, r.UserAgent(), clientIP(r), time.Now())
	if err != nil {
		http.Error(w, "could not create session", 500)
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
func (s *Server) render(w http.ResponseWriter, name string, data any) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := s.templates.ExecuteTemplate(w, name, data); err != nil {
		log.Printf("render %s: %v", name, err)
		http.Error(w, "page rendering failed", 500)
	}
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
func newState() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}
func clientIP(r *http.Request) net.IP {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err == nil {
		return net.ParseIP(host)
	}
	return net.ParseIP(r.RemoteAddr)
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
