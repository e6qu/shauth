// SPDX-License-Identifier: AGPL-3.0-or-later

// Package app provides Shauth's browser login, OAuth broker, and HTMX admin UI.
package app

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"html/template"
	"log"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"regexp"
	"strings"
	"time"

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
const githubStateCookie = "shauth_github_state"
const logoutIntentCookie = "shauth_logout_intent"
const bootstrapRetryInterval = time.Second
const bootstrapRetryTimeout = 45 * time.Second

var oidcClientIDPattern = regexp.MustCompile(`^[a-z][a-z0-9-]{2,127}$`)

type oidcClient struct {
	ID           string   `json:"client_id"`
	Name         string   `json:"client_name"`
	RedirectURIs []string `json:"redirect_uris"`
}

type oidcClientInput struct {
	ID           string
	Name         string
	Secret       string
	RedirectURIs []string
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
	for _, rawURI := range input.RedirectURIs {
		uri, err := url.Parse(rawURI)
		if err != nil || uri.Scheme == "" || uri.Host == "" || uri.Fragment != "" {
			return fmt.Errorf("redirect URI %q must be an absolute URI without a fragment", rawURI)
		}
		if uri.Scheme != "https" && !isLoopbackRedirect(uri) {
			return fmt.Errorf("redirect URI %q must use HTTPS unless it targets loopback", rawURI)
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
	httpClient  *http.Client
	templates   *template.Template
	hydraPublic *httputil.ReverseProxy
	mailer      mailer.Invitations
	managedApps *managedapps.Controller
}

func New(cfg config.Config, store *identity.Store) (*Server, error) {
	client, err := githubapi.NewClient(http.DefaultClient)
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
	proxy.ErrorHandler = func(w http.ResponseWriter, r *http.Request, err error) {
		log.Printf("proxy Hydra public request %s: %v", r.URL.Path, err)
		http.Error(w, "OAuth provider unavailable", http.StatusBadGateway)
	}
	server := &Server{config: cfg, store: store, github: client, httpClient: http.DefaultClient, templates: templates, hydraPublic: proxy, mailer: inviter, managedApps: appController, oauth: &oauth2.Config{ClientID: cfg.GitHubClientID, ClientSecret: cfg.GitHubClientSecret, Endpoint: oauthgithub.Endpoint, RedirectURL: callback, Scopes: []string{"read:user", "user:email", "read:org"}}}
	if err := server.bootstrapApps(context.Background()); err != nil {
		return nil, err
	}
	return server, nil
}

func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", s.health)
	mux.HandleFunc("GET /assets/theme.js", serveThemeScript)
	mux.Handle("/.well-known/{path...}", s.hydraPublic)
	mux.Handle("/oauth2/{path...}", s.hydraPublic)
	mux.HandleFunc("GET /{$}", s.home)
	mux.HandleFunc("GET /apps", s.apps)
	mux.HandleFunc("GET /login", s.login)
	mux.HandleFunc("POST /login", s.passwordLogin)
	mux.HandleFunc("GET /logout", s.logoutConfirm)
	mux.HandleFunc("POST /logout", s.logout)
	mux.HandleFunc("GET /oauth/github", s.githubStart)
	mux.HandleFunc("GET /oauth/github/callback", s.githubCallback)
	mux.HandleFunc("GET /oauth/login", s.hydraLogin)
	mux.HandleFunc("GET /oauth/consent", s.hydraConsent)
	mux.HandleFunc("GET /oauth/error", s.hydraError)
	mux.HandleFunc("POST /oauth/consent", s.hydraConsentAccept)
	mux.HandleFunc("GET /oauth/logout", s.hydraLogout)
	mux.HandleFunc("POST /oauth/logout", s.hydraLogoutAccept)
	mux.HandleFunc("GET /admin", s.admin)
	mux.HandleFunc("GET /admin/apps", s.adminApps)
	mux.HandleFunc("POST /admin/apps", s.adminCreateApp)
	mux.HandleFunc("POST /admin/apps/{id}/delete", s.adminDeleteApp)
	mux.HandleFunc("GET /admin/clients", s.adminOIDCClients)
	mux.HandleFunc("POST /admin/clients", s.adminCreateOIDCClient)
	mux.HandleFunc("POST /admin/clients/{id}/delete", s.adminDeleteOIDCClient)
	mux.HandleFunc("GET /admin/github", s.adminGitHubMappings)
	mux.HandleFunc("POST /admin/github", s.adminCreateGitHubMapping)
	mux.HandleFunc("POST /admin/github/{id}/delete", s.adminDeleteGitHubMapping)
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
		w.Header().Set("Content-Security-Policy", "default-src 'self'; script-src 'self' https://unpkg.com; style-src 'self' 'unsafe-inline'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'")
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
	s.render(w, "login", map[string]any{"Next": relativeNext(r.URL.Query().Get("next")), "Error": r.URL.Query().Get("error")})
}
func (s *Server) passwordLogin(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "invalid form", 400)
		return
	}
	user, err := s.store.AuthenticatePassword(r.Context(), r.Form.Get("username"), r.Form.Get("password"))
	if err != nil {
		s.render(w, "login", map[string]any{"Error": "Invalid username or password.", "Next": relativeNext(r.Form.Get("next"))})
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
	// The browser must visit Hydra so it can remove its own authentication cookie.
	// This short-lived marker binds the resulting front-channel callback to this
	// same-origin, user-confirmed sign-out action.
	s.setCookie(w, &http.Cookie{Name: logoutIntentCookie, Value: "1", Path: "/oauth/logout", HttpOnly: true, Secure: !s.config.AllowInsecureCookies, SameSite: http.SameSiteStrictMode, MaxAge: 300})
	http.Redirect(w, r, "/oauth2/sessions/logout", http.StatusSeeOther)
}
func (s *Server) githubStart(w http.ResponseWriter, r *http.Request) {
	state, err := newState()
	if err != nil {
		http.Error(w, "could not begin GitHub login", 500)
		return
	}
	s.setCookie(w, &http.Cookie{Name: githubStateCookie, Value: state, Path: "/oauth/github", HttpOnly: true, Secure: !s.config.AllowInsecureCookies, SameSite: http.SameSiteLaxMode, MaxAge: 600})
	http.Redirect(w, r, s.oauth.AuthCodeURL(state), http.StatusFound)
}
func (s *Server) githubCallback(w http.ResponseWriter, r *http.Request) {
	cookie, err := r.Cookie(githubStateCookie)
	if err != nil || r.URL.Query().Get("state") == "" || cookie.Value != r.URL.Query().Get("state") {
		http.Error(w, "GitHub login state did not match", http.StatusBadRequest)
		return
	}
	s.expireCookie(w, githubStateCookie)
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
	http.Redirect(w, r, "/", http.StatusSeeOther)
}
func (s *Server) hydraLogin(w http.ResponseWriter, r *http.Request) {
	if challenge := r.URL.Query().Get("login_challenge"); challenge == "" {
		http.Error(w, "missing login_challenge", 400)
		return
	}
	user, _, err := s.current(r)
	if err != nil {
		http.Redirect(w, r, "/login?next="+url.QueryEscape(r.URL.RequestURI()), http.StatusSeeOther)
		return
	}
	redirect, err := s.hydraAccept(r.Context(), "/admin/oauth2/auth/requests/login/accept", r.URL.Query().Get("login_challenge"), map[string]any{"subject": user.ID, "remember": true, "remember_for": 2592000})
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
	return s.hydraAccept(ctx, "/admin/oauth2/auth/requests/consent/accept", challenge, map[string]any{"grant_scope": scopes, "remember": true, "remember_for": 2592000, "session": map[string]any{"id_token": map[string]any{"sub": user.ID, "email": user.Email, "preferred_username": user.Username, "role": user.Role}, "access_token": map[string]any{"role": user.Role}}})
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
		http.Error(w, "could not load OAuth logout request", http.StatusBadGateway)
		return
	}
	user, session, currentErr := s.current(r)
	if currentErr == nil && user.ID != request.Subject {
		http.Error(w, "OAuth logout request belongs to a different account", http.StatusForbidden)
		return
	}
	if _, err := r.Cookie(logoutIntentCookie); err == nil && currentErr == nil {
		s.completeLogout(w, r, session, challenge)
		return
	}
	s.render(w, "oauth-logout", map[string]any{"SignedIn": currentErr == nil, "User": user, "IsAdmin": currentErr == nil && user.Role == identity.RoleAdmin, "Challenge": challenge})
}

func (s *Server) hydraLogoutAccept(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "invalid form", http.StatusBadRequest)
		return
	}
	challenge := r.Form.Get("challenge")
	request, err := s.hydraLogoutRequest(r.Context(), challenge)
	if err != nil {
		http.Error(w, "could not load OAuth logout request", http.StatusBadGateway)
		return
	}
	user, session, currentErr := s.current(r)
	if currentErr == nil {
		if user.ID != request.Subject {
			http.Error(w, "OAuth logout request belongs to a different account", http.StatusForbidden)
			return
		}
		s.completeLogout(w, r, session, challenge)
		return
	}
	redirect, err := s.hydraAcceptLogout(r.Context(), challenge)
	if err != nil {
		http.Error(w, "could not complete OAuth logout", http.StatusBadGateway)
		return
	}
	s.expireCookie(w, browserSessionCookie)
	s.expireCookieAtPath(w, logoutIntentCookie, "/oauth/logout")
	http.Redirect(w, r, redirect, http.StatusSeeOther)
}

// completeLogout ends the local browser session before accepting Hydra's
// front-channel logout. A failure therefore never leaves the local account
// authenticated after the user has confirmed sign-out.
func (s *Server) completeLogout(w http.ResponseWriter, r *http.Request, session identity.Session, challenge string) {
	if err := s.store.RevokeSession(r.Context(), session.ID, time.Now()); err != nil {
		http.Error(w, "could not end local session", http.StatusInternalServerError)
		return
	}
	s.expireCookie(w, browserSessionCookie)
	s.expireCookieAtPath(w, logoutIntentCookie, "/oauth/logout")
	redirect, err := s.hydraAcceptLogout(r.Context(), challenge)
	if err != nil {
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
		ID:     strings.TrimSpace(r.Form.Get("client_id")),
		Name:   strings.TrimSpace(r.Form.Get("client_name")),
		Secret: r.Form.Get("client_secret"),
	}
	for _, rawURI := range strings.Split(r.Form.Get("redirect_uris"), "\n") {
		if uri := strings.TrimSpace(rawURI); uri != "" {
			input.RedirectURIs = append(input.RedirectURIs, uri)
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

func (s *Server) hydraClients(ctx context.Context) ([]oidcClient, error) {
	endpoint := s.config.HydraAdminURL.ResolveReference(&url.URL{Path: "/admin/clients"})
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint.String(), nil)
	if err != nil {
		return nil, err
	}
	response, err := s.httpClient.Do(request)
	if err != nil {
		return nil, err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("Hydra list clients returned %s", response.Status)
	}
	var clients []oidcClient
	if err := json.NewDecoder(response.Body).Decode(&clients); err != nil {
		return nil, fmt.Errorf("decode Hydra clients: %w", err)
	}
	return clients, nil
}

func (s *Server) createHydraClient(ctx context.Context, input oidcClientInput) error {
	body, err := marshalHydraClient(input)
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

func marshalHydraClient(input oidcClientInput) ([]byte, error) {
	payload := map[string]any{
		"client_id":                  input.ID,
		"client_name":                input.Name,
		"client_secret":              input.Secret,
		"redirect_uris":              input.RedirectURIs,
		"grant_types":                []string{"authorization_code", "refresh_token"},
		"response_types":             []string{"code"},
		"scope":                      "openid offline_access profile email",
		"token_endpoint_auth_method": "client_secret_post",
	}
	return json.Marshal(payload)
}

func (s *Server) updateHydraClient(ctx context.Context, input oidcClientInput) error {
	body, err := marshalHydraClient(input)
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
	apps, err := s.store.ListManagedApps(ctx)
	if err != nil {
		return fmt.Errorf("list bootstrap managed apps: %w", err)
	}
	bySlug := make(map[string]identity.ManagedApp, len(apps))
	for _, managedApp := range apps {
		bySlug[managedApp.Slug] = managedApp
	}
	for _, bootstrap := range s.config.BootstrapApps {
		input := oidcClientInput{ID: bootstrap.OIDCClientID, Name: bootstrap.Name, Secret: bootstrap.OIDCClientSecret, RedirectURIs: bootstrap.RedirectURIs}
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
		if existing, ok := bySlug[managedApp.Slug]; ok {
			if existing.Name != managedApp.Name || existing.Description != managedApp.Description || existing.LaunchURL != managedApp.LaunchURL || existing.OIDCClientID != managedApp.OIDCClientID || existing.HealthURL != managedApp.HealthURL || existing.MonitoringURL != managedApp.MonitoringURL {
				return fmt.Errorf("bootstrap managed app %q conflicts with the registered app", managedApp.Slug)
			}
			continue
		}
		if _, err := s.store.CreateManagedApp(ctx, managedApp); err != nil {
			return fmt.Errorf("create bootstrap managed app %q: %w", managedApp.Slug, err)
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
	if err := s.store.RevokeSession(r.Context(), sessionID, time.Now()); err != nil {
		http.Error(w, "could not revoke session", 500)
		return
	}
	http.Redirect(w, r, r.Referer(), 303)
}
func (s *Server) revokeHydraSessions(ctx context.Context, subject string) error {
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
	if err != nil || parsed.IsAbs() || !strings.HasPrefix(parsed.Path, "/") {
		return "/"
	}
	return value
}
