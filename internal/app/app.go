// SPDX-License-Identifier: AGPL-3.0-or-later

// Package app provides Shauth's browser login, OAuth broker, and HTMX admin UI.
package app

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"html/template"
	"log"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"
	"time"

	"github.com/e6qu/shauth/internal/config"
	githubapi "github.com/e6qu/shauth/internal/github"
	"github.com/e6qu/shauth/internal/identity"
	"github.com/e6qu/shauth/internal/mailer"
	"golang.org/x/oauth2"
	oauthgithub "golang.org/x/oauth2/github"
)

const browserSessionCookie = "shauth_session"
const githubStateCookie = "shauth_github_state"

type Server struct {
	config      config.Config
	store       *identity.Store
	github      *githubapi.Client
	oauth       *oauth2.Config
	httpClient  *http.Client
	templates   *template.Template
	hydraPublic *httputil.ReverseProxy
	mailer      mailer.Invitations
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
	proxy := httputil.NewSingleHostReverseProxy(cfg.HydraPublicURL)
	proxy.ErrorHandler = func(w http.ResponseWriter, r *http.Request, err error) {
		log.Printf("proxy Hydra public request %s: %v", r.URL.Path, err)
		http.Error(w, "OAuth provider unavailable", http.StatusBadGateway)
	}
	return &Server{config: cfg, store: store, github: client, httpClient: http.DefaultClient, templates: templates, hydraPublic: proxy, mailer: inviter, oauth: &oauth2.Config{ClientID: cfg.GitHubClientID, ClientSecret: cfg.GitHubClientSecret, Endpoint: oauthgithub.Endpoint, RedirectURL: callback, Scopes: []string{"read:user", "user:email", "read:org"}}}, nil
}

func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", s.health)
	mux.Handle("/.well-known/{path...}", s.hydraPublic)
	mux.Handle("/oauth2/{path...}", s.hydraPublic)
	mux.HandleFunc("GET /{$}", s.home)
	mux.HandleFunc("GET /login", s.login)
	mux.HandleFunc("POST /login", s.passwordLogin)
	mux.HandleFunc("POST /logout", s.logout)
	mux.HandleFunc("GET /oauth/github", s.githubStart)
	mux.HandleFunc("GET /oauth/github/callback", s.githubCallback)
	mux.HandleFunc("GET /oauth/login", s.hydraLogin)
	mux.HandleFunc("GET /oauth/consent", s.hydraConsent)
	mux.HandleFunc("POST /oauth/consent", s.hydraConsentAccept)
	mux.HandleFunc("GET /admin", s.admin)
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
	return securityHeaders(sameOriginPosts(s.config.PublicURL, mux))
}

func securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Security-Policy", "default-src 'self'; script-src 'self' https://unpkg.com; style-src 'self' 'unsafe-inline'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'")
		w.Header().Set("Referrer-Policy", "no-referrer")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		next.ServeHTTP(w, r)
	})
}
func sameOriginPosts(publicURL *url.URL, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost {
			origin := r.Header.Get("Origin")
			if origin == "" {
				http.Error(w, "origin header is required for state-changing requests", http.StatusForbidden)
				return
			}
			parsed, err := url.Parse(origin)
			if err != nil || parsed.Scheme != publicURL.Scheme || parsed.Host != publicURL.Host {
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
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	_, _ = fmt.Fprintln(w, "ok")
}
func (s *Server) home(w http.ResponseWriter, r *http.Request) {
	user, _, err := s.current(r)
	s.render(w, "home", map[string]any{"User": user, "SignedIn": err == nil})
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
func (s *Server) logout(w http.ResponseWriter, r *http.Request) {
	if cookie, err := r.Cookie(browserSessionCookie); err == nil {
		_, session, err := s.store.CurrentUser(r.Context(), cookie.Value, time.Now())
		if err == nil {
			_ = s.store.RevokeSession(r.Context(), session.ID, time.Now())
		}
	}
	s.expireCookie(w, browserSessionCookie)
	http.Redirect(w, r, "/", http.StatusSeeOther)
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
	if _, _, err := s.current(r); err != nil {
		http.Redirect(w, r, "/login?next="+url.QueryEscape(r.URL.RequestURI()), http.StatusSeeOther)
		return
	}
	challenge := r.URL.Query().Get("consent_challenge")
	if challenge == "" {
		http.Error(w, "missing consent_challenge", http.StatusBadRequest)
		return
	}
	scopes, err := s.hydraConsentScopes(r.Context(), challenge)
	if err != nil {
		http.Error(w, "could not load OAuth consent request", http.StatusBadGateway)
		return
	}
	s.render(w, "consent", map[string]any{"Challenge": challenge, "Scopes": scopes})
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
	redirect, err := s.hydraAccept(r.Context(), "/admin/oauth2/auth/requests/consent/accept", r.Form.Get("challenge"), map[string]any{"grant_scope": r.Form["scope"], "remember": true, "remember_for": 2592000, "session": map[string]any{"id_token": map[string]any{"sub": user.ID, "email": user.Email, "preferred_username": user.Username, "role": user.Role}, "access_token": map[string]any{"role": user.Role}}})
	if err != nil {
		http.Error(w, "could not complete OAuth consent", 502)
		return
	}
	http.Redirect(w, r, redirect, 302)
}
func (s *Server) admin(w http.ResponseWriter, r *http.Request) {
	if !s.requireAdmin(w, r) {
		return
	}
	s.render(w, "admin", nil)
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
	s.render(w, "github-mappings", map[string]any{"Mappings": mappings})
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
	s.render(w, "users", map[string]any{"Users": users, "Query": r.URL.Query().Get("q")})
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
	s.render(w, "invitations", nil)
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
	s.render(w, "sessions", map[string]any{"Sessions": sessions, "UserID": r.PathValue("id")})
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
		http.Error(w, "could not inspect session", http.StatusNotFound)
		return
	}
	if err := s.revokeHydraSessions(r.Context(), userID); err != nil {
		http.Error(w, "could not revoke OAuth sessions", http.StatusBadGateway)
		return
	}
	if err := s.store.RevokeSession(r.Context(), sessionID, time.Now()); err != nil {
		http.Error(w, "could not revoke session", 500)
		return
	}
	http.Redirect(w, r, r.Referer(), 303)
}
func (s *Server) revokeHydraSessions(ctx context.Context, subject string) error {
	for _, kind := range []string{"login", "consent"} {
		endpoint := s.config.HydraAdminURL.ResolveReference(&url.URL{Path: "/admin/oauth2/auth/sessions/" + kind + "/" + url.PathEscape(subject)})
		request, err := http.NewRequestWithContext(ctx, http.MethodDelete, endpoint.String(), nil)
		if err != nil {
			return err
		}
		response, err := s.httpClient.Do(request)
		if err != nil {
			return err
		}
		response.Body.Close()
		if response.StatusCode != http.StatusNoContent && response.StatusCode != http.StatusNotFound {
			return fmt.Errorf("Hydra %s session deletion returned HTTP %d", kind, response.StatusCode)
		}
	}
	return nil
}
func (s *Server) hydraConsentScopes(ctx context.Context, challenge string) ([]string, error) {
	endpoint := s.config.HydraAdminURL.ResolveReference(&url.URL{Path: "/admin/oauth2/auth/requests/consent", RawQuery: "consent_challenge=" + url.QueryEscape(challenge)})
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
		return nil, fmt.Errorf("Hydra consent request returned HTTP %d", response.StatusCode)
	}
	var consent struct {
		RequestedScope []string `json:"requested_scope"`
	}
	if err := json.NewDecoder(response.Body).Decode(&consent); err != nil {
		return nil, fmt.Errorf("decode Hydra consent request: %w", err)
	}
	if len(consent.RequestedScope) == 0 {
		return nil, fmt.Errorf("Hydra consent request has no scopes")
	}
	return consent.RequestedScope, nil
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
	s.render(w, "monitoring", map[string]any{"ActiveSessions": active, "HydraHealthy": s.hydraReady(r.Context()), "Now": time.Now().UTC()})
}
func (s *Server) hydraReady(ctx context.Context) bool {
	ctx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	endpoint := s.config.HydraPublicURL.ResolveReference(&url.URL{Path: "/health/ready"})
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint.String(), nil)
	if err != nil {
		return false
	}
	response, err := s.httpClient.Do(request)
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
	s.setCookie(w, &http.Cookie{Name: name, Value: "", Path: "/", HttpOnly: true, Secure: !s.config.AllowInsecureCookies, MaxAge: -1, Expires: time.Unix(0, 0)})
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
