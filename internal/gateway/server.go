// SPDX-License-Identifier: AGPL-3.0-or-later

package gateway

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"mime"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/jackc/pgx/v5/pgxpool"
	"golang.org/x/oauth2"
)

const (
	sessionCookieName       = "__Host-shauth-gateway"
	transactionCookieName   = "__Host-shauth-gateway-transaction"
	logoutEvent             = "http://schemas.openid.net/event/backchannel-logout"
	maximumLogoutTokenBytes = 32 * 1024
)

type transaction struct {
	State     string `json:"state"`
	Nonce     string `json:"nonce"`
	Verifier  string `json:"verifier"`
	ReturnTo  string `json:"return_to"`
	ExpiresAt int64  `json:"expires_at"`
}

type identityClaims struct {
	Subject           string `json:"sub"`
	ProviderSessionID string `json:"sid"`
	Username          string `json:"preferred_username"`
	Email             string `json:"email"`
	EmailVerified     bool   `json:"email_verified"`
	Role              string `json:"role"`
	Nonce             string `json:"nonce"`
}

type logoutClaims struct {
	ProviderSessionID string                     `json:"sid"`
	TokenID           string                     `json:"jti"`
	IssuedAt          int64                      `json:"iat"`
	ExpiresAt         int64                      `json:"exp"`
	Nonce             *string                    `json:"nonce"`
	Events            map[string]json.RawMessage `json:"events"`
}

type contextKey string

const identityContextKey contextKey = "oidc-gateway-identity"

type Server struct {
	config             Config
	store              *Store
	verifier           *oidc.IDTokenVerifier
	oauth              *oauth2.Config
	endSessionEndpoint string
	transactions       cipher.AEAD
	proxy              *httputil.ReverseProxy
	now                func() time.Time
}

func New(ctx context.Context, config Config, pool *pgxpool.Pool) (*Server, error) {
	discoveryContext, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	provider, err := oidc.NewProvider(discoveryContext, config.Issuer.String())
	if err != nil {
		return nil, fmt.Errorf("discover OpenID Connect provider: %w", err)
	}
	var metadata struct {
		EndSessionEndpoint string `json:"end_session_endpoint"`
	}
	if err := provider.Claims(&metadata); err != nil || metadata.EndSessionEndpoint == "" {
		return nil, fmt.Errorf("OpenID Connect provider did not publish end_session_endpoint")
	}
	endSessionURL, err := url.Parse(metadata.EndSessionEndpoint)
	if err != nil || endSessionURL.Scheme != config.Issuer.Scheme || endSessionURL.Host != config.Issuer.Host {
		return nil, fmt.Errorf("OpenID Connect end_session_endpoint did not use the configured issuer origin")
	}
	store, err := NewStore(pool, config.ClientID, config.Issuer.String(), config.CookieSecret)
	if err != nil {
		return nil, err
	}
	key := sha256.Sum256([]byte(config.CookieSecret + "\x00transaction"))
	block, err := aes.NewCipher(key[:])
	if err != nil {
		return nil, err
	}
	transactions, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	proxy := httputil.NewSingleHostReverseProxy(config.UpstreamURL)
	originalDirector := proxy.Director
	proxy.Director = func(request *http.Request) {
		originalDirector(request)
		sanitizeProxyHeaders(request, config)
		removeCookie(request, configCookieName(config.InsecureCookie))
		removeCookie(request, configTransactionCookieName(config.InsecureCookie))
		for _, name := range []string{"X-Forwarded-User", "X-Forwarded-Email", "X-Forwarded-Preferred-Username", "X-Forwarded-Role", "X-Forwarded-Subject"} {
			request.Header.Del(name)
		}
		if session, ok := request.Context().Value(identityContextKey).(Session); ok {
			request.Header.Set("X-Forwarded-User", session.Username)
			request.Header.Set("X-Forwarded-Preferred-Username", session.Username)
			request.Header.Set("X-Forwarded-Email", session.Email)
			request.Header.Set("X-Forwarded-Role", session.Role)
			request.Header.Set("X-Forwarded-Subject", session.Subject)
		}
	}
	proxy.ErrorHandler = func(response http.ResponseWriter, request *http.Request, err error) {
		log.Printf("OIDC gateway upstream %s failed: %v", request.URL.Path, err)
		http.Error(response, "Upstream service unavailable", http.StatusBadGateway)
	}
	tokenEndpoint := provider.Endpoint()
	tokenEndpoint.AuthStyle = oauth2.AuthStyleInParams
	return &Server{
		config:   config,
		store:    store,
		verifier: provider.Verifier(&oidc.Config{ClientID: config.ClientID}),
		oauth: &oauth2.Config{
			ClientID:     config.ClientID,
			ClientSecret: config.ClientSecret,
			Endpoint:     tokenEndpoint,
			RedirectURL:  config.PublicURL.ResolveReference(&url.URL{Path: "/auth/callback"}).String(),
			Scopes:       []string{oidc.ScopeOpenID, "profile", "email"},
		},
		endSessionEndpoint: metadata.EndSessionEndpoint,
		transactions:       transactions,
		proxy:              proxy,
		now:                time.Now,
	}, nil
}

func sanitizeProxyHeaders(request *http.Request, config Config) {
	for name := range request.Header {
		if strings.EqualFold(name, "Authorization") || strings.EqualFold(name, "Forwarded") || strings.EqualFold(name, "X-Real-IP") || strings.HasPrefix(strings.ToLower(name), "x-forwarded-") {
			request.Header.Del(name)
		}
	}
	request.Header.Set("X-Forwarded-Host", config.PublicURL.Host)
	request.Header.Set("X-Forwarded-Proto", config.PublicURL.Scheme)
}

func (server *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /auth/login", server.login)
	mux.HandleFunc("GET /auth/callback", server.callback)
	mux.HandleFunc("GET /auth/session", server.session)
	mux.HandleFunc("GET /auth/signed-out", server.signedOut)
	mux.HandleFunc("GET /auth/gateway.css", gatewayStyles)
	mux.HandleFunc("POST /auth/logout", server.logout)
	mux.HandleFunc("GET /auth/frontchannel-logout", server.frontchannelLogout)
	mux.HandleFunc("POST /auth/backchannel-logout", server.backchannelLogout)
	mux.HandleFunc("GET /auth/healthz", func(response http.ResponseWriter, _ *http.Request) {
		response.Header().Set("Content-Type", "text/plain; charset=utf-8")
		_, _ = response.Write([]byte("ok"))
	})
	mux.Handle("/", server.requireSession(server.proxy))
	return server.securityHeaders(mux)
}

func (server *Server) signedOut(response http.ResponseWriter, _ *http.Request) {
	response.Header().Set("Content-Type", "text/html; charset=utf-8")
	response.Header().Set("Cache-Control", "no-store")
	_, _ = response.Write([]byte(signedOutPage))
}

func (server *Server) frontchannelLogout(response http.ResponseWriter, request *http.Request) {
	response.Header().Set("Cache-Control", "no-store")
	sid := request.URL.Query().Get("sid")
	if request.URL.Query().Get("iss") != server.config.Issuer.String() || sid == "" {
		writeFrontchannelLogoutResponse(response)
		return
	}
	currentSession, _, currentSessionError := server.currentSession(request)
	if err := server.store.RevokeFrontchannelSession(request.Context(), sid, server.now()); err != nil {
		http.Error(response, "Could not revoke application session", http.StatusInternalServerError)
		return
	}
	if currentSessionError == nil && subtle.ConstantTimeCompare([]byte(sid), []byte(currentSession.ProviderSessionID)) == 1 {
		server.clearCookie(response, server.sessionCookieName())
	}
	writeFrontchannelLogoutResponse(response)
}

func writeFrontchannelLogoutResponse(response http.ResponseWriter) {
	response.Header().Set("Content-Type", "text/html; charset=utf-8")
	_, _ = response.Write([]byte("<!doctype html><title>Signed out</title>"))
}

func (server *Server) login(response http.ResponseWriter, request *http.Request) {
	response.Header().Set("Cache-Control", "no-store")
	returnTo := relativeReturnTo(request.URL.Query().Get("return_to"))
	state, err := randomValue(32)
	if err != nil {
		http.Error(response, "Could not start authentication", http.StatusInternalServerError)
		return
	}
	nonce, err := randomValue(32)
	if err != nil {
		http.Error(response, "Could not start authentication", http.StatusInternalServerError)
		return
	}
	verifier := oauth2.GenerateVerifier()
	value, err := server.sealTransaction(transaction{State: state, Nonce: nonce, Verifier: verifier, ReturnTo: returnTo, ExpiresAt: server.now().Add(10 * time.Minute).Unix()})
	if err != nil {
		http.Error(response, "Could not start authentication", http.StatusInternalServerError)
		return
	}
	server.setCookie(response, server.transactionCookieName(), value, 10*time.Minute)
	target := server.oauth.AuthCodeURL(state, oidc.Nonce(nonce), oauth2.S256ChallengeOption(verifier))
	http.Redirect(response, request, target, http.StatusFound)
}

func (server *Server) callback(response http.ResponseWriter, request *http.Request) {
	response.Header().Set("Cache-Control", "no-store")
	cookie, err := request.Cookie(server.transactionCookieName())
	if err != nil {
		http.Error(response, "Authentication transaction is unavailable", http.StatusBadRequest)
		return
	}
	server.clearCookie(response, server.transactionCookieName())
	var pending transaction
	if err := server.openTransaction(cookie.Value, &pending); err != nil || pending.ExpiresAt <= server.now().Unix() || subtle.ConstantTimeCompare([]byte(pending.State), []byte(request.URL.Query().Get("state"))) != 1 {
		http.Error(response, "Authentication transaction is invalid", http.StatusBadRequest)
		return
	}
	token, err := server.oauth.Exchange(request.Context(), request.URL.Query().Get("code"), oauth2.VerifierOption(pending.Verifier))
	if err != nil {
		http.Error(response, "Authorization code exchange failed", http.StatusBadGateway)
		return
	}
	rawIDToken, ok := token.Extra("id_token").(string)
	if !ok || rawIDToken == "" {
		http.Error(response, "Authorization response omitted the ID token", http.StatusBadGateway)
		return
	}
	verified, err := server.verifier.Verify(request.Context(), rawIDToken)
	if err != nil {
		http.Error(response, "ID token verification failed", http.StatusUnauthorized)
		return
	}
	var claims identityClaims
	if err := verified.Claims(&claims); err != nil || claims.Subject == "" || claims.ProviderSessionID == "" || claims.Username == "" || claims.Email == "" || !claims.EmailVerified || (claims.Role != "developer" && claims.Role != "admin") || subtle.ConstantTimeCompare([]byte(claims.Nonce), []byte(pending.Nonce)) != 1 {
		http.Error(response, "ID token identity is incomplete", http.StatusUnauthorized)
		return
	}
	browserToken, err := randomBytes(32)
	if err != nil {
		http.Error(response, "Could not create application session", http.StatusInternalServerError)
		return
	}
	sessionID, err := randomUUID()
	if err != nil {
		http.Error(response, "Could not create application session", http.StatusInternalServerError)
		return
	}
	now := server.now()
	session := Session{ID: sessionID, Subject: claims.Subject, ProviderSessionID: claims.ProviderSessionID, IDToken: rawIDToken, Username: claims.Username, Email: claims.Email, Role: claims.Role, ExpiresAt: now.Add(server.config.SessionMaxAge)}
	if err := server.store.Create(request.Context(), session, browserToken, now); err != nil {
		http.Error(response, "Could not persist application session", http.StatusInternalServerError)
		return
	}
	server.setCookie(response, server.sessionCookieName(), base64.RawURLEncoding.EncodeToString(browserToken), server.config.SessionMaxAge)
	http.Redirect(response, request, pending.ReturnTo, http.StatusSeeOther)
}

func (server *Server) session(response http.ResponseWriter, request *http.Request) {
	session, _, err := server.currentSession(request)
	if err != nil {
		http.Error(response, "Authentication required", http.StatusUnauthorized)
		return
	}
	writeJSON(response, http.StatusOK, map[string]string{"subject": session.Subject, "username": session.Username, "email": session.Email, "role": session.Role})
}

func (server *Server) logout(response http.ResponseWriter, request *http.Request) {
	response.Header().Set("Cache-Control", "no-store")
	if !server.sameOrigin(request) {
		http.Error(response, "Cross-origin request denied", http.StatusForbidden)
		return
	}
	session, browserToken, err := server.currentSession(request)
	if err != nil {
		server.clearCookie(response, server.sessionCookieName())
		http.Redirect(response, request, server.endSessionURL(""), http.StatusSeeOther)
		return
	}
	if err := server.store.RevokeToken(request.Context(), browserToken, server.now()); err != nil {
		http.Error(response, "Could not revoke application session", http.StatusInternalServerError)
		return
	}
	server.clearCookie(response, server.sessionCookieName())
	http.Redirect(response, request, server.endSessionURL(session.IDToken), http.StatusSeeOther)
}

func (server *Server) endSessionURL(idToken string) string {
	target, _ := url.Parse(server.endSessionEndpoint)
	query := target.Query()
	query.Set("client_id", server.config.ClientID)
	if idToken != "" {
		query.Set("id_token_hint", idToken)
	}
	query.Set("post_logout_redirect_uri", server.config.PostLogoutURL.String())
	target.RawQuery = query.Encode()
	return target.String()
}

func (server *Server) backchannelLogout(response http.ResponseWriter, request *http.Request) {
	response.Header().Set("Cache-Control", "no-store")
	contentType, _, err := mime.ParseMediaType(request.Header.Get("Content-Type"))
	if err != nil || !strings.EqualFold(contentType, "application/x-www-form-urlencoded") {
		http.Error(response, "Unsupported media type", http.StatusUnsupportedMediaType)
		return
	}
	request.Body = http.MaxBytesReader(response, request.Body, maximumLogoutTokenBytes)
	if err := request.ParseForm(); err != nil || len(request.PostForm["logout_token"]) != 1 {
		http.Error(response, "A single logout_token is required", http.StatusBadRequest)
		return
	}
	verified, err := server.verifier.Verify(request.Context(), request.PostForm.Get("logout_token"))
	if err != nil {
		http.Error(response, "Invalid logout token", http.StatusBadRequest)
		return
	}
	var claims logoutClaims
	if err := verified.Claims(&claims); err != nil || claims.ProviderSessionID == "" || claims.TokenID == "" || claims.IssuedAt == 0 || claims.ExpiresAt == 0 || claims.Nonce != nil {
		http.Error(response, "Invalid logout token claims", http.StatusBadRequest)
		return
	}
	issuedAgo := server.now().Sub(time.Unix(claims.IssuedAt, 0))
	if !validLogoutEvent(claims.Events) || issuedAgo < -5*time.Second || issuedAgo > 5*time.Minute || time.Unix(claims.ExpiresAt, 0).Before(server.now()) {
		http.Error(response, "Invalid logout token event", http.StatusBadRequest)
		return
	}
	if err := server.store.RevokeProviderSession(request.Context(), claims.ProviderSessionID, claims.TokenID, time.Unix(claims.ExpiresAt, 0), server.now()); err != nil {
		http.Error(response, "Logout token was rejected", http.StatusBadRequest)
		return
	}
	response.WriteHeader(http.StatusOK)
}

func validLogoutEvent(events map[string]json.RawMessage) bool {
	raw, ok := events[logoutEvent]
	if !ok {
		return false
	}
	var event map[string]json.RawMessage
	return json.Unmarshal(raw, &event) == nil && event != nil && len(event) == 0
}

func (server *Server) requireSession(next http.Handler) http.Handler {
	return http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		session, _, err := server.currentSession(request)
		if err != nil {
			if request.Method == http.MethodGet || request.Method == http.MethodHead {
				target := "/auth/login?return_to=" + url.QueryEscape(request.URL.RequestURI())
				http.Redirect(response, request, target, http.StatusFound)
				return
			}
			http.Error(response, "Authentication required", http.StatusUnauthorized)
			return
		}
		next.ServeHTTP(response, request.WithContext(context.WithValue(request.Context(), identityContextKey, session)))
	})
}

func (server *Server) currentSession(request *http.Request) (Session, []byte, error) {
	cookie, err := request.Cookie(server.sessionCookieName())
	if err != nil {
		return Session{}, nil, err
	}
	token, err := base64.RawURLEncoding.DecodeString(cookie.Value)
	if err != nil || len(token) != 32 {
		return Session{}, nil, fmt.Errorf("session cookie is invalid")
	}
	session, err := server.store.Find(request.Context(), token, server.now())
	return session, token, err
}

func (server *Server) sameOrigin(request *http.Request) bool {
	originValue := request.Header.Get("Origin")
	if originValue == "" || originValue == "null" {
		originValue = request.Referer()
	}
	origin, err := url.Parse(originValue)
	if err == nil && origin.Scheme == server.config.PublicURL.Scheme && origin.Host == server.config.PublicURL.Host {
		return true
	}
	return request.Header.Get("Sec-Fetch-Site") == "same-origin" && request.Host == server.config.PublicURL.Host
}

func (server *Server) setCookie(response http.ResponseWriter, name, value string, maxAge time.Duration) {
	http.SetCookie(response, &http.Cookie{Name: name, Value: value, Path: "/", HttpOnly: true, Secure: !server.config.InsecureCookie, SameSite: http.SameSiteLaxMode, MaxAge: int(maxAge.Seconds())})
}

func (server *Server) clearCookie(response http.ResponseWriter, name string) {
	http.SetCookie(response, &http.Cookie{Name: name, Path: "/", HttpOnly: true, Secure: !server.config.InsecureCookie, SameSite: http.SameSiteLaxMode, MaxAge: -1})
}

func (server *Server) sessionCookieName() string {
	return configCookieName(server.config.InsecureCookie)
}

func configCookieName(insecure bool) string {
	if insecure {
		return strings.TrimPrefix(sessionCookieName, "__Host-")
	}
	return sessionCookieName
}

func removeCookie(request *http.Request, name string) {
	cookies := request.Cookies()
	request.Header.Del("Cookie")
	for _, cookie := range cookies {
		if cookie.Name != name {
			request.AddCookie(cookie)
		}
	}
}

func (server *Server) transactionCookieName() string {
	return configTransactionCookieName(server.config.InsecureCookie)
}

func configTransactionCookieName(insecure bool) string {
	if insecure {
		return strings.TrimPrefix(transactionCookieName, "__Host-")
	}
	return transactionCookieName
}

func (server *Server) sealTransaction(value transaction) (string, error) {
	plain, err := json.Marshal(value)
	if err != nil {
		return "", err
	}
	nonce, err := randomBytes(server.transactions.NonceSize())
	if err != nil {
		return "", err
	}
	sealed := append(nonce, server.transactions.Seal(nil, nonce, plain, []byte(server.config.ClientID))...)
	return base64.RawURLEncoding.EncodeToString(sealed), nil
}

func (server *Server) openTransaction(value string, destination *transaction) error {
	sealed, err := base64.RawURLEncoding.DecodeString(value)
	if err != nil || len(sealed) < server.transactions.NonceSize() {
		return fmt.Errorf("transaction cookie is invalid")
	}
	plain, err := server.transactions.Open(nil, sealed[:server.transactions.NonceSize()], sealed[server.transactions.NonceSize():], []byte(server.config.ClientID))
	if err != nil {
		return err
	}
	return json.Unmarshal(plain, destination)
}

func randomBytes(length int) ([]byte, error) {
	value := make([]byte, length)
	if _, err := rand.Read(value); err != nil {
		return nil, err
	}
	return value, nil
}

func randomValue(length int) (string, error) {
	value, err := randomBytes(length)
	return base64.RawURLEncoding.EncodeToString(value), err
}

func randomUUID() (string, error) {
	value, err := randomBytes(16)
	if err != nil {
		return "", err
	}
	value[6] = (value[6] & 0x0f) | 0x40
	value[8] = (value[8] & 0x3f) | 0x80
	return fmt.Sprintf("%x-%x-%x-%x-%x", value[0:4], value[4:6], value[6:8], value[8:10], value[10:16]), nil
}

func relativeReturnTo(value string) string {
	parsed, err := url.Parse(value)
	if err != nil || !strings.HasPrefix(parsed.Path, "/") || strings.HasPrefix(parsed.Path, "//") || strings.Contains(parsed.Path, "\\") || parsed.IsAbs() || parsed.Host != "" {
		return "/"
	}
	return parsed.RequestURI()
}

func writeJSON(response http.ResponseWriter, status int, value any) {
	response.Header().Set("Content-Type", "application/json; charset=utf-8")
	response.Header().Set("Cache-Control", "no-store")
	response.WriteHeader(status)
	if err := json.NewEncoder(response).Encode(value); err != nil && !errors.Is(err, io.ErrClosedPipe) {
		log.Printf("encode OIDC gateway response: %v", err)
	}
}

func (server *Server) securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		if !strings.HasPrefix(request.URL.Path, "/auth/") {
			next.ServeHTTP(response, request)
			return
		}
		if request.URL.Path == "/auth/frontchannel-logout" {
			response.Header().Set("Content-Security-Policy", fmt.Sprintf("default-src 'none'; frame-ancestors %s://%s; base-uri 'none'; form-action 'none'", server.config.Issuer.Scheme, server.config.Issuer.Host))
		} else {
			response.Header().Set("Content-Security-Policy", fmt.Sprintf("default-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self' %s://%s", server.config.Issuer.Scheme, server.config.Issuer.Host))
			response.Header().Set("X-Frame-Options", "DENY")
		}
		response.Header().Set("Referrer-Policy", "no-referrer")
		response.Header().Set("X-Content-Type-Options", "nosniff")
		next.ServeHTTP(response, request)
	})
}
