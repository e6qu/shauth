// SPDX-License-Identifier: AGPL-3.0-or-later

// Administration operations. Every administrative state change in Shauth is
// implemented exactly once, here. The token-authorized JSON API and the
// signed-in browser interface are both thin transports over these
// operations: they parse their own input, call one operation, and render its
// typed result or its typed failure. Neither reimplements an operation, so
// the two can no longer drift.
//
// Transport concerns stay out of this file: no http.Request, no cookies, no
// CSRF, no redirects, no bearer tokens, no status codes at the call sites.
// Operations report failures as typed sentinels and describeOperationFailure
// maps them once for both transports.
package app

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"sort"
	"time"

	"github.com/e6qu/shauth/internal/identity"
	"github.com/e6qu/shauth/internal/monitoring"
)

// actor identifies who requested an operation. Browser callers supply the
// signed-in administrator; token-authorized callers supply the zero value.
// It is durable state -- it becomes an invitation's inviter and a validation
// run's requester -- so it is an explicit input and is never recovered from
// a request inside an operation.
type actor struct{ UserID string }

func (a actor) isSelf(userID string) bool { return a.UserID != "" && a.UserID == userID }

var (
	// errOIDCClientInUse reports that a managed app still depends on the
	// OpenID Connect client a caller asked to delete.
	errOIDCClientInUse = errors.New("delete the connected app before deleting its OAuth client")
	// errSelfDisable reports an administrator attempting to disable the
	// account they are signed in with, which would lock them out.
	errSelfDisable = errors.New("you cannot disable the account you are signed in with")
)

// dependencyError reports that a required external dependency -- the
// authorization provider or the invitation mailer -- did not complete. It is
// answered as a gateway failure rather than a rejection, because the request
// itself was valid.
type dependencyError struct {
	message string
	cause   error
}

func (err dependencyError) Error() string { return err.message }
func (err dependencyError) Unwrap() error { return err.cause }

func dependencyFailure(message string, cause error) error {
	return dependencyError{message: message, cause: cause}
}

// describeOperationFailure maps an operation failure onto the status and the
// caller-safe message both transports use. Anything unrecognized is an
// internal fault: it is logged with its detail and answered generically, so
// database and provider internals never reach a caller.
func describeOperationFailure(action string, err error) (int, string) {
	var invalid identity.InvalidInputError
	var dependency dependencyError
	switch {
	case errors.As(err, &invalid):
		return http.StatusBadRequest, invalid.Error()
	case errors.As(err, &dependency):
		log.Printf("%s: %v", action, err)
		return http.StatusBadGateway, dependency.Error()
	case errors.Is(err, identity.ErrAlreadyExists):
		return http.StatusConflict, action + " already exists"
	case errors.Is(err, errHydraClientConflict):
		return http.StatusConflict, "an OAuth client with that identifier already exists"
	case errors.Is(err, errOIDCClientInUse), errors.Is(err, errSelfDisable),
		errors.Is(err, identity.ErrValidationUserProtected), errors.Is(err, identity.ErrActiveSessionNotFound):
		return http.StatusConflict, err.Error()
	case errors.Is(err, identity.ErrUserNotFound), errors.Is(err, identity.ErrSessionNotFound),
		errors.Is(err, identity.ErrInvitationNotRevocable), errors.Is(err, identity.ErrManagedAppNotFound),
		errors.Is(err, identity.ErrGitHubRoleMappingNotFound), errors.Is(err, errHydraClientNotFound):
		return http.StatusNotFound, err.Error()
	default:
		log.Printf("%s: %v", action, err)
		return http.StatusInternalServerError, "could not complete the request"
	}
}

// requireUUID rejects a malformed identifier before it reaches PostgreSQL,
// where an invalid UUID cast would surface as an internal fault rather than
// the "not found" the caller deserves.
func requireUUID(id string, missing error) error {
	if !uuidPathPattern.MatchString(id) {
		return missing
	}
	return nil
}

// createUser registers a local password account.
func (s *Server) createUser(ctx context.Context, input userCreateRequest) (identity.User, error) {
	return s.store.CreatePasswordUser(ctx, input.Username, input.Email, input.Password, identity.Role(input.Role))
}

// disableUser contains an account: it ends every browser session, revokes the
// correlated provider sessions, and blocks sign-in. Session revocation alone
// is not containment, because the same credential can sign straight back in.
func (s *Server) disableUser(ctx context.Context, userID string, requester actor) (identity.User, error) {
	if err := requireUUID(userID, identity.ErrUserNotFound); err != nil {
		return identity.User{}, err
	}
	if requester.isSelf(userID) {
		return identity.User{}, errSelfDisable
	}
	hydraSessionIDs, err := s.store.DisableUser(ctx, userID, time.Now())
	if err != nil {
		return identity.User{}, err
	}
	for _, hydraSessionID := range hydraSessionIDs {
		if err := s.revokeHydraLoginSession(ctx, hydraSessionID); err != nil {
			return identity.User{}, dependencyFailure("the account was disabled and its sessions ended, but OAuth session revocation did not complete", err)
		}
	}
	if err := s.revokeHydraSubjectSessions(ctx, userID); err != nil {
		return identity.User{}, dependencyFailure("the account was disabled and its sessions ended, but OAuth session revocation did not complete", err)
	}
	return s.store.UserByID(ctx, userID)
}

// enableUser restores a disabled account. It grants no session; the account
// holder must authenticate again.
func (s *Server) enableUser(ctx context.Context, userID string) (identity.User, error) {
	if err := requireUUID(userID, identity.ErrUserNotFound); err != nil {
		return identity.User{}, err
	}
	if err := s.store.EnableUser(ctx, userID, time.Now()); err != nil {
		return identity.User{}, err
	}
	return s.store.UserByID(ctx, userID)
}

// createInvitation records an invitation and delivers its single-use link by
// email. The link is never returned to the caller. If the email cannot be
// sent the invitation is revoked, so an undeliverable invitation can never be
// redeemed.
func (s *Server) createInvitation(ctx context.Context, email, role string, requester actor) (identity.Invitation, error) {
	raw, invitation, err := s.store.CreateInvitation(ctx, email, identity.Role(role), requester.UserID, time.Now())
	if err != nil {
		return identity.Invitation{}, err
	}
	link := s.config.PublicURL.ResolveReference(&url.URL{Path: "/accept-invitation", RawQuery: "token=" + url.QueryEscape(raw)}).String()
	if err := s.mailer.SendInvitation(ctx, invitation.Email, link); err != nil {
		if revokeErr := s.store.RevokeInvitation(ctx, invitation.ID, time.Now()); revokeErr != nil {
			log.Printf("revoke unsent invitation %s: %v", invitation.ID, revokeErr)
		}
		return identity.Invitation{}, dependencyFailure("the invitation email could not be sent, so the invitation was withdrawn", err)
	}
	return invitation, nil
}

// revokeInvitation withdraws an unaccepted invitation so a link sent to the
// wrong address can no longer create an account.
func (s *Server) revokeInvitation(ctx context.Context, invitationID string) error {
	if err := requireUUID(invitationID, identity.ErrInvitationNotRevocable); err != nil {
		return err
	}
	return s.store.RevokeInvitation(ctx, invitationID, time.Now())
}

// revokeSessionResult reports which account a revoked session belonged to, so
// a browser caller can return to that account and a machine caller can record
// what it ended.
type revokeSessionResult struct {
	SessionID string
	UserID    string
}

// revokeSession ends one browser session and the provider sessions
// correlated with it.
func (s *Server) revokeSession(ctx context.Context, sessionID string) (revokeSessionResult, error) {
	if err := requireUUID(sessionID, identity.ErrSessionNotFound); err != nil {
		return revokeSessionResult{}, err
	}
	userID, err := s.store.SessionUserID(ctx, sessionID)
	if err != nil {
		return revokeSessionResult{}, err
	}
	if err := s.store.RevokeSession(ctx, sessionID, time.Now()); err != nil {
		return revokeSessionResult{}, err
	}
	hydraSessionIDs, err := s.store.HydraLoginSessionIDs(ctx, sessionID)
	if err != nil {
		return revokeSessionResult{}, fmt.Errorf("load OAuth session correlation: %w", err)
	}
	for _, hydraSessionID := range hydraSessionIDs {
		if err := s.revokeHydraLoginSession(ctx, hydraSessionID); err != nil {
			return revokeSessionResult{}, dependencyFailure("the session ended, but OAuth session revocation did not complete", err)
		}
	}
	return revokeSessionResult{SessionID: sessionID, UserID: userID}, nil
}

// revokeUserSessions ends every browser session for one account and the
// provider sessions correlated with them. The account stays enabled and can
// sign in again; disableUser is the containing operation.
func (s *Server) revokeUserSessions(ctx context.Context, userID, email string) (string, error) {
	if userID == "" {
		if email == "" {
			return "", identity.Invalid("provide a user identifier or an email address")
		}
		resolved, err := s.store.UserIDByEmail(ctx, email)
		if err != nil {
			return "", identity.ErrUserNotFound
		}
		userID = resolved
	}
	if err := requireUUID(userID, identity.ErrUserNotFound); err != nil {
		return "", err
	}
	if err := s.store.RevokeUserSessions(ctx, userID, time.Now()); err != nil {
		return "", err
	}
	if err := s.revokeHydraSessions(ctx, userID); err != nil {
		return "", dependencyFailure("the sessions ended, but OAuth session revocation did not complete", err)
	}
	return userID, nil
}

// updateSessionPolicy applies the requested lifetimes to every registered
// OAuth client and then persists them, restoring the previous policy if
// either step fails so the provider and PostgreSQL cannot disagree.
func (s *Server) updateSessionPolicy(ctx context.Context, request sessionPolicyRecord) (sessionPolicyRecord, error) {
	policy, err := request.sessionPolicy()
	if err != nil {
		return sessionPolicyRecord{}, err
	}
	previous, err := s.store.SessionPolicy(ctx)
	if err != nil {
		return sessionPolicyRecord{}, fmt.Errorf("load current session policy: %w", err)
	}
	if err := s.applyHydraSessionPolicy(ctx, policy); err != nil {
		if rollbackErr := s.applyHydraSessionPolicy(ctx, previous); rollbackErr != nil {
			log.Printf("restore Ory Hydra session policy after client update failed: %v", rollbackErr)
		}
		return sessionPolicyRecord{}, dependencyFailure("the OAuth client lifetimes could not be updated, so the previous policy was restored", err)
	}
	if err := s.store.UpdateSessionPolicy(ctx, policy, time.Now()); err != nil {
		if rollbackErr := s.applyHydraSessionPolicy(ctx, previous); rollbackErr != nil {
			log.Printf("restore Ory Hydra session policy after PostgreSQL update failed: %v", rollbackErr)
		}
		return sessionPolicyRecord{}, err
	}
	return newSessionPolicyRecord(policy), nil
}

// createOIDCClient registers a confidential client with the authorization
// provider and reports the registration as the provider now holds it.
func (s *Server) createOIDCClient(ctx context.Context, input oidcClientInput) (oidcClient, error) {
	if err := input.validate(); err != nil {
		return oidcClient{}, err
	}
	if err := s.createHydraClient(ctx, input); err != nil {
		if errors.Is(err, errHydraClientConflict) {
			return oidcClient{}, err
		}
		return oidcClient{}, dependencyFailure("the OAuth client could not be registered", err)
	}
	client := registeredOIDCClient(input)
	client.Name = input.Name
	return client, nil
}

// deleteOIDCClient removes a client registration, refusing while a managed
// app still depends on it.
func (s *Server) deleteOIDCClient(ctx context.Context, clientID string) error {
	if !deletableOIDCClientID(clientID) {
		return identity.Invalid("OAuth client identifier is invalid")
	}
	used, err := s.store.ManagedAppUsesOIDCClient(ctx, clientID)
	if err != nil {
		return fmt.Errorf("verify connected apps: %w", err)
	}
	if used {
		return errOIDCClientInUse
	}
	if err := s.deleteHydraClient(ctx, clientID); err != nil {
		if errors.Is(err, errHydraClientNotFound) {
			return err
		}
		return dependencyFailure("the OAuth client could not be deleted", err)
	}
	return nil
}

// createGitHubMapping records a rule granting a role to a GitHub user,
// organization, or team.
func (s *Server) createGitHubMapping(ctx context.Context, kind, target, role string) (identity.GitHubRoleMapping, error) {
	return s.store.CreateGitHubRoleMapping(ctx, kind, target, identity.Role(role))
}

func (s *Server) deleteGitHubMapping(ctx context.Context, mappingID string) error {
	if err := requireUUID(mappingID, identity.ErrGitHubRoleMappingNotFound); err != nil {
		return err
	}
	return s.store.DeleteGitHubRoleMapping(ctx, mappingID)
}

// createApp registers a managed app against an already-registered OpenID
// Connect client, enforcing the one-origin and logout-bridge invariants that
// make single sign-out reachable for every relying party.
func (s *Server) createApp(ctx context.Context, app identity.ManagedApp) (identity.ManagedApp, error) {
	clients, err := s.hydraClients(ctx)
	if err != nil {
		return identity.ManagedApp{}, dependencyFailure("the OAuth client could not be verified", err)
	}
	var registered *oidcClient
	for _, client := range clients {
		if client.ID == app.OIDCClientID {
			match := client
			registered = &match
			break
		}
	}
	if registered == nil {
		return identity.ManagedApp{}, identity.Invalid("register the OIDC client before adding its app")
	}
	app.OIDCContractHash = oidcClientContractHash(*registered)
	if err := identity.ValidateManagedApp(app); err != nil {
		return identity.ManagedApp{}, err
	}
	if err := validateManagedAppClient(app, *registered); err != nil {
		return identity.ManagedApp{}, err
	}
	return s.store.CreateManagedApp(ctx, app)
}

func (s *Server) deleteApp(ctx context.Context, ref identity.ManagedAppRef) error {
	if ref.ID != "" {
		if err := requireUUID(ref.ID, identity.ErrManagedAppNotFound); err != nil {
			return err
		}
	}
	return s.store.DeleteManagedApp(ctx, ref)
}

// enqueueAppValidations queues both browser checks for the referenced app, or
// for every registered app. The requesting operator is recorded on every
// path, including token-authorized ones that supply no actor.
func (s *Server) enqueueAppValidations(ctx context.Context, ref identity.ManagedAppRef, requester actor) ([]validationEnqueueRecord, error) {
	if ref.ID != "" {
		if err := requireUUID(ref.ID, identity.ErrManagedAppNotFound); err != nil {
			return nil, err
		}
	}
	slugs, err := s.store.EnqueueAppValidations(ctx, ref, requester.UserID, time.Now())
	if err != nil {
		return nil, err
	}
	enqueued := make([]validationEnqueueRecord, 0, len(slugs)*2)
	for _, slug := range slugs {
		for _, direction := range []string{identity.ValidationFromShauth, identity.ValidationFromApp} {
			enqueued = append(enqueued, validationEnqueueRecord{Slug: slug, Direction: direction})
		}
	}
	return enqueued, nil
}

// listOIDCClients reports the provider's client catalog in a stable order, so
// the browser table and the machine contract agree row for row.
func (s *Server) listOIDCClients(ctx context.Context) ([]oidcClient, error) {
	clients, err := s.hydraClients(ctx)
	if err != nil {
		return nil, dependencyFailure("the OAuth clients could not be listed", err)
	}
	sort.Slice(clients, func(i, j int) bool { return clients[i].ID < clients[j].ID })
	return clients, nil
}

// connectorStatus reports which upstream identity sources are configured.
type connectorStatus struct {
	GitHubEnabled       bool
	GitHubAdminTeam     string
	GitHubDeveloperTeam string
	EntraEnabled        bool
	EntraTenantID       string
}

func (s *Server) connectors() connectorStatus {
	status := connectorStatus{GitHubEnabled: s.oauth != nil, EntraEnabled: s.entraOAuth != nil}
	if status.GitHubEnabled {
		status.GitHubAdminTeam, status.GitHubDeveloperTeam = s.config.GitHubAdminTeam, s.config.GitHubDeveloperTeam
	}
	if status.EntraEnabled {
		status.EntraTenantID = s.config.EntraTenantID
	}
	return status
}

// monitoringSnapshot reports service and infrastructure health. The active
// session count needs PostgreSQL, so it is absent rather than fatal when
// PostgreSQL is unreachable: this observation exists to report an outage and
// must not go dark during one.
type monitoringSnapshot struct {
	ActiveSessions    *int
	PostgreSQLHealthy bool
	HydraHealthy      bool
	Infrastructure    []monitoring.Result
}

func (s *Server) monitoringSnapshot(ctx context.Context) monitoringSnapshot {
	checkContext, cancel := context.WithTimeout(ctx, 2*time.Second)
	snapshot := monitoringSnapshot{PostgreSQLHealthy: s.store.Ping(checkContext) == nil}
	cancel()
	if snapshot.PostgreSQLHealthy {
		if counted, err := s.store.CountActiveSessions(ctx, time.Now()); err != nil {
			log.Printf("count active sessions: %v", err)
		} else {
			snapshot.ActiveSessions = &counted
		}
	}
	snapshot.Infrastructure = s.monitoringClient.FetchAll(ctx, s.config.MonitoringSources)
	snapshot.HydraHealthy = s.hydraReady(ctx)
	return snapshot
}
