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
	"net"
	"net/http"
	"net/url"
	"slices"
	"sort"
	"strings"
	"time"

	githubapi "github.com/e6qu/shauth/internal/github"
	"github.com/e6qu/shauth/internal/identity"
	"github.com/e6qu/shauth/internal/monitoring"
	"github.com/e6qu/shauth/internal/observe"
)

// actor identifies who requested an operation. Browser callers supply the
// signed-in administrator; token-authorized callers supply the zero value.
// It is durable state -- it becomes an invitation's inviter and a validation
// run's requester -- so it is an explicit input and is never recovered from
// a request inside an operation.
type actor struct {
	UserID    string
	SessionID string
	Address   net.IP
	// Kind says who acted when no account did: "token" for a bearer
	// credential, "visitor" for someone without a session. Empty means
	// Shauth acted on its own.
	Kind string
}

func (a actor) isSelf(userID string) bool { return a.UserID != "" && a.UserID == userID }

// tokenActor describes a token-authorized caller. Bearer credentials are
// shared and opaque, so no person can be named; the address the call came
// from is recorded instead, which is what an operator has to work with.
func tokenActor(r *http.Request) actor { return actor{Address: clientIP(r), Kind: "token"} }

// visitorActor describes somebody acting before they have an account or a
// session, such as an invitation recipient. Only the address is knowable.
func visitorActor(r *http.Request) actor { return actor{Address: clientIP(r), Kind: "visitor"} }

// browserActor describes the signed-in administrator performing an action,
// including the session and address they acted from.
func browserActor(r *http.Request, user identity.User, session identity.Session) actor {
	return actor{UserID: user.ID, SessionID: session.ID, Address: clientIP(r)}
}

// record appends one audit event. A failure to record is logged and never
// fails the operation: losing the record is bad, but refusing a legitimate
// administrative action because a log write failed is worse.
func (s *Server) record(ctx context.Context, requester actor, eventType, subjectUserID string, details map[string]any) {
	if requester.UserID == "" {
		// Without an account the record still says what kind of caller
		// acted, so a token-driven change is not mistaken for a visitor.
		kind := requester.Kind
		if kind == "" {
			kind = "service"
		}
		labelled := make(map[string]any, len(details)+1)
		for key, value := range details {
			labelled[key] = value
		}
		labelled["actor_kind"] = kind
		details = labelled
	}
	entry := identity.AuditEntry{
		EventType: eventType, ActorUserID: requester.UserID, SubjectUserID: subjectUserID,
		SessionID: requester.SessionID, RemoteAddress: requester.Address, Details: details,
	}
	if err := s.store.RecordAuditEvent(ctx, entry, time.Now()); err != nil {
		observe.Errorf("record audit event %s: %v", eventType, err)
	}
}

var (
	// errOIDCClientInUse reports that a managed app still depends on the
	// OpenID Connect client a caller asked to delete.
	errOIDCClientInUse = errors.New("remove the connected app before deleting its OAuth client")
	// errOIDCClientDeploymentOwned reports an attempt to delete the OAuth
	// client of an app the deployment's bootstrap configuration declares;
	// every start would recreate it.
	errOIDCClientDeploymentOwned = errors.New("this OAuth client belongs to an app declared by the deployment's bootstrap configuration; remove it there")
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
	case errors.Is(err, githubapi.ErrAccountNotFound), errors.Is(err, githubapi.ErrInvalidLogin):
		return http.StatusBadRequest, err.Error()
	case errors.As(err, &dependency):
		// The caller sees only the safe message; the cause is what an
		// operator needs to diagnose the dependency.
		observe.Errorf("%s: %s: %v", action, dependency.message, dependency.cause)
		return http.StatusBadGateway, dependency.Error()
	case errors.Is(err, identity.ErrAlreadyExists):
		// The action names what was being created ("create user"); the
		// caller is told that such a thing already exists.
		return http.StatusConflict, "that " + userFacingNoun(strings.TrimPrefix(action, "create ")) + " already exists"
	case errors.Is(err, errHydraClientConflict):
		return http.StatusConflict, "an OAuth client with that identifier already exists"
	case errors.Is(err, errOIDCClientInUse), errors.Is(err, errSelfDisable),
		errors.Is(err, errOIDCClientDeploymentOwned), errors.Is(err, identity.ErrManagedAppDeploymentOwned),
		errors.Is(err, identity.ErrValidationUserProtected), errors.Is(err, identity.ErrActiveSessionNotFound),
		errors.Is(err, identity.ErrUserInactive):
		return http.StatusConflict, err.Error()
	case errors.Is(err, identity.ErrUserNotFound), errors.Is(err, identity.ErrSessionNotFound),
		errors.Is(err, identity.ErrInvitationNotRevocable), errors.Is(err, identity.ErrManagedAppNotFound),
		errors.Is(err, identity.ErrGitHubRoleMappingNotFound), errors.Is(err, errHydraClientNotFound):
		return http.StatusNotFound, err.Error()
	default:
		observe.Errorf("%s: %v", action, err)
		return http.StatusInternalServerError, "could not complete the request"
	}
}

// userFacingNoun names a stored thing the way the interface does.
func userFacingNoun(noun string) string {
	switch noun {
	case "GitHub role mapping":
		return "GitHub access rule"
	case "managed app":
		return "application"
	default:
		return noun
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
func (s *Server) createUser(ctx context.Context, input userCreateRequest, requester actor) (identity.User, error) {
	user, err := s.store.CreatePasswordUser(ctx, input.Username, input.Email, input.Password, identity.Role(input.Role))
	if err != nil {
		return identity.User{}, err
	}
	s.record(ctx, requester, identity.AuditAccountCreated, user.ID, map[string]any{
		"username": user.Username, "email": user.Email, "role": string(user.Role),
	})
	return user, nil
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
	revokeErr := s.revokeOtherHydraSessions(ctx, hydraSessionIDs)
	if revokeErr == nil {
		revokeErr = s.revokeHydraSubjectSessions(ctx, userID)
	}
	if revokeErr != nil {
		// The account is disabled whatever the provider answered, so the
		// audit record says so, and that provider revocation is unfinished.
		s.record(ctx, requester, identity.AuditAccountDisabled, userID, map[string]any{
			"revoked_provider_sessions": 0, "oauth_revocation": "failed",
		})
		return identity.User{}, dependencyFailure("the account was disabled and its sessions ended, but OAuth session revocation did not complete", revokeErr)
	}
	user, err := s.store.UserByID(ctx, userID)
	if err != nil {
		return identity.User{}, err
	}
	s.record(ctx, requester, identity.AuditAccountDisabled, userID, map[string]any{
		"username": user.Username, "revoked_provider_sessions": len(hydraSessionIDs),
	})
	return user, nil
}

// enableUser restores a disabled account. It grants no session; the account
// holder must authenticate again.
func (s *Server) enableUser(ctx context.Context, userID string, requester actor) (identity.User, error) {
	if err := requireUUID(userID, identity.ErrUserNotFound); err != nil {
		return identity.User{}, err
	}
	if err := s.store.EnableUser(ctx, userID, time.Now()); err != nil {
		return identity.User{}, err
	}
	user, err := s.store.UserByID(ctx, userID)
	if err != nil {
		return identity.User{}, err
	}
	s.record(ctx, requester, identity.AuditAccountEnabled, userID, map[string]any{"username": user.Username})
	return user, nil
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
			observe.Errorf("revoke unsent invitation %s: %v", invitation.ID, revokeErr)
		}
		return identity.Invitation{}, dependencyFailure("the invitation email could not be sent, so the invitation was withdrawn", err)
	}
	s.record(ctx, requester, identity.AuditInvitationCreated, "", map[string]any{
		"invitation_id": invitation.ID, "email": invitation.Email, "role": string(invitation.Role),
	})
	return invitation, nil
}

// claimInvitation turns one invitation into an account. The recipient is not
// signed in yet, so the record carries the address the link was used from and
// names the account it created as its subject. Both the acceptance and the
// account creation are recorded: an operator asking how an account came to
// exist should find it under the same event type as every other account.
func (s *Server) claimInvitation(ctx context.Context, token, username, password string, requester actor) (identity.User, error) {
	user, err := s.store.AcceptInvitation(ctx, token, username, password, time.Now())
	if err != nil {
		return identity.User{}, err
	}
	details := map[string]any{"username": user.Username, "email": user.Email, "role": string(user.Role), "via": "invitation"}
	s.record(ctx, requester, identity.AuditInvitationAccepted, user.ID, details)
	s.record(ctx, requester, identity.AuditAccountCreated, user.ID, details)
	return user, nil
}

// revokeInvitation withdraws an unaccepted invitation so a link sent to the
// wrong address can no longer create an account.
func (s *Server) revokeInvitation(ctx context.Context, invitationID string, requester actor) error {
	if err := requireUUID(invitationID, identity.ErrInvitationNotRevocable); err != nil {
		return err
	}
	if err := s.store.RevokeInvitation(ctx, invitationID, time.Now()); err != nil {
		return err
	}
	s.record(ctx, requester, identity.AuditInvitationRevoked, "", map[string]any{"invitation_id": invitationID})
	return nil
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
func (s *Server) revokeSession(ctx context.Context, sessionID string, requester actor) (revokeSessionResult, error) {
	if err := requireUUID(sessionID, identity.ErrSessionNotFound); err != nil {
		return revokeSessionResult{}, err
	}
	userID, err := s.store.SessionUserID(ctx, sessionID)
	if err != nil {
		return revokeSessionResult{}, err
	}
	// A browser session that already ended is still reported as a conflict,
	// but its provider sessions are revoked again first: when an earlier
	// attempt ended the browser session and then failed to reach Ory Hydra,
	// retrying is the operator's only way to finish the job.
	localErr := s.store.RevokeSession(ctx, sessionID, time.Now())
	if localErr != nil && !errors.Is(localErr, identity.ErrActiveSessionNotFound) {
		return revokeSessionResult{}, localErr
	}
	hydraSessionIDs, err := s.store.HydraLoginSessionIDs(ctx, sessionID)
	if err != nil {
		return revokeSessionResult{}, fmt.Errorf("load OAuth session correlation: %w", err)
	}
	if err := s.revokeOtherHydraSessions(ctx, hydraSessionIDs); err != nil {
		if localErr == nil {
			s.record(ctx, requester, identity.AuditSessionRevoked, userID, map[string]any{
				"session_id": sessionID, "revoked_provider_sessions": 0, "oauth_revocation": "failed",
			})
		}
		return revokeSessionResult{}, dependencyFailure("the session ended, but OAuth session revocation did not complete", err)
	}
	if localErr != nil {
		return revokeSessionResult{}, localErr
	}
	s.record(ctx, requester, identity.AuditSessionRevoked, userID, map[string]any{
		"session_id": sessionID, "revoked_provider_sessions": len(hydraSessionIDs),
	})
	return revokeSessionResult{SessionID: sessionID, UserID: userID}, nil
}

// revokeUserSessions ends every browser session for one account and the
// provider sessions correlated with them. The account stays enabled and can
// sign in again; disableUser is the containing operation.
func (s *Server) revokeUserSessions(ctx context.Context, userID, email string, requester actor) (string, error) {
	if userID == "" {
		if email == "" {
			return "", identity.Invalid("provide a user identifier or an email address")
		}
		resolved, err := s.store.UserIDByEmail(ctx, email)
		if err != nil {
			return "", err
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
		s.record(ctx, requester, identity.AuditAccountSessionsEnded, userID, map[string]any{"addressed_by_email": email != "", "oauth_revocation": "failed"})
		return "", dependencyFailure("the sessions ended, but OAuth session revocation did not complete", err)
	}
	s.record(ctx, requester, identity.AuditAccountSessionsEnded, userID, map[string]any{"addressed_by_email": email != ""})
	return userID, nil
}

// updateSessionPolicy applies the requested lifetimes to every registered
// OAuth client and then persists them, restoring the previous policy if
// either step fails so the provider and PostgreSQL cannot disagree.
func (s *Server) updateSessionPolicy(ctx context.Context, request sessionPolicyRecord, requester actor) (sessionPolicyRecord, error) {
	policy, err := request.sessionPolicy()
	if err != nil {
		return sessionPolicyRecord{}, err
	}
	// Held for the whole change: a client registered meanwhile would be
	// missed by the update below yet created with the old lifetimes, and two
	// concurrent changes could leave Hydra and PostgreSQL holding different
	// policies.
	var applied sessionPolicyRecord
	err = s.store.WithSessionPolicyLock(ctx, func(ctx context.Context) error {
		applied, err = s.replaceSessionPolicy(ctx, policy, requester)
		return err
	})
	return applied, err
}

func (s *Server) replaceSessionPolicy(ctx context.Context, policy identity.SessionPolicy, requester actor) (sessionPolicyRecord, error) {
	previous, err := s.store.SessionPolicy(ctx)
	if err != nil {
		return sessionPolicyRecord{}, fmt.Errorf("load current session policy: %w", err)
	}
	if err := s.applyHydraSessionPolicy(ctx, policy); err != nil {
		if rollbackErr := s.applyHydraSessionPolicy(ctx, previous); rollbackErr != nil {
			observe.Errorf("restore Ory Hydra session policy after client update failed: %v", rollbackErr)
		}
		return sessionPolicyRecord{}, dependencyFailure("the OAuth client lifetimes could not be updated, so the previous policy was restored", err)
	}
	changedAt, err := s.store.UpdateSessionPolicy(ctx, policy)
	if err != nil {
		if rollbackErr := s.applyHydraSessionPolicy(ctx, previous); rollbackErr != nil {
			observe.Errorf("restore Ory Hydra session policy after PostgreSQL update failed: %v", rollbackErr)
		}
		return sessionPolicyRecord{}, err
	}
	policy.UpdatedAt = changedAt
	s.record(ctx, requester, identity.AuditSessionPolicyUpdated, "", map[string]any{
		"previous": newSessionPolicyRecord(previous), "applied": newSessionPolicyRecord(policy),
	})
	return newSessionPolicyRecord(policy), nil
}

// createOIDCClient registers a confidential client with the authorization
// provider and reports the registration as the provider now holds it.
func (s *Server) createOIDCClient(ctx context.Context, input oidcClientInput, requester actor) (oidcClient, error) {
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
	s.record(ctx, requester, identity.AuditOIDCClientCreated, "", map[string]any{
		"client_id": client.ID, "client_name": client.Name, "redirect_uris": client.RedirectURIs,
	})
	return client, nil
}

// deleteOIDCClient removes a client registration, refusing while a managed
// app still depends on it.
func (s *Server) deleteOIDCClient(ctx context.Context, clientID string, requester actor) error {
	if !deletableOIDCClientID(clientID) {
		return identity.Invalid("OAuth client identifier is invalid")
	}
	if s.isBootstrapClient(clientID) {
		return errOIDCClientDeploymentOwned
	}
	// Registering an app against this client checks the provider and then
	// writes the catalog row, so the usage check and the deletion have to
	// hold the same lock or the two can cross and strand the app.
	err := s.store.WithOIDCClientLock(ctx, clientID, func(ctx context.Context) error {
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
	})
	if err != nil {
		return err
	}
	s.record(ctx, requester, identity.AuditOIDCClientDeleted, "", map[string]any{"client_id": clientID})
	return nil
}

// createGitHubMapping records a rule granting a role to a GitHub user,
// organization, or team. A user rule is bound to the account's numeric ID
// now, while the login names the account the administrator means: a login
// can later be renamed and claimed by someone else, the ID cannot.
func (s *Server) createGitHubMapping(ctx context.Context, kind, target, role string, requester actor) (identity.GitHubRoleMapping, error) {
	if err := identity.ValidateGitHubRoleMapping(kind, target, identity.Role(role)); err != nil {
		return identity.GitHubRoleMapping{}, err
	}
	var githubUserID int64
	if kind == "user" {
		id, err := s.github.AccountID(ctx, target)
		if errors.Is(err, githubapi.ErrAccountNotFound) || errors.Is(err, githubapi.ErrInvalidLogin) {
			return identity.GitHubRoleMapping{}, err
		}
		if err != nil {
			return identity.GitHubRoleMapping{}, dependencyFailure("GitHub could not confirm the account; try again", err)
		}
		githubUserID = id
	}
	mapping, err := s.store.CreateGitHubRoleMapping(ctx, kind, target, githubUserID, identity.Role(role))
	if err != nil {
		return identity.GitHubRoleMapping{}, err
	}
	details := map[string]any{"mapping_id": mapping.ID, "kind": mapping.Kind, "target": mapping.Target, "role": string(mapping.Role)}
	if mapping.GitHubUserID > 0 {
		details["github_user_id"] = mapping.GitHubUserID
	}
	s.record(ctx, requester, identity.AuditGitHubMappingCreated, "", details)
	return mapping, nil
}

func (s *Server) deleteGitHubMapping(ctx context.Context, mappingID string, requester actor) error {
	if err := requireUUID(mappingID, identity.ErrGitHubRoleMappingNotFound); err != nil {
		return err
	}
	mapping, err := s.store.DeleteGitHubRoleMapping(ctx, mappingID)
	if err != nil {
		return err
	}
	s.record(ctx, requester, identity.AuditGitHubMappingDeleted, "", map[string]any{
		"mapping_id": mapping.ID, "kind": mapping.Kind, "target": mapping.Target, "role": string(mapping.Role),
	})
	// A role granted by a rule that no longer exists must not outlive it in
	// a browser session or an OAuth token. The accounts it may have granted
	// are signed out everywhere and re-evaluated at their next sign-in.
	accounts, err := s.store.GitHubAccountsPossiblyGrantedBy(ctx, mapping)
	if err != nil {
		return dependencyFailure("the rule was removed, but the sessions it granted could not be listed; end them from the sessions page", err)
	}
	var failures []error
	for _, userID := range accounts {
		if _, err := s.revokeUserSessions(ctx, userID, "", requester); err != nil {
			failures = append(failures, err)
		}
	}
	if len(failures) > 0 {
		return dependencyFailure(fmt.Sprintf("the rule was removed, but %d of %d affected accounts could not be signed out; end their sessions from the sessions page", len(failures), len(accounts)), errors.Join(failures...))
	}
	return nil
}

// bootstrapSlugs lists the apps the deployment's configuration declares.
func (s *Server) bootstrapSlugs() []string {
	slugs := make([]string, 0, len(s.config.BootstrapApps))
	for _, app := range s.config.BootstrapApps {
		slugs = append(slugs, app.Slug)
	}
	return slugs
}

func (s *Server) isBootstrapSlug(slug string) bool {
	return slices.Contains(s.bootstrapSlugs(), slug)
}

func (s *Server) isBootstrapClient(clientID string) bool {
	for _, app := range s.config.BootstrapApps {
		if app.OIDCClientID == clientID {
			return true
		}
	}
	return false
}

// createApp registers a managed app against an already-registered OpenID
// Connect client, enforcing the one-origin and logout-bridge invariants that
// make single sign-out reachable for every relying party.
func (s *Server) createApp(ctx context.Context, app identity.ManagedApp, requester actor) (identity.ManagedApp, error) {
	// Held against deleteOIDCClient: verifying the client and writing the
	// catalog row must be one step, or the client can be deleted in between
	// and the new app is registered against nothing.
	var created identity.ManagedApp
	err := s.store.WithOIDCClientLock(ctx, app.OIDCClientID, func(ctx context.Context) error {
		clients, err := s.hydraClients(ctx)
		if err != nil {
			return dependencyFailure("the OAuth client could not be verified", err)
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
			return identity.Invalid("register the OIDC client before adding its app")
		}
		app.OIDCContractHash = oidcClientContractHash(*registered)
		if err := identity.ValidateManagedApp(app); err != nil {
			return err
		}
		if err := validateManagedAppClient(app, *registered); err != nil {
			return err
		}
		created, err = s.store.CreateManagedApp(ctx, app)
		return err
	})
	if err != nil {
		return identity.ManagedApp{}, err
	}
	s.record(ctx, requester, identity.AuditAppCreated, "", map[string]any{
		"slug": created.Slug, "oidc_client_id": created.OIDCClientID, "release_revision": created.ReleaseRevision,
	})
	return created, nil
}

func (s *Server) deleteApp(ctx context.Context, ref identity.ManagedAppRef, requester actor) error {
	if ref.ID != "" {
		if err := requireUUID(ref.ID, identity.ErrManagedAppNotFound); err != nil {
			return err
		}
	}
	slug, err := s.store.DeleteManagedApp(ctx, ref, s.bootstrapSlugs())
	if err != nil {
		return err
	}
	s.record(ctx, requester, identity.AuditAppDeleted, "", map[string]any{"id": ref.ID, "slug": slug})
	return nil
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
	s.record(ctx, requester, identity.AuditValidationEnqueued, "", map[string]any{"applications": slugs})
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
			observe.Errorf("count active sessions: %v", err)
		} else {
			snapshot.ActiveSessions = &counted
		}
	}
	snapshot.Infrastructure = s.monitoringClient.FetchAll(ctx, s.monitoringSources(ctx))
	snapshot.HydraHealthy = s.hydraReady(ctx)
	return snapshot
}
