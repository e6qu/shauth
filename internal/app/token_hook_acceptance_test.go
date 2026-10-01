// SPDX-License-Identifier: AGPL-3.0-or-later
//go:build acceptance

package app

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"testing"
	"time"

	"github.com/e6qu/shauth/internal/identity"
)

// Ory Hydra asks the token hook before every token it issues, including each
// refresh. The answer must follow the account as it is now, not as it was at
// consent, and must keep the claims Hydra itself put in the token.
func TestTokenHookReissuesCurrentClaimsAndRefusesDisabledAccounts(t *testing.T) {
	_, handler, store := newAdminAPIAcceptanceServer(t)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	user, err := store.CreatePasswordUser(ctx, "token-hook-user", "hook@token-hook.test", "token-hook-password-1", identity.RoleAdmin)
	if err != nil {
		t.Fatal(err)
	}
	_, browserSession, err := store.CreateSession(ctx, user.ID, "token hook acceptance", net.ParseIP("192.0.2.40"), time.Now())
	if err != nil {
		t.Fatal(err)
	}
	const sid = "6a1d6c3e-hook-acceptance-login-session"
	if err := store.RecordHydraLoginSession(ctx, browserSession.ID, sid, time.Now()); err != nil {
		t.Fatal(err)
	}
	call := func(token, subject, sessionID, grant string) (int, map[string]map[string]any) {
		t.Helper()
		ext := `"role":"developer","email":"stale@token-hook.test"`
		if sessionID != "" {
			ext = fmt.Sprintf(`"sid":%q,`, sessionID) + ext
		}
		body := fmt.Sprintf(`{"session":{"id_token":{"subject":%[1]q,"id_token_claims":{"sub":%[1]q,"ext":{%[2]s}}},"extra":{"role":"developer","custom":"kept"}},"request":{"client_id":"app","grant_types":[%[3]q]}}`, subject, ext, grant)
		response := adminAPIAcceptanceRequest(t, handler, http.MethodPost, "https://auth.example.test/internal/hydra/token-hook", token, body)
		var decoded struct {
			Session map[string]map[string]any `json:"session"`
		}
		if response.Code == http.StatusOK {
			if err := json.Unmarshal(response.Body.Bytes(), &decoded); err != nil {
				t.Fatalf("decode token hook answer: %v: %s", err, response.Body.String())
			}
		}
		return response.Code, decoded.Session
	}
	hook := func(token, subject string) (int, map[string]map[string]any) {
		t.Helper()
		return call(token, subject, sid, "refresh_token")
	}

	if status, _ := call(tokenHookAcceptanceToken, "machine-client", "", "client_credentials"); status != http.StatusNoContent {
		t.Fatalf("hook for a client-credentials grant = %d, want 204", status)
	}
	if status, _ := call(tokenHookAcceptanceToken, user.ID, sid, "urn:ietf:params:oauth:grant-type:jwt-bearer"); status != http.StatusForbidden {
		t.Fatalf("hook for a JWT bearer grant naming an account = %d, want 403", status)
	}
	if status, _ := call(tokenHookAcceptanceToken, user.ID, "", "refresh_token"); status != http.StatusForbidden {
		t.Fatalf("hook for a token with no sign-in session = %d, want 403", status)
	}
	if status, _ := call(tokenHookAcceptanceToken, user.ID, "unknown-login-session", "refresh_token"); status != http.StatusForbidden {
		t.Fatalf("hook for an uncorrelated sign-in session = %d, want 403", status)
	}
	if status, _ := hook("wrong-token-wrong-token-wrong-token-wrong", user.ID); status != http.StatusUnauthorized {
		t.Fatalf("hook with a wrong credential = %d, want 401", status)
	}
	if status, _ := hook(tokenHookAcceptanceToken, "not-an-account"); status != http.StatusForbidden {
		t.Fatalf("hook for a foreign subject = %d, want 403", status)
	}
	if status, _ := hook(tokenHookAcceptanceToken, "00000000-0000-4000-8000-000000000000"); status != http.StatusForbidden {
		t.Fatalf("hook for a deleted account = %d, want 403", status)
	}

	status, session := hook(tokenHookAcceptanceToken, user.ID)
	if status != http.StatusOK {
		t.Fatalf("hook for an active account = %d", status)
	}
	for _, name := range []string{"access_token", "id_token"} {
		claims := session[name]
		if claims["role"] != "admin" || claims["email"] != "hook@token-hook.test" || claims["sub"] != user.ID {
			t.Fatalf("%s claims = %v, want the account's current role and email", name, claims)
		}
	}
	if session["id_token"]["sid"] != sid {
		t.Fatalf("id token lost Hydra's sid claim: %v", session["id_token"])
	}
	if session["access_token"]["custom"] != "kept" {
		t.Fatalf("access token lost an existing claim: %v", session["access_token"])
	}

	// Another account cannot borrow this sign-in session.
	other, err := store.CreatePasswordUser(ctx, "token-hook-other", "other@token-hook.test", "token-hook-password-2", identity.RoleAdmin)
	if err != nil {
		t.Fatal(err)
	}
	if status, _ := hook(tokenHookAcceptanceToken, other.ID); status != http.StatusForbidden {
		t.Fatalf("hook for another account's sign-in session = %d, want 403", status)
	}

	// Ending this one session, with the account still active, stops the
	// tokens issued under it.
	if err := store.RevokeSession(ctx, browserSession.ID, time.Now()); err != nil {
		t.Fatal(err)
	}
	if status, _ := hook(tokenHookAcceptanceToken, user.ID); status != http.StatusForbidden {
		t.Fatalf("hook after the sign-in session ended = %d, want 403", status)
	}

	if _, err := store.DisableUser(ctx, user.ID, time.Now()); err != nil {
		t.Fatal(err)
	}
	if status, _ := hook(tokenHookAcceptanceToken, user.ID); status != http.StatusForbidden {
		t.Fatalf("hook for a disabled account = %d, want 403", status)
	}
}
