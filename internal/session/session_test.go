// SPDX-License-Identifier: AGPL-3.0-or-later

package session

import (
	"testing"
	"time"
)

func TestRecordIsActiveBeforeExpiry(t *testing.T) {
	createdAt := time.Date(2026, time.July, 15, 12, 0, 0, 0, time.UTC)
	record, err := NewRecord("session-1", "user-1", "family-1", createdAt, createdAt.Add(time.Hour))
	if err != nil {
		t.Fatalf("NewRecord() error = %v", err)
	}
	if state := record.CurrentState(createdAt.Add(time.Minute)); state != StateActive {
		t.Fatalf("CurrentState() = %q, want active", state)
	}
}

func TestRevokeInvalidatesSession(t *testing.T) {
	createdAt := time.Date(2026, time.July, 15, 12, 0, 0, 0, time.UTC)
	record, err := NewRecord("session-1", "user-1", "family-1", createdAt, createdAt.Add(time.Hour))
	if err != nil {
		t.Fatalf("NewRecord() error = %v", err)
	}
	revoked, err := record.Revoke(createdAt.Add(time.Minute))
	if err != nil {
		t.Fatalf("Revoke() error = %v", err)
	}
	if revoked.State != StateRevoked {
		t.Fatalf("state = %q, want revoked", revoked.State)
	}
	if revoked.RevokedAt.IsZero() {
		t.Fatal("RevokedAt is zero")
	}
}

func TestExpiredSessionCannotBeRevoked(t *testing.T) {
	createdAt := time.Date(2026, time.July, 15, 12, 0, 0, 0, time.UTC)
	record, err := NewRecord("session-1", "user-1", "family-1", createdAt, createdAt.Add(time.Hour))
	if err != nil {
		t.Fatalf("NewRecord() error = %v", err)
	}
	if _, err := record.Revoke(createdAt.Add(2 * time.Hour)); err == nil {
		t.Fatal("Revoke() succeeded for expired session")
	}
}
