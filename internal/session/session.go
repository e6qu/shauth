// SPDX-License-Identifier: AGPL-3.0-or-later

// Package session contains the security-critical multi-device session and
// refresh-token-family lifecycle rules shared by the HTTP and admin surfaces.
package session

import (
	"fmt"
	"strings"
	"time"
)

type ID string
type UserID string
type FamilyID string

type State string

const (
	StateActive  State = "active"
	StateRevoked State = "revoked"
	StateExpired State = "expired"
)

// Record is one browser/device session and the refresh-token family attached
// to it. Token material is never stored here: persistence stores only hashes.
type Record struct {
	ID        ID
	UserID    UserID
	FamilyID  FamilyID
	CreatedAt time.Time
	ExpiresAt time.Time
	RevokedAt time.Time
	State     State
}

// NewRecord validates a newly issued independent device/profile session.
func NewRecord(id ID, userID UserID, familyID FamilyID, createdAt, expiresAt time.Time) (Record, error) {
	if strings.TrimSpace(string(id)) == "" {
		return Record{}, fmt.Errorf("session ID must not be empty")
	}
	if strings.TrimSpace(string(userID)) == "" {
		return Record{}, fmt.Errorf("user ID must not be empty")
	}
	if strings.TrimSpace(string(familyID)) == "" {
		return Record{}, fmt.Errorf("refresh-token family ID must not be empty")
	}
	if !expiresAt.After(createdAt) {
		return Record{}, fmt.Errorf("session expiry must be after creation")
	}
	return Record{ID: id, UserID: userID, FamilyID: familyID, CreatedAt: createdAt, ExpiresAt: expiresAt, State: StateActive}, nil
}

// CurrentState derives expiry without mutating stored records.
func (record Record) CurrentState(now time.Time) State {
	if record.State == StateRevoked {
		return StateRevoked
	}
	if !now.Before(record.ExpiresAt) {
		return StateExpired
	}
	return StateActive
}

// Revoke invalidates this device/profile and its refresh-token family.
func (record Record) Revoke(now time.Time) (Record, error) {
	if record.CurrentState(now) != StateActive {
		return Record{}, fmt.Errorf("only an active session can be revoked")
	}
	record.State = StateRevoked
	record.RevokedAt = now.UTC()
	return record, nil
}
