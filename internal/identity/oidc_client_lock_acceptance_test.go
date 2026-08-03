// SPDX-License-Identifier: AGPL-3.0-or-later
//go:build acceptance

package identity

import (
	"context"
	"errors"
	"os"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

// TestOIDCClientLockSerializesOneClientAndOnlyThatClient proves the guarantee
// deleting a client depends on: two operations naming the same client never
// overlap, while operations on different clients still run concurrently.
func TestOIDCClientLockSerializesOneClientAndOnlyThatClient(t *testing.T) {
	databaseURL := os.Getenv("SHAUTH_ACCEPTANCE_DATABASE_URL")
	if databaseURL == "" {
		t.Fatal("SHAUTH_ACCEPTANCE_DATABASE_URL is required")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	pool, err := pgxpool.New(ctx, databaseURL)
	if err != nil {
		t.Fatalf("connect PostgreSQL: %v", err)
	}
	defer pool.Close()
	store, err := NewStore(pool)
	if err != nil {
		t.Fatal(err)
	}

	const contested = "lock-acceptance-contested"
	var inside, overlaps atomic.Int32
	var completed atomic.Int32
	var group sync.WaitGroup
	for worker := 0; worker < 6; worker++ {
		group.Add(1)
		go func() {
			defer group.Done()
			err := store.WithOIDCClientLock(ctx, contested, func(context.Context) error {
				if inside.Add(1) > 1 {
					overlaps.Add(1)
				}
				// Long enough that an unlocked implementation overlaps
				// on any machine that can run this suite at all.
				time.Sleep(150 * time.Millisecond)
				inside.Add(-1)
				completed.Add(1)
				return nil
			})
			if err != nil {
				t.Errorf("hold the contested OAuth client lock: %v", err)
			}
		}()
	}
	group.Wait()
	if completed.Load() != 6 {
		t.Fatalf("%d of 6 locked operations ran, want all of them", completed.Load())
	}
	if overlaps.Load() != 0 {
		t.Fatalf("%d operations on one OAuth client overlapped, want none", overlaps.Load())
	}

	// A lock that serialized every client would turn one slow provider call
	// into a queue for the whole catalog, so prove it does not.
	held := make(chan struct{})
	released := make(chan struct{})
	go func() {
		err := store.WithOIDCClientLock(ctx, "lock-acceptance-first", func(context.Context) error {
			close(held)
			<-released
			return nil
		})
		if err != nil {
			t.Errorf("hold the first OAuth client lock: %v", err)
		}
	}()
	<-held
	second := make(chan error, 1)
	go func() {
		second <- store.WithOIDCClientLock(ctx, "lock-acceptance-second", func(context.Context) error { return nil })
	}()
	select {
	case err := <-second:
		if err != nil {
			t.Fatalf("lock a different OAuth client while the first is held: %v", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("locking a different OAuth client waited on an unrelated client's lock")
	}
	close(released)

	// The lock reports the operation's own outcome rather than swallowing it.
	sentinel := errors.New("operation refused")
	if err := store.WithOIDCClientLock(ctx, contested, func(context.Context) error { return sentinel }); !errors.Is(err, sentinel) {
		t.Fatalf("WithOIDCClientLock returned %v, want the operation's own error", err)
	}
	if err := store.WithOIDCClientLock(ctx, contested, func(context.Context) error { return nil }); err != nil {
		t.Fatalf("the lock was not released after a refused operation: %v", err)
	}
}
