// SPDX-License-Identifier: AGPL-3.0-or-later

package observe

import (
	"bytes"
	"fmt"
	"log"
	"strings"
	"sync"
	"testing"
	"time"
)

// TestCapturedLinesKeepTheirLevelAndReachBothDestinations covers the contract
// the log page depends on: the buffer holds what the container stream holds,
// and a line's severity comes from the writer rather than from a guess about
// its wording.
func TestCapturedLinesKeepTheirLevelAndReachBothDestinations(t *testing.T) {
	buffer := NewBuffer(10)
	var stream bytes.Buffer
	previous := log.Writer()
	t.Cleanup(func() { log.SetOutput(previous) })
	Capture(buffer, &stream)

	Infof("bootstrapped %d applications", 3)
	Warnf("waiting for the provider")
	Errorf("revoke session: %v", fmt.Errorf("connection refused"))
	log.Printf("a dependency wrote this straight to the logger")

	if !strings.Contains(stream.String(), "bootstrapped 3 applications") {
		t.Fatalf("standard error did not receive the line: %q", stream.String())
	}
	records, held := buffer.Records(Filter{})
	if held != 4 {
		t.Fatalf("held = %d, want 4", held)
	}
	if len(records) != 4 {
		t.Fatalf("records = %d, want 4", len(records))
	}
	// Newest first: that is the order an operator reads an incident in.
	want := []struct{ level, message string }{
		{LevelUnlabelled, "a dependency wrote this straight to the logger"},
		{LevelError, "revoke session: connection refused"},
		{LevelWarn, "waiting for the provider"},
		{LevelInfo, "bootstrapped 3 applications"},
	}
	for index, expected := range want {
		if records[index].Level != expected.level || records[index].Message != expected.message {
			t.Fatalf("record %d = %+v, want %s %q", index, records[index], expected.level, expected.message)
		}
	}
	if records[0].Sequence <= records[1].Sequence {
		t.Fatalf("sequence did not increase with each line: %+v", records)
	}
	if records[0].At.IsZero() {
		t.Fatal("a captured line carried no time")
	}
}

// TestTheBufferKeepsTheNewestLinesWhenItWraps is why the buffer is bounded:
// it must be the recent past, not a memory leak.
func TestTheBufferKeepsTheNewestLinesWhenItWraps(t *testing.T) {
	buffer := NewBuffer(4)
	for index := 0; index < 10; index++ {
		if _, err := buffer.Write([]byte(fmt.Sprintf("INFO line %d\n", index))); err != nil {
			t.Fatal(err)
		}
	}
	records, held := buffer.Records(Filter{})
	if held != 4 || len(records) != 4 {
		t.Fatalf("held = %d, records = %d, want 4 of each", held, len(records))
	}
	if records[0].Message != "line 9" || records[3].Message != "line 6" {
		t.Fatalf("wrapped buffer = %+v, want lines 9 down to 6", records)
	}
	if buffer.Capacity() != 4 {
		t.Fatalf("capacity = %d, want 4", buffer.Capacity())
	}
}

func TestFiltersNarrowBySeverityTextAndTime(t *testing.T) {
	buffer := NewBuffer(20)
	for _, line := range []string{
		"INFO signed in username=ada",
		"WARN provider slow",
		"ERROR revoke session for ADA failed",
		"INFO signed out username=grace",
	} {
		if _, err := buffer.Write([]byte(line + "\n")); err != nil {
			t.Fatal(err)
		}
	}

	errorsOnly, _ := buffer.Records(Filter{MinimumLevel: LevelError})
	if len(errorsOnly) != 1 || errorsOnly[0].Level != LevelError {
		t.Fatalf("errors only = %+v", errorsOnly)
	}
	warnAndWorse, _ := buffer.Records(Filter{MinimumLevel: LevelWarn})
	if len(warnAndWorse) != 2 {
		t.Fatalf("warn and worse = %+v, want the warning and the error", warnAndWorse)
	}
	// Searching for a name should not depend on how it was capitalised.
	named, _ := buffer.Records(Filter{Contains: "ada"})
	if len(named) != 2 {
		t.Fatalf("contains ada = %+v, want both lines naming her", named)
	}
	limited, _ := buffer.Records(Filter{Limit: 1})
	if len(limited) != 1 || limited[0].Message != "signed out username=grace" {
		t.Fatalf("limited = %+v, want only the newest line", limited)
	}
	future, _ := buffer.Records(Filter{Since: time.Now().Add(time.Hour)})
	if len(future) != 0 {
		t.Fatalf("since the future = %+v, want nothing", future)
	}
	counts := buffer.Counts()
	if counts[LevelError] != 1 || counts[LevelWarn] != 1 || counts[LevelInfo] != 2 {
		t.Fatalf("counts = %v", counts)
	}
}

// TestTheStandardLoggerPrefixIsReadRatherThanRepeated keeps the date and time
// out of the message, so a search for text does not match a timestamp.
func TestTheStandardLoggerPrefixIsReadRatherThanRepeated(t *testing.T) {
	buffer := NewBuffer(4)
	if _, err := buffer.Write([]byte("2026/08/03 11:22:33 ERROR something failed\n")); err != nil {
		t.Fatal(err)
	}
	records, _ := buffer.Records(Filter{})
	if len(records) != 1 {
		t.Fatalf("records = %+v", records)
	}
	if records[0].Message != "something failed" {
		t.Fatalf("message = %q, want the prefix removed", records[0].Message)
	}
	if records[0].Level != LevelError {
		t.Fatalf("level = %q, want %q", records[0].Level, LevelError)
	}
	if hour, minute, second := records[0].At.Local().Clock(); hour != 11 || minute != 22 || second != 33 {
		t.Fatalf("time = %s, want the logger's own stamp", records[0].At)
	}
}

// TestAnEnormousLineCannotHoldTheBuffersMemory bounds one record.
func TestAnEnormousLineCannotHoldTheBuffersMemory(t *testing.T) {
	buffer := NewBuffer(2)
	if _, err := buffer.Write([]byte("ERROR " + strings.Repeat("x", 100_000) + "\n")); err != nil {
		t.Fatal(err)
	}
	records, _ := buffer.Records(Filter{})
	if len(records[0].Message) > maximumMessageBytes+8 {
		t.Fatalf("stored message length = %d, want it truncated near %d", len(records[0].Message), maximumMessageBytes)
	}
}

// TestConcurrentWritersAndReadersDoNotRace is worth stating because every
// request handler in the service can write here at once.
func TestConcurrentWritersAndReadersDoNotRace(t *testing.T) {
	buffer := NewBuffer(64)
	var group sync.WaitGroup
	for writer := 0; writer < 8; writer++ {
		group.Add(1)
		go func(id int) {
			defer group.Done()
			for index := 0; index < 50; index++ {
				_, _ = buffer.Write([]byte(fmt.Sprintf("INFO writer %d line %d\n", id, index)))
			}
		}(writer)
	}
	for reader := 0; reader < 4; reader++ {
		group.Add(1)
		go func() {
			defer group.Done()
			for index := 0; index < 50; index++ {
				buffer.Records(Filter{Limit: 10})
				buffer.Counts()
			}
		}()
	}
	group.Wait()
	if _, held := buffer.Records(Filter{}); held != 64 {
		t.Fatalf("held = %d, want the buffer full", held)
	}
}
