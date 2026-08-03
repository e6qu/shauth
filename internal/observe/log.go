// SPDX-License-Identifier: AGPL-3.0-or-later

// Package observe carries the service log: the leveled helpers every package
// writes through, and the bounded buffer that keeps the most recent lines
// readable without shelling into a container.
//
// The helpers write through the standard logger, so the container stream and
// the buffer are the same text. Nothing is written here that is not already
// written to standard error; exposing the buffer therefore adds no new place
// for a secret to appear, and the rule that secrets are never logged is what
// keeps it that way.
package observe

import (
	"io"
	"log"
	"strings"
	"sync"
	"time"
)

// Levels. They are a prefix on the line rather than structure around it, so
// one format serves the container stream, a grep, and the buffer.
const (
	LevelError = "error"
	LevelWarn  = "warn"
	LevelInfo  = "info"
	// LevelUnlabelled is what a line written straight to the standard
	// logger gets -- by a dependency, for instance. Guessing a severity
	// from the words in a message would put a confident label on a guess.
	LevelUnlabelled = "log"
)

// severity orders the levels for filtering. An unlabelled line sorts with
// information, because that is the weakest claim that can be made about it.
var severity = map[string]int{LevelError: 3, LevelWarn: 2, LevelInfo: 1, LevelUnlabelled: 1}

// Errorf reports something an operator has to act on.
func Errorf(format string, args ...any) { log.Printf("ERROR "+format, args...) }

// Warnf reports something that worked but should not have been necessary, or
// a degraded state that has not yet failed.
func Warnf(format string, args ...any) { log.Printf("WARN "+format, args...) }

// Infof reports a normal event worth keeping.
func Infof(format string, args ...any) { log.Printf("INFO "+format, args...) }

// Record is one captured line.
type Record struct {
	Sequence uint64    `json:"sequence"`
	At       time.Time `json:"at"`
	Level    string    `json:"level"`
	Message  string    `json:"message"`
}

// maximumMessageBytes bounds one record. A single enormous line must not be
// able to hold the whole buffer's memory.
const maximumMessageBytes = 4096

// Buffer keeps the most recent lines in a fixed ring. It is deliberately
// process-local and lost on restart: it answers what this instance has been
// reporting, which is the question during an incident. The durable record of
// who did what is the audit log, not this.
type Buffer struct {
	mutex    sync.Mutex
	records  []Record
	next     int
	filled   bool
	sequence uint64
	now      func() time.Time
}

// NewBuffer creates a buffer holding at most size lines.
func NewBuffer(size int) *Buffer {
	if size < 1 {
		size = 1
	}
	return &Buffer{records: make([]Record, size), now: time.Now}
}

// Capture tees the standard logger into the buffer. The original destination
// is kept, so the container stream is unchanged and nothing depends on this
// to see the logs.
func Capture(buffer *Buffer, stream io.Writer) {
	log.SetOutput(io.MultiWriter(stream, buffer))
}

// Write accepts one formatted log line from the standard logger.
func (b *Buffer) Write(line []byte) (int, error) {
	written := len(line)
	at, level, message := parseLine(string(line), b.timestamp())
	if message == "" {
		return written, nil
	}
	if len(message) > maximumMessageBytes {
		message = message[:maximumMessageBytes] + "…"
	}
	b.mutex.Lock()
	defer b.mutex.Unlock()
	b.sequence++
	b.records[b.next] = Record{Sequence: b.sequence, At: at, Level: level, Message: message}
	b.next = (b.next + 1) % len(b.records)
	if b.next == 0 {
		b.filled = true
	}
	return written, nil
}

func (b *Buffer) timestamp() time.Time {
	if b.now == nil {
		return time.Now()
	}
	return b.now()
}

// parseLine splits the standard logger's own date and time prefix and the
// level token this package writes. A line carrying neither is kept whole and
// stamped with its arrival, so output from a dependency is never dropped and
// never relabelled.
func parseLine(line string, arrived time.Time) (time.Time, string, string) {
	line = strings.TrimRight(line, "\n")
	at := arrived.UTC()
	if len(line) >= 19 {
		if stamped, err := time.ParseInLocation("2006/01/02 15:04:05", line[:19], time.Local); err == nil {
			at = stamped.UTC()
			line = strings.TrimPrefix(line[19:], " ")
		}
	}
	level := LevelUnlabelled
	for token, named := range map[string]string{"ERROR ": LevelError, "WARN ": LevelWarn, "INFO ": LevelInfo} {
		if strings.HasPrefix(line, token) {
			level, line = named, line[len(token):]
			break
		}
	}
	return at, level, strings.TrimSpace(line)
}

// Filter narrows a read of the buffer.
type Filter struct {
	// MinimumLevel drops anything less severe. Empty keeps everything.
	MinimumLevel string
	// Contains keeps only lines containing this text, matched without
	// regard to case because an operator searching for a slug should not
	// have to know how it was capitalised.
	Contains string
	// Since keeps only lines at or after this instant.
	Since time.Time
	// Limit bounds the answer. Zero means the buffer's default window.
	Limit int
}

// Records reports the most recent matching lines, newest first, and how many
// lines the buffer currently holds.
func (b *Buffer) Records(filter Filter) ([]Record, int) {
	limit := filter.Limit
	if limit < 1 {
		limit = 200
	}
	contains := strings.ToLower(strings.TrimSpace(filter.Contains))
	wanted := severity[filter.MinimumLevel]

	b.mutex.Lock()
	defer b.mutex.Unlock()
	held := b.heldLocked()
	matching := make([]Record, 0, limit)
	// Walk backwards from the newest so a small limit reads a small number
	// of records rather than the whole ring.
	for index := 0; index < held && len(matching) < limit; index++ {
		record := b.records[((b.next-1-index)%len(b.records)+len(b.records))%len(b.records)]
		if severity[record.Level] < wanted {
			continue
		}
		if !filter.Since.IsZero() && record.At.Before(filter.Since) {
			continue
		}
		if contains != "" && !strings.Contains(strings.ToLower(record.Message), contains) {
			continue
		}
		matching = append(matching, record)
	}
	return matching, held
}

// Counts reports how many held lines carry each level, so a page can say
// "three errors" without reading every record.
func (b *Buffer) Counts() map[string]int {
	b.mutex.Lock()
	defer b.mutex.Unlock()
	counts := map[string]int{LevelError: 0, LevelWarn: 0, LevelInfo: 0, LevelUnlabelled: 0}
	held := b.heldLocked()
	for index := 0; index < held; index++ {
		record := b.records[((b.next-1-index)%len(b.records)+len(b.records))%len(b.records)]
		counts[record.Level]++
	}
	return counts
}

// Capacity reports how many lines the buffer can hold, so a reader can tell a
// quiet service from one whose older lines have already been overwritten.
func (b *Buffer) Capacity() int { return len(b.records) }

func (b *Buffer) heldLocked() int {
	if b.filled {
		return len(b.records)
	}
	return b.next
}
