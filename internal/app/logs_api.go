// SPDX-License-Identifier: AGPL-3.0-or-later

package app

import (
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/e6qu/shauth/internal/identity"
	"github.com/e6qu/shauth/internal/observe"
)

// serviceLogSize is how many lines the buffer keeps. It is large enough to
// cover a startup and the minutes around an incident, and small enough that
// the memory it costs is not worth measuring.
const serviceLogSize = 2000

// serviceLog is the process-wide buffer. The standard logger is global, so
// what captures it is global too; a Server reads it rather than owning it.
var serviceLog = observe.NewBuffer(serviceLogSize)

// ServiceLog reports the buffer the entrypoint tees the standard logger into.
func ServiceLog() *observe.Buffer { return serviceLog }

// logRecord is one captured line as published.
type logRecord struct {
	Sequence uint64    `json:"sequence"`
	At       time.Time `json:"at"`
	Level    string    `json:"level"`
	Message  string    `json:"message"`
}

// logsAPI publishes what this instance has reported. Until now the only way
// to read it was to shell into a running container, which needs a different
// kind of access than reading the service's own contracts and is not
// available at all once the container has been replaced.
func (s *Server) logsAPI(w http.ResponseWriter, r *http.Request) {
	noStore(w)
	if !s.requireAdminAPIReadToken(w, r) {
		return
	}
	filter, err := requestedLogFilter(r)
	if err != nil {
		writeOperationFailure(w, "read service log", err)
		return
	}
	records, held := s.serviceLog().Records(filter)
	published := make([]logRecord, 0, len(records))
	for _, record := range records {
		published = append(published, logRecord{Sequence: record.Sequence, At: record.At, Level: record.Level, Message: record.Message})
	}
	writeAdminAPIJSON(w, http.StatusOK, map[string]any{
		"schema_version": "shauth.logs/v1",
		"observed_at":    time.Now().UTC(),
		"build":          buildRecord(),
		"buffer":         map[string]any{"held": held, "capacity": s.serviceLog().Capacity(), "by_level": s.serviceLog().Counts()},
		"entries":        published,
	})
}

// requestedLogFilter reads the filters an operator narrows a search with.
func requestedLogFilter(r *http.Request) (observe.Filter, error) {
	query := r.URL.Query()
	filter := observe.Filter{
		Contains: strings.TrimSpace(query.Get("contains")),
	}
	switch level := strings.ToLower(strings.TrimSpace(query.Get("level"))); level {
	case "", "all":
	case observe.LevelError, observe.LevelWarn, observe.LevelInfo:
		filter.MinimumLevel = level
	default:
		return observe.Filter{}, identity.Invalid("level must be error, warn, info, or all")
	}
	if raw := strings.TrimSpace(query.Get("since")); raw != "" {
		since, err := time.Parse(time.RFC3339, raw)
		if err != nil {
			return observe.Filter{}, identity.Invalid("since must be an RFC 3339 timestamp")
		}
		filter.Since = since
	}
	if raw := strings.TrimSpace(query.Get("limit")); raw != "" {
		limit, err := strconv.Atoi(raw)
		if err != nil || limit < 1 || limit > serviceLogSize {
			return observe.Filter{}, identity.Invalid("limit must be a whole number between 1 and %d", serviceLogSize)
		}
		filter.Limit = limit
	}
	return filter, nil
}

// adminLogs is the browser view of the same buffer, with the same filters.
func (s *Server) adminLogs(w http.ResponseWriter, r *http.Request) {
	if !s.requireAdmin(w, r) {
		return
	}
	filter, err := requestedLogFilter(r)
	message := ""
	if err != nil {
		_, message = describeOperationFailure("read service log", err)
		filter = observe.Filter{}
	}
	if filter.Limit == 0 {
		filter.Limit = 200
	}
	records, held := s.serviceLog().Records(filter)
	entries := make([]logRecord, 0, len(records))
	for _, record := range records {
		entries = append(entries, logRecord{Sequence: record.Sequence, At: record.At, Level: record.Level, Message: record.Message})
	}
	counts := s.serviceLog().Counts()
	s.render(w, "logs", s.view(r, "Service log", map[string]any{
		"SignedIn": true, "IsAdmin": true, "Entries": entries, "Error": message,
		"Level": filter.MinimumLevel, "Contains": filter.Contains, "Limit": filter.Limit,
		"Held": held, "Capacity": s.serviceLog().Capacity(),
		"Errors": counts[observe.LevelError], "Warnings": counts[observe.LevelWarn],
	}))
}

// serviceLog reports the buffer this server reads, defaulting to the process
// buffer so a directly constructed server still answers.
func (s *Server) serviceLog() *observe.Buffer {
	if s.logs != nil {
		return s.logs
	}
	return serviceLog
}
