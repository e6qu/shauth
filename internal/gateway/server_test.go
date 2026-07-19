// SPDX-License-Identifier: AGPL-3.0-or-later

package gateway

import (
	"encoding/json"
	"testing"
)

func TestValidLogoutEvent(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name   string
		events map[string]json.RawMessage
		want   bool
	}{
		{name: "empty object", events: map[string]json.RawMessage{logoutEvent: json.RawMessage(`{}`)}, want: true},
		{name: "nonempty object", events: map[string]json.RawMessage{logoutEvent: json.RawMessage(`{"reason":"administrator"}`)}, want: true},
		{name: "missing event", events: map[string]json.RawMessage{}, want: false},
		{name: "null", events: map[string]json.RawMessage{logoutEvent: json.RawMessage(`null`)}, want: false},
		{name: "string", events: map[string]json.RawMessage{logoutEvent: json.RawMessage(`"logout"`)}, want: false},
		{name: "array", events: map[string]json.RawMessage{logoutEvent: json.RawMessage(`[]`)}, want: false},
		{name: "invalid JSON", events: map[string]json.RawMessage{logoutEvent: json.RawMessage(`{`)}, want: false},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			if got := validLogoutEvent(test.events); got != test.want {
				t.Fatalf("validLogoutEvent() = %v, want %v", got, test.want)
			}
		})
	}
}
