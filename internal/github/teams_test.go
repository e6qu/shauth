// SPDX-License-Identifier: AGPL-3.0-or-later

package github

import "testing"

func TestParseTeam(t *testing.T) {
	organization, slug, err := ParseTeam("e6qu-org/e6qu-org-admins")
	if err != nil {
		t.Fatalf("ParseTeam() error = %v", err)
	}
	if organization != "e6qu-org" || slug != "e6qu-org-admins" {
		t.Fatalf("ParseTeam() = %q/%q", organization, slug)
	}
}

func TestParseTeamRejectsInvalidValue(t *testing.T) {
	if _, _, err := ParseTeam("e6qu-org"); err == nil {
		t.Fatal("ParseTeam() accepted an invalid team")
	}
}
