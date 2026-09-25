package handler

import (
	"net/url"
	"testing"

	"github.com/nazimdjebloun/go-auth/api"
)

func TestSortParsersRejectInvalidExplicitValues(t *testing.T) {
	parsers := []struct {
		name  string
		parse func(url.Values) error
	}{
		{"users", func(q url.Values) error { _, _, err := parseUserSort(q); return err }},
		{"sessions", func(q url.Values) error { _, _, err := parseSessionSort(q); return err }},
		{"invites", func(q url.Values) error { _, _, err := parseInviteSort(q); return err }},
		{"org members", func(q url.Values) error { _, _, err := parseOrgMemberSort(q); return err }},
		{"user orgs", func(q url.Values) error { _, _, err := parseUserOrgSort(q); return err }},
		{"orgs", func(q url.Values) error { _, _, err := parseOrgSort(q); return err }},
		{"org invites", func(q url.Values) error { _, _, err := parseOrgInviteSort(q); return err }},
	}

	for _, parser := range parsers {
		t.Run(parser.name+" orderBy", func(t *testing.T) {
			if err := parser.parse(url.Values{"orderBy": {"not_a_field"}}); err == nil {
				t.Fatal("expected invalid orderBy error")
			}
		})
		t.Run(parser.name+" orderDirection", func(t *testing.T) {
			if err := parser.parse(url.Values{"orderDirection": {"sideways"}}); err == nil {
				t.Fatal("expected invalid orderDirection error")
			}
		})
	}
}

func TestSortParsersSupplyEstablishedDefaults(t *testing.T) {
	userField, userDirection, err := parseUserSort(url.Values{})
	if err != nil || userField != api.UserSortCreatedAt || userDirection != api.SortDescending {
		t.Fatalf("user defaults = (%q, %q, %v)", userField, userDirection, err)
	}

	memberField, memberDirection, err := parseOrgMemberSort(url.Values{})
	if err != nil || memberField != api.OrgMemberSortJoinedAt || memberDirection != api.SortAscending {
		t.Fatalf("member defaults = (%q, %q, %v)", memberField, memberDirection, err)
	}
}
