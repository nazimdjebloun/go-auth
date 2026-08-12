package routes

import "testing"

func TestGlob(t *testing.T) {
	cases := []struct {
		pattern string
		want    string
	}{
		{Login, "POST /auth/login"},
		{GetOrg, "GET /auth/orgs/*"},
		{RemoveOrgMember, "DELETE /auth/orgs/*/members/*"},
		{ResendOrgInvite, "POST /auth/orgs/*/invites/*/resend"},
		{SetActiveOrg, "PUT /auth/orgs/active"},
	}
	for _, c := range cases {
		if got := Glob(c.pattern); got != c.want {
			t.Errorf("Glob(%q) = %q, want %q", c.pattern, got, c.want)
		}
	}
}
