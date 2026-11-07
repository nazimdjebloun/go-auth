package api

// Actor identifies a user and the session established by trusted backend
// authentication. It contains no credentials, roles or cached permission grants.
// A value is attribution, not proof of authentication or continuing access.
// Never construct it from client-supplied user/session IDs or persist it as an
// authorization decision. JSON cannot populate or serialize its identity fields.
type Actor struct {
	UserID    string `json:"-"`
	SessionID string `json:"-"`
}

// ForOrg selects an organization for a subsequent live permission check. It
// neither validates the organization nor establishes membership or authority.
func (a Actor) ForOrg(orgID string) OrgPermissionActor {
	return OrgPermissionActor{UserID: a.UserID, SessionID: a.SessionID, OrgID: orgID}
}
