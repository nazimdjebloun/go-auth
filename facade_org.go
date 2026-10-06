package goauth

import (
	"fmt"
	"net/http"

	"github.com/nazimdjebloun/go-auth/domain"
	"github.com/nazimdjebloun/go-auth/internal/httperr"
	"github.com/nazimdjebloun/go-auth/middleware"
)

// OrgScope is the authenticated and authorized tenant identity for an
// application handler. It is constructed only after the session, membership,
// and minimum-role checks have succeeded.
//
// Pass the complete scope into tenant-owned repository methods and include
// OrgID in every query. go-auth cannot add an organization predicate to SQL
// issued by the consuming application.
type OrgScope struct {
	OrgID  string
	UserID string
	Role   domain.OrgRole
}

// OrgHandlerFunc handles a request after go-auth has resolved its OrgScope.
// RequireOrgScope and RequireActiveOrgScope adapt it to http.Handler.
type OrgHandlerFunc func(http.ResponseWriter, *http.Request, OrgScope)

// RequireOrg protects a consumer route with an org membership check plus a
// minimum role, using the same org repository and auth context as the built-in
// org routes. It resolves the org from the {orgID} path segment, falling back
// to the org_id query parameter, and must run after RequireAuth.
//
// For handlers that query tenant-owned application data, prefer
// RequireOrgScope. It performs the authentication and organization checks in
// the correct order and passes the resolved OrgScope directly to the handler.
//
// When organizations are disabled the returned middleware rejects every
// request with 503 — add goauth.WithOrganizations(goauth.OrganizationConfig{
// Enable: true}) to enable them.
func (a *Auth) RequireOrg(role domain.OrgRole) func(http.Handler) http.Handler {
	if !role.IsValid() {
		panic(fmt.Sprintf(
			"goauth: invalid org role %q — use domain.OrgRoleMember, domain.OrgRoleAdmin, or domain.OrgRoleOwner",
			role,
		))
	}
	if a.services.Org == nil {
		return func(_ http.Handler) http.Handler {
			return http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				httperr.Write(w, http.StatusServiceUnavailable, "organizations_disabled", "Organizations are not enabled", a.cfg.logger)
			})
		}
	}
	roleMW := middleware.RequireOrgRole(role)
	return func(next http.Handler) http.Handler {
		return a.orgMemberMW(roleMW(next))
	}
}

// RequireActiveOrg protects a consumer route with an org membership check
// plus a minimum role, same as RequireOrg, but resolves the org from the
// caller's session (session.ActiveOrgID/ActiveOrgRole, set via SetActiveOrg)
// instead of an {orgID} path segment. Use this for routes that operate
// implicitly on "the org I'm currently working in" — most of an app's own
// business routes (projects, tasks, and the like) — reserving RequireOrg for
// routes that name a specific org explicitly. Must run after RequireAuth.
//
// For handlers that query tenant-owned application data, prefer
// RequireActiveOrgScope. It passes the authenticated tenant scope directly to
// the handler instead of requiring it to recover the org ID from context.
//
// When organizations are disabled the returned middleware rejects every
// request with 503 — add goauth.WithOrganizations(goauth.OrganizationConfig{
// Enable: true}) to enable them.
func (a *Auth) RequireActiveOrg(role domain.OrgRole) func(http.Handler) http.Handler {
	if !role.IsValid() {
		panic(fmt.Sprintf(
			"goauth: invalid org role %q — use domain.OrgRoleMember, domain.OrgRoleAdmin, or domain.OrgRoleOwner",
			role,
		))
	}
	if a.services.Org == nil {
		return func(_ http.Handler) http.Handler {
			return http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				httperr.Write(w, http.StatusServiceUnavailable, "organizations_disabled", "Organizations are not enabled", a.cfg.logger)
			})
		}
	}
	return middleware.RequireActiveOrg(role)
}

// RequireOrgScope protects an application handler with authentication,
// membership, and minimum-role checks, then passes the authorized organization
// scope to next. It resolves the organization from the {orgID} path segment,
// falling back to the org_id query parameter.
//
// Authentication is included; do not wrap the returned handler in RequireAuth.
// CORS, CSRF, and rate limiting remain explicit so consumers can apply the
// layers appropriate to the route.
func (a *Auth) RequireOrgScope(role domain.OrgRole, next OrgHandlerFunc) http.Handler {
	return a.RequireAuth(a.RequireOrg(role)(a.orgScopeHandler(next)))
}

// RequireActiveOrgScope is RequireOrgScope for routes scoped by the active
// organization stored on the authenticated session instead of an {orgID} path
// segment.
//
// Authentication is included; do not wrap the returned handler in RequireAuth.
// CORS, CSRF, and rate limiting remain explicit so consumers can apply the
// layers appropriate to the route.
func (a *Auth) RequireActiveOrgScope(role domain.OrgRole, next OrgHandlerFunc) http.Handler {
	return a.RequireAuth(a.RequireActiveOrg(role)(a.orgScopeHandler(next)))
}

// orgScopeHandler is the final, fail-closed adapter in the scoped middleware
// chain. The preceding middleware owns each value checked here; an incomplete
// scope therefore indicates a wiring invariant failure, never input the
// application handler should be asked to interpret.
func (a *Auth) orgScopeHandler(next OrgHandlerFunc) http.Handler {
	if next == nil {
		panic("goauth: nil OrgHandlerFunc")
	}

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		user := middleware.GetUserFromContext(r.Context())
		session := middleware.GetSessionFromContext(r.Context())
		orgID := middleware.GetOrgID(r.Context())
		role := middleware.GetOrgRole(r.Context())
		if user == nil || session == nil || user.ID == "" || session.UserID != user.ID || orgID == "" || !role.IsValid() {
			if a.cfg.logger != nil {
				a.cfg.logger.Error("goauth: incomplete organization scope after authorization",
					"has_user", user != nil,
					"has_session", session != nil,
					"has_org_id", orgID != "",
					"valid_role", role.IsValid(),
				)
			}
			httperr.Write(w, http.StatusInternalServerError, domain.ErrInternal.Code, domain.ErrInternal.Message, a.cfg.logger)
			return
		}

		next(w, r, OrgScope{
			OrgID:  orgID,
			UserID: user.ID,
			Role:   role,
		})
	})
}
