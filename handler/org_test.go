package handler

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/nazimdjebloun/go-auth/domain"
	"github.com/nazimdjebloun/go-auth/middleware"
)

func seedOrgUser(t *testing.T, th *testHarness) *domain.User {
	t.Helper()
	user := &domain.User{
		ID:        "user-1",
		Email:     "owner@test.com",
		Name:      "Owner",
		Role:      domain.RoleUser,
		IsVerified: true,
		CreatedAt: time.Now().UTC(),
		UpdatedAt: time.Now().UTC(),
	}
	if err := th.users.Create(context.Background(), user); err != nil {
		t.Fatal(err)
	}
	return user
}

func seedOrg(t *testing.T, th *testHarness, userID string) *domain.Organization {
	t.Helper()
	org := &domain.Organization{
		ID:          "org-1",
		Name:        "TestOrg",
		Slug:        "test-org",
		OwnerCount:  1,
		MemberCount: 1,
		CreatedBy:   &userID,
		CreatedAt:   time.Now().UTC(),
		UpdatedAt:   time.Now().UTC(),
	}
	if err := th.orgs.Create(context.Background(), org); err != nil {
		t.Fatal(err)
	}
	member := &domain.OrgMember{
		OrgID:    org.ID,
		UserID:   userID,
		Role:     domain.OrgRoleOwner,
		JoinedAt: time.Now().UTC(),
	}
	if err := th.orgs.AddMember(context.Background(), member); err != nil {
		t.Fatal(err)
	}
	return org
}

func seedSecondUser(t *testing.T, th *testHarness) *domain.User {
	t.Helper()
	user := &domain.User{
		ID:        "user-2",
		Email:     "member@test.com",
		Name:      "Member",
		Role:      domain.RoleUser,
		IsVerified: true,
		CreatedAt: time.Now().UTC(),
		UpdatedAt: time.Now().UTC(),
	}
	if err := th.users.Create(context.Background(), user); err != nil {
		t.Fatal(err)
	}
	return user
}

func TestCreateOrg_HappyPath(t *testing.T) {
	th := newTestHarness()
	user := seedOrgUser(t, th)

	body := `{"name":"NewOrg","slug":"new-org"}`
	req := httptest.NewRequest(http.MethodPost, "/orgs", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req = req.WithContext(middleware.ContextWithUser(req.Context(), user))
	w := httptest.NewRecorder()
	th.handler.CreateOrg(w, req)

	res := w.Result()
	if res.StatusCode != http.StatusCreated {
		t.Fatalf("expected 201, got %d", res.StatusCode)
	}
	var org domain.Organization
	json.NewDecoder(res.Body).Decode(&org)
	if org.Name != "NewOrg" || org.Slug != "new-org" {
		t.Errorf("unexpected org: %+v", org)
	}
}

func TestCreateOrg_Unauthenticated(t *testing.T) {
	th := newTestHarness()

	body := `{"name":"X","slug":"x"}`
	req := httptest.NewRequest(http.MethodPost, "/orgs", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	th.handler.CreateOrg(w, req)

	res := w.Result()
	if res.StatusCode != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", res.StatusCode)
	}
}

func TestCreateOrg_InvalidBody(t *testing.T) {
	th := newTestHarness()
	user := seedOrgUser(t, th)

	req := httptest.NewRequest(http.MethodPost, "/orgs", strings.NewReader(`not json`))
	req.Header.Set("Content-Type", "application/json")
	req = req.WithContext(middleware.ContextWithUser(req.Context(), user))
	w := httptest.NewRecorder()
	th.handler.CreateOrg(w, req)

	res := w.Result()
	if res.StatusCode != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", res.StatusCode)
	}
}

func TestGetOrg_HappyPath(t *testing.T) {
	th := newTestHarness()
	user := seedOrgUser(t, th)
	org := seedOrg(t, th, user.ID)

	req := httptest.NewRequest(http.MethodGet, "/orgs/"+org.ID, nil)
	req.SetPathValue("orgID", org.ID)
	w := httptest.NewRecorder()
	th.handler.GetOrg(w, req)

	res := w.Result()
	if res.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", res.StatusCode)
	}
	var got domain.Organization
	json.NewDecoder(res.Body).Decode(&got)
	if got.ID != org.ID {
		t.Errorf("expected id %s, got %s", org.ID, got.ID)
	}
}

func TestGetOrg_NotFound(t *testing.T) {
	th := newTestHarness()

	req := httptest.NewRequest(http.MethodGet, "/orgs/nonexistent", nil)
	req.SetPathValue("orgID", "nonexistent")
	w := httptest.NewRecorder()
	th.handler.GetOrg(w, req)

	res := w.Result()
	if res.StatusCode != http.StatusNotFound {
		t.Fatalf("expected 404, got %d", res.StatusCode)
	}
}

func TestUpdateOrg_HappyPath(t *testing.T) {
	th := newTestHarness()
	user := seedOrgUser(t, th)
	org := seedOrg(t, th, user.ID)

	body := `{"name":"Updated","slug":"updated-org"}`
	req := httptest.NewRequest(http.MethodPatch, "/orgs/"+org.ID, strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.SetPathValue("orgID", org.ID)
	w := httptest.NewRecorder()
	th.handler.UpdateOrg(w, req)

	res := w.Result()
	if res.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", res.StatusCode)
	}
	var got domain.Organization
	json.NewDecoder(res.Body).Decode(&got)
	if got.Name != "Updated" || got.Slug != "updated-org" {
		t.Errorf("unexpected org: %+v", got)
	}
}

func TestUpdateOrg_NotFound(t *testing.T) {
	th := newTestHarness()

	body := `{"name":"Nope"}`
	req := httptest.NewRequest(http.MethodPatch, "/orgs/bad-id", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.SetPathValue("orgID", "bad-id")
	w := httptest.NewRecorder()
	th.handler.UpdateOrg(w, req)

	res := w.Result()
	if res.StatusCode != http.StatusNotFound {
		t.Fatalf("expected 404, got %d", res.StatusCode)
	}
}

func TestDeleteOrg_HappyPath(t *testing.T) {
	th := newTestHarness()
	user := seedOrgUser(t, th)
	org := seedOrg(t, th, user.ID)

	req := httptest.NewRequest(http.MethodDelete, "/orgs/"+org.ID, nil)
	req.SetPathValue("orgID", org.ID)
	w := httptest.NewRecorder()
	th.handler.DeleteOrg(w, req)

	res := w.Result()
	if res.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", res.StatusCode)
	}

	_, err := th.orgs.GetByID(context.Background(), org.ID)
	if err != nil {
		t.Fatal(err)
	}
}

func TestDeleteOrg_NotFound(t *testing.T) {
	th := newTestHarness()

	req := httptest.NewRequest(http.MethodDelete, "/orgs/bad-id", nil)
	req.SetPathValue("orgID", "bad-id")
	w := httptest.NewRecorder()
	th.handler.DeleteOrg(w, req)

	res := w.Result()
	if res.StatusCode != http.StatusNotFound {
		t.Fatalf("expected 404, got %d", res.StatusCode)
	}
}

func TestListUserOrgs_HappyPath(t *testing.T) {
	th := newTestHarness()
	user := seedOrgUser(t, th)
	org := seedOrg(t, th, user.ID)

	req := httptest.NewRequest(http.MethodGet, "/orgs", nil)
	req = req.WithContext(middleware.ContextWithUser(req.Context(), user))
	w := httptest.NewRecorder()
	th.handler.ListUserOrgs(w, req)

	res := w.Result()
	if res.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", res.StatusCode)
	}
	var resp struct {
		Orgs []domain.Organization `json:"orgs"`
	}
	json.NewDecoder(res.Body).Decode(&resp)
	if len(resp.Orgs) != 1 || resp.Orgs[0].ID != org.ID {
		t.Errorf("expected [%s], got %+v", org.ID, resp.Orgs)
	}
}

func TestListUserOrgs_Unauthenticated(t *testing.T) {
	th := newTestHarness()

	req := httptest.NewRequest(http.MethodGet, "/orgs", nil)
	w := httptest.NewRecorder()
	th.handler.ListUserOrgs(w, req)

	res := w.Result()
	if res.StatusCode != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", res.StatusCode)
	}
}

func TestListOrgMembers_HappyPath(t *testing.T) {
	th := newTestHarness()
	user := seedOrgUser(t, th)
	org := seedOrg(t, th, user.ID)

	req := httptest.NewRequest(http.MethodGet, "/orgs/"+org.ID+"/members", nil)
	req.SetPathValue("orgID", org.ID)
	w := httptest.NewRecorder()
	th.handler.ListOrgMembers(w, req)

	res := w.Result()
	if res.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", res.StatusCode)
	}
	var resp struct {
		Members []domain.OrgMemberDetail `json:"members"`
		Total   int                      `json:"total"`
	}
	json.NewDecoder(res.Body).Decode(&resp)
	if resp.Total != 1 || len(resp.Members) != 1 {
		t.Errorf("expected 1 member, got %d total, %d in list", resp.Total, len(resp.Members))
	}
}

func TestListOrgMembers_NotFound(t *testing.T) {
	th := newTestHarness()

	req := httptest.NewRequest(http.MethodGet, "/orgs/bad-id/members", nil)
	req.SetPathValue("orgID", "bad-id")
	w := httptest.NewRecorder()
	th.handler.ListOrgMembers(w, req)

	res := w.Result()
	if res.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 with empty list, got %d", res.StatusCode)
	}
	var resp struct {
		Members []domain.OrgMemberDetail `json:"members"`
		Total   int                      `json:"total"`
	}
	json.NewDecoder(res.Body).Decode(&resp)
	if resp.Total != 0 {
		t.Errorf("expected 0 total, got %d", resp.Total)
	}
}

func TestRemoveMember_HappyPath(t *testing.T) {
	th := newTestHarness()
	owner := seedOrgUser(t, th)
	member := seedSecondUser(t, th)
	org := seedOrg(t, th, owner.ID)

	if err := th.orgs.AddMember(context.Background(), &domain.OrgMember{
		OrgID: org.ID, UserID: member.ID, Role: domain.OrgRoleMember, JoinedAt: time.Now().UTC(),
	}); err != nil {
		t.Fatal(err)
	}

	req := httptest.NewRequest(http.MethodDelete, "/orgs/"+org.ID+"/members/"+member.ID, nil)
	req.SetPathValue("orgID", org.ID)
	req.SetPathValue("userID", member.ID)
	w := httptest.NewRecorder()
	th.handler.RemoveMember(w, req)

	res := w.Result()
	if res.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", res.StatusCode)
	}

	mem, _ := th.orgs.GetMembership(context.Background(), org.ID, member.ID)
	if mem != nil {
		t.Error("expected member to be removed")
	}
}

func TestRemoveMember_NotFound(t *testing.T) {
	th := newTestHarness()
	owner := seedOrgUser(t, th)
	org := seedOrg(t, th, owner.ID)

	req := httptest.NewRequest(http.MethodDelete, "/orgs/"+org.ID+"/members/nobody", nil)
	req.SetPathValue("orgID", org.ID)
	req.SetPathValue("userID", "nobody")
	w := httptest.NewRecorder()
	th.handler.RemoveMember(w, req)

	res := w.Result()
	if res.StatusCode != http.StatusNotFound {
		t.Fatalf("expected 404, got %d", res.StatusCode)
	}
}

func TestUpdateMemberRole_HappyPath(t *testing.T) {
	th := newTestHarness()
	owner := seedOrgUser(t, th)
	member := seedSecondUser(t, th)
	org := seedOrg(t, th, owner.ID)

	if err := th.orgs.AddMember(context.Background(), &domain.OrgMember{
		OrgID: org.ID, UserID: member.ID, Role: domain.OrgRoleMember, JoinedAt: time.Now().UTC(),
	}); err != nil {
		t.Fatal(err)
	}

	body := `{"role":"admin"}`
	req := httptest.NewRequest(http.MethodPatch, "/orgs/"+org.ID+"/members/"+member.ID+"/role", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.SetPathValue("orgID", org.ID)
	req.SetPathValue("userID", member.ID)
	req = req.WithContext(middleware.ContextWithUser(req.Context(), owner))
	w := httptest.NewRecorder()
	th.handler.UpdateMemberRole(w, req)

	res := w.Result()
	if res.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", res.StatusCode)
	}
}

func TestUpdateMemberRole_Unauthenticated(t *testing.T) {
	th := newTestHarness()

	body := `{"role":"admin"}`
	req := httptest.NewRequest(http.MethodPatch, "/orgs/x/members/y/role", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.SetPathValue("orgID", "x")
	req.SetPathValue("userID", "y")
	w := httptest.NewRecorder()
	th.handler.UpdateMemberRole(w, req)

	res := w.Result()
	if res.StatusCode != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", res.StatusCode)
	}
}

func TestLeaveOrg_HappyPath(t *testing.T) {
	th := newTestHarness()
	owner := seedOrgUser(t, th)
	member := seedSecondUser(t, th)
	org := seedOrg(t, th, owner.ID)

	if err := th.orgs.AddMember(context.Background(), &domain.OrgMember{
		OrgID: org.ID, UserID: member.ID, Role: domain.OrgRoleMember, JoinedAt: time.Now().UTC(),
	}); err != nil {
		t.Fatal(err)
	}

	req := httptest.NewRequest(http.MethodPost, "/orgs/"+org.ID+"/leave", nil)
	req.Header.Set("Content-Type", "application/json")
	req.SetPathValue("orgID", org.ID)
	req = req.WithContext(middleware.ContextWithUser(req.Context(), member))
	w := httptest.NewRecorder()
	th.handler.LeaveOrg(w, req)

	res := w.Result()
	if res.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", res.StatusCode)
	}
}

func TestLeaveOrg_Unauthenticated(t *testing.T) {
	th := newTestHarness()

	req := httptest.NewRequest(http.MethodPost, "/orgs/x/leave", nil)
	req.SetPathValue("orgID", "x")
	w := httptest.NewRecorder()
	th.handler.LeaveOrg(w, req)

	res := w.Result()
	if res.StatusCode != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", res.StatusCode)
	}
}

func TestSetActiveOrg_HappyPath(t *testing.T) {
	th := newTestHarness()
	user := seedOrgUser(t, th)
	org := seedOrg(t, th, user.ID)

	session := &domain.Session{
		ID:        "sess-1",
		UserID:    user.ID,
		TokenHash: "tokhash",
		ExpiresAt: time.Now().UTC().Add(time.Hour),
		CreatedAt: time.Now().UTC(),
	}
	if err := th.sessions.Create(context.Background(), session); err != nil {
		t.Fatal(err)
	}

	body := `{"orgId":"` + org.ID + `"}`
	req := httptest.NewRequest(http.MethodPut, "/auth/active-org", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req = req.WithContext(middleware.ContextWithUser(req.Context(), user))
	req = req.WithContext(middleware.ContextWithSession(req.Context(), session))
	w := httptest.NewRecorder()
	th.handler.SetActiveOrg(w, req)

	res := w.Result()
	if res.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", res.StatusCode)
	}
}

func TestClearActiveOrg_HappyPath(t *testing.T) {
	th := newTestHarness()
	user := seedOrgUser(t, th)

	session := &domain.Session{
		ID:        "sess-1",
		UserID:    user.ID,
		TokenHash: "tokhash",
		ExpiresAt: time.Now().UTC().Add(time.Hour),
		CreatedAt: time.Now().UTC(),
	}
	if err := th.sessions.Create(context.Background(), session); err != nil {
		t.Fatal(err)
	}

	req := httptest.NewRequest(http.MethodDelete, "/auth/active-org", nil)
	req = req.WithContext(middleware.ContextWithSession(req.Context(), session))
	w := httptest.NewRecorder()
	th.handler.ClearActiveOrg(w, req)

	res := w.Result()
	if res.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", res.StatusCode)
	}
}

func TestCreateOrgInvite_HappyPath(t *testing.T) {
	th := newTestHarness()
	owner := seedOrgUser(t, th)
	org := seedOrg(t, th, owner.ID)

	body := `{"email":"invitee@test.com","role":"member"}`
	req := httptest.NewRequest(http.MethodPost, "/orgs/"+org.ID+"/invites", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.SetPathValue("orgID", org.ID)
	req = req.WithContext(middleware.ContextWithUser(req.Context(), owner))
	w := httptest.NewRecorder()
	th.handler.CreateOrgInvite(w, req)

	res := w.Result()
	if res.StatusCode != http.StatusCreated {
		t.Fatalf("expected 201, got %d", res.StatusCode)
	}
	var invite domain.OrgInvite
	json.NewDecoder(res.Body).Decode(&invite)
	if invite.Email != "invitee@test.com" || invite.RawCode == "" {
		t.Errorf("unexpected invite: %+v", invite)
	}
}

func TestCreateOrgInvite_InvalidRole(t *testing.T) {
	th := newTestHarness()
	owner := seedOrgUser(t, th)
	org := seedOrg(t, th, owner.ID)

	body := `{"email":"x@test.com","role":"superadmin"}`
	req := httptest.NewRequest(http.MethodPost, "/orgs/"+org.ID+"/invites", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.SetPathValue("orgID", org.ID)
	req = req.WithContext(middleware.ContextWithUser(req.Context(), owner))
	w := httptest.NewRecorder()
	th.handler.CreateOrgInvite(w, req)

	res := w.Result()
	if res.StatusCode != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", res.StatusCode)
	}
}

func TestListOrgInvites_HappyPath(t *testing.T) {
	th := newTestHarness()
	owner := seedOrgUser(t, th)
	org := seedOrg(t, th, owner.ID)

	if err := th.orgInvites.Create(context.Background(), &domain.OrgInvite{
		ID:        "inv-1",
		OrgID:     org.ID,
		Email:     "pending@test.com",
		Role:      domain.OrgRoleMember,
		CodeHash:  "hash",
		InvitedBy: owner.ID,
		ExpiresAt: time.Now().UTC().Add(time.Hour),
		CreatedAt: time.Now().UTC(),
	}); err != nil {
		t.Fatal(err)
	}

	req := httptest.NewRequest(http.MethodGet, "/orgs/"+org.ID+"/invites", nil)
	req.SetPathValue("orgID", org.ID)
	w := httptest.NewRecorder()
	th.handler.ListOrgInvites(w, req)

	res := w.Result()
	if res.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", res.StatusCode)
	}
	var resp struct {
		Invites []domain.OrgInvite `json:"invites"`
	}
	json.NewDecoder(res.Body).Decode(&resp)
	if len(resp.Invites) != 1 {
		t.Errorf("expected 1 invite, got %d", len(resp.Invites))
	}
}

func TestDeleteOrgInvite_HappyPath(t *testing.T) {
	th := newTestHarness()
	owner := seedOrgUser(t, th)
	org := seedOrg(t, th, owner.ID)

	if err := th.orgInvites.Create(context.Background(), &domain.OrgInvite{
		ID:        "inv-1",
		OrgID:     org.ID,
		Email:     "pending@test.com",
		Role:      domain.OrgRoleMember,
		CodeHash:  "hash",
		InvitedBy: owner.ID,
		ExpiresAt: time.Now().UTC().Add(time.Hour),
		CreatedAt: time.Now().UTC(),
	}); err != nil {
		t.Fatal(err)
	}

	req := httptest.NewRequest(http.MethodDelete, "/orgs/"+org.ID+"/invites/inv-1", nil)
	req.SetPathValue("orgID", org.ID)
	req.SetPathValue("inviteID", "inv-1")
	w := httptest.NewRecorder()
	th.handler.DeleteOrgInvite(w, req)

	res := w.Result()
	if res.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", res.StatusCode)
	}

	inv, _ := th.orgInvites.GetByID(context.Background(), "inv-1")
	if inv != nil {
		t.Error("expected invite to be deleted")
	}
}

func TestDeleteOrgInvite_NotFound(t *testing.T) {
	th := newTestHarness()

	req := httptest.NewRequest(http.MethodDelete, "/orgs/x/invites/nonexistent", nil)
	req.SetPathValue("orgID", "x")
	req.SetPathValue("inviteID", "nonexistent")
	w := httptest.NewRecorder()
	th.handler.DeleteOrgInvite(w, req)

	res := w.Result()
	if res.StatusCode != http.StatusNotFound {
		t.Fatalf("expected 404, got %d", res.StatusCode)
	}
}
