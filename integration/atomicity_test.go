package integration_test

// Atomicity regression tests for multi-statement authentication flows.
// Each test drives two requests that race the same guard against a real
// SQLite database and asserts that exactly one wins while the shared
// counters, tokens, and membership rows stay consistent — the property the
// conditional writes and service-level transactions in this change exist to
// provide. Mirrors the style of TestRegister_ConcurrentSameEmail and
// TestTwoFactor_ConcurrentGuesses_NeverExceedCap.

import (
	"context"
	"database/sql"
	"errors"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	goauth "github.com/nazimdjebloun/go-auth"
	"github.com/nazimdjebloun/go-auth/domain"
	"github.com/nazimdjebloun/go-auth/internal/service"
	"github.com/nazimdjebloun/go-auth/port"
)

// authCode extracts the domain error code for assertions.
func authCode(err error) string {
	var ae *domain.AuthError
	if errors.As(err, &ae) {
		return ae.Code
	}
	return ""
}

// isBusy reports a transient SQLite lock-contention failure. Concurrent
// multi-statement transactions on the file-backed test database can surface
// SQLITE_BUSY_SNAPSHOT when two writers interleave reads and writes — the
// busy_timeout pragma only covers statement-level waits. Production
// Postgres/MySQL serialize these on row locks instead. Tests retry the
// whole operation on busy so the assertions below verify the guarded-write
// logic rather than the driver's lock granularity.
func isBusy(err error) bool {
	return err != nil && strings.Contains(err.Error(), "SQLITE_BUSY")
}

func doWithBusyRetry(fn func() error) error {
	var err error
	for range 50 {
		if err = fn(); !isBusy(err) {
			return err
		}
		time.Sleep(5 * time.Millisecond)
	}
	return err
}

// ---------------------------------------------------------------------------
// Set-password single use
// ---------------------------------------------------------------------------

func TestSetPassword_ConcurrentConfirm_OneWins(t *testing.T) {
	testSetPasswordOneWinner(t, false)
}

// A goroutine can reach the initial user read after the winner commits.
// Exercise that ordering explicitly instead of depending on scheduler timing.
func TestSetPassword_ConfirmAfterCommit_AlreadySet(t *testing.T) {
	testSetPasswordOneWinner(t, true)
}

func testSetPasswordOneWinner(t *testing.T, afterCommit bool) {
	t.Helper()
	db, closeDB := newSQLiteDB(t)
	defer closeDB()
	mailer := &testMailer{}
	a := openAuth(t, db, mailer)
	defer a.Close()
	ctx := context.Background()

	reg, aerr := a.Register(ctx, goauth.RegisterInput{
		Email: "oauthonly@test.com", Password: validTestPassword(), Name: "OAuthOnly",
	})
	if aerr != nil {
		t.Fatal(aerr)
	}
	// Simulate an OAuth-only account: no password hash yet.
	if _, err := db.Exec("UPDATE users SET password_hash = NULL WHERE id = ?", reg.User.ID); err != nil {
		t.Fatal(err)
	}

	if aerr := a.Services.Password.RequestSetPassword(ctx, reg.User.ID); aerr != nil {
		t.Fatal(aerr)
	}
	code := extractCodeAfter(mailer.lastBody(), "Your code: ")
	if code == "" {
		t.Fatal("could not extract set-password code")
	}

	passwords := []string{"FirstP@ss1", "SecondP@ss2"}
	results := make([]error, len(passwords))
	confirm := func(i int) {
		results[i] = doWithBusyRetry(func() error {
			return a.Services.Password.ConfirmSetPassword(ctx, service.ConfirmSetPasswordInput{
				UserID: reg.User.ID, Code: code, NewPassword: passwords[i],
			})
		})
	}
	if afterCommit {
		confirm(0)
		confirm(1)
	} else {
		var wg sync.WaitGroup
		start := make(chan struct{})
		for i := range passwords {
			wg.Add(1)
			go func(i int) {
				defer wg.Done()
				<-start
				confirm(i)
			}(i)
		}
		close(start)
		wg.Wait()
	}

	succeeded, rejected, winner := 0, 0, -1
	for i, err := range results {
		if err == nil {
			succeeded++
			winner = i
			continue
		}
		// A loser that read before commit can lose the token claim;
		// one that reads after commit sees an existing password instead.
		switch authCode(err) {
		case "code_used", "already_set":
			rejected++
		default:
			t.Fatalf("confirm %d returned unexpected error: %v", i, err)
		}
	}
	if succeeded != 1 || rejected != 1 {
		t.Fatalf("want one success and one rejection, got successes=%d rejections=%d", succeeded, rejected)
	}
	if afterCommit && (winner != 0 || authCode(results[1]) != "already_set") {
		t.Fatalf("post-commit confirm must return already_set; winner=%d error=%v", winner, results[1])
	}

	// The code is stamped used exactly once.
	var usedCount int
	if err := db.QueryRow("SELECT COUNT(*) FROM verification_tokens WHERE user_id = ? AND type = ? AND used_at IS NOT NULL",
		reg.User.ID, domain.TokenSetPass).Scan(&usedCount); err != nil {
		t.Fatal(err)
	}
	if usedCount != 1 {
		t.Errorf("used set-password tokens = %d, want 1", usedCount)
	}

	// Verify the successful request's password specifically, not just that
	// some password works: the loser must not overwrite the winner.
	for i, pw := range passwords {
		_, err := a.Services.Auth.Login(ctx, service.LoginInput{
			Email: "oauthonly@test.com", Password: pw,
		})
		if i == winner {
			if err != nil {
				t.Errorf("winner's password must authenticate: %v", err)
			}
		} else if authCode(err) != "invalid_credentials" {
			t.Errorf("loser's password must return invalid_credentials, got %v", err)
		}
	}
}

// ---------------------------------------------------------------------------
// Invite redemption
// ---------------------------------------------------------------------------

// TestInvite_ConcurrentComplete_OneWins races two completions of the same
// invite code: the claim serializes them, the loser gets invite_already_used,
// and exactly one account is created.
func TestInvite_ConcurrentComplete_OneWins(t *testing.T) {
	db, closeDB := newSQLiteDB(t)
	defer closeDB()
	mailer := &testMailer{}
	a := openAuth(t, db, mailer)
	defer a.Close()
	ctx := context.Background()

	admin, aerr := a.Register(ctx, goauth.RegisterInput{
		Email: "admin@test.com", Password: validTestPassword(), Name: "Admin",
	})
	if aerr != nil {
		t.Fatal(aerr)
	}
	if _, err := db.Exec("UPDATE users SET role = 'admin' WHERE id = ?", admin.User.ID); err != nil {
		t.Fatal(err)
	}
	invite, aerr := a.Services.Invite.CreateInvite(ctx, service.CreateInviteInput{
		Email: "invitee@example.com", AdminID: admin.User.ID,
	})
	if aerr != nil {
		t.Fatal(aerr)
	}
	const knownRaw = "test-race-invite-code-1"
	if _, err := db.Exec("UPDATE invites SET code = ? WHERE id = ?", sha256Hex(knownRaw), invite.ID); err != nil {
		t.Fatal(err)
	}

	var wg sync.WaitGroup
	var succeeded, alreadyUsed, other int32
	for range 2 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			err := doWithBusyRetry(func() error {
				_, err := a.CompleteInviteRegistration(ctx, goauth.CompleteInviteInput{
					Code: knownRaw, Name: "Invitee", Password: "Inv@lidPwd1", ConfirmPassword: "Inv@lidPwd1",
				})
				return err
			})
			switch authCode(err) {
			case "":
				atomic.AddInt32(&succeeded, 1)
			case "invite_already_used":
				atomic.AddInt32(&alreadyUsed, 1)
			default:
				t.Errorf("unexpected error: %v", err)
				atomic.AddInt32(&other, 1)
			}
		}()
	}
	wg.Wait()

	if succeeded != 1 {
		t.Errorf("expected exactly 1 successful redemption, got %d", succeeded)
	}
	if alreadyUsed != 1 || other != 0 {
		t.Errorf("expected loser invite_already_used (other=%d), got alreadyUsed=%d", other, alreadyUsed)
	}
	var userCount int
	if err := db.QueryRow("SELECT COUNT(*) FROM users WHERE email = ?", "invitee@example.com").Scan(&userCount); err != nil {
		t.Fatal(err)
	}
	if userCount != 1 {
		t.Errorf("users with invite email = %d, want exactly 1", userCount)
	}
	var status string
	if err := db.QueryRow("SELECT status FROM invites WHERE id = ?", invite.ID).Scan(&status); err != nil {
		t.Fatal(err)
	}
	if status != "accepted" {
		t.Errorf("invite status = %q, want accepted", status)
	}
}

// TestInvite_DuplicateEmail_RollsBackClaim proves the redemption transaction:
// when the account insert fails (the address registered through another
// path), the invite claim rolls back with it and the invite stays pending.
func TestInvite_DuplicateEmail_RollsBackClaim(t *testing.T) {
	db, closeDB := newSQLiteDB(t)
	defer closeDB()
	mailer := &testMailer{}
	a := openAuth(t, db, mailer)
	defer a.Close()
	ctx := context.Background()

	admin, aerr := a.Register(ctx, goauth.RegisterInput{
		Email: "admin@test.com", Password: validTestPassword(), Name: "Admin",
	})
	if aerr != nil {
		t.Fatal(aerr)
	}
	if _, err := db.Exec("UPDATE users SET role = 'admin' WHERE id = ?", admin.User.ID); err != nil {
		t.Fatal(err)
	}
	invite, aerr := a.Services.Invite.CreateInvite(ctx, service.CreateInviteInput{
		Email: "late@example.com", AdminID: admin.User.ID,
	})
	if aerr != nil {
		t.Fatal(aerr)
	}
	const knownRaw = "test-race-invite-code-2"
	if _, err := db.Exec("UPDATE invites SET code = ? WHERE id = ?", sha256Hex(knownRaw), invite.ID); err != nil {
		t.Fatal(err)
	}

	// The address registers normally after the invite was sent.
	if _, aerr := a.Register(ctx, goauth.RegisterInput{
		Email: "late@example.com", Password: validTestPassword(), Name: "Late",
	}); aerr != nil {
		t.Fatal(aerr)
	}

	_, err := a.CompleteInviteRegistration(ctx, goauth.CompleteInviteInput{
		Code: knownRaw, Name: "Late", Password: "Inv@lidPwd1", ConfirmPassword: "Inv@lidPwd1",
	})
	if authCode(err) != "email_already_exists" {
		t.Fatalf("code = %q, want email_already_exists", authCode(err))
	}
	var status string
	if err := db.QueryRow("SELECT status FROM invites WHERE id = ?", invite.ID).Scan(&status); err != nil {
		t.Fatal(err)
	}
	if status != "pending" {
		t.Errorf("invite status = %q after failed redemption, want pending (claim rolled back)", status)
	}
}

// ---------------------------------------------------------------------------
// Organization membership counters
// ---------------------------------------------------------------------------

func readOrgCounts(t *testing.T, db *sql.DB, orgID string) (ownerCount, memberCount int) {
	t.Helper()
	if err := db.QueryRow("SELECT owner_count, member_count FROM organizations WHERE id = ?", orgID).
		Scan(&ownerCount, &memberCount); err != nil {
		t.Fatal(err)
	}
	return ownerCount, memberCount
}

func readUserOwnerCount(t *testing.T, db *sql.DB, userID string) int {
	t.Helper()
	var n int
	if err := db.QueryRow("SELECT org_owner_count FROM users WHERE id = ?", userID).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}

// TestOrg_ConcurrentRemoveMember_CountsConsistent races two removals of the
// same member: exactly one wins, and the denormalized owner/member counts
// move exactly once.
func TestOrg_ConcurrentRemoveMember_CountsConsistent(t *testing.T) {
	db, closeDB := newSQLiteDB(t)
	defer closeDB()
	a := openOrgAuth(t, db, &testMailer{})
	defer a.Close()
	ctx := context.Background()

	owner, aerr := a.Register(ctx, goauth.RegisterInput{
		Email: "owner@test.com", Password: validTestPassword(), Name: "Owner",
	})
	if aerr != nil {
		t.Fatal(aerr)
	}
	member, aerr := a.Register(ctx, goauth.RegisterInput{
		Email: "member@test.com", Password: validTestPassword(), Name: "Member",
	})
	if aerr != nil {
		t.Fatal(aerr)
	}
	org, err := a.Services.Org.CreateOrg(ctx, service.CreateOrgInput{
		Name: "Race", Slug: "race", OwnerID: owner.User.ID,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := a.Services.Org.AddMember(ctx, service.AddMemberInput{
		OrgID: org.ID, UserID: member.User.ID, Role: domain.OrgRoleMember, ActorID: owner.User.ID,
	}); err != nil {
		t.Fatal(err)
	}

	var wg sync.WaitGroup
	var succeeded int32
	for range 2 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			err := doWithBusyRetry(func() error {
				return a.Services.Org.RemoveMember(ctx, service.RemoveMemberInput{
					OrgID: org.ID, UserID: member.User.ID, ActorID: owner.User.ID,
				})
			})
			code := authCode(err)
			if err == nil {
				atomic.AddInt32(&succeeded, 1)
			} else if code != "org_member_not_found" && code != "org_member_conflict" {
				t.Errorf("unexpected loser error: %v", err)
			}
		}()
	}
	wg.Wait()

	if succeeded != 1 {
		t.Fatalf("expected exactly 1 successful removal, got %d", succeeded)
	}
	ownerCount, memberCount := readOrgCounts(t, db, org.ID)
	if memberCount != 1 {
		t.Errorf("member_count = %d, want 1 (decremented exactly once)", memberCount)
	}
	if ownerCount != 1 {
		t.Errorf("owner_count = %d, want 1 (untouched)", ownerCount)
	}
	if n := readUserOwnerCount(t, db, owner.User.ID); n != 1 {
		t.Errorf("owner users.org_owner_count = %d, want 1", n)
	}
	var memberships int
	if err := db.QueryRow("SELECT COUNT(*) FROM organization_members WHERE org_id = ? AND user_id = ?",
		org.ID, member.User.ID).Scan(&memberships); err != nil {
		t.Fatal(err)
	}
	if memberships != 0 {
		t.Errorf("membership rows = %d, want 0", memberships)
	}
}

// TestOrg_ConcurrentDemoteSameMemberTwice races two identical demotions: the
// winner applies the change, the loser observes the already-applied target
// role and reports a no-op — and the owner counts move exactly once.
func TestOrg_ConcurrentDemoteSameMemberTwice(t *testing.T) {
	db, closeDB := newSQLiteDB(t)
	defer closeDB()
	a := openOrgAuth(t, db, &testMailer{})
	defer a.Close()
	ctx := context.Background()

	owner1, aerr := a.Register(ctx, goauth.RegisterInput{
		Email: "owner1@test.com", Password: validTestPassword(), Name: "Owner1",
	})
	if aerr != nil {
		t.Fatal(aerr)
	}
	owner2, aerr := a.Register(ctx, goauth.RegisterInput{
		Email: "owner2@test.com", Password: validTestPassword(), Name: "Owner2",
	})
	if aerr != nil {
		t.Fatal(aerr)
	}
	org, err := a.Services.Org.CreateOrg(ctx, service.CreateOrgInput{
		Name: "Race", Slug: "race", OwnerID: owner1.User.ID,
	})
	if err != nil {
		t.Fatal(err)
	}
	// owner-2 joins as a second owner so demoting owner-1 is legal.
	if err := a.Services.Org.AddMember(ctx, service.AddMemberInput{
		OrgID: org.ID, UserID: owner2.User.ID, Role: domain.OrgRoleOwner, ActorID: owner1.User.ID,
	}); err != nil {
		t.Fatal(err)
	}

	var wg sync.WaitGroup
	for range 2 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := doWithBusyRetry(func() error {
				return a.Services.Org.UpdateMemberRole(ctx, service.UpdateMemberRoleInput{
					OrgID: org.ID, UserID: owner1.User.ID, NewRole: domain.OrgRoleMember, ActorID: owner2.User.ID,
				})
			}); err != nil {
				t.Errorf("identical concurrent demote must converge, got %v", err)
			}
		}()
	}
	wg.Wait()

	var role string
	if err := db.QueryRow("SELECT role FROM organization_members WHERE org_id = ? AND user_id = ?",
		org.ID, owner1.User.ID).Scan(&role); err != nil {
		t.Fatal(err)
	}
	if role != "member" {
		t.Fatalf("final role = %q, want member", role)
	}
	ownerCount, memberCount := readOrgCounts(t, db, org.ID)
	if ownerCount != 1 {
		t.Errorf("owner_count = %d, want 1 (decremented exactly once)", ownerCount)
	}
	if memberCount != 2 {
		t.Errorf("member_count = %d, want 2 (unchanged by a role change)", memberCount)
	}
	if n := readUserOwnerCount(t, db, owner1.User.ID); n != 0 {
		t.Errorf("demoted user org_owner_count = %d, want 0", n)
	}
}

// TestOrg_ConcurrentRemoveVsDemote races a removal against a demotion of the
// same owner. Whichever wins, the loser rolls back cleanly, so the final
// database state must be consistent with the final membership row in every
// interleaving.
func TestOrg_ConcurrentRemoveVsDemote(t *testing.T) {
	db, closeDB := newSQLiteDB(t)
	defer closeDB()
	a := openOrgAuth(t, db, &testMailer{})
	defer a.Close()
	ctx := context.Background()

	owner1, aerr := a.Register(ctx, goauth.RegisterInput{
		Email: "owner1@test.com", Password: validTestPassword(), Name: "Owner1",
	})
	if aerr != nil {
		t.Fatal(aerr)
	}
	owner2, aerr := a.Register(ctx, goauth.RegisterInput{
		Email: "owner2@test.com", Password: validTestPassword(), Name: "Owner2",
	})
	if aerr != nil {
		t.Fatal(aerr)
	}
	org, err := a.Services.Org.CreateOrg(ctx, service.CreateOrgInput{
		Name: "Race", Slug: "race", OwnerID: owner1.User.ID,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := a.Services.Org.AddMember(ctx, service.AddMemberInput{
		OrgID: org.ID, UserID: owner2.User.ID, Role: domain.OrgRoleOwner, ActorID: owner1.User.ID,
	}); err != nil {
		t.Fatal(err)
	}

	var wg sync.WaitGroup
	var removeErr, demoteErr error
	wg.Add(2)
	go func() {
		defer wg.Done()
		removeErr = doWithBusyRetry(func() error {
			return a.Services.Org.RemoveMember(ctx, service.RemoveMemberInput{
				OrgID: org.ID, UserID: owner1.User.ID, ActorID: owner2.User.ID,
			})
		})
	}()
	go func() {
		defer wg.Done()
		demoteErr = doWithBusyRetry(func() error {
			return a.Services.Org.UpdateMemberRole(ctx, service.UpdateMemberRoleInput{
				OrgID: org.ID, UserID: owner1.User.ID, NewRole: domain.OrgRoleMember, ActorID: owner2.User.ID,
			})
		})
	}()
	wg.Wait()

	for _, err := range []error{removeErr, demoteErr} {
		if err == nil {
			continue
		}
		switch authCode(err) {
		case "org_member_not_found", "org_member_conflict":
		default:
			t.Fatalf("unexpected race-loser error: %v", err)
		}
	}

	var role *string
	var roleVal string
	if err := db.QueryRow("SELECT role FROM organization_members WHERE org_id = ? AND user_id = ?",
		org.ID, owner1.User.ID).Scan(&roleVal); err == nil {
		role = &roleVal
	}
	ownerCount, memberCount := readOrgCounts(t, db, org.ID)
	userOwnerCount := readUserOwnerCount(t, db, owner1.User.ID)
	if role == nil {
		// Removal won (possibly after the demotion, in which case the
		// remover's role-asserted delete matched the demoted row and only
		// member_count moved): exactly one member row gone either way.
		if memberCount != 1 {
			t.Errorf("member_count = %d, want 1 after removal", memberCount)
		}
		if ownerCount != 1 {
			t.Errorf("owner_count = %d, want 1", ownerCount)
		}
		if userOwnerCount != 0 {
			t.Errorf("removed owner users.org_owner_count = %d, want 0", userOwnerCount)
		}
	} else {
		if *role != "member" {
			t.Fatalf("surviving role = %q, want member (demote won)", *role)
		}
		if ownerCount != 1 {
			t.Errorf("owner_count = %d, want 1", ownerCount)
		}
		if memberCount != 2 {
			t.Errorf("member_count = %d, want 2", memberCount)
		}
		if userOwnerCount != 0 {
			t.Errorf("demoted user org_owner_count = %d, want 0", userOwnerCount)
		}
	}
}

// TestOrg_ConcurrentDeleteOrg_CountsConsistent races two deletions of the
// same org: exactly one wins, and the owner's org_owner_count moves exactly
// once — the loser's guarded delete matches nothing and rolls its upkeep
// back instead of decrementing a second time.
func TestOrg_ConcurrentDeleteOrg_CountsConsistent(t *testing.T) {
	db, closeDB := newSQLiteDB(t)
	defer closeDB()
	a := openOrgAuth(t, db, &testMailer{})
	defer a.Close()
	ctx := context.Background()

	owner, aerr := a.Register(ctx, goauth.RegisterInput{
		Email: "owner@test.com", Password: validTestPassword(), Name: "Owner",
	})
	if aerr != nil {
		t.Fatal(aerr)
	}
	org, err := a.Services.Org.CreateOrg(ctx, service.CreateOrgInput{
		Name: "Race", Slug: "race", OwnerID: owner.User.ID,
	})
	if err != nil {
		t.Fatal(err)
	}

	var wg sync.WaitGroup
	var succeeded int32
	for range 2 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			err := doWithBusyRetry(func() error {
				return a.Services.Org.DeleteOrg(ctx, service.DeleteOrgInput{
					OrgID: org.ID, ActorID: owner.User.ID,
				})
			})
			if err == nil {
				atomic.AddInt32(&succeeded, 1)
			} else {
				switch authCode(err) {
				case "org_member_not_found", "org_not_found":
				default:
					t.Errorf("unexpected loser error: %v", err)
				}
			}
		}()
	}
	wg.Wait()

	if succeeded != 1 {
		t.Fatalf("expected exactly 1 successful deletion, got %d", succeeded)
	}
	var orgs int
	if err := db.QueryRow("SELECT COUNT(*) FROM organizations WHERE id = ?", org.ID).Scan(&orgs); err != nil {
		t.Fatal(err)
	}
	if orgs != 0 {
		t.Errorf("organizations rows = %d, want 0", orgs)
	}
	if n := readUserOwnerCount(t, db, owner.User.ID); n != 0 {
		t.Errorf("owner users.org_owner_count = %d, want 0 (decremented exactly once)", n)
	}
}

// TestOrg_ConcurrentAddMember_CountsConsistent races two adds of the same
// user: exactly one wins, the loser gets org_member_exists (via the unique
// backstop when it loses the check-then-insert race), and member_count moves
// exactly once.
func TestOrg_ConcurrentAddMember_CountsConsistent(t *testing.T) {
	db, closeDB := newSQLiteDB(t)
	defer closeDB()
	a := openOrgAuth(t, db, &testMailer{})
	defer a.Close()
	ctx := context.Background()

	owner, aerr := a.Register(ctx, goauth.RegisterInput{
		Email: "owner@test.com", Password: validTestPassword(), Name: "Owner",
	})
	if aerr != nil {
		t.Fatal(aerr)
	}
	member, aerr := a.Register(ctx, goauth.RegisterInput{
		Email: "member@test.com", Password: validTestPassword(), Name: "Member",
	})
	if aerr != nil {
		t.Fatal(aerr)
	}
	org, err := a.Services.Org.CreateOrg(ctx, service.CreateOrgInput{
		Name: "Race", Slug: "race", OwnerID: owner.User.ID,
	})
	if err != nil {
		t.Fatal(err)
	}

	var wg sync.WaitGroup
	var succeeded, exists, other int32
	for range 2 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			err := doWithBusyRetry(func() error {
				return a.Services.Org.AddMember(ctx, service.AddMemberInput{
					OrgID: org.ID, UserID: member.User.ID, Role: domain.OrgRoleMember, ActorID: owner.User.ID,
				})
			})
			switch authCode(err) {
			case "":
				atomic.AddInt32(&succeeded, 1)
			case "org_member_exists":
				atomic.AddInt32(&exists, 1)
			default:
				t.Errorf("unexpected error: %v", err)
				atomic.AddInt32(&other, 1)
			}
		}()
	}
	wg.Wait()

	if succeeded != 1 {
		t.Errorf("expected exactly 1 successful add, got %d", succeeded)
	}
	if exists != 1 || other != 0 {
		t.Errorf("expected loser org_member_exists (other=%d), got exists=%d", other, exists)
	}
	ownerCount, memberCount := readOrgCounts(t, db, org.ID)
	if memberCount != 2 {
		t.Errorf("member_count = %d, want 2 (incremented exactly once)", memberCount)
	}
	if ownerCount != 1 {
		t.Errorf("owner_count = %d, want 1", ownerCount)
	}
}

// ---------------------------------------------------------------------------
// Organization invite rotation
// ---------------------------------------------------------------------------

// TestOrgInvite_RotatedCodeRejected proves the claim binds the invite row to
// the code that was validated: after an admin resend rotates the code hash,
// the previously emailed code no longer redeems, and the invite row survives
// the failed attempt.
func TestOrgInvite_RotatedCodeRejected(t *testing.T) {
	db, closeDB := newSQLiteDB(t)
	defer closeDB()
	a := openOrgAuth(t, db, &testMailer{})
	defer a.Close()
	ctx := context.Background()

	owner, aerr := a.Register(ctx, goauth.RegisterInput{
		Email: "owner@test.com", Password: validTestPassword(), Name: "Owner",
	})
	if aerr != nil {
		t.Fatal(aerr)
	}
	invitee, aerr := a.Register(ctx, goauth.RegisterInput{
		Email: "invitee@test.com", Password: validTestPassword(), Name: "Invitee",
	})
	if aerr != nil {
		t.Fatal(aerr)
	}
	org, err := a.Services.Org.CreateOrg(ctx, service.CreateOrgInput{
		Name: "Race", Slug: "race", OwnerID: owner.User.ID,
	})
	if err != nil {
		t.Fatal(err)
	}
	invite, err := a.Services.OrgInvite.CreateOrgInvite(ctx, service.CreateOrgInviteInput{
		OrgID: org.ID, Email: "invitee@test.com", Role: domain.OrgRoleMember, InvitedBy: owner.User.ID,
	})
	if err != nil {
		t.Fatalf("CreateOrgInvite failed: %v", err)
	}
	oldCode := invite.RawCode
	if oldCode == "" {
		t.Fatal("expected RawCode on creation")
	}

	// Admin rotates the code; the old email must stop working.
	if err := a.Services.OrgInvite.ResendOrgInviteEmail(ctx, org.ID, invite.ID, owner.User.ID); err != nil {
		t.Fatalf("ResendOrgInviteEmail failed: %v", err)
	}
	if err := a.Services.OrgInvite.AcceptInvite(ctx, service.AcceptInviteInput{
		UserID: invitee.User.ID, RawCode: oldCode,
	}); authCode(err) != "org_invite_expired" {
		t.Fatalf("stale code accept: code = %q, want org_invite_expired", authCode(err))
	}

	var remaining int
	if err := db.QueryRow("SELECT COUNT(*) FROM organization_invites WHERE id = ?", invite.ID).Scan(&remaining); err != nil {
		t.Fatal(err)
	}
	if remaining != 1 {
		t.Errorf("invite rows = %d after failed accept, want the row to survive", remaining)
	}
	var memberships int
	if err := db.QueryRow("SELECT COUNT(*) FROM organization_members WHERE org_id = ? AND user_id = ?",
		org.ID, invitee.User.ID).Scan(&memberships); err != nil {
		t.Fatal(err)
	}
	if memberships != 0 {
		t.Errorf("membership rows = %d after failed accept, want 0", memberships)
	}
}

// ---------------------------------------------------------------------------
// OAuth registration and unlink
// ---------------------------------------------------------------------------

// stubOAuthProvider is a programmable port.OAuthProvider for driving the
// OAuth flows without network access.
type stubOAuthProvider struct {
	name           string
	providerUserID string
	email          string
}

func (p *stubOAuthProvider) Name() string { return p.name }

func (p *stubOAuthProvider) AuthURL(state, _ string) string {
	return "https://stub.test/auth?state=" + state
}

func (p *stubOAuthProvider) Exchange(_ context.Context, _, _ string) (*port.OAuthProfile, error) {
	return &port.OAuthProfile{
		Provider:       p.name,
		ProviderUserID: p.providerUserID,
		Email:          p.email,
		EmailVerified:  true,
		Name:           "Stub User",
	}, nil
}

// openOAuthAuth mirrors newTestAuth but additionally registers the given
// OAuth providers, so the OAuth callback/link/unlink flows run end to end.
func openOAuthAuth(t *testing.T, db *sql.DB, mailer port.Mailer, providers ...port.OAuthProvider) *goauth.Auth {
	t.Helper()
	migrateDB(t, db, "sqlite")
	opts := []goauth.Option{
		goauth.WithBcryptCost(4),
		goauth.WithApp(goauth.AppConfig{
			Name:    "TestApp",
			BaseURL: "http://localhost:8080",
			Database: goauth.DatabaseConfig{
				DB:     db,
				Driver: goauth.DriverSQLite,
			},
		}),
		goauth.WithSession(goauth.SessionConfig{
			TTL:             1 * time.Hour,
			IdleTTL:         1 * time.Hour,
			RefreshTokenTTL: 1 * time.Hour,
			TokenTTL:        1 * time.Hour,
			GraceWindow:     goauth.Duration(0),
		}),
		goauth.WithSecurity(goauth.SecurityConfig{
			AllowHTTPURLs:  goauth.AllowPlaintextEmailLinks(),
			AllowedOrigins: []string{"http://localhost:8080"},
		}),
		goauth.WithRegistration(goauth.RegistrationConfig{
			EnableEmailPassword: true,
			EnableOAuth:         true,
			EnableInvite:        true,
			AllowPublic:         true,
			InviteTTL:           1 * time.Hour,
			VerificationCodeTTL: 1 * time.Hour,
		}),
		goauth.WithCookie(goauth.CookieConfig{Name: "goauth_session"}),
		goauth.WithMailer(mailer),
		goauth.WithSecret("0123456789abcdef0123456789abcdef"),
		goauth.WithAudit(goauth.AuditConfig{Enabled: true}),
	}
	for _, p := range providers {
		opts = append(opts, goauth.WithProvider(p))
	}
	cfg, err := goauth.NewConfig(opts...)
	if err != nil {
		t.Fatal(err)
	}
	a, err := goauth.New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	return a
}

// oauthRegister drives a full OAuth registration through the public service
// surface and returns the new user's ID.
func oauthRegister(ctx context.Context, t *testing.T, a *goauth.Auth, provider string) string {
	t.Helper()
	flow, err := a.Services.OAuth.Initiate(ctx, provider)
	if err != nil {
		t.Fatal(err)
	}
	res, err := a.Services.OAuth.Callback(ctx, provider, "code", flow.State, flow.State, "", "127.0.0.1", "test-agent")
	if err != nil {
		t.Fatalf("OAuth callback failed: %v", err)
	}
	if !res.IsNewUser {
		t.Fatal("expected a new user registration")
	}
	user, _, err := a.Services.Auth.ValidateSession(ctx, res.SessionToken)
	if err != nil {
		t.Fatalf("cannot resolve the registered user: %v", err)
	}
	return user.ID
}

func oauthLink(ctx context.Context, t *testing.T, a *goauth.Auth, provider, userID string) {
	t.Helper()
	session, err := a.Services.Session.Create(ctx, userID, "127.0.0.1", "test-agent")
	if err != nil {
		t.Fatal(err)
	}
	flow, err := a.Services.OAuth.InitiateLink(ctx, provider, userID, session.Session.TokenHash)
	if err != nil {
		t.Fatal(err)
	}
	res, err := a.Services.OAuth.Callback(ctx, provider, "code", flow.State, flow.State, session.SessionToken, "127.0.0.1", "test-agent")
	if err != nil {
		t.Fatalf("OAuth link failed: %v", err)
	}
	if !res.IsLink {
		t.Fatal("expected a link result")
	}
}

// TestUnlink_ConcurrentLastProvider races two unlinks of a passwordless
// user's two providers: exactly one wins, and the survivor still
// authenticates — the user is never stranded with zero login methods.
func TestUnlink_ConcurrentLastProvider(t *testing.T) {
	db, closeDB := newSQLiteDB(t)
	defer closeDB()
	a := openOAuthAuth(t, db, &testMailer{},
		&stubOAuthProvider{name: "stubA", providerUserID: "user-a", email: "oauth@test.com"},
		&stubOAuthProvider{name: "stubB", providerUserID: "user-b", email: "oauth@test.com"},
	)
	defer a.Close()
	ctx := context.Background()

	userID := oauthRegister(ctx, t, a, "stubA")
	oauthLink(ctx, t, a, "stubB", userID)

	var wg sync.WaitGroup
	var succeeded int32
	var refused int32
	for _, provider := range []string{"stubA", "stubB"} {
		wg.Add(1)
		go func(provider string) {
			defer wg.Done()
			err := doWithBusyRetry(func() error {
				return a.Services.OAuth.Unlink(ctx, userID, provider)
			})
			switch authCode(err) {
			case "":
				atomic.AddInt32(&succeeded, 1)
			case "cannot_unlink_last_provider":
				atomic.AddInt32(&refused, 1)
			default:
				t.Errorf("unexpected unlink error: %v", err)
			}
		}(provider)
	}
	wg.Wait()

	if succeeded != 1 {
		t.Fatalf("expected exactly 1 successful unlink, got %d", succeeded)
	}
	if refused != 1 {
		t.Fatalf("expected the loser to get cannot_unlink_last_provider, got %d", refused)
	}

	remaining, err := a.Services.OAuth.ListConnected(ctx, userID)
	if err != nil {
		t.Fatal(err)
	}
	if len(remaining) != 1 {
		t.Fatalf("linked providers = %d, want exactly 1 survivor", len(remaining))
	}

	// The surviving login method still works — no lockout.
	flow, err := a.Services.OAuth.Initiate(ctx, remaining[0].Provider)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := a.Services.OAuth.Callback(ctx, remaining[0].Provider, "code", flow.State, flow.State, "", "127.0.0.1", "test-agent"); err != nil {
		t.Fatalf("login via the surviving provider failed: %v", err)
	}
}

// TestOAuth_ConcurrentSameEmail_OneWins races two OAuth registrations for
// the same address through different providers: the unique email constraint
// arbitrates, the loser gets email_already_exists, and no orphaned user row
// is left behind by a half-finished registration.
func TestOAuth_ConcurrentSameEmail_OneWins(t *testing.T) {
	db, closeDB := newSQLiteDB(t)
	defer closeDB()
	a := openOAuthAuth(t, db, &testMailer{},
		&stubOAuthProvider{name: "stubA", providerUserID: "user-a", email: "race@test.com"},
		&stubOAuthProvider{name: "stubB", providerUserID: "user-b", email: "race@test.com"},
	)
	defer a.Close()
	ctx := context.Background()

	states := map[string]string{}
	for _, provider := range []string{"stubA", "stubB"} {
		flow, err := a.Services.OAuth.Initiate(ctx, provider)
		if err != nil {
			t.Fatal(err)
		}
		states[provider] = flow.State
	}

	var wg sync.WaitGroup
	var succeeded, duplicates, other int32
	for provider, state := range states {
		wg.Add(1)
		go func(provider, state string) {
			defer wg.Done()
			err := doWithBusyRetry(func() error {
				_, err := a.Services.OAuth.Callback(ctx, provider, "code", state, state, "", "127.0.0.1", "test-agent")
				return err
			})
			switch authCode(err) {
			case "":
				atomic.AddInt32(&succeeded, 1)
			case "email_already_exists":
				atomic.AddInt32(&duplicates, 1)
			default:
				t.Errorf("unexpected error: %v", err)
				atomic.AddInt32(&other, 1)
			}
		}(provider, state)
	}
	wg.Wait()

	if succeeded != 1 {
		t.Errorf("expected exactly 1 successful registration, got %d", succeeded)
	}
	if duplicates != 1 || other != 0 {
		t.Errorf("expected the loser to get email_already_exists, got duplicates=%d other=%d", duplicates, other)
	}
	var userCount int
	if err := db.QueryRow("SELECT COUNT(*) FROM users WHERE email = ?", "race@test.com").Scan(&userCount); err != nil {
		t.Fatal(err)
	}
	if userCount != 1 {
		t.Errorf("users with the raced email = %d, want exactly 1 (no orphan)", userCount)
	}
}
