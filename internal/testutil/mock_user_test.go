package testutil

import (
	"reflect"
	"sync"
	"testing"
	"time"

	"github.com/nazimdjebloun/go-auth/domain"
	"github.com/nazimdjebloun/go-auth/port"
)

func snapshotUserFixture() *domain.User {
	hash, version := "original hash", uint32(1)
	verified, banned, login := time.Unix(1, 0).UTC(), time.Unix(2, 0).UTC(), time.Unix(3, 0).UTC()
	return &domain.User{
		ID: "user", Email: "user@example.com", Name: "Original",
		PasswordHash: &hash, PasswordPepperVersion: &version,
		VerifiedAt: &verified, BannedAt: &banned, LastLoginAt: &login,
	}
}

func mutateUserSnapshot(user *domain.User) {
	user.Name, user.Email = "Mutated", "changed@example.com"
	*user.PasswordHash = "changed hash"
	*user.PasswordPepperVersion = 2
	*user.VerifiedAt = time.Unix(100, 0)
	*user.BannedAt = time.Unix(200, 0)
	*user.LastLoginAt = time.Unix(300, 0)
}

func TestMockUserRepoDetachedSnapshots(t *testing.T) {
	repo := NewMockUserRepo()
	input := snapshotUserFixture()
	if err := repo.Create(t.Context(), input); err != nil {
		t.Fatal(err)
	}
	mutateUserSnapshot(input)
	for _, read := range []func() (*domain.User, error){
		func() (*domain.User, error) { return repo.GetByID(t.Context(), "user") },
		func() (*domain.User, error) { return repo.GetByEmail(t.Context(), "user@example.com") },
		func() (*domain.User, error) { return repo.GetByIDForUpdate(t.Context(), "user") },
		func() (*domain.User, error) {
			users, err := repo.List(t.Context(), port.UserFilter{})
			if err != nil || len(users) != 1 {
				t.Fatalf("list = %+v, %v", users, err)
			}
			return &users[0], nil
		},
	} {
		user, err := read()
		if err != nil || !reflect.DeepEqual(user, snapshotUserFixture()) {
			t.Fatalf("stored user changed through a caller's snapshot: %+v, %v", user, err)
		}
		mutateUserSnapshot(user)
	}
	user, err := repo.GetByID(t.Context(), "user")
	if err != nil || !reflect.DeepEqual(user, snapshotUserFixture()) {
		t.Fatal("read result shared mutable state with the stored user")
	}
	user.Email = "new@example.com"
	if err := repo.Update(t.Context(), user); err != nil {
		t.Fatal(err)
	}
	mutateUserSnapshot(user)
	if old, err := repo.GetByEmail(t.Context(), "user@example.com"); err != nil || old != nil {
		t.Fatal("email update left a stale lookup alias")
	}
	want := snapshotUserFixture()
	want.Email = "new@example.com"
	if stored, err := repo.GetByEmail(t.Context(), want.Email); err != nil || !reflect.DeepEqual(stored, want) {
		t.Fatal("update input shared mutable state with the stored user")
	}
}

func TestMockUserRepoConcurrentDetachedReads(t *testing.T) {
	repo := NewMockUserRepo()
	if err := repo.Create(t.Context(), snapshotUserFixture()); err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	for range 16 {
		wg.Go(func() {
			for range 50 {
				user, err := repo.GetByID(t.Context(), "user")
				if err != nil || user == nil {
					t.Errorf("read = %+v, %v", user, err)
					return
				}
				mutateUserSnapshot(user)
			}
		})
	}
	wg.Wait()
	if user, err := repo.GetByID(t.Context(), "user"); err != nil || !reflect.DeepEqual(user, snapshotUserFixture()) {
		t.Fatal("concurrent readers changed stored state")
	}
}

func TestMockUserRepoCopiesBanTimestampInputs(t *testing.T) {
	for _, guarded := range []bool{false, true} {
		repo := NewMockUserRepo()
		if err := repo.Create(t.Context(), snapshotUserFixture()); err != nil {
			t.Fatal(err)
		}
		bannedAt := time.Unix(50, 0).UTC()
		if guarded {
			if ok, err := repo.BanWithAdminGuard(t.Context(), "user", true, &bannedAt, bannedAt); err != nil || !ok {
				t.Fatalf("ban = %v, %v", ok, err)
			}
		} else if err := repo.SetBanStatus(t.Context(), "user", true, &bannedAt, bannedAt); err != nil {
			t.Fatal(err)
		}
		bannedAt = time.Unix(60, 0).UTC()
		user, err := repo.GetByID(t.Context(), "user")
		if err != nil || user.BannedAt == nil || !user.BannedAt.Equal(time.Unix(50, 0)) {
			t.Fatalf("guarded=%v: ban timestamp mutated through input: %+v, %v", guarded, user, err)
		}
	}
}
