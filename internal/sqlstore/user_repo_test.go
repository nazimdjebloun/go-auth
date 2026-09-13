package sqlstore

import (
	"context"
	"reflect"
	"testing"
	"time"

	"github.com/nazimdjebloun/go-auth/domain"
)

func TestUpdatePasswordHash_GuardsHashAndPepperVersion(t *testing.T) {
	db := newSQLiteTestDB(t)
	if _, err := db.Exec(`
		CREATE TABLE users (
			id TEXT PRIMARY KEY,
			password_hash TEXT,
			password_pepper_version INTEGER,
			updated_at DATETIME NOT NULL
		)`); err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	if _, err := db.Exec("INSERT INTO users (id, password_hash, password_pepper_version, updated_at) VALUES (?, ?, ?, ?)", "u1", "old", 1, now); err != nil {
		t.Fatal(err)
	}
	repo := NewUserRepository(db)
	v1, v2 := uint32(1), uint32(2)

	updated, err := repo.UpdatePasswordHash(context.Background(), "u1", "old", nil, "wrong", &v2, now)
	if err != nil {
		t.Fatal(err)
	}
	if updated {
		t.Fatal("update ignored an old pepper-version mismatch")
	}

	updated, err = repo.UpdatePasswordHash(context.Background(), "u1", "old", &v1, "new", &v2, now.Add(time.Second))
	if err != nil {
		t.Fatal(err)
	}
	if !updated {
		t.Fatal("matching hash and pepper version did not update")
	}

	updated, err = repo.UpdatePasswordHash(context.Background(), "u1", "new", &v2, "downgraded", &v1, now.Add(2*time.Second))
	if err != nil {
		t.Fatal(err)
	}
	if updated {
		t.Fatal("guarded update allowed a password pepper version downgrade")
	}
	var storedHash string
	var storedVersion uint32
	if err := db.QueryRowContext(context.Background(),
		"SELECT password_hash, password_pepper_version FROM users WHERE id = ?", "u1",
	).Scan(&storedHash, &storedVersion); err != nil {
		t.Fatal(err)
	}
	if storedHash != "new" || storedVersion != 2 {
		t.Fatalf("downgrade attempt stored hash/version = %q/%d, want new/2", storedHash, storedVersion)
	}

	// A concurrent password change has now replaced both values. The stale
	// rehash must not clobber it even if it presents the once-correct guard.
	updated, err = repo.UpdatePasswordHash(context.Background(), "u1", "old", &v1, "stale", &v2, now.Add(3*time.Second))
	if err != nil {
		t.Fatal(err)
	}
	if updated {
		t.Fatal("stale rehash overwrote a concurrent password change")
	}

	versions, err := repo.ListPasswordPepperVersions(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(versions, []uint32{2}) {
		t.Fatalf("stored versions = %v, want [2]", versions)
	}
}

func TestUserUpdate_DoesNotReplacePasswordCredential(t *testing.T) {
	db := newSQLiteTestDB(t)
	if _, err := db.Exec(`
		CREATE TABLE users (
			id TEXT PRIMARY KEY,
			email TEXT NOT NULL,
			password_hash TEXT,
			password_pepper_version INTEGER,
			name TEXT NOT NULL,
			role TEXT NOT NULL,
			is_verified INTEGER NOT NULL,
			verified_at DATETIME,
			is_banned INTEGER NOT NULL,
			updated_at DATETIME NOT NULL
		)`); err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	if _, err := db.Exec(`
		INSERT INTO users (
			id, email, password_hash, password_pepper_version, name, role,
			is_verified, is_banned, updated_at
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
	`, "u1", "old@example.com", "current-hash", 3, "Old Name", "user", false, false, now); err != nil {
		t.Fatal(err)
	}

	staleHash := "stale-hash"
	staleVersion := uint32(1)
	repo := NewUserRepository(db)
	if err := repo.Update(context.Background(), &domain.User{
		ID:                    "u1",
		Email:                 "new@example.com",
		PasswordHash:          &staleHash,
		PasswordPepperVersion: &staleVersion,
		Name:                  "New Name",
		Role:                  domain.RoleUser,
		UpdatedAt:             now.Add(time.Second),
	}); err != nil {
		t.Fatal(err)
	}

	var storedEmail, storedName, storedHash string
	var storedVersion uint32
	if err := db.QueryRowContext(context.Background(), `
		SELECT email, name, password_hash, password_pepper_version
		FROM users WHERE id = ?
	`, "u1").Scan(&storedEmail, &storedName, &storedHash, &storedVersion); err != nil {
		t.Fatal(err)
	}
	if storedEmail != "new@example.com" || storedName != "New Name" {
		t.Fatalf("metadata update stored email/name = %q/%q", storedEmail, storedName)
	}
	if storedHash != "current-hash" || storedVersion != 3 {
		t.Fatalf("metadata update replaced credential = %q/v%d, want current-hash/v3", storedHash, storedVersion)
	}
}
