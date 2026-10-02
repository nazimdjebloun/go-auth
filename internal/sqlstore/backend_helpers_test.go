package sqlstore

import (
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/nazimdjebloun/go-auth/domain"
	"github.com/nazimdjebloun/go-auth/internal/testdb"
)

func backendDB(t *testing.T) *DB {
	t.Helper()
	raw := testdb.OpenSelected(t)
	testdb.Apply(t, raw)
	return NewDB(raw, testdb.Driver(raw))
}

func backendUser(t *testing.T, db *DB) string {
	t.Helper()
	id := uuid.NewString()
	now := time.Now().UTC()
	if err := NewUserRepository(db).Create(t.Context(), &domain.User{ID: id, Email: id + "@example.com", Name: "Unicode 名 😀", Role: domain.RoleUser, CreatedAt: now, UpdatedAt: now}); err != nil {
		t.Fatal(err)
	}
	return id
}
