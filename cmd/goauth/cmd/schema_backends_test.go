package cmd

import (
	"testing"

	goauth "github.com/nazimdjebloun/go-auth"
	"github.com/nazimdjebloun/go-auth/internal/testdb"
)

func TestApplySchema_SelectedBackend(t *testing.T) {
	db := testdb.OpenSelected(t)
	driver := testdb.Driver(db)
	for range 2 {
		if err := applySchema(t.Context(), db, driver); err != nil {
			t.Fatal(err)
		}
		testdb.AssertSchema(t, db)
		testdb.AssertKeys(t, db)
		testdb.AssertForeignKeyIntegrity(t, db)
	}
}

func TestAdoptSchema_SelectedBackend(t *testing.T) {
	db := testdb.OpenSelected(t)
	testdb.Apply(t, db)
	status, err := goauth.AdoptSchema(t.Context(), db, goauth.BaselineAdoptionOptions{
		MigrationOptions: goauth.MigrationOptions{Driver: testdb.Driver(db)}, BaselineRevision: 1,
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(status.History) != 1 || status.History[0].Mode != "adopted" {
		t.Fatalf("incorrect adoption history: %+v", status)
	}
	if err := applySchema(t.Context(), db, testdb.Driver(db)); err != nil {
		t.Fatal(err)
	}
}
