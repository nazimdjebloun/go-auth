package cmd

import (
	"testing"

	goauth "github.com/nazimdjebloun/go-auth"
	"github.com/nazimdjebloun/go-auth/internal/schema"
	"github.com/nazimdjebloun/go-auth/internal/testdb"
)

func TestApplySchema_SelectedBackend(t *testing.T) {
	db := testdb.OpenSelected(t)
	driver := testdb.Driver(db)
	script, err := goauth.GetSchema(driver)
	if err != nil {
		t.Fatal(err)
	}
	// Replay after partial application, then again after full application.
	for _, statement := range schema.SplitSQL(script)[:2] {
		if _, err := db.ExecContext(t.Context(), statement); err != nil {
			t.Fatal(err)
		}
	}
	for range 2 {
		if err := applySchema(t.Context(), db, driver); err != nil {
			t.Fatal(err)
		}
		testdb.AssertSchema(t, db)
		testdb.AssertKeys(t, db)
		testdb.AssertForeignKeyIntegrity(t, db)
	}
}
