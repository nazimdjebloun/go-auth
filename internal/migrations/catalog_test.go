package migrations

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/nazimdjebloun/go-auth/internal/schema"
)

func TestCatalogMatchesCanonicalSchemas(t *testing.T) {
	for _, dialect := range []string{"postgres", "mysql", "sqlite"} {
		t.Run(dialect, func(t *testing.T) {
			catalog, err := Load(dialect)
			if err != nil {
				t.Fatal(err)
			}
			ddl, err := schema.For(dialect)
			if err != nil {
				t.Fatal(err)
			}
			if strings.ReplaceAll(ddl, "\r\n", "\n") != catalog.Migrations[len(catalog.Migrations)-1].schemaSQL {
				t.Fatal("canonical schema differs from published target snapshot")
			}
			def, err := parseDefinition(dialect, ddl)
			if err != nil {
				t.Fatal(err)
			}
			if len(def.tables) != 15 || len(def.indexes) < 30 {
				t.Fatal("incomplete auth object inventory")
			}
		})
	}
}

func TestStatementBoundariesPreserveCompoundSQL(t *testing.T) {
	script := "-- goauth:statement\nDO $$ BEGIN PERFORM 1; PERFORM 2; END $$;\n" +
		"-- goauth:statement\nSELECT 'a;b';\n"
	got, err := statements(script)
	if err != nil || len(got) != 2 || !strings.Contains(got[0], "PERFORM 2;") {
		t.Fatalf("compound statement was split: %v, %v", got, err)
	}
	if _, err := statements("SELECT 1;"); err == nil {
		t.Fatal("unbounded SQL was accepted")
	}
}

func TestExpressionsPreservePrecedenceAndCase(t *testing.T) {
	for _, tc := range []struct {
		left, right string
		equal       bool
	}{
		{"a OR b AND c", "(a OR b) AND c", false},
		{"status = 'pending'", "status = 'Pending'", false},
		{"role IN ('user', 'admin')", "role = ANY (ARRAY['user'::text, 'admin'::text])", true},
		{"revision > 0", "((revision > 0))", true},
	} {
		left, err := expression(tc.left)
		if err != nil {
			t.Fatal(err)
		}
		right, err := expression(tc.right)
		if err != nil {
			t.Fatal(err)
		}
		if (left == right) != tc.equal {
			t.Errorf("unexpected equivalence: %q and %q", left, right)
		}
	}
}

func TestExportRefusesChangedPublishedSQL(t *testing.T) {
	directory := filepath.Join(t.TempDir(), "auth")
	if err := Export("sqlite", directory); err != nil {
		t.Fatal(err)
	}
	catalog, err := Load("sqlite")
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(directory, "migrations", catalog.Migrations[0].File)
	if err := os.WriteFile(path, []byte("modified"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := Export("sqlite", directory); err == nil {
		t.Fatal("modified published migration was overwritten")
	}
	if content, err := os.ReadFile(path); err != nil || string(content) != "modified" {
		t.Fatal("changed migration was not preserved")
	}
}
