package migrationtool

import (
	"net/url"
	"os"
	"strings"
	"testing"
)

func TestSQLiteDraftPreservesUniqueDefinitionsWithoutGeneratedNames(t *testing.T) {
	f := authorCheckout(t)
	f.diff = func(_ string) error {
		args := f.atlasCalls[len(f.atlasCalls)-1]
		for i, arg := range args {
			if arg != "--to" {
				continue
			}
			source, err := url.Parse(args[i+1])
			if err != nil {
				return err
			}
			// #nosec G304 -- The fake Atlas call receives a temporary file created by this test's tool.
			contents, err := os.ReadFile(source.Path)
			if err != nil {
				return err
			}
			if !strings.HasSuffix(source.Path, ".hcl") || strings.Contains(string(contents), "sqlite_autoindex_") ||
				!strings.Contains(string(contents), "unique = true") || !strings.Contains(string(contents), "columns = [column.email]") {
				t.Fatal("SQLite UNIQUE constraint was changed or its generated name retained")
			}
			return nil
		}
		t.Fatal("Atlas received no desired schema")
		return nil
	}
	if _, err := f.tool.CreateDraft(t.Context(), DraftOptions{Driver: "sqlite", Release: "v0.5.0", Sequence: 1}); err == nil {
		t.Fatal("unchanged schema produced a draft")
	}
}

func TestSQLiteAutoindexLabelsLeaveExplicitIndexesIntact(t *testing.T) {
	const input = `table "users" {
  index "sqlite_autoindex_users_2" {
    unique = true
    columns = [column.email]
  }
  index "idx_users_email" {
    columns = [column.email]
  }
}`
	got := sqliteAutoindexLabel.ReplaceAllString(input, "${1}index {")
	if strings.Contains(got, `index "sqlite_autoindex_users_2"`) ||
		!strings.Contains(got, `index "idx_users_email"`) ||
		strings.Count(got, "columns = [column.email]") != 2 || !strings.Contains(got, "unique = true") {
		t.Fatal("index definitions were removed or explicit index identity changed")
	}
}
