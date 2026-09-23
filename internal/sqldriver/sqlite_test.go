package sqldriver

import (
	"net/url"
	"strings"
	"testing"
)

func TestSQLiteForeignKeyDSN(t *testing.T) {
	for _, tt := range []struct {
		name, driver, dsn, param, want string
	}{
		{"modernc memory", "sqlite", ":memory:", "_pragma", "foreign_keys(1)"},
		{"modernc override", "sqlite", "plain%23.db?_pragma=foreign_keys(0)&_pragma=busy_timeout(1000)", "_pragma", "foreign_keys(1)"},
		{"mattn alias", "sqlite3", "file:test.db?_fk=off&_foreign_keys=0", "_foreign_keys", "1"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			got, err := SQLiteForeignKeyDSN(tt.driver, tt.dsn)
			if err != nil {
				t.Fatal(err)
			}
			filename, query, _ := strings.Cut(got, "?")
			original, _, _ := strings.Cut(tt.dsn, "?")
			if filename != original {
				t.Fatalf("filename changed: %q != %q", filename, original)
			}
			params, err := url.ParseQuery(query)
			if err != nil {
				t.Fatal(err)
			}
			values := params[tt.param]
			if len(values) == 0 || values[len(values)-1] != tt.want {
				t.Fatalf("params: %v", params)
			}
			if params.Has("_fk") {
				t.Fatal("mattn alias retained")
			}
			if tt.name == "modernc override" && (len(values) != 2 || values[0] != "busy_timeout(1000)") {
				t.Fatalf("unrelated pragma lost: %v", values)
			}
		})
	}
	if _, err := SQLiteForeignKeyDSN("sqlite", "file:test.db?bad=%zz"); err == nil {
		t.Fatal("accepted malformed parameters")
	}
	if _, err := SQLiteForeignKeyDSN("unknown", "test.db"); err == nil {
		t.Fatal("accepted unknown driver")
	}
}
