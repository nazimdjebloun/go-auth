package sqlstore

import (
	"os"
	"path/filepath"
	"regexp"
	"testing"
)

// TestQueries_NoReusedPlaceholders is the cheap static guard against the
// $N footgun: DB.Rebind rewrites placeholders positionally, so a query that
// reuses $1 twice works on Postgres and breaks on MySQL/SQLite (wrong
// argument count). Every repeated use needs its own number — pass the same
// argument twice instead.
func TestQueries_NoReusedPlaceholders(t *testing.T) {
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatal(err)
	}
	queryFile := regexp.MustCompile(`_queries\.go$`)
	// Backtick strings are the query literals; $N inside them is a placeholder.
	literal := regexp.MustCompile("`[^`]*`")
	placeholder := regexp.MustCompile(`\$(\d+)`)

	for _, e := range entries {
		if !queryFile.MatchString(e.Name()) {
			continue
		}
		src, err := os.ReadFile(filepath.Join(".", e.Name()))
		if err != nil {
			t.Fatal(err)
		}
		for _, lit := range literal.FindAllString(string(src), -1) {
			seen := map[string]int{}
			for _, m := range placeholder.FindAllStringSubmatch(lit, -1) {
				seen[m[1]]++
				if seen[m[1]] > 1 {
					t.Errorf("%s: placeholder $%s reused in %q — use distinct numbers", e.Name(), m[1], lit)
				}
			}
		}
	}
}
