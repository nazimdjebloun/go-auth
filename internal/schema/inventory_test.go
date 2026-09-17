package schema

import (
	"reflect"
	"regexp"
	"sort"
	"strings"
	"testing"
)

// Compare the split inventory to the actual line-oriented canonical DDL,
// independently of SplitSQL so a skipped leading-comment index is observable.
func TestSplitSQL_EmbeddedInventories(t *testing.T) {
	definition := regexp.MustCompile(`(?m)^CREATE (?:TABLE IF NOT EXISTS|INDEX(?: IF NOT EXISTS)?) ([a-z_]+)`)
	for _, driver := range []string{"sqlite", "postgres", "mysql"} {
		t.Run(driver, func(t *testing.T) {
			script, err := For(driver)
			if err != nil {
				t.Fatal(err)
			}
			var want, got []string
			for _, match := range definition.FindAllStringSubmatch(script, -1) {
				want = append(want, match[1])
			}
			for _, stmt := range SplitSQL(script) {
				match := definition.FindStringSubmatch(stmt)
				if match != nil {
					got = append(got, match[1])
				} else if !strings.HasPrefix(stmt, "PRAGMA ") && !strings.HasPrefix(stmt, "CREATE EXTENSION IF NOT EXISTS ") {
					t.Errorf("unexpected statement: %s", stmt)
				}
			}
			sort.Strings(want)
			sort.Strings(got)
			if len(want) < 45 {
				t.Fatalf("incomplete raw schema inventory: %d definitions", len(want))
			}
			if !reflect.DeepEqual(got, want) {
				t.Fatalf("split inventory = %v, raw DDL inventory = %v", got, want)
			}
		})
	}
}

func TestSplitSQL_QuotedAndCommentContent(t *testing.T) {
	for _, tc := range []struct {
		input string
		want  []string
	}{
		{"SELECT 'hello;--world'; SELECT 2", []string{"SELECT 'hello;--world'", "SELECT 2"}},
		{"SELECT 'it''s;--quoted';", []string{"SELECT 'it''s;--quoted'"}},
		{"-- header;\r\nSELECT-- middle;\r\n1;-- end", []string{"SELECT\n1"}},
		{"SELECT 1;-- no final newline;", []string{"SELECT 1"}},
	} {
		if got := SplitSQL(tc.input); !reflect.DeepEqual(got, tc.want) {
			t.Errorf("SplitSQL(%q) = %q, want %q", tc.input, got, tc.want)
		}
	}
}
