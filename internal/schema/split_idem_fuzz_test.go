package schema

import (
	"reflect"
	"strings"
	"testing"
)

// FuzzSplitSQLIdempotent checks that splitting is a fixed point: rejoining the
// produced statements with ";" and re-splitting must produce the identical
// list. This catches lossy or inconsistent segmentation — a statement that
// leaks a top-level semicolon, a stray empty segment, or a boundary that makes
// re-splitting disagree with the first pass. It complements the shape checks in
// FuzzSplitSQL (same package, user-provided) by testing the boundary behavior
// the first pass's comment-dropping and quote handling feed into.
func FuzzSplitSQLIdempotent(f *testing.F) {
	for _, s := range []string{
		"",
		"SELECT 1",
		"SELECT 1; SELECT 2",
		"SELECT 1;SELECT 2;",
		"SELECT 'hello;world'; SELECT 2",
		"-- comment\nSELECT 1",
		"SELECT 1; -- comment\nSELECT 2",
		"SELECT 'it''s;''quoted'; SELECT 1",
		";;;",
		";  \n  ;SELECT 1",
		"SELECT ';'; SELECT ';'",
		"SELECT 'a\\';b'; SELECT 2",
		"\n\t ;SELECT 1; \n ;SELECT 'x'y'; ;SELECT 3",
	} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, input string) {
		first := SplitSQL(input)
		joined := strings.Join(first, ";")
		second := SplitSQL(joined)
		if !reflect.DeepEqual(first, second) {
			t.Errorf("SplitSQL is not idempotent:\n first: %#v\nsecond: %#v\n input: %q", first, second, input)
		}
	})
}
