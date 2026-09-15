package schema

import "testing"

func FuzzSplitSQL(f *testing.F) {
	f.Add("")
	f.Add("SELECT 1")
	f.Add("SELECT 1; SELECT 2")
	f.Add("SELECT 'hello;world'")
	f.Add("-- comment\nSELECT 1")
	f.Add("SELECT 1; -- comment\nSELECT 2")
	f.Add("SELECT 'it''s a test'; SELECT 1")
	f.Add(";;;")
	f.Add("SELECT 1; SELECT 'a;b;c'; SELECT 3")
	f.Add("\n\t\n;SELECT 1;  \n  ")
	f.Fuzz(func(t *testing.T, input string) {
		stmts := SplitSQL(input)
		for _, s := range stmts {
			if s == "" {
				t.Error("SplitSQL returned an empty statement")
			}
		}
	})
}
