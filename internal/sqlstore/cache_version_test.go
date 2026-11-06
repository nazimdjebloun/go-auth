package sqlstore

import (
	"errors"
	"testing"
)

func TestVersionedUpdateRejectsUnsupportedSQLBeforeExecution(t *testing.T) {
	for _, tc := range []struct {
		name  string
		query string
	}{
		{"missing assignment", "UPDATE sessions WHERE id=$1"},
		{"lowercase assignment", "UPDATE sessions set token_hash=$1 WHERE id=$2"},
		{"comment-separated assignment", "UPDATE sessions SET/* assignment */token_hash=$1 WHERE id=$2"},
		{"newline-separated assignment", "UPDATE sessions SET\ntoken_hash=$1 WHERE id=$2"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			// No database exists: unsupported SQL must fail before any I/O.
			var db *DB
			if _, err := db.execVersioned(t.Context(), tc.query, "hash", "id"); !errors.Is(err, errVersionedUpdate) {
				t.Fatalf("exec error = %v", err)
			}
			if err := db.queryVersioned(t.Context(), tc.query, "hash", "id").Scan(); !errors.Is(err, errVersionedUpdate) {
				t.Fatalf("query error = %v", err)
			}
		})
	}
}
