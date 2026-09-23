package sqlstore

import (
	"reflect"
	"regexp"
	"strings"
	"testing"
)

// SQLite and PostgreSQL evaluate UPDATE expressions against the old row, so
// executing this query on SQLite cannot detect MySQL assignment-order drift.
func TestSessionRotateRefreshMySQLAssignmentOrder(t *testing.T) {
	query := strings.Join(strings.Fields(sessionRotateRefreshNoReturningQuery), " ")
	preserve := strings.Index(query, "prev_refresh_token_hash = refresh_token_hash")
	replace := strings.Index(query, "refresh_token_hash = $2")
	if preserve < 0 || replace < 0 || preserve >= replace {
		t.Fatal("MySQL rotation must preserve the previous refresh hash before replacing the current hash")
	}

	// Rebind converts numbered placeholders to positional question marks;
	// changing their order without changing the caller's arguments is unsafe.
	got := regexp.MustCompile(`\$[0-9]+`).FindAllString(query, -1)
	want := []string{"$1", "$2", "$3", "$4", "$5", "$6", "$7", "$8"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("placeholder order = %v, want %v", got, want)
	}
}
