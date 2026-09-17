package cmd

import (
	"errors"
	"fmt"
	"testing"

	"github.com/go-sql-driver/mysql"
)

func TestMySQLDuplicateIndexClassification(t *testing.T) {
	for _, tc := range []struct {
		name string
		err  error
		want bool
	}{
		{"nil", nil, false},
		{"duplicate index", &mysql.MySQLError{Number: 1061}, true},
		{"wrapped", fmt.Errorf("exec: %w", &mysql.MySQLError{Number: 1061}), true},
		{"duplicate row", &mysql.MySQLError{Number: 1062, Message: "Duplicate key name"}, false},
		{"text lookalike", errors.New("Error 1061: Duplicate key name"), false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := isMySQLDuplicateIndexErr(tc.err); got != tc.want {
				t.Errorf("got %v, want %v", got, tc.want)
			}
		})
	}
	for _, tc := range []struct {
		stmt string
		want bool
	}{
		{"CREATE INDEX idx ON users(id)", true},
		{"create\nunique\tindex idx ON users(id)", true},
		{"CREATE TABLE users(id INT, INDEX idx(id), INDEX idx(id))", false},
		{"ALTER TABLE users ADD INDEX idx(id)", false},
		{"CREATE INDEX", false},
		{"", false},
	} {
		if got := isCreateIndex(tc.stmt); got != tc.want {
			t.Errorf("isCreateIndex(%q) = %v, want %v", tc.stmt, got, tc.want)
		}
	}
}
