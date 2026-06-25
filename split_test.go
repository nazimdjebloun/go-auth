package goauth

import (
	"reflect"
	"testing"
)

func TestSplitSQL_Empty(t *testing.T) {
	res := SplitSQL("")
	if len(res) != 0 {
		t.Fatalf("expected 0 statements, got %d", len(res))
	}
}

func TestSplitSQL_SemicolonOnly(t *testing.T) {
	res := SplitSQL(";;;")
	if len(res) != 0 {
		t.Fatalf("expected 0 statements, got %d", len(res))
	}
}

func TestSplitSQL_SingleStatement(t *testing.T) {
	res := SplitSQL("SELECT * FROM users")
	if len(res) != 1 || res[0] != "SELECT * FROM users" {
		t.Fatalf("expected [SELECT * FROM users], got %v", res)
	}
}

func TestSplitSQL_MultipleStatements(t *testing.T) {
	sql := "CREATE TABLE foo (id INT); INSERT INTO foo VALUES (1); SELECT * FROM foo"
	res := SplitSQL(sql)
	expected := []string{
		"CREATE TABLE foo (id INT)",
		"INSERT INTO foo VALUES (1)",
		"SELECT * FROM foo",
	}
	if !reflect.DeepEqual(res, expected) {
		t.Fatalf("expected %v, got %v", expected, res)
	}
}

func TestSplitSQL_TrailingSemicolon(t *testing.T) {
	res := SplitSQL("SELECT 1;")
	if len(res) != 1 || res[0] != "SELECT 1" {
		t.Fatalf("expected [SELECT 1], got %v", res)
	}
}

func TestSplitSQL_LeadingComment(t *testing.T) {
	sql := "-- this is a comment"
	res := SplitSQL(sql)
	if len(res) != 0 {
		t.Fatalf("expected 0 statements, got %d: %v", len(res), res)
	}
}

func TestSplitSQL_CommentLine(t *testing.T) {
	sql := "-- comment only line"
	res := SplitSQL(sql)
	if len(res) != 0 {
		t.Fatalf("expected 0 statements, got %d: %v", len(res), res)
	}
}

func TestSplitSQL_SQLAfterCommentOnSameSegment(t *testing.T) {
	// When a segment starts with --, the entire segment is skipped even if SQL
	// follows on a later line within the same segment.
	sql := "-- schema version 1\nCREATE TABLE users (id INT);"
	res := SplitSQL(sql)
	if len(res) != 0 {
		t.Fatalf("expected 0 statements (segment starts with --), got %d: %v", len(res), res)
	}
}

func TestSplitSQL_WhitespaceLines(t *testing.T) {
	sql := "  \n\t  \n;SELECT 1;  \n  "
	res := SplitSQL(sql)
	if len(res) != 1 || res[0] != "SELECT 1" {
		t.Fatalf("expected [SELECT 1], got %v", res)
	}
}

func TestSplitSQL_MixedContent(t *testing.T) {
	sql := `
		CREATE TABLE users (id INT);
		INSERT INTO users VALUES (1);
		SELECT * FROM users;
	`
	res := SplitSQL(sql)
	if len(res) != 3 {
		t.Fatalf("expected 3 statements, got %d: %v", len(res), res)
	}
}
