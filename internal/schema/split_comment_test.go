package schema

import (
	"reflect"
	"testing"
)

func TestSplitSQL_CommentPreservesTokenBoundary(t *testing.T) {
	got := SplitSQL("SELECT-- comment; ignored\n1;")
	want := []string{"SELECT\n1"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("SplitSQL() = %q, want %q", got, want)
	}
}
