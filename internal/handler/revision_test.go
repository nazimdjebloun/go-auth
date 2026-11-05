package handler

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestExpectedRevision(t *testing.T) {
	for _, tc := range []struct {
		name   string
		values []string
		query  string
		want   uint64
	}{
		{name: "positive", values: []string{`"17"`}, want: 17},
		{name: "outer whitespace", values: []string{" \t\"17\" "}, want: 17},
		{name: "maximum uint64", values: []string{`"18446744073709551615"`}, want: ^uint64(0)},
		{name: "missing"},
		{name: "unquoted", values: []string{"17"}},
		{name: "zero", values: []string{`"0"`}},
		{name: "negative", values: []string{`"-1"`}},
		{name: "leading zeros", values: []string{`"01"`}},
		{name: "overflow", values: []string{`"18446744073709551616"`}},
		{name: "weak tag", values: []string{`W/"17"`}},
		{name: "wildcard", values: []string{"*"}},
		{name: "list", values: []string{`"17", "18"`}},
		{name: "duplicate headers", values: []string{`"17"`, `"17"`}},
		{name: "query only", query: "?expectedRevision=17"},
		{name: "mixed transports", values: []string{`"17"`}, query: "?expectedRevision=17"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := httptest.NewRequest(http.MethodDelete, "/"+tc.query, nil)
			for _, value := range tc.values {
				r.Header.Add("If-Match", value)
			}
			w := httptest.NewRecorder()
			got, ok := New(Deps{}).expectedRevision(w, r)
			if got != tc.want || ok != (tc.want != 0) {
				t.Fatalf("revision=%d ok=%v", got, ok)
			}
			if !ok && w.Code != 400 {
				t.Fatalf("status=%d", w.Code)
			}
		})
	}
}
