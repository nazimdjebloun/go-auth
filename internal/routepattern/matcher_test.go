package routepattern

import (
	"net/http/httptest"
	"testing"
)

func TestMatcherServeMuxSemantics(t *testing.T) {
	m, err := New(map[string]int{
		"GET /things/{id}":      1,
		"GET /things/special":   2,
		"POST /files/{rest...}": 3,
		"GET /only/{$}":         4,
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		method, path string
		want         int
	}{
		{"GET", "/things/a", 1}, {"HEAD", "/things/a", 1},
		{"GET", "/things/special", 2}, {"GET", "/things/a/b", 0},
		{"POST", "/things/a", 0}, {"GET", "/things/a%2Fb", 1},
		{"POST", "/files/a/b", 3}, {"POST", "/files", 0},
		{"GET", "/only/", 4}, {"GET", "/only/sub", 0},
		{"GET", "/things//a", 0},
	} {
		r := httptest.NewRequest(tc.method, tc.path, nil)
		r.Pattern = "unchanged"
		r.SetPathValue("id", "existing")
		value, _, ok := m.Match(r)
		if value != tc.want || ok != (tc.want != 0) {
			t.Errorf("%s %s: value=%d, ok=%t", tc.method, tc.path, value, ok)
		}
		if r.Pattern != "unchanged" || r.PathValue("id") != "existing" {
			t.Fatal("matcher mutated routing context")
		}
	}
}

func TestMatcherRejectsInvalidAndAmbiguousPatterns(t *testing.T) {
	for _, patterns := range [][]string{
		{""}, {"GET /items/*"}, {"GET /items/{id"},
		{"GET /items/{id}", "GET /items/{other}"},
		{"GET /{left}/fixed", "GET /fixed/{right}"},
	} {
		values := map[string]bool{}
		for _, pattern := range patterns {
			values[pattern] = true
		}
		if _, err := New(values); err == nil {
			t.Errorf("accepted patterns %v", patterns)
		}
	}
}
