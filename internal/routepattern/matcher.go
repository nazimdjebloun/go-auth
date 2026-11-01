// Package routepattern matches the same patterns used by http.ServeMux.
package routepattern

import (
	"fmt"
	"net/http"
	"sort"
	"strings"
)

// Matcher is immutable after construction and safe for concurrent requests.
// It selects values without dispatching handlers or modifying PathValue.
type Matcher[T any] struct{ mux *http.ServeMux }

type entry[T any] struct{ value T }

func (*entry[T]) ServeHTTP(http.ResponseWriter, *http.Request) {}

// New validates every pattern and rejects ambiguous registrations. Old star
// globs are refused explicitly rather than silently becoming literal paths.
func New[T any](values map[string]T) (_ *Matcher[T], err error) {
	m := &Matcher[T]{mux: http.NewServeMux()}
	patterns := make([]string, 0, len(values))
	for pattern := range values {
		patterns = append(patterns, pattern)
	}
	sort.Strings(patterns)
	for _, pattern := range patterns {
		if strings.Contains(pattern, "*") {
			return nil, fmt.Errorf("route pattern %q: use {name} or {name...} instead of star globs", pattern)
		}
		if err := register(m.mux, pattern, &entry[T]{value: values[pattern]}); err != nil {
			return nil, err
		}
	}
	return m, nil
}

// register confines recovery to ServeMux's documented registration panics.
func register(mux *http.ServeMux, pattern string, h http.Handler) (err error) {
	defer func() {
		if failure := recover(); failure != nil {
			err = fmt.Errorf("route pattern %q: %v", pattern, failure)
		}
	}()
	mux.Handle(pattern, h)
	return nil
}

// Match ignores ServeMux's automatic redirect and method-error handlers: only
// a registered pattern can supply a policy or authorize a declared route.
func (m *Matcher[T]) Match(r *http.Request) (value T, pattern string, ok bool) {
	h, pattern := m.mux.Handler(r)
	if selected, found := h.(*entry[T]); found {
		return selected.value, pattern, true
	}
	return value, "", false
}
