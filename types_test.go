package goauth

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// constructionOnly are internal/service types a consumer never needs to name:
// they exist to build a service, and the constructors that take them are
// unreachable from outside this module. SessionConfig is excluded for a second
// reason — aliasing it would collide with the public SessionConfig section.
var constructionOnly = map[string]bool{
	"Config":                 true,
	"CommonConfig":           true,
	"SessionConfig":          true,
	"OAuthServiceConfig":     true,
	"OrgServiceConfig":       true,
	"OrgInviteServiceConfig": true,
	"AuditPublisher":         true,
	// Built and attached internally by New(); consumers never name it.
	"AccountDeletion": true,
}

// TestServiceTypesAreAliased fails when a type is added to internal/service
// without a matching alias in types.go.
//
// internal/service is unreachable from outside this module, so an un-aliased
// type that reaches a consumer-facing signature cannot be written down by the
// consumer at all — they can hold it with := and nothing else. That failure is
// invisible from inside the module, where the import always resolves, so it
// needs a test rather than a convention.
func TestServiceTypesAreAliased(t *testing.T) {
	declared := exportedTypesIn(t, "internal/service")
	aliased := aliasedTypes(t)

	for _, name := range declared {
		if constructionOnly[name] {
			if aliased[name] {
				t.Errorf("%s is marked construction-only but is aliased in types.go — "+
					"drop the alias or remove it from constructionOnly", name)
			}
			continue
		}
		if !aliased[name] {
			t.Errorf("service.%s has no alias in types.go — a consumer cannot name it. "+
				"Add `type %s = service.%s`, or add it to constructionOnly if it is "+
				"only ever used to build a service.", name, name, name)
		}
	}
}

func exportedTypesIn(t *testing.T, dir string) []string {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("read %s: %v", dir, err)
	}
	var names []string
	fset := token.NewFileSet()
	for _, e := range entries {
		name := e.Name()
		if !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		f, err := parser.ParseFile(fset, filepath.Join(dir, name), nil, 0)
		if err != nil {
			t.Fatalf("parse %s: %v", name, err)
		}
		for _, d := range f.Decls {
			gd, ok := d.(*ast.GenDecl)
			if !ok || gd.Tok != token.TYPE {
				continue
			}
			for _, spec := range gd.Specs {
				ts := spec.(*ast.TypeSpec)
				if ts.Name.IsExported() {
					names = append(names, ts.Name.Name)
				}
			}
		}
	}
	return names
}

func aliasedTypes(t *testing.T) map[string]bool {
	t.Helper()
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, "types.go", nil, 0)
	if err != nil {
		t.Fatalf("parse types.go: %v", err)
	}
	out := map[string]bool{}
	for _, d := range f.Decls {
		gd, ok := d.(*ast.GenDecl)
		if !ok || gd.Tok != token.TYPE {
			continue
		}
		for _, spec := range gd.Specs {
			ts := spec.(*ast.TypeSpec)
			// Assign is set only for `type X = Y`; a defined type would be a
			// distinct type and would not satisfy the same contract.
			if ts.Assign.IsValid() {
				out[ts.Name.Name] = true
			}
		}
	}
	return out
}
