package httperr

import (
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"
)

// TestStatusFor_CoversEveryNewErrorCode walks the repo source (excluding
// _test.go files and PLANS/) and asserts every string literal code passed to
// domain.NewError(...) or, within the domain package itself, NewError(...)
// has an entry in byCode. A code missing here would silently fall back to
// StatusFor's 500 default in production instead of failing here in CI.
func TestStatusFor_CoversEveryNewErrorCode(t *testing.T) {
	_, thisFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("could not determine test file path")
	}
	repoRoot := filepath.Join(filepath.Dir(thisFile), "..", "..")

	var codes []string
	err := filepath.WalkDir(repoRoot, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			switch d.Name() {
			case "PLANS", ".git", "cmd":
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}

		fset := token.NewFileSet()
		file, perr := parser.ParseFile(fset, path, nil, 0)
		if perr != nil {
			return perr
		}
		ast.Inspect(file, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok {
				return true
			}
			var fnName string
			switch fn := call.Fun.(type) {
			case *ast.Ident:
				fnName = fn.Name
			case *ast.SelectorExpr:
				fnName = fn.Sel.Name
			default:
				return true
			}
			if fnName != "NewError" || len(call.Args) < 1 {
				return true
			}
			lit, ok := call.Args[0].(*ast.BasicLit)
			if !ok || lit.Kind != token.STRING {
				return true
			}
			code, uerr := strconv.Unquote(lit.Value)
			if uerr != nil {
				return true
			}
			codes = append(codes, code)
			return true
		})
		return nil
	})
	if err != nil {
		t.Fatalf("walking repo for NewError(...) calls: %v", err)
	}

	if len(codes) == 0 {
		t.Fatal("found zero NewError(...) calls in the repo — walk path or AST matching is wrong")
	}

	seen := make(map[string]bool)
	for _, code := range codes {
		if seen[code] {
			continue
		}
		seen[code] = true
		if _, ok := byCode[code]; !ok {
			t.Errorf("error code %q has no entry in httperr.byCode — falls back to 500", code)
		}
	}
}
