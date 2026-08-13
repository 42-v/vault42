package config

import (
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"slices"
	"strconv"
	"strings"
	"testing"
)

// boolReaders are the helpers that turn an environment variable into a bool,
// mapped to the argument position holding the variable name.
var boolReaders = map[string]int{
	"envBool":        0,
	"envBoolDefault": 0,
	"setDefaultBool": 2,
}

// Every boolean setting must be registered in boolEnvVars, because that list is
// what Load walks to refuse an unrecognized spelling. A setting added later and
// left off it keeps the old behavior for itself: the operator's value is
// unparseable, the helper answers false or the profile default, and a control
// that was configured is silently absent. That is the defect this list exists to
// close, and it closes only for the variables named in it.
func TestEveryBooleanEnvironmentVariableIsRegistered(t *testing.T) {
	fset := token.NewFileSet()
	pkgs, err := parser.ParseDir(fset, ".", func(fi fs.FileInfo) bool {
		return !strings.HasSuffix(fi.Name(), "_test.go")
	}, 0)
	if err != nil {
		t.Fatalf("parse package: %v", err)
	}

	for _, pkg := range pkgs {
		for path, file := range pkg.Files {
			ast.Inspect(file, func(n ast.Node) bool {
				call, ok := n.(*ast.CallExpr)
				if !ok {
					return true
				}
				fn, ok := call.Fun.(*ast.Ident)
				if !ok {
					return true
				}
				argPos, watched := boolReaders[fn.Name]
				if !watched || len(call.Args) <= argPos {
					return true
				}
				lit, ok := call.Args[argPos].(*ast.BasicLit)
				if !ok || lit.Kind != token.STRING {
					return true
				}
				key, err := strconv.Unquote(lit.Value)
				if err != nil {
					return true
				}
				if !slices.Contains(boolEnvVars, key) {
					t.Errorf("%s:%d reads %s as a boolean but it is missing from boolEnvVars, so an unrecognized value silently means false",
						path, fset.Position(lit.Pos()).Line, key)
				}
				return true
			})
		}
	}
}

// The reverse direction: a registered variable nobody reads is a promise in the
// documentation that no code keeps.
func TestEveryRegisteredBooleanIsReadSomewhere(t *testing.T) {
	fset := token.NewFileSet()
	pkgs, err := parser.ParseDir(fset, ".", func(fi fs.FileInfo) bool {
		return !strings.HasSuffix(fi.Name(), "_test.go")
	}, 0)
	if err != nil {
		t.Fatalf("parse package: %v", err)
	}

	seen := map[string]bool{}
	for _, pkg := range pkgs {
		for _, file := range pkg.Files {
			ast.Inspect(file, func(n ast.Node) bool {
				lit, ok := n.(*ast.BasicLit)
				if !ok || lit.Kind != token.STRING {
					return true
				}
				if key, err := strconv.Unquote(lit.Value); err == nil {
					seen[key] = true
				}
				return true
			})
		}
	}

	for _, key := range boolEnvVars {
		if !seen[key] {
			t.Errorf("boolEnvVars lists %s but nothing in the package names it", key)
		}
	}
}
