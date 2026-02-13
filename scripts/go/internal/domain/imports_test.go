// Feature: scripts-lib-hexagonal-refactor
// Validates: Requirements 10.3 — Domain core has no forbidden imports
package domain

import (
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestDomainCoreHasNoForbiddenImports(t *testing.T) {
	forbiddenImports := []string{
		"net/http",
		"os/exec",
		"github.com/PuerkitoBio/goquery",
		"golang.org/x/net/html",
	}

	domainDir := "."
	entries, err := os.ReadDir(domainDir)
	if err != nil {
		t.Fatalf("failed to read domain directory: %v", err)
	}

	fset := token.NewFileSet()
	for _, entry := range entries {
		name := entry.Name()
		if entry.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}

		path := filepath.Join(domainDir, name)
		f, err := parser.ParseFile(fset, path, nil, parser.ImportsOnly)
		if err != nil {
			t.Fatalf("failed to parse %s: %v", name, err)
		}

		for _, imp := range f.Imports {
			importPath := strings.Trim(imp.Path.Value, `"`)
			for _, forbidden := range forbiddenImports {
				if importPath == forbidden {
					t.Errorf("file %s imports forbidden package %q", name, forbidden)
				}
			}
		}
	}
}
