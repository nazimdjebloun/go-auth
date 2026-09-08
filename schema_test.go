package goauth

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestGenerateSchema_WritesEmbeddedSchemaForEachDriverAlias(t *testing.T) {
	// Compared against GetSchema rather than the embedded vars directly: those
	// now live in internal/schema, and going through the public accessor also
	// asserts that the alias table and the writer agree on every spelling.
	drivers := []string{"postgres", "pg", "sqlite", "sqlite3", "mysql"}

	for _, driver := range drivers {
		t.Run(driver, func(t *testing.T) {
			want, err := GetSchema(driver)
			if err != nil {
				t.Fatalf("GetSchema(%q): %v", driver, err)
			}
			if want == "" {
				t.Fatalf("GetSchema(%q) returned an empty schema", driver)
			}

			outPath := filepath.Join(t.TempDir(), "auth.schema.sql")
			if err := GenerateSchema(driver, outPath); err != nil {
				t.Fatalf("GenerateSchema(%q): %v", driver, err)
			}

			got, err := os.ReadFile(outPath)
			if err != nil {
				t.Fatalf("reading generated file: %v", err)
			}
			if string(got) != want {
				t.Fatalf("GenerateSchema(%q) wrote content that does not match GetSchema(%q)", driver, driver)
			}
		})
	}
}

func TestGenerateSchema_UnsupportedDriver_ReturnsErrorWithoutWritingAFile(t *testing.T) {
	outPath := filepath.Join(t.TempDir(), "auth.schema.sql")

	err := GenerateSchema("oracle", outPath)
	if err == nil {
		t.Fatal("expected an error for an unsupported driver, got nil")
	}
	if !errors.Is(err, ErrUnsupportedDriver) {
		t.Fatalf("expected error to wrap ErrUnsupportedDriver, got: %v", err)
	}
	if !strings.Contains(err.Error(), "oracle") {
		t.Fatalf("expected error to name the unsupported driver, got: %v", err)
	}
	if _, statErr := os.Stat(outPath); !os.IsNotExist(statErr) {
		t.Fatal("GenerateSchema should not have written a file for an unsupported driver")
	}
}
