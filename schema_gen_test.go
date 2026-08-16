package goauth

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestGenerateSchema_WritesEmbeddedSchemaForEachDriverAlias(t *testing.T) {
	cases := []struct {
		driver string
		want   string
	}{
		{"postgres", embeddedPostgresSchema},
		{"pg", embeddedPostgresSchema},
		{"sqlite", embeddedSQLiteSchema},
		{"sqlite3", embeddedSQLiteSchema},
		{"mysql", embeddedMySQLSchema},
	}

	for _, c := range cases {
		t.Run(c.driver, func(t *testing.T) {
			outPath := filepath.Join(t.TempDir(), "auth.schema.sql")

			if err := GenerateSchema(c.driver, outPath); err != nil {
				t.Fatalf("GenerateSchema(%q): %v", c.driver, err)
			}

			got, err := os.ReadFile(outPath)
			if err != nil {
				t.Fatalf("reading generated file: %v", err)
			}
			if string(got) != c.want {
				t.Fatalf("GenerateSchema(%q) wrote content that does not match the embedded %s schema", c.driver, c.driver)
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
	if !strings.Contains(err.Error(), "oracle") {
		t.Fatalf("expected error to name the unsupported driver, got: %v", err)
	}
	if _, statErr := os.Stat(outPath); !os.IsNotExist(statErr) {
		t.Fatal("GenerateSchema should not have written a file for an unsupported driver")
	}
}
