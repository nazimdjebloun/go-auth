package migrationtool

import (
	"context"
	"errors"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/nazimdjebloun/go-auth/internal/migrations"
	"github.com/nazimdjebloun/go-auth/internal/schema"
)

type authorFixture struct {
	tool       Tool
	base       map[string][]byte
	atlasCalls [][]string
	diff       func(string) error
	version    string
}

func authorCheckout(t *testing.T) *authorFixture {
	t.Helper()
	f := &authorFixture{base: map[string][]byte{}, version: "atlas version v1.3.0\n"}
	f.tool = Tool{Root: t.TempDir(), BaseRef: "published", run: f.command}
	write := func(relative string, contents []byte) {
		path := filepath.Join(f.tool.Root, relative)
		if err := os.MkdirAll(filepath.Dir(path), 0750); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, contents, 0600); err != nil {
			t.Fatal(err)
		}
		f.base[filepath.ToSlash(relative)] = append([]byte(nil), contents...)
	}
	write("go.mod", []byte("module github.com/nazimdjebloun/go-auth\n"))
	for _, dialect := range []string{"postgres", "mysql", "sqlite"} {
		catalog, err := migrations.Load(dialect)
		if err != nil {
			t.Fatal(err)
		}
		manifest, err := jsonBytes(catalog)
		if err != nil {
			t.Fatal(err)
		}
		write(filepath.Join("internal/migrations", dialect, "catalog.json"), manifest)
		for _, step := range catalog.Migrations {
			write(filepath.Join("internal/migrations", dialect, step.File), []byte(step.SQL))
			snapshot, err := os.ReadFile(filepath.Join("../migrations", dialect, step.Schema))
			if err != nil {
				t.Fatal(err)
			}
			write(filepath.Join("internal/migrations", dialect, step.Schema), snapshot)
		}
		desired, err := schema.For(dialect)
		if err != nil {
			t.Fatal(err)
		}
		write(filepath.Join("internal/schema", dialect+".sql"), []byte(strings.ReplaceAll(desired, "\r\n", "\n")))
	}
	return f
}

func (f *authorFixture) command(_ context.Context, executable, _ string, args ...string) ([]byte, error) {
	if executable == "git" {
		if args[0] == "rev-parse" {
			return []byte(strings.Repeat("1", 40) + "\n"), nil
		}
		_, path, ok := strings.Cut(args[1], ":")
		if contents, exists := f.base[path]; ok && exists {
			return contents, nil
		}
		return nil, os.ErrNotExist
	}
	f.atlasCalls = append(f.atlasCalls, append([]string(nil), args...))
	if args[0] == "version" {
		return []byte(f.version), nil
	}
	if len(args) > 1 && args[1] == "diff" && f.diff != nil {
		for i, arg := range args {
			if arg == "--dir" {
				u, err := url.Parse(args[i+1])
				if err != nil {
					return nil, err
				}
				return nil, f.diff(u.Path)
			}
		}
	}
	return nil, nil
}

func TestDraftUsesPinnedDisposableHistoryAndExplicitBoundaries(t *testing.T) {
	f := authorCheckout(t)
	f.diff = func(directory string) error {
		files, err := os.ReadDir(directory)
		if err != nil {
			return err
		}
		if len(files) != 1 || files[0].Name() != "000001_v0.4.0_001.sql" {
			t.Fatal("Atlas history lost numeric migration identities")
		}
		return os.WriteFile(filepath.Join(directory, "20261011000000_review.sql"), []byte("-- goauth:statement\nALTER TABLE users ADD COLUMN example TEXT;\n"), 0600)
	}
	directory, err := f.tool.CreateDraft(t.Context(), DraftOptions{Driver: "postgres", Release: "v0.5.0", Sequence: 1})
	if err != nil {
		t.Fatal(err)
	}
	var draft Draft
	if err := readJSON(filepath.Join(directory, "draft.json"), &draft); err != nil {
		t.Fatal(err)
	}
	if draft.File != "000002_v0.5.0_001.sql" || draft.ID != 2 || !draft.Transactional {
		t.Fatalf("incorrect draft identity: %+v", draft)
	}
	args := f.atlasCalls[len(f.atlasCalls)-1]
	if !strings.Contains(strings.Join(args, "\n"), "docker://postgres/18.0/dev?search_path=public") || args[len(args)-1] != statementFormat {
		t.Fatal("unversioned dev database or unsupported SQL boundaries")
	}
	if err := f.tool.Check(t.Context()); err != nil {
		t.Fatal("draft mutated source catalog", err)
	}
	if _, err := f.tool.CreateDraft(t.Context(), DraftOptions{Driver: "postgres", Release: "v0.5.0", Sequence: 1}); err == nil {
		t.Fatal("existing review files were overwritten")
	}
}

func TestWrongAtlasVersionAndNoChangeProduceNoDraft(t *testing.T) {
	for _, version := range []string{"atlas version v1.2.0\n", "atlas version v1.3.0\n"} {
		t.Run(strings.TrimSpace(version), func(t *testing.T) {
			f := authorCheckout(t)
			f.version = version
			if _, err := f.tool.CreateDraft(t.Context(), DraftOptions{Driver: "sqlite", Release: "v0.5.0", Sequence: 1}); err == nil {
				t.Fatal("wrong toolchain or empty migration was accepted")
			}
			if _, err := os.Stat(filepath.Join(f.tool.Root, ".migration-drafts/sqlite")); !os.IsNotExist(err) {
				t.Fatal("failed drafting left a review directory")
			}
		})
	}
}

func TestSealAppendsReviewedDataMigrationAndPreservesPublishedArtifacts(t *testing.T) {
	f := authorCheckout(t)
	directory, err := f.tool.CreateDraft(t.Context(), DraftOptions{Driver: "sqlite", Release: "v0.5.0", Sequence: 1, Manual: true})
	if err != nil {
		t.Fatal(err)
	}
	if err := f.tool.Seal(t.Context(), directory, false); err == nil || len(f.atlasCalls) != 0 {
		t.Fatal("unreviewed draft reached Atlas or publication")
	}
	if err := f.tool.Seal(t.Context(), directory, true); err == nil || len(f.atlasCalls) != 0 {
		t.Fatal("unfilled manual skeleton reached Atlas or publication")
	}
	if err := os.WriteFile(filepath.Join(directory, "migration.sql"), []byte("-- goauth:statement\nUPDATE users SET name=name;\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := f.tool.Seal(t.Context(), directory, true); err != nil {
		t.Fatal(err)
	}
	if err := f.tool.SetRelease(t.Context(), "v0.5.0"); err != nil {
		t.Fatal(err)
	}
	if err := f.tool.Check(t.Context()); err != nil {
		t.Fatal(err)
	}
	for path, previous := range f.base {
		if !strings.HasPrefix(path, "internal/migrations/") || strings.HasSuffix(path, "catalog.json") {
			continue
		}
		contents, err := os.ReadFile(filepath.Join(f.tool.Root, path))
		if err != nil || string(contents) != string(previous) {
			t.Fatal("immutable migration or fixture was rewritten", path, err)
		}
	}
	if err := f.tool.Seal(t.Context(), directory, true); err == nil {
		t.Fatal("stale draft was sealed twice")
	}
}

func TestSealRejectsIncompleteReplayBeforeSourceMutation(t *testing.T) {
	f := authorCheckout(t)
	directory, err := f.tool.CreateDraft(t.Context(), DraftOptions{Driver: "sqlite", Release: "v0.5.0", Sequence: 1, Manual: true})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(directory, "migration.sql"), []byte("-- goauth:statement\nSELECT 1;\n"), 0600); err != nil {
		t.Fatal(err)
	}
	f.diff = func(directory string) error {
		return os.WriteFile(filepath.Join(directory, "20261011000000_missing.sql"), []byte("missing SQL"), 0600)
	}
	if err := f.tool.Seal(t.Context(), directory, true); err == nil {
		t.Fatal("a replay requiring more structural work was published")
	}
	if _, err := os.Stat(filepath.Join(f.tool.Root, "internal/migrations/sqlite/000002_v0.5.0_001.sql")); !os.IsNotExist(err) {
		t.Fatal("failed verification wrote a migration")
	}
}

func TestCheckRejectsChangedMetadataAndOrphanedArtifacts(t *testing.T) {
	for _, mutation := range []string{"metadata", "orphan"} {
		t.Run(mutation, func(t *testing.T) {
			f := authorCheckout(t)
			directory := filepath.Join(f.tool.Root, "internal/migrations/sqlite")
			if mutation == "metadata" {
				var catalog migrations.Catalog
				if err := readJSON(filepath.Join(directory, "catalog.json"), &catalog); err != nil {
					t.Fatal(err)
				}
				catalog.Migrations[0].Checks = []string{"SELECT TRUE"}
				contents, err := jsonBytes(catalog)
				if err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(filepath.Join(directory, "catalog.json"), contents, 0600); err != nil {
					t.Fatal(err)
				}
			} else if err := os.WriteFile(filepath.Join(directory, "000002_v0.5.0_001.sql"), []byte("orphan"), 0600); err != nil {
				t.Fatal(err)
			}
			if err := f.tool.Check(t.Context()); err == nil {
				t.Fatal("modified immutable metadata or interrupted publication was accepted")
			}
		})
	}
}

func TestCanceledAuthoringDoesNotPublish(t *testing.T) {
	f := authorCheckout(t)
	f.tool.run = func(ctx context.Context, _ string, _ string, _ ...string) ([]byte, error) {
		return nil, ctx.Err()
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if _, err := f.tool.CreateDraft(ctx, DraftOptions{Driver: "sqlite", Release: "v0.5.0", Sequence: 1}); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancellation was lost: %v", err)
	}
}
