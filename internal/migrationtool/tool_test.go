package migrationtool

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/nazimdjebloun/go-auth/internal/migrations"
	"github.com/nazimdjebloun/go-auth/internal/schema"
)

type authorFixture struct {
	tool        Tool
	base        map[string][]byte
	atlasCalls  [][]string
	diff        func(string) error
	version     string
	tags        []string
	catalogTags map[string]int
	gitRefs     map[string]string
	gitFiles    map[string]map[string][]byte
}

func authorCheckout(t *testing.T) *authorFixture {
	return authorCheckoutCatalog(t, true)
}

// Existing synthetic publication cases describe the v0.4.0 -> v0.5.0 history.
// Keep them on their immutable baseline as new real catalog steps are published.
func authorCheckoutCatalog(t *testing.T, baselineOnly bool) *authorFixture {
	t.Helper()
	f := &authorFixture{base: map[string][]byte{}, version: "atlas version v1.3.0\n"}
	f.tool = Tool{Root: t.TempDir(), BaseRef: "published", run: f.command}
	write := func(relative string, contents []byte) {
		path := filepath.Join(f.tool.Root, relative)
		if err := os.MkdirAll(filepath.Dir(path), 0750); err != nil {
			t.Fatal(err)
		}
		// #nosec G703 -- Fixture paths are authored by these tests beneath their private temporary root.
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
		if baselineOnly {
			catalog.Migrations = catalog.Migrations[:1]
			catalog.TargetRevision = catalog.BootstrapRevision
			catalog.Release = "v0.4.0"
		}
		manifest, err := jsonBytes(catalog)
		if err != nil {
			t.Fatal(err)
		}
		write(filepath.Join("internal/migrations", dialect, "catalog.json"), manifest)
		for _, step := range catalog.Migrations {
			write(filepath.Join("internal/migrations", dialect, step.File), []byte(step.SQL))
			// #nosec G304 -- Both dialect and snapshot filename come from the validated embedded catalog.
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
		if baselineOnly {
			snapshot, err := os.ReadFile(filepath.Join("../migrations", dialect, catalog.Migrations[0].Schema))
			if err != nil {
				t.Fatal(err)
			}
			desired = string(snapshot)
		}
		write(filepath.Join("internal/schema", dialect+".sql"), []byte(strings.ReplaceAll(desired, "\r\n", "\n")))
	}
	return f
}

func TestDraftAppendsToCurrentPublishedCatalog(t *testing.T) {
	f := authorCheckoutCatalog(t, false)
	catalog, err := migrations.Load("postgres")
	if err != nil {
		t.Fatal(err)
	}
	last := catalog.Migrations[len(catalog.Migrations)-1]
	sequence := 1
	if strings.Contains(last.File, "_"+catalog.Release+"_") {
		parts := strings.Split(strings.TrimSuffix(last.File, ".sql"), "_")
		prior, err := strconv.Atoi(parts[len(parts)-1])
		if err != nil {
			t.Fatal(err)
		}
		sequence = prior + 1
	}
	f.diff = func(directory string) error {
		entries, err := os.ReadDir(directory)
		if err != nil {
			return err
		}
		if len(entries) != len(catalog.Migrations) {
			t.Fatal("Atlas did not receive every published migration")
		}
		for i, entry := range entries {
			if entry.Name() != catalog.Migrations[i].File {
				t.Fatal("published migration identity changed", entry.Name())
			}
		}
		return os.WriteFile(filepath.Join(directory, "20261024000000_review.sql"), []byte("-- goauth:statement\nUPDATE users SET name=name;\n"), 0600)
	}
	directory, err := f.tool.CreateDraft(t.Context(), DraftOptions{Driver: "postgres", Release: catalog.Release, Sequence: sequence})
	if err != nil {
		t.Fatal(err)
	}
	var draft Draft
	if err := readJSON(filepath.Join(directory, "draft.json"), &draft); err != nil {
		t.Fatal(err)
	}
	want := fmt.Sprintf("%06d_%s_%03d.sql", catalog.TargetRevision+1, catalog.Release, sequence)
	if draft.ID != catalog.TargetRevision+1 || draft.File != want || draft.BaseRevision != catalog.TargetRevision {
		t.Fatalf("incorrect next identity: %+v, want %s", draft, want)
	}
	if err := f.tool.Check(t.Context()); err != nil {
		t.Fatal("drafting changed the published catalog", err)
	}
}

func (f *authorFixture) command(_ context.Context, executable, _ string, args ...string) ([]byte, error) {
	if executable == "git" {
		if args[0] == "rev-parse" {
			if commit, ok := f.gitRefs[args[2]]; ok {
				return []byte(commit + "\n"), nil
			}
			return []byte(strings.Repeat("1", 40) + "\n"), nil
		}
		if args[0] == "tag" {
			return []byte(strings.Join(f.tags, "\n")), nil
		}
		if args[0] == "ls-tree" {
			tag := strings.TrimPrefix(strings.TrimSuffix(args[3], "^{commit}"), "refs/tags/")
			var paths []string
			for i, dialect := range []string{"postgres", "mysql", "sqlite"} {
				if i < f.catalogTags[tag] {
					paths = append(paths, "internal/migrations/"+dialect+"/catalog.json")
				}
			}
			return []byte(strings.Join(paths, "\n")), nil
		}
		commit, path, ok := strings.Cut(args[1], ":")
		source := f.base
		if files, exists := f.gitFiles[commit]; exists {
			source = files
		}
		if contents, exists := source[path]; ok && exists {
			return contents, nil
		}
		return nil, os.ErrNotExist
	}
	f.atlasCalls = append(f.atlasCalls, append([]string(nil), args...))
	if args[0] == "version" {
		return []byte(f.version), nil
	}
	if len(args) > 1 && args[0] == "schema" && args[1] == "inspect" {
		return []byte("table \"users\" {\n  index \"sqlite_autoindex_users_2\" {\n    unique = true\n    columns = [column.email]\n  }\n}\n"), nil
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

func TestPublicationChecksLegacyTagsReleaseMetadataAndAllDialectReplay(t *testing.T) {
	f := authorCheckout(t)
	f.tags = []string{"v0.3.0", "v0.4.0"}
	f.catalogTags = map[string]int{"v0.4.0": 3}
	f.version = "atlas community version v1.3.0\n"
	if err := f.tool.CheckPublication(t.Context(), CheckOptions{Published: true, Release: "v0.4.0", Replay: true}); err != nil {
		t.Fatal(err)
	}
	devs := map[string]bool{}
	for _, args := range f.atlasCalls {
		for i, arg := range args {
			if arg == "--dev-url" {
				devs[args[i+1]] = true
			}
		}
	}
	if len(devs) != 3 || !devs["docker://postgres/18.0/dev?search_path=public"] ||
		!devs["docker://mysql/8.4.0/dev"] || !devs["sqlite://dev?mode=memory"] {
		t.Fatal("publication did not replay all pinned dialects")
	}
	for path, expected := range f.base {
		// #nosec G304 -- Baseline paths are authored by this fixture inside its private temporary checkout.
		contents, err := os.ReadFile(filepath.Join(f.tool.Root, path))
		if err != nil || string(contents) != string(expected) {
			t.Fatal("publication check mutated source", path, err)
		}
	}
}

func TestPublicationRefusesPartialTagsAndMismatchedReleaseLabels(t *testing.T) {
	for _, test := range []struct {
		name    string
		tag     string
		count   int
		release string
	}{
		{"partial tag", "v0.4.0", 2, ""},
		{"published tag label", "v0.5.0", 3, ""},
		{"requested release label", "v0.4.0", 3, "v0.5.0"},
	} {
		t.Run(test.name, func(t *testing.T) {
			f := authorCheckout(t)
			f.tags = []string{test.tag}
			f.catalogTags = map[string]int{test.tag: test.count}
			if err := f.tool.CheckPublication(t.Context(), CheckOptions{Published: true, Release: test.release, Replay: true}); err == nil {
				t.Fatal("inconsistent publication was accepted")
			}
			if len(f.atlasCalls) != 0 {
				t.Fatal("inconsistent publication reached Atlas")
			}
		})
	}
}

func TestPublicationProtectsReleasedMetadataEvenWhenHEADWasRewritten(t *testing.T) {
	f := authorCheckout(t)
	f.tool.BaseRef = "HEAD"
	f.tags = []string{"v0.4.0"}
	f.catalogTags = map[string]int{"v0.4.0": 3}
	published := map[string][]byte{}
	for path, contents := range f.base {
		published[path] = append([]byte(nil), contents...)
	}
	path := "internal/migrations/sqlite/catalog.json"
	var catalog migrations.Catalog
	if err := json.Unmarshal(f.base[path], &catalog); err != nil {
		t.Fatal(err)
	}
	catalog.Migrations[0].Checks = []string{"SELECT FALSE"}
	changed, err := jsonBytes(catalog)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(f.tool.Root, path), changed, 0600); err != nil {
		t.Fatal(err)
	}
	f.base[path] = changed // HEAD now contains the edited metadata.
	commit := strings.Repeat("2", 40)
	f.gitRefs = map[string]string{"refs/tags/v0.4.0^{commit}": commit}
	f.gitFiles = map[string]map[string][]byte{commit: published}
	if err := f.tool.Check(t.Context()); err != nil {
		t.Fatal("fixture HEAD does not match its working tree", err)
	}
	err = f.tool.CheckPublication(t.Context(), CheckOptions{Published: true})
	if err == nil || !strings.Contains(err.Error(), "immutable metadata") {
		t.Fatal("released checks were overwritten through a rewritten HEAD", err)
	}
}

func TestPublicationRejectsRemainingAtlasDiff(t *testing.T) {
	f := authorCheckout(t)
	f.diff = func(directory string) error {
		return os.WriteFile(filepath.Join(directory, "20261011000000_remaining.sql"), []byte("missing DDL"), 0600)
	}
	if err := f.tool.CheckPublication(t.Context(), CheckOptions{Replay: true}); err == nil {
		t.Fatal("unmatched history replay passed publication checks")
	}
}

func TestSealRefusesInputsEditedDuringAtlasReplay(t *testing.T) {
	for _, mutation := range []string{"canonical", "sql", "metadata", "history"} {
		t.Run(mutation, func(t *testing.T) {
			f := authorCheckout(t)
			directory, err := f.tool.CreateDraft(t.Context(), DraftOptions{Driver: "sqlite", Release: "v0.5.0", Sequence: 1, Manual: true})
			if err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(directory, "migration.sql"), []byte("-- goauth:statement\nSELECT 1;\n"), 0600); err != nil {
				t.Fatal(err)
			}
			var editedPath string
			var edited []byte
			f.diff = func(string) error {
				switch mutation {
				case "canonical":
					editedPath = filepath.Join(f.tool.Root, "internal/schema/sqlite.sql")
					edited = append(append([]byte(nil), f.base["internal/schema/sqlite.sql"]...), []byte("\n-- Edited during replay.\n")...)
				case "sql":
					editedPath, edited = filepath.Join(directory, "migration.sql"), []byte("-- goauth:statement\nSELECT 2;\n")
				case "metadata":
					editedPath = filepath.Join(directory, "draft.json")
					var draft Draft
					if err := readJSON(editedPath, &draft); err != nil {
						return err
					}
					draft.Checks = []string{"SELECT FALSE"}
					edited, err = jsonBytes(draft)
				case "history":
					editedPath = filepath.Join(f.tool.Root, "internal/migrations/sqlite/catalog.json")
					var catalog migrations.Catalog
					if err := readJSON(editedPath, &catalog); err != nil {
						return err
					}
					catalog.Release = "v0.5.0"
					edited, err = jsonBytes(catalog)
				}
				if err != nil {
					return err
				}
				return os.WriteFile(editedPath, edited, 0600)
			}
			if err := f.tool.Seal(t.Context(), directory, true); err == nil {
				t.Fatal("stale reviewed inputs were published")
			}
			// #nosec G304 -- Inspect the exact temporary fixture file deliberately edited by this test.
			if contents, err := os.ReadFile(editedPath); err != nil || string(contents) != string(edited) {
				t.Fatal("editing during replay was overwritten", err)
			}
			if _, err := os.Stat(filepath.Join(f.tool.Root, "internal/migrations/sqlite/000002_v0.5.0_001.sql")); !os.IsNotExist(err) {
				t.Fatal("stale replay published a migration")
			}
		})
	}
}

func TestSealHonorsCancellationAfterAtlasReplay(t *testing.T) {
	f := authorCheckout(t)
	directory, err := f.tool.CreateDraft(t.Context(), DraftOptions{Driver: "sqlite", Release: "v0.5.0", Sequence: 1, Manual: true})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(directory, "migration.sql"), []byte("-- goauth:statement\nSELECT 1;\n"), 0600); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	f.diff = func(string) error { cancel(); return nil }
	if err := f.tool.Seal(ctx, directory, true); !errors.Is(err, context.Canceled) {
		t.Fatal("late cancellation was ignored", err)
	}
	if _, err := os.Stat(filepath.Join(f.tool.Root, "internal/migrations/sqlite/000002_v0.5.0_001.sql")); !os.IsNotExist(err) {
		t.Fatal("canceled sealing published a migration")
	}
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

func TestPinnedAtlasAcceptsOfficialAndCommunityVersionOutput(t *testing.T) {
	for _, test := range []struct {
		output string
		valid  bool
	}{
		{"atlas version v1.3.0\nhttps://github.com/ariga/atlas/releases/tag/v1.3.0\n", true},
		{"atlas community version v1.3.0\nhttps://github.com/ariga/atlas/releases/tag/v1.3.0\n", true},
		{"atlas version v1.3.0-community\n", true},
		{"atlas community version v1.2.0\n", false},
		{"atlas version v1.3.01\n", false},
		{"another-tool version v1.3.0\n", false},
	} {
		t.Run(strings.Split(test.output, "\n")[0], func(t *testing.T) {
			tool := Tool{run: func(context.Context, string, string, ...string) ([]byte, error) {
				return []byte(test.output), nil
			}}
			_, err := tool.pinnedAtlas(t.Context())
			if (err == nil) != test.valid {
				t.Fatalf("version acceptance=%t, want %t: %v", err == nil, test.valid, err)
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
		// #nosec G304 -- Only validated immutable artifacts from the temporary fixture checkout are read.
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

func TestSealPreservesReviewedPreconditionsAndRetryPolicy(t *testing.T) {
	f := authorCheckout(t)
	directory, err := f.tool.CreateDraft(t.Context(), DraftOptions{Driver: "postgres", Release: "v0.5.0", Sequence: 1, Manual: true})
	if err != nil {
		t.Fatal(err)
	}
	var draft Draft
	if err := readJSON(filepath.Join(directory, "draft.json"), &draft); err != nil {
		t.Fatal(err)
	}
	draft.Transactional = false
	draft.Preconditions = []string{"SELECT TRUE"}
	draft.Retry = &migrations.RetryPolicy{Checks: []string{"SELECT TRUE"}, Instructions: "Inspect and verify the unchanged starting data before replay."}
	metadata, err := jsonBytes(draft)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(directory, "draft.json"), metadata, 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(directory, "migration.sql"), []byte("-- goauth:statement\nUPDATE users SET name=name;\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := f.tool.Seal(t.Context(), directory, true); err != nil {
		t.Fatal(err)
	}
	catalog, err := migrations.ReadCatalog(os.DirFS(filepath.Join(f.tool.Root, "internal/migrations")), "postgres")
	if err != nil {
		t.Fatal(err)
	}
	step := catalog.Migrations[1]
	if len(step.Preconditions) != 1 || step.Preconditions[0] != "SELECT TRUE" || step.Retry == nil ||
		len(step.Retry.Checks) != 1 || step.Retry.Instructions != draft.Retry.Instructions {
		t.Fatal("sealing dropped reviewed execution conditions")
	}
}
