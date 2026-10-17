// Command migrationtool drafts and seals auth migrations in a maintainer checkout.
package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/nazimdjebloun/go-auth/internal/migrationtool"
	"github.com/spf13/cobra"
)

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if err := newCommand().ExecuteContext(ctx); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func newCommand() *cobra.Command {
	var tool migrationtool.Tool
	var timeout time.Duration
	var diagnostics bool
	root := &cobra.Command{
		Use: "migrationtool", Short: "Maintainer-only auth migration authoring",
		SilenceUsage: true, SilenceErrors: true,
	}
	root.PersistentFlags().StringVar(&tool.Root, "root", ".", "go-auth checkout root")
	root.PersistentFlags().StringVar(&tool.AtlasPath, "atlas", "atlas", "Path to the pinned Atlas executable")
	root.PersistentFlags().StringVar(&tool.BaseRef, "base-ref", "HEAD", "Git ref containing immutable migration history")
	root.PersistentFlags().DurationVar(&timeout, "timeout", 20*time.Minute, "Overall command timeout")
	root.PersistentFlags().BoolVar(&diagnostics, "diagnostics", false, "Show raw failed Atlas output on stderr (trusted maintainer terminals only)")
	run := func(action func(context.Context, *cobra.Command) error) func(*cobra.Command, []string) error {
		return func(cmd *cobra.Command, _ []string) error {
			if timeout <= 0 {
				return fmt.Errorf("migrationtool: --timeout must be positive")
			}
			ctx, cancel := context.WithTimeout(cmd.Context(), timeout)
			defer cancel()
			tool.Diagnostics = nil
			if diagnostics {
				tool.Diagnostics = cmd.ErrOrStderr()
			}
			return action(ctx, cmd)
		}
	}
	var options migrationtool.DraftOptions
	draft := &cobra.Command{
		Use: "draft", Short: "Draft a numbered migration using disposable Atlas databases", Args: cobra.NoArgs,
		RunE: run(func(ctx context.Context, cmd *cobra.Command) error {
			directory, err := tool.CreateDraft(ctx, options)
			if err != nil {
				return err
			}
			_, err = fmt.Fprintln(cmd.OutOrStdout(), directory)
			return err
		}),
	}
	draft.Flags().StringVar(&options.Driver, "driver", "", "postgres, mysql, or sqlite")
	draft.Flags().StringVar(&options.Release, "release", "", "Target library release, e.g. v0.5.0")
	draft.Flags().IntVar(&options.Sequence, "step", 1, "Next step within the release, 1..999")
	draft.Flags().StringVar(&options.Directory, "out", "", "New review directory (default .migration-drafts/<driver>)")
	draft.Flags().BoolVar(&options.Manual, "manual", false, "Prepare a skeleton for a reviewed backfill or rename")
	_ = draft.MarkFlagRequired("driver")
	_ = draft.MarkFlagRequired("release")
	var directory string
	var reviewed bool
	seal := &cobra.Command{
		Use: "seal", Short: "Validate and append a reviewed draft to the source catalog", Args: cobra.NoArgs,
		RunE: run(func(ctx context.Context, cmd *cobra.Command) error {
			if err := tool.Seal(ctx, directory, reviewed); err != nil {
				return err
			}
			_, err := fmt.Fprintln(cmd.OutOrStdout(), "Reviewed migration appended; add populated upgrade tests before release.")
			return err
		}),
	}
	seal.Flags().StringVar(&directory, "draft", "", "Directory containing reviewed draft.json, migration.sql and schema.sql")
	seal.Flags().BoolVar(&reviewed, "reviewed", false, "Confirm SQL, backfills, checks, execution mode and recovery were reviewed")
	_ = seal.MarkFlagRequired("draft")
	var checks migrationtool.CheckOptions
	check := &cobra.Command{
		Use: "check", Short: "Check canonical targets, immutable history and optional release replay", Args: cobra.NoArgs,
		RunE: run(func(ctx context.Context, cmd *cobra.Command) error {
			if err := tool.CheckPublication(ctx, checks); err != nil {
				return err
			}
			_, err := fmt.Fprintln(cmd.OutOrStdout(), "Migration catalog checks passed.")
			return err
		}),
	}
	check.Flags().BoolVar(&checks.Published, "published", false, "Verify the immutable prefix of every fetched migration-enabled release tag")
	check.Flags().StringVar(&checks.Release, "release", "", "Require all dialect catalogs to declare this library release")
	check.Flags().BoolVar(&checks.Replay, "replay", false, "Replay all dialect histories with pinned Atlas and disposable databases")
	var release string
	metadata := &cobra.Command{
		Use: "release", Short: "Set library release metadata without creating empty migrations", Args: cobra.NoArgs,
		RunE: run(func(ctx context.Context, cmd *cobra.Command) error {
			if err := tool.SetRelease(ctx, release); err != nil {
				return err
			}
			_, err := fmt.Fprintln(cmd.OutOrStdout(), "Release metadata updated; schema revisions preserved.")
			return err
		}),
	}
	metadata.Flags().StringVar(&release, "release", "", "Target library release, e.g. v0.5.0")
	_ = metadata.MarkFlagRequired("release")
	root.AddCommand(draft, seal, check, metadata)
	return root
}
