package cmd

import (
	"fmt"

	goauth "github.com/nazimdjebloun/go-auth"
	"github.com/spf13/cobra"
)

func newGenerateCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "generate",
		Short: "Export the desired auth schema, FK reference and published migrations",
		Long: `Writes auth.schema.sql, reference.md and the immutable migration catalog
into an auth-only directory. Export does not inspect or modify a database.
Keep these artifacts separate from application/ORM schema management.`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			driver, err := cmd.Flags().GetString("driver")
			if err != nil {
				return err
			}
			directory, err := cmd.Flags().GetString("out")
			if err != nil {
				return err
			}
			if err := goauth.ExportSchema(driver, directory); err != nil {
				return err
			}
			_, err = fmt.Fprintf(cmd.OutOrStdout(), "goauth: exported auth schema and migrations to %s\n", directory)
			return err
		},
	}
	cmd.Flags().String("driver", "", "Database driver (postgres, sqlite, mysql)")
	cmd.Flags().StringP("out", "o", "goauth", "Auth artifact output directory")
	mustMarkFlagRequired(cmd, "driver")
	return cmd
}

func init() { rootCmd.AddCommand(newGenerateCommand()) }
