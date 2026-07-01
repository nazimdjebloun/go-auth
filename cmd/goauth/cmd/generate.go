package cmd

import (
	"fmt"
	"os"

	"github.com/nazimdjebloun/go-auth"
	"github.com/spf13/cobra"
)

var generateCmd = &cobra.Command{
	Use:   "generate",
	Short: "Generate auth.schema.sql for the given driver",
	Long: `Writes the canonical schema file (auth.schema.sql) for the specified
database driver to the current working directory.

Supported drivers: postgres, sqlite, mysql`,
	Args: cobra.NoArgs,
	Run: func(cmd *cobra.Command, args []string) {
		driver, _ := cmd.Flags().GetString("driver")
		outPath, _ := cmd.Flags().GetString("out")

		if driver == "" {
			fmt.Fprintf(os.Stderr, "goauth: --driver is required\n")
			os.Exit(1)
		}

		err := goauth.GenerateSchema(driver, outPath)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}

		fmt.Printf("goauth: generated %s\n", outPath)
	},
}

func init() {
	generateCmd.Flags().String("driver", "", "Database driver (postgres, sqlite, mysql)")
	generateCmd.Flags().StringP("out", "o", "auth.schema.sql", "Output file path")
	generateCmd.MarkFlagRequired("driver")
	rootCmd.AddCommand(generateCmd)
}
