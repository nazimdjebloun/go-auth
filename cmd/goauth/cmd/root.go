// Package cmd implements the goauth command-line interface.
package cmd

import (
	"os"

	"github.com/spf13/cobra"
)

var rootCmd = &cobra.Command{
	Use:   "goauth",
	Short: "Go-Auth CLI — schema generation and migration tooling",
}

// Execute runs the goauth command-line interface.
func Execute() {
	err := rootCmd.Execute()
	if err != nil {
		os.Exit(1)
	}
}

func mustMarkFlagRequired(cmd *cobra.Command, name string) {
	if err := cmd.MarkFlagRequired(name); err != nil {
		panic(err)
	}
}
