package commands

import (
	"fmt"

	"github.com/gleicon/sonnel/internal/scanner"
	"github.com/spf13/cobra"
)

var save bool

var reconCmd = &cobra.Command{
	Use:   "recon [domain]",
	Short: "Run the full reconnaissance pipeline on a domain",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		domain := args[0]
		err := scanner.RunFullReconPipeline(domain, save)
		if err != nil {
			return fmt.Errorf("recon pipeline failed: %v", err)
		}
		return nil
	},
}

func init() {
	reconCmd.Flags().BoolVarP(&save, "save", "s", false, "Save raw output files")
	rootCmd.AddCommand(reconCmd)
}
