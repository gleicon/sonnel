package commands

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/gleicon/sonnel/internal/scanner"
	"github.com/spf13/cobra"
)

var verbose bool

var scanCmd = &cobra.Command{
	Use:   "scan [target-url]",
	Short: "Scan a web application for OWASP Top 10 vulnerabilities",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		targetURL := args[0]
		outputDir := "sonnel_output"
		evidenceDir := filepath.Join(outputDir, "evidence")

		// Create output directories
		if err := os.MkdirAll(evidenceDir, 0755); err != nil {
			return fmt.Errorf("failed to create output directory: %v", err)
		}

		// Initialize scanner
		s, err := scanner.NewScanner(targetURL, evidenceDir)
		if err != nil {
			return fmt.Errorf("failed to create scanner: %v", err)
		}

		// Set verbose mode
		s.SetVerbose(verbose)

		// Run scan
		vulns, err := s.Scan(targetURL)
		if err != nil {
			return fmt.Errorf("scan failed: %v", err)
		}

		// Print final summary
		fmt.Println("\n=== Scan Summary ===")
		fmt.Printf("Total Vulnerabilities Found: %d\n", len(vulns))
		fmt.Printf("Evidence files saved to %s\n", evidenceDir)
		return nil
	},
}

func init() {
	scanCmd.Flags().BoolVarP(&verbose, "verbose", "v", false, "Enable verbose output")
	rootCmd.AddCommand(scanCmd)
}
