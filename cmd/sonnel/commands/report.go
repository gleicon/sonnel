package commands

import (
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/gleicon/sonnel/internal/models"
	"github.com/gleicon/sonnel/internal/reporter"
	"github.com/gleicon/sonnel/internal/scanner"
	"github.com/spf13/cobra"
)

var reportCmd = &cobra.Command{
	Use:   "report [target-url]",
	Short: "Generate a security assessment report",
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

		// Scan for vulnerabilities
		vulns, err := s.Scan(targetURL)
		if err != nil {
			return fmt.Errorf("failed to scan target: %v", err)
		}

		// Generate report
		reportPath := filepath.Join(outputDir, "report.pdf")
		if err := generateReport(vulns, reportPath, evidenceDir); err != nil {
			return fmt.Errorf("failed to generate report: %v", err)
		}

		fmt.Printf("Report generated at %s\n", reportPath)
		return nil
	},
}

func init() {
	rootCmd.AddCommand(reportCmd)
}

func generateReport(vulnerabilities []models.Vulnerability, outputPath string, evidenceDir string) error {
	// Create scan result
	scanResult := &models.ScanResult{
		Target:          "http://example.com", // TODO: Get actual target from scan
		Timestamp:       time.Now().Format(time.RFC3339),
		Vulnerabilities: vulnerabilities,
		Summary:         make(map[models.OWASPCategory]int),
		SeverityCount:   make(map[models.SeverityLevel]int),
	}

	// Count vulnerabilities by category and severity
	for _, vuln := range vulnerabilities {
		scanResult.Summary[vuln.Category]++
		scanResult.SeverityCount[vuln.Severity]++
	}

	// Generate report
	report := reporter.GenerateReport(scanResult)

	// Write report to file
	if err := os.WriteFile(outputPath, []byte(report), 0644); err != nil {
		return fmt.Errorf("failed to write report: %v", err)
	}

	return nil
}
