package commands

import (
	"github.com/spf13/cobra"
)

var rootCmd = &cobra.Command{
	Use:   "sonnel",
	Short: "Sonnel - Web Application Security Assessment Tool",
	Long: `Sonnel is a comprehensive web application security assessment tool
that helps identify OWASP Top 10 vulnerabilities and other common security issues.`,
}

func Execute() error {
	return rootCmd.Execute()
}

func init() {
	rootCmd.AddCommand(scanCmd)
	rootCmd.AddCommand(reportCmd)
}
