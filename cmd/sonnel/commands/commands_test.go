package commands

import (
	"os"
	"path/filepath"
	"testing"
)

func setupTestDirs(t *testing.T) (string, string) {
	baseDir := filepath.Join(os.TempDir(), "sonnel_test")
	evidenceDir := filepath.Join(baseDir, "evidence")
	reportDir := filepath.Join(baseDir, "reports")

	if err := os.MkdirAll(evidenceDir, 0755); err != nil {
		t.Fatalf("Failed to create test evidence directory: %v", err)
	}
	if err := os.MkdirAll(reportDir, 0755); err != nil {
		t.Fatalf("Failed to create test report directory: %v", err)
	}

	return evidenceDir, reportDir
}

func cleanupTestDirs(t *testing.T, baseDir string) {
	if err := os.RemoveAll(baseDir); err != nil {
		t.Logf("Warning: Failed to clean up test directories: %v", err)
	}
}

func TestScanCommand(t *testing.T) {
	evidenceDir, _ := setupTestDirs(t)
	defer cleanupTestDirs(t, filepath.Dir(evidenceDir))

	// Test with a non-existent target
	err := scanCmd.RunE(nil, []string{"http://nonexistent.example.com"})
	if err == nil {
		t.Error("Expected error for non-existent target")
	}

	// Test with invalid URL
	err = scanCmd.RunE(nil, []string{"not-a-url"})
	if err == nil {
		t.Error("Expected error for invalid URL")
	}
}

func TestReportCommand(t *testing.T) {
	_, reportDir := setupTestDirs(t)
	defer cleanupTestDirs(t, filepath.Dir(reportDir))

	// Test with non-existent target
	err := reportCmd.RunE(nil, []string{"http://nonexistent.example.com"})
	if err == nil {
		t.Error("Expected error for non-existent target")
	}

	// Test with invalid URL
	err = reportCmd.RunE(nil, []string{"not-a-url"})
	if err == nil {
		t.Error("Expected error for invalid URL")
	}
}

func TestCommandFlags(t *testing.T) {
	// Test scan command flags
	if !scanCmd.Flags().HasAvailableFlags() {
		t.Error("Expected scan command to have available flags")
	}

	verboseFlag := scanCmd.Flags().Lookup("verbose")
	if verboseFlag == nil {
		t.Error("Expected scan command to have verbose flag")
	}
	if verboseFlag.Value.Type() != "bool" {
		t.Errorf("Expected verbose flag to be bool, got %s", verboseFlag.Value.Type())
	}
}
