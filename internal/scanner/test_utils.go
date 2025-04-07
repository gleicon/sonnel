package scanner

import (
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

// setupTestEvidence creates a temporary directory for test evidence
func setupTestEvidence(t *testing.T) string {
	dir := filepath.Join(os.TempDir(), "sonnel_test_evidence")
	if err := os.MkdirAll(dir, 0755); err != nil {
		t.Fatalf("Failed to create test evidence directory: %v", err)
	}
	return dir
}

// cleanupTestEvidence removes the temporary directory after tests
func cleanupTestEvidence(t *testing.T, dir string) {
	if err := os.RemoveAll(dir); err != nil {
		t.Logf("Warning: Failed to clean up test evidence directory: %v", err)
	}
}

// checkToolAvailability checks if a tool is available and returns true if it is
func checkToolAvailability(t *testing.T, tool string) bool {
	_, err := exec.LookPath(tool)
	if err != nil {
		t.Logf("Skipping test: %s is not available", tool)
		return false
	}
	return true
}

// requireTool checks if a tool is available and skips the test if it's not
func requireTool(t *testing.T, tool string) {
	if !checkToolAvailability(t, tool) {
		t.Skipf("Skipping test: %s is not available", tool)
	}
}
