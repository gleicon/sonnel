package main

import (
	"os"
	"path/filepath"
	"testing"
)

func setupTestDirs(t *testing.T) string {
	baseDir := filepath.Join(os.TempDir(), "sonnel_test")
	if err := os.MkdirAll(baseDir, 0755); err != nil {
		t.Fatalf("Failed to create test directory: %v", err)
	}
	return baseDir
}

func cleanupTestDirs(t *testing.T, dir string) {
	if err := os.RemoveAll(dir); err != nil {
		t.Logf("Warning: Failed to clean up test directory: %v", err)
	}
}

func TestMainFunction(t *testing.T) {
	// Save original args and restore them after the test
	originalArgs := os.Args
	defer func() { os.Args = originalArgs }()

	// Test with no arguments
	os.Args = []string{"sonnel"}
	main()

	// Test with help flag
	os.Args = []string{"sonnel", "--help"}
	main()

	// Test with scan command
	os.Args = []string{"sonnel", "scan", "http://example.com"}
	main()

	// Test with report command
	os.Args = []string{"sonnel", "report", "http://example.com"}
	main()
}

func TestCommandExecution(t *testing.T) {
	testDir := setupTestDirs(t)
	defer cleanupTestDirs(t, testDir)

	// Test scan command execution
	os.Args = []string{"sonnel", "scan", "http://example.com"}
	main()

	// Test report command execution
	os.Args = []string{"sonnel", "report", "http://example.com"}
	main()
}

func TestInvalidCommand(t *testing.T) {
	// Save original args and restore them after the test
	originalArgs := os.Args
	defer func() { os.Args = originalArgs }()

	// Test with invalid command
	os.Args = []string{"sonnel", "invalid-command"}
	main()
}
