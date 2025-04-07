package evidence

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func setupTestEvidence(t *testing.T) string {
	dir := filepath.Join(os.TempDir(), "sonnel_test_evidence")
	if err := os.MkdirAll(dir, 0755); err != nil {
		t.Fatalf("Failed to create test evidence directory: %v", err)
	}
	return dir
}

func cleanupTestEvidence(t *testing.T, dir string) {
	if err := os.RemoveAll(dir); err != nil {
		t.Logf("Warning: Failed to clean up test evidence directory: %v", err)
	}
}

func TestNewEvidenceCollector(t *testing.T) {
	evidenceDir := setupTestEvidence(t)
	defer cleanupTestEvidence(t, evidenceDir)

	collector, err := NewEvidenceCollector(evidenceDir)
	if err != nil {
		t.Fatalf("Failed to create evidence collector: %v", err)
	}

	if collector == nil {
		t.Error("Expected collector to be non-nil")
	}
}

func TestCollectEvidence(t *testing.T) {
	evidenceDir := setupTestEvidence(t)
	defer cleanupTestEvidence(t, evidenceDir)

	// Create a test server
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("Hello, World!"))
	}))
	defer ts.Close()

	// Create evidence collector
	collector, err := NewEvidenceCollector(evidenceDir)
	if err != nil {
		t.Fatalf("Failed to create evidence collector: %v", err)
	}

	// Create test request
	req, err := http.NewRequest("GET", ts.URL, nil)
	if err != nil {
		t.Fatalf("Failed to create request: %v", err)
	}

	// Make request
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("Failed to make request: %v", err)
	}
	defer resp.Body.Close()

	// Collect evidence
	evidence, err := collector.CollectEvidence(ts.URL, req, resp)
	if err != nil {
		t.Fatalf("Failed to collect evidence: %v", err)
	}

	// Verify evidence
	if evidence == nil {
		t.Error("Expected evidence to be non-nil")
	}
	if evidence.URL != ts.URL {
		t.Errorf("Expected URL %s, got %s", ts.URL, evidence.URL)
	}
	if evidence.CurlCommand == "" {
		t.Error("Expected curl command to be non-empty")
	}
}

func TestGenerateCurlCommand(t *testing.T) {
	evidenceDir := setupTestEvidence(t)
	defer cleanupTestEvidence(t, evidenceDir)

	collector, err := NewEvidenceCollector(evidenceDir)
	if err != nil {
		t.Fatalf("Failed to create evidence collector: %v", err)
	}

	// Create test request with headers
	req, err := http.NewRequest("GET", "http://example.com", nil)
	if err != nil {
		t.Fatalf("Failed to create request: %v", err)
	}
	req.Header.Add("User-Agent", "test-agent")
	req.Header.Add("Accept", "application/json")

	curlCmd := collector.generateCurlCommand(req)
	if curlCmd == "" {
		t.Error("Expected curl command to be non-empty")
	}
	if !strings.Contains(curlCmd, "User-Agent: test-agent") {
		t.Error("Expected curl command to contain User-Agent header")
	}
	if !strings.Contains(curlCmd, "Accept: application/json") {
		t.Error("Expected curl command to contain Accept header")
	}
}
