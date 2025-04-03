package scanner

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestScanner(t *testing.T) {
	// Create a test server that simulates vulnerabilities
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/search":
			w.Write([]byte("Error: MySQL syntax error"))
		case "/api/search":
			w.Write([]byte("Error: MongoDB query error"))
		case "/login":
			w.WriteHeader(http.StatusOK)
		case "/api/process":
			w.Write([]byte("root:x:0:0:root:/root:/bin/bash"))
		default:
			w.Write([]byte("Credit card: 4111-1111-1111-1111"))
		}
	}))
	defer ts.Close()

	// Create a scanner
	s, err := NewScanner(ts.URL, "test_evidence")
	if err != nil {
		t.Fatalf("Failed to create scanner: %v", err)
	}

	// Run the scan
	vulns, err := s.Scan(ts.URL)
	if err != nil {
		t.Fatalf("Failed to scan: %v", err)
	}

	// Verify results
	if len(vulns) == 0 {
		t.Error("Expected to find vulnerabilities but found none")
	}
}
