package scanner

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestCheckInjection(t *testing.T) {
	// Create a test server that simulates SQL injection vulnerability
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/search" {
			w.Write([]byte("Error: MySQL syntax error"))
		} else if r.URL.Path == "/api/search" {
			w.Write([]byte("Error: MongoDB query error"))
		}
	}))
	defer ts.Close()

	// Create a scanner
	s, err := NewScanner(ts.URL, "test_evidence")
	if err != nil {
		t.Fatalf("Failed to create scanner: %v", err)
	}

	// Run the check
	vulns, err := CheckInjection(s, ts.URL)
	if err != nil {
		t.Fatalf("Failed to check injection: %v", err)
	}

	// Verify results
	if len(vulns) == 0 {
		t.Error("Expected to find injection vulnerabilities but found none")
	}
}

func TestCheckBrokenAuth(t *testing.T) {
	// Create a test server that simulates weak password policy
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/login" {
			w.WriteHeader(http.StatusOK)
		}
	}))
	defer ts.Close()

	// Create a scanner
	s, err := NewScanner(ts.URL, "test_evidence")
	if err != nil {
		t.Fatalf("Failed to create scanner: %v", err)
	}

	// Run the check
	vulns, err := CheckBrokenAuth(s, ts.URL)
	if err != nil {
		t.Fatalf("Failed to check broken auth: %v", err)
	}

	// Verify results
	if len(vulns) == 0 {
		t.Error("Expected to find authentication vulnerabilities but found none")
	}
}

func TestCheckSensitiveDataExposure(t *testing.T) {
	// Create a test server that simulates sensitive data exposure
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("Credit card: 4111-1111-1111-1111"))
	}))
	defer ts.Close()

	// Create a scanner
	s, err := NewScanner(ts.URL, "test_evidence")
	if err != nil {
		t.Fatalf("Failed to create scanner: %v", err)
	}

	// Run the check
	vulns, err := CheckSensitiveDataExposure(s, ts.URL)
	if err != nil {
		t.Fatalf("Failed to check sensitive data exposure: %v", err)
	}

	// Verify results
	if len(vulns) == 0 {
		t.Error("Expected to find sensitive data exposure but found none")
	}
}

func TestCheckXXE(t *testing.T) {
	// Create a test server that simulates XXE vulnerability
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/process" {
			w.Write([]byte("root:x:0:0:root:/root:/bin/bash"))
		}
	}))
	defer ts.Close()

	// Create a scanner
	s, err := NewScanner(ts.URL, "test_evidence")
	if err != nil {
		t.Fatalf("Failed to create scanner: %v", err)
	}

	// Run the check
	vulns, err := CheckXXE(s, ts.URL)
	if err != nil {
		t.Fatalf("Failed to check XXE: %v", err)
	}

	// Verify results
	if len(vulns) == 0 {
		t.Error("Expected to find XXE vulnerability but found none")
	}
}
