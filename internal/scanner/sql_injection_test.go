package scanner

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gleicon/sonnel/internal/evidence"
)

func TestSQLInjectionDetector(t *testing.T) {
	// Create a test server that simulates different SQL injection scenarios
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Simulate SQL error response
		if r.URL.Query().Get("id") == "' OR '1'='1" {
			w.WriteHeader(http.StatusInternalServerError)
			w.Write([]byte("SQL Error: You have an error in your SQL syntax"))
			return
		}

		// Simulate successful response
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("OK"))
	}))
	defer ts.Close()

	// Create scanner and SQL injection detector
	scanner, err := NewScanner(ts.URL, "test_evidence")
	if err != nil {
		t.Fatalf("Failed to create scanner: %v", err)
	}

	sid, err := NewSQLInjectionDetector(scanner, false)
	if err != nil {
		t.Fatalf("Failed to create SQL injection detector: %v", err)
	}

	// Test GET parameters
	t.Run("Test GET Parameters", func(t *testing.T) {
		urlStr := ts.URL + "?id=1"
		results, err := sid.testGETParameters(urlStr)
		if err != nil {
			t.Fatalf("Failed to test GET parameters: %v", err)
		}

		// We expect to find at least one vulnerability
		if len(results) == 0 {
			t.Error("Expected to find SQL injection vulnerability in GET parameters")
		}

		// Verify the vulnerability details
		for _, result := range results {
			if result.Evidence == nil {
				t.Error("Expected evidence to be collected")
			}
		}
	})

	// Test POST parameters
	t.Run("Test POST Parameters", func(t *testing.T) {
		results, err := sid.testPOSTParameters(ts.URL)
		if err != nil {
			t.Fatalf("Failed to test POST parameters: %v", err)
		}

		// We expect to find at least one vulnerability
		if len(results) == 0 {
			t.Error("Expected to find SQL injection vulnerability in POST parameters")
		}

		// Verify the vulnerability details
		for _, result := range results {
			if result.Evidence == nil {
				t.Error("Expected evidence to be collected")
			}
		}
	})

	// Test form-encoded POST
	t.Run("Test Form-encoded POST", func(t *testing.T) {
		results, err := sid.testFormPOST(ts.URL)
		if err != nil {
			t.Fatalf("Failed to test form-encoded POST: %v", err)
		}

		// We expect to find at least one vulnerability
		if len(results) == 0 {
			t.Error("Expected to find SQL injection vulnerability in form-encoded POST")
		}

		// Verify the vulnerability details
		for _, result := range results {
			if result.Evidence == nil {
				t.Error("Expected evidence to be collected")
			}
		}
	})

	// Test JSON POST
	t.Run("Test JSON POST", func(t *testing.T) {
		results, err := sid.testJSONPOST(ts.URL)
		if err != nil {
			t.Fatalf("Failed to test JSON POST: %v", err)
		}

		// We expect to find at least one vulnerability
		if len(results) == 0 {
			t.Error("Expected to find SQL injection vulnerability in JSON POST")
		}

		// Verify the vulnerability details
		for _, result := range results {
			if result.Evidence == nil {
				t.Error("Expected evidence to be collected")
			}
		}
	})

	// Test timing-based detection
	t.Run("Test Timing-based Detection", func(t *testing.T) {
		// Create a test server that simulates timing-based SQL injection
		ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Simulate delay for SQL injection payload
			if r.URL.Query().Get("id") == "' OR SLEEP(5)--" {
				time.Sleep(5 * time.Second)
			}
			w.WriteHeader(http.StatusOK)
			w.Write([]byte("OK"))
		}))
		defer ts.Close()

		urlStr := ts.URL + "?id=1"
		results, err := sid.testGETParameters(urlStr)
		if err != nil {
			t.Fatalf("Failed to test timing-based detection: %v", err)
		}

		// Verify timing-based detection
		for _, result := range results {
			if result.Evidence == nil {
				t.Error("Expected evidence to be collected")
			}
		}
	})

	// Test vulnerability creation
	t.Run("Test Vulnerability Creation", func(t *testing.T) {
		result := SQLInjectionResult{
			Parameter:    "id",
			Payload:      "' OR '1'='1",
			Status:       http.StatusInternalServerError,
			ResponseTime: time.Second,
			Evidence:     &evidence.Evidence{},
			IsVulnerable: true,
			Indicators:   []string{"SQL Error"},
		}

		vuln := sid.createVulnerability(result)
		if vuln.Title != "SQL Injection Vulnerability" {
			t.Error("Expected correct vulnerability title")
		}
		if vuln.Severity != "High" {
			t.Error("Expected high severity")
		}
		if vuln.Category != "A3: Injection" {
			t.Error("Expected correct OWASP category")
		}
		if vuln.Evidence == nil {
			t.Error("Expected evidence to be included")
		}
	})

	// Test error handling
	t.Run("Test Error Handling", func(t *testing.T) {
		// Test with invalid URL
		_, err := sid.testGETParameters("")
		if err == nil {
			t.Error("Expected error with invalid URL")
		}

		// Test with empty parameters
		results, err := sid.testGETParameters(ts.URL)
		if err != nil {
			t.Fatalf("Unexpected error with empty parameters: %v", err)
		}
		if len(results) > 0 {
			t.Error("Expected no vulnerabilities with empty parameters")
		}
	})

	// Test false positive prevention
	t.Run("Test False Positive Prevention", func(t *testing.T) {
		// Create a test server that simulates common false positive scenarios
		ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Simulate normal error response (not SQL-related)
			if r.URL.Query().Get("id") == "' OR '1'='1" {
				w.WriteHeader(http.StatusBadRequest)
				w.Write([]byte("Invalid input format"))
				return
			}

			// Simulate generic error message
			if r.URL.Query().Get("id") == "1 OR 1=1" {
				w.WriteHeader(http.StatusInternalServerError)
				w.Write([]byte("An error occurred while processing your request"))
				return
			}

			// Simulate normal response with SQL-like content
			if r.URL.Query().Get("id") == "SELECT * FROM users" {
				w.WriteHeader(http.StatusOK)
				w.Write([]byte("Welcome to our SQL training page!"))
				return
			}

			// Simulate normal response
			w.WriteHeader(http.StatusOK)
			w.Write([]byte("OK"))
		}))
		defer ts.Close()

		// Create scanner and SQL injection detector
		scanner, err := NewScanner(ts.URL, "test_evidence")
		if err != nil {
			t.Fatalf("Failed to create scanner: %v", err)
		}

		sid, err := NewSQLInjectionDetector(scanner, false)
		if err != nil {
			t.Fatalf("Failed to create SQL injection detector: %v", err)
		}

		// Test with normal error response
		t.Run("Test Normal Error Response", func(t *testing.T) {
			urlStr := ts.URL + "?id=' OR '1'='1"
			results, err := sid.testGETParameters(urlStr)
			if err != nil {
				t.Fatalf("Failed to test GET parameters: %v", err)
			}

			// Should not detect SQL injection in normal error response
			for _, result := range results {
				if result.Evidence != nil {
					t.Error("False positive detected: Normal error response incorrectly identified as SQL injection")
				}
			}
		})

		// Test with generic error message
		t.Run("Test Generic Error Message", func(t *testing.T) {
			urlStr := ts.URL + "?id=1 OR 1=1"
			results, err := sid.testGETParameters(urlStr)
			if err != nil {
				t.Fatalf("Failed to test GET parameters: %v", err)
			}

			// Should not detect SQL injection in generic error message
			for _, result := range results {
				if result.Evidence != nil {
					t.Error("False positive detected: Generic error message incorrectly identified as SQL injection")
				}
			}
		})

		// Test with SQL-like content in normal response
		t.Run("Test SQL-like Content", func(t *testing.T) {
			urlStr := ts.URL + "?id=SELECT * FROM users"
			results, err := sid.testGETParameters(urlStr)
			if err != nil {
				t.Fatalf("Failed to test GET parameters: %v", err)
			}

			// Should not detect SQL injection in SQL-like content
			for _, result := range results {
				if result.Evidence != nil {
					t.Error("False positive detected: SQL-like content incorrectly identified as SQL injection")
				}
			}
		})

		// Test with normal response
		t.Run("Test Normal Response", func(t *testing.T) {
			urlStr := ts.URL + "?id=1"
			results, err := sid.testGETParameters(urlStr)
			if err != nil {
				t.Fatalf("Failed to test GET parameters: %v", err)
			}

			// Should not detect SQL injection in normal response
			for _, result := range results {
				if result.Evidence != nil {
					t.Error("False positive detected: Normal response incorrectly identified as SQL injection")
				}
			}
		})

		// Test with multiple indicators required
		t.Run("Test Multiple Indicators", func(t *testing.T) {
			// Create a test server that requires multiple indicators
			ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				// Simulate response with single indicator
				if r.URL.Query().Get("id") == "' OR '1'='1" {
					w.WriteHeader(http.StatusInternalServerError)
					w.Write([]byte("Error in your SQL syntax"))
					return
				}

				// Simulate response with multiple indicators
				if r.URL.Query().Get("id") == "' UNION SELECT * FROM users--" {
					w.WriteHeader(http.StatusInternalServerError)
					w.Write([]byte("Error in your SQL syntax near 'UNION' at line 1"))
					return
				}

				w.WriteHeader(http.StatusOK)
				w.Write([]byte("OK"))
			}))
			defer ts.Close()

			// Test with single indicator
			urlStr := ts.URL + "?id=' OR '1'='1"
			results, err := sid.testGETParameters(urlStr)
			if err != nil {
				t.Fatalf("Failed to test GET parameters: %v", err)
			}

			// Should not detect SQL injection with single indicator
			for _, result := range results {
				if result.Evidence != nil {
					t.Error("False positive detected: Single indicator incorrectly identified as SQL injection")
				}
			}

			// Test with multiple indicators
			urlStr = ts.URL + "?id=' UNION SELECT * FROM users--"
			results, err = sid.testGETParameters(urlStr)
			if err != nil {
				t.Fatalf("Failed to test GET parameters: %v", err)
			}

			// Should detect SQL injection with multiple indicators
			found := false
			for _, result := range results {
				if result.Evidence != nil {
					found = true
					break
				}
			}
			if !found {
				t.Error("Failed to detect SQL injection with multiple indicators")
			}
		})
	})
}
