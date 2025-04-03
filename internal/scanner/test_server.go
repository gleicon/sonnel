package scanner

import (
	"encoding/base64"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
)

// TestServer represents a test server with known vulnerabilities
type TestServer struct {
	server *httptest.Server
}

// NewTestServer creates a new test server with known vulnerabilities
func NewTestServer() *TestServer {
	mux := http.NewServeMux()

	// A1: Broken Access Control
	mux.HandleFunc("/admin", func(w http.ResponseWriter, r *http.Request) {
		// No authentication check
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, "Admin panel accessed. User list: admin, user1, user2")
	})

	// A2: Cryptographic Failures
	mux.HandleFunc("/login", func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "POST" {
			username := r.FormValue("username")
			password := r.FormValue("password")
			// Plain text password in response
			w.Header().Set("Set-Cookie", fmt.Sprintf("auth=%s:%s", username, password))
			if username == "admin" && password == "admin" {
				w.WriteHeader(http.StatusOK)
				fmt.Fprint(w, "Login successful")
				return
			}
		}
		w.WriteHeader(http.StatusUnauthorized)
	})

	// A3: Injection
	mux.HandleFunc("/search", func(w http.ResponseWriter, r *http.Request) {
		query := r.URL.Query().Get("q")
		if strings.Contains(query, "'") {
			// Simulating SQL error disclosure
			w.WriteHeader(http.StatusInternalServerError)
			fmt.Fprintf(w, "Error executing query: ORA-01756: quoted string not properly terminated near '%s'", query)
			return
		}
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, "Search results")
	})

	mux.HandleFunc("/api/search", func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "POST" {
			query := r.FormValue("query")
			// Simulating NoSQL injection vulnerability
			if strings.Contains(query, "$") {
				w.WriteHeader(http.StatusOK)
				fmt.Fprintf(w, "Found users: admin, user1, user2")
				return
			}
		}
		w.WriteHeader(http.StatusBadRequest)
	})

	// A4: Insecure Design
	var requestCount int
	mux.HandleFunc("/api/user", func(w http.ResponseWriter, r *http.Request) {
		// No rate limiting
		requestCount++
		w.WriteHeader(http.StatusOK)
		fmt.Fprintf(w, "User data. Request count: %d", requestCount)
	})

	// A5: Security Misconfiguration
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		// Exposing sensitive headers and version information
		w.Header().Set("Server", "Apache/2.4.1 (Vulnerable)")
		w.Header().Set("X-Powered-By", "PHP/5.6.0")
		w.Header().Set("X-Debug-Mode", "true")
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, "Welcome to the vulnerable server")
	})

	// A6: Vulnerable Components
	mux.HandleFunc("/version", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Version", "1.0.0-beta")
		w.Header().Set("X-Framework", "Spring-2.5.6")
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, "Running on vulnerable components")
	})

	// A7: Authentication Failures
	mux.HandleFunc("/register", func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "POST" {
			password := r.FormValue("password")
			// Accept any password
			w.WriteHeader(http.StatusOK)
			fmt.Fprintf(w, "User registered with password: %s", password)
		}
	})

	// A8: Software and Data Integrity Failures
	mux.HandleFunc("/update", func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "POST" {
			data := r.FormValue("data")
			// Try to decode as base64 without validation
			if _, err := base64.StdEncoding.DecodeString(data); err == nil {
				w.WriteHeader(http.StatusOK)
				fmt.Fprint(w, "Update processed successfully")
				return
			}
			// Accept PHP serialized data
			if strings.Contains(data, "O:8:\"stdClass\"") {
				w.WriteHeader(http.StatusOK)
				fmt.Fprint(w, "PHP object processed successfully")
				return
			}
		}
		w.WriteHeader(http.StatusBadRequest)
	})

	// A9: Security Logging and Monitoring Failures
	mux.HandleFunc("/debug", func(w http.ResponseWriter, r *http.Request) {
		param := r.URL.Query().Get("param")
		if strings.Contains(param, "<script>") {
			// Expose stack trace
			w.WriteHeader(http.StatusInternalServerError)
			fmt.Fprintf(w, "Exception in thread \"main\" java.lang.RuntimeException\n"+
				"    at com.example.Debug.processParam(%s)\n"+
				"    at com.example.Debug.main(Debug.java:10)\n", param)
			return
		}
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, "Debug mode active")
	})

	// A10: SSRF
	mux.HandleFunc("/fetch", func(w http.ResponseWriter, r *http.Request) {
		url := r.FormValue("url")
		// No URL validation
		if strings.Contains(url, "localhost") || strings.Contains(url, "127.0.0.1") {
			w.WriteHeader(http.StatusOK)
			fmt.Fprintf(w, "Fetched internal resource: %s", url)
			return
		}
		w.WriteHeader(http.StatusBadRequest)
	})

	return &TestServer{
		server: httptest.NewServer(mux),
	}
}

// URL returns the test server's URL
func (ts *TestServer) URL() string {
	return ts.server.URL
}

// Close shuts down the test server
func (ts *TestServer) Close() {
	ts.server.Close()
}
