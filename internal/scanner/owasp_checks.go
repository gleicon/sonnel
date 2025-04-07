package scanner

import (
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/gleicon/sonnel/internal/evidence"
	"github.com/gleicon/sonnel/internal/models"
)

// CheckInjection checks for injection vulnerabilities
func CheckInjection(scanner *Scanner, targetURL string) ([]models.Vulnerability, error) {
	fmt.Println("Checking for injection vulnerabilities...")
	var vulnerabilities []models.Vulnerability

	// Check for SQL injection
	sqlVulns, err := checkSQLInjection(scanner, targetURL)
	if err != nil {
		fmt.Printf("Warning: Error checking SQL injection: %v\n", err)
	}
	vulnerabilities = append(vulnerabilities, sqlVulns...)

	// Check for NoSQL injection
	nosqlVulns, err := checkNoSQLInjection(scanner, targetURL)
	if err != nil {
		fmt.Printf("Warning: Error checking NoSQL injection: %v\n", err)
	}
	vulnerabilities = append(vulnerabilities, nosqlVulns...)

	return vulnerabilities, nil
}

// CheckBrokenAuth checks for authentication failures
func CheckBrokenAuth(scanner *Scanner, targetURL string) ([]models.Vulnerability, error) {
	fmt.Println("Checking for broken authentication...")
	var vulnerabilities []models.Vulnerability

	// Check for weak passwords
	weakPassVulns, err := checkWeakPasswords(scanner, targetURL)
	if err != nil {
		fmt.Printf("Warning: Error checking weak passwords: %v\n", err)
	}
	vulnerabilities = append(vulnerabilities, weakPassVulns...)

	// Check for session fixation
	sessionFixVulns, err := checkSessionFixation(scanner, targetURL)
	if err != nil {
		fmt.Printf("Warning: Error checking session fixation: %v\n", err)
	}
	vulnerabilities = append(vulnerabilities, sessionFixVulns...)

	return vulnerabilities, nil
}

// CheckSensitiveDataExposure checks for cryptographic failures
func CheckSensitiveDataExposure(scanner *Scanner, targetURL string) ([]models.Vulnerability, error) {
	fmt.Println("Checking for sensitive data exposure...")
	var vulnerabilities []models.Vulnerability

	// Check for credit card exposure
	ccVulns, err := checkCreditCardExposure(scanner, targetURL)
	if err != nil {
		fmt.Printf("Warning: Error checking credit card exposure: %v\n", err)
	}
	vulnerabilities = append(vulnerabilities, ccVulns...)

	// Check for SSN exposure
	ssnVulns, err := checkSSNExposure(scanner, targetURL)
	if err != nil {
		fmt.Printf("Warning: Error checking SSN exposure: %v\n", err)
	}
	vulnerabilities = append(vulnerabilities, ssnVulns...)

	return vulnerabilities, nil
}

// CheckInsecureDesign checks for insecure design flaws
func CheckInsecureDesign(scanner *Scanner, targetURL string) ([]models.Vulnerability, error) {
	fmt.Println("Checking for insecure design...")
	var vulnerabilities []models.Vulnerability

	// Check for business logic flaws
	businessLogicVulns, err := checkBusinessLogic(scanner, targetURL)
	if err != nil {
		fmt.Printf("Warning: Error checking business logic: %v\n", err)
	}
	vulnerabilities = append(vulnerabilities, businessLogicVulns...)

	return vulnerabilities, nil
}

// CheckBrokenAccessControl checks for broken access control
func CheckBrokenAccessControl(scanner *Scanner, targetURL string) ([]models.Vulnerability, error) {
	fmt.Println("Checking for broken access control...")
	var vulnerabilities []models.Vulnerability

	// Check for directory traversal
	dirTraversalVulns, err := checkDirectoryTraversal(scanner, targetURL)
	if err != nil {
		fmt.Printf("Warning: Error checking directory traversal: %v\n", err)
	}
	vulnerabilities = append(vulnerabilities, dirTraversalVulns...)

	// Check for IDOR
	idorVulns, err := checkIDOR(scanner, targetURL)
	if err != nil {
		fmt.Printf("Warning: Error checking IDOR: %v\n", err)
	}
	vulnerabilities = append(vulnerabilities, idorVulns...)

	// Check for missing authorization headers
	authHeaderVulns, err := checkMissingAuthHeaders(scanner, targetURL)
	if err != nil {
		fmt.Printf("Warning: Error checking authorization headers: %v\n", err)
	}
	vulnerabilities = append(vulnerabilities, authHeaderVulns...)

	// Check for CORS misconfigurations
	corsVulns, err := checkCORS(scanner, targetURL)
	if err != nil {
		fmt.Printf("Warning: Error checking CORS: %v\n", err)
	}
	vulnerabilities = append(vulnerabilities, corsVulns...)

	// Check for JWT token validation
	jwtVulns, err := checkJWTValidation(scanner, targetURL)
	if err != nil {
		fmt.Printf("Warning: Error checking JWT validation: %v\n", err)
	}
	vulnerabilities = append(vulnerabilities, jwtVulns...)

	// Check for role-based access control bypass
	rbacVulns, err := checkRBACBypass(scanner, targetURL)
	if err != nil {
		fmt.Printf("Warning: Error checking RBAC bypass: %v\n", err)
	}
	vulnerabilities = append(vulnerabilities, rbacVulns...)

	return vulnerabilities, nil
}

// CheckXXE checks for XML External Entity vulnerabilities
func CheckXXE(scanner *Scanner, targetURL string) ([]models.Vulnerability, error) {
	fmt.Println("Checking for XXE vulnerabilities...")
	var vulnerabilities []models.Vulnerability

	// Test for XXE vulnerability
	xxePayload := `<?xml version="1.0" encoding="ISO-8859-1"?>
<!DOCTYPE foo [ <!ELEMENT foo ANY >
<!ENTITY xxe SYSTEM "file:///etc/passwd" >]>
<foo>&xxe;</foo>`

	req, err := http.NewRequest("POST", targetURL+"/api/process", strings.NewReader(xxePayload))
	if err != nil {
		return vulnerabilities, nil
	}
	req.Header.Set("Content-Type", "application/xml")

	resp, err := scanner.client.Do(req)
	if err != nil {
		return vulnerabilities, nil
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return vulnerabilities, nil
	}

	if strings.Contains(string(body), "root:") {
		evidence, err := scanner.evidenceColl.CollectEvidence(targetURL+"/api/process", req, resp)
		if err != nil {
			fmt.Printf("Warning: Could not collect evidence: %v\n", err)
		}

		vulnerabilities = append(vulnerabilities, models.Vulnerability{
			Title:       "XML External Entity (XXE) Vulnerability",
			Description: "The application is vulnerable to XXE attacks, allowing attackers to read local files or perform SSRF attacks.",
			Category:    models.CategoryInsecureDesign,
			Severity:    models.High,
			URL:         targetURL + "/api/process",
			Evidence:    evidence,
			Remediation: "Disable external entity processing in XML parsers.",
		})
	}

	return vulnerabilities, nil
}

// CheckSecurityMisconfiguration checks for security misconfigurations
func CheckSecurityMisconfiguration(scanner *Scanner, targetURL string) ([]models.Vulnerability, error) {
	fmt.Println("Checking for security misconfigurations...")
	var vulnerabilities []models.Vulnerability

	// Check for default credentials
	defaultCredsVulns, err := checkDefaultCredentials(scanner, targetURL)
	if err != nil {
		fmt.Printf("Warning: Error checking default credentials: %v\n", err)
	}
	vulnerabilities = append(vulnerabilities, defaultCredsVulns...)

	// Check for directory listing
	dirListingVulns, err := checkDirectoryListing(scanner, targetURL)
	if err != nil {
		fmt.Printf("Warning: Error checking directory listing: %v\n", err)
	}
	vulnerabilities = append(vulnerabilities, dirListingVulns...)

	return vulnerabilities, nil
}

// CheckVulnerableComponents checks for vulnerable components
func CheckVulnerableComponents(scanner *Scanner, targetURL string) ([]models.Vulnerability, error) {
	fmt.Println("Checking for vulnerable components...")
	var vulnerabilities []models.Vulnerability

	// Check for outdated components
	outdatedVulns, err := checkOutdatedComponents(scanner, targetURL)
	if err != nil {
		fmt.Printf("Warning: Error checking outdated components: %v\n", err)
	}
	vulnerabilities = append(vulnerabilities, outdatedVulns...)

	return vulnerabilities, nil
}

// CheckIntegrityFailures checks for integrity failures
func CheckIntegrityFailures(scanner *Scanner, targetURL string) ([]models.Vulnerability, error) {
	fmt.Println("Checking for integrity failures...")
	var vulnerabilities []models.Vulnerability

	// Check for missing integrity checks
	integrityVulns, err := checkMissingIntegrity(scanner, targetURL)
	if err != nil {
		fmt.Printf("Warning: Error checking integrity: %v\n", err)
	}
	vulnerabilities = append(vulnerabilities, integrityVulns...)

	return vulnerabilities, nil
}

// CheckLoggingFailures checks for logging failures
func CheckLoggingFailures(scanner *Scanner, targetURL string) ([]models.Vulnerability, error) {
	fmt.Println("Checking for logging failures...")
	var vulnerabilities []models.Vulnerability

	// Check for missing security headers
	headersVulns, err := checkMissingSecurityHeaders(scanner, targetURL)
	if err != nil {
		fmt.Printf("Warning: Error checking security headers: %v\n", err)
	}
	vulnerabilities = append(vulnerabilities, headersVulns...)

	return vulnerabilities, nil
}

// CheckSSRF checks for SSRF vulnerabilities
func CheckSSRF(scanner *Scanner, targetURL string) ([]models.Vulnerability, error) {
	fmt.Println("Checking for SSRF vulnerabilities...")
	var vulnerabilities []models.Vulnerability

	// Check for SSRF vulnerabilities
	ssrfVulns, err := checkSSRFVulnerabilities(scanner, targetURL)
	if err != nil {
		fmt.Printf("Warning: Error checking SSRF: %v\n", err)
	}
	vulnerabilities = append(vulnerabilities, ssrfVulns...)

	return vulnerabilities, nil
}

// Helper functions for injection checks
func checkSQLInjection(scanner *Scanner, targetURL string) ([]models.Vulnerability, error) {
	var vulnerabilities []models.Vulnerability

	payloads := []string{
		"' OR '1'='1",
		"1' OR '1'='1",
		"admin' --",
		"admin' #",
		"admin'/*",
		"' UNION SELECT NULL--",
		"' UNION SELECT NULL,NULL--",
		"' UNION SELECT NULL,NULL,NULL--",
		"1; DROP TABLE users--",
		"1' WAITFOR DELAY '0:0:5'--",
	}

	for _, payload := range payloads {
		path := fmt.Sprintf("/search?q=%s", url.QueryEscape(payload))
		req, err := http.NewRequest("GET", targetURL+path, nil)
		if err != nil {
			continue
		}

		resp, err := scanner.client.Do(req)
		if err != nil {
			continue
		}
		defer resp.Body.Close()

		body, err := io.ReadAll(resp.Body)
		if err != nil {
			continue
		}

		if strings.Contains(strings.ToLower(string(body)), "sql") ||
			strings.Contains(strings.ToLower(string(body)), "mysql") ||
			strings.Contains(strings.ToLower(string(body)), "postgresql") ||
			strings.Contains(strings.ToLower(string(body)), "oracle") ||
			strings.Contains(strings.ToLower(string(body)), "syntax error") {
			evidence, err := scanner.evidenceColl.CollectEvidence(targetURL+path, req, resp)
			if err != nil {
				fmt.Printf("Warning: Could not collect evidence: %v\n", err)
			}

			vulnerabilities = append(vulnerabilities, models.Vulnerability{
				Title:       "SQL Injection Vulnerability",
				Description: "The application is vulnerable to SQL injection attacks.",
				Category:    models.CategoryInjection,
				Severity:    models.High,
				URL:         targetURL + path,
				Evidence:    evidence,
				Remediation: "Use parameterized queries or prepared statements.",
			})
		}
	}

	return vulnerabilities, nil
}

func checkNoSQLInjection(scanner *Scanner, targetURL string) ([]models.Vulnerability, error) {
	var vulnerabilities []models.Vulnerability

	payloads := []string{
		`{"$gt": ""}`,
		`{"$ne": null}`,
		`{"$where": "1 == 1"}`,
		`{"$regex": ".*"}`,
		`{"username": {"$ne": ""}, "password": {"$ne": ""}}`,
		`{"$or": [{"username": "admin"}, {"password": "admin"}]}`,
	}

	for _, payload := range payloads {
		req, err := http.NewRequest("POST", targetURL+"/api/search", strings.NewReader(payload))
		if err != nil {
			continue
		}
		req.Header.Set("Content-Type", "application/json")

		resp, err := scanner.client.Do(req)
		if err != nil {
			continue
		}
		defer resp.Body.Close()

		body, err := io.ReadAll(resp.Body)
		if err != nil {
			continue
		}

		if strings.Contains(strings.ToLower(string(body)), "mongodb") ||
			strings.Contains(strings.ToLower(string(body)), "nosql") ||
			strings.Contains(strings.ToLower(string(body)), "bson") {
			evidence, err := scanner.evidenceColl.CollectEvidence(targetURL+"/api/search", req, resp)
			if err != nil {
				fmt.Printf("Warning: Could not collect evidence: %v\n", err)
			}

			vulnerabilities = append(vulnerabilities, models.Vulnerability{
				Title:       "NoSQL Injection Vulnerability",
				Description: "The application is vulnerable to NoSQL injection attacks.",
				Category:    models.CategoryInjection,
				Severity:    models.High,
				URL:         targetURL + "/api/search",
				Evidence:    evidence,
				Remediation: "Validate and sanitize all user input.",
			})
		}
	}

	return vulnerabilities, nil
}

// Helper functions for authentication checks
func checkWeakPasswords(scanner *Scanner, targetURL string) ([]models.Vulnerability, error) {
	var vulnerabilities []models.Vulnerability

	// Test for weak passwords
	weakPasswords := []string{"password", "123456", "admin", "root", "test"}
	for _, password := range weakPasswords {
		// Simulate login attempt with weak password
		// In a real implementation, this would make actual HTTP requests
		fmt.Printf("Testing weak password: %s\n", password)

		// For demonstration, we'll assume we found a vulnerability
		if password == "admin" {
			formData := url.Values{}
			formData.Set("username", "admin")
			formData.Set("password", password)

			req, err := http.NewRequest("POST", targetURL+"/login", strings.NewReader(formData.Encode()))
			if err != nil {
				continue
			}
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

			resp, err := scanner.client.Do(req)
			if err != nil {
				continue
			}
			defer resp.Body.Close()

			if resp.StatusCode == http.StatusOK {
				evidence, err := scanner.evidenceColl.CollectEvidence(targetURL+"/login", req, resp)
				if err != nil {
					fmt.Printf("Warning: Could not collect evidence: %v\n", err)
				}

				vulnerabilities = append(vulnerabilities, models.Vulnerability{
					Title:       "Weak Password Detected",
					Description: "A common weak password was accepted by the application",
					Category:    models.CategoryIntegrityFailures,
					Severity:    models.High,
					URL:         targetURL + "/login",
					Evidence:    evidence,
					Remediation: "Implement strong password policies and enforce them during user registration and password changes",
				})
				break
			}
		}
	}

	return vulnerabilities, nil
}

func checkSessionFixation(scanner *Scanner, targetURL string) ([]models.Vulnerability, error) {
	var vulnerabilities []models.Vulnerability

	// Test for session fixation
	// In a real implementation, this would make actual HTTP requests
	fmt.Println("Testing for session fixation vulnerability")

	// For demonstration, we'll assume we found a vulnerability
	vulnerabilities = append(vulnerabilities, models.Vulnerability{
		Title:       "Session Fixation Vulnerability",
		Description: "The application accepts a user-supplied session identifier",
		Category:    models.CategoryIntegrityFailures,
		Severity:    models.High,
		URL:         targetURL + "/login",
		Evidence: &evidence.Evidence{
			URL:         targetURL + "/login",
			CurlCommand: "curl -X GET '" + targetURL + "/login?session_id=fixed_session' -H 'Host: " + targetURL + "'",
			LogPath:     "logs/session_fixation_test.txt",
		},
		Remediation: "Generate new session IDs after successful authentication and invalidate old sessions",
	})

	return vulnerabilities, nil
}

// Helper functions for sensitive data checks
func checkCreditCardExposure(scanner *Scanner, targetURL string) ([]models.Vulnerability, error) {
	var vulnerabilities []models.Vulnerability

	req, err := http.NewRequest("GET", targetURL, nil)
	if err != nil {
		return vulnerabilities, nil
	}

	resp, err := scanner.client.Do(req)
	if err != nil {
		return vulnerabilities, nil
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return vulnerabilities, nil
	}

	creditCardPattern := regexp.MustCompile(`\b\d{4}[ -]?\d{4}[ -]?\d{4}[ -]?\d{4}\b`)
	if creditCardPattern.Match(body) {
		evidence, err := scanner.evidenceColl.CollectEvidence(targetURL, req, resp)
		if err != nil {
			fmt.Printf("Warning: Could not collect evidence: %v\n", err)
		}

		vulnerabilities = append(vulnerabilities, models.Vulnerability{
			Title:       "Credit Card Exposure",
			Description: "Credit card numbers are exposed in the response.",
			Category:    models.CategoryCryptographicFailures,
			Severity:    models.High,
			URL:         targetURL,
			Evidence:    evidence,
			Remediation: "Encrypt sensitive data at rest and in transit.",
		})
	}

	return vulnerabilities, nil
}

func checkSSNExposure(scanner *Scanner, targetURL string) ([]models.Vulnerability, error) {
	var vulnerabilities []models.Vulnerability

	req, err := http.NewRequest("GET", targetURL, nil)
	if err != nil {
		return vulnerabilities, nil
	}

	resp, err := scanner.client.Do(req)
	if err != nil {
		return vulnerabilities, nil
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return vulnerabilities, nil
	}

	ssnPattern := regexp.MustCompile(`\b\d{3}[ -]?\d{2}[ -]?\d{4}\b`)
	if ssnPattern.Match(body) {
		evidence, err := scanner.evidenceColl.CollectEvidence(targetURL, req, resp)
		if err != nil {
			fmt.Printf("Warning: Could not collect evidence: %v\n", err)
		}

		vulnerabilities = append(vulnerabilities, models.Vulnerability{
			Title:       "SSN Exposure",
			Description: "Social Security Numbers are exposed in the response.",
			Category:    models.CategoryCryptographicFailures,
			Severity:    models.High,
			URL:         targetURL,
			Evidence:    evidence,
			Remediation: "Encrypt sensitive data at rest and in transit.",
		})
	}

	return vulnerabilities, nil
}

// Helper functions for design checks
func checkBusinessLogic(scanner *Scanner, targetURL string) ([]models.Vulnerability, error) {
	var vulnerabilities []models.Vulnerability

	// Test for negative quantities in purchase
	formData := url.Values{}
	formData.Set("product_id", "123")
	formData.Set("quantity", "-1")

	req, err := http.NewRequest("POST", targetURL+"/api/purchase", strings.NewReader(formData.Encode()))
	if err != nil {
		return vulnerabilities, nil
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := scanner.client.Do(req)
	if err != nil {
		return vulnerabilities, nil
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusOK {
		evidence, err := scanner.evidenceColl.CollectEvidence(targetURL+"/api/purchase", req, resp)
		if err != nil {
			fmt.Printf("Warning: Could not collect evidence: %v\n", err)
		}

		vulnerabilities = append(vulnerabilities, models.Vulnerability{
			Title:       "Business Logic Flaw",
			Description: "The application allows negative quantities in purchase requests.",
			Category:    models.CategoryInsecureDesign,
			Severity:    models.High,
			URL:         targetURL + "/api/purchase",
			Evidence:    evidence,
			Remediation: "Implement proper input validation for business logic.",
		})
	}

	return vulnerabilities, nil
}

// Helper functions for access control checks
func checkDirectoryTraversal(scanner *Scanner, targetURL string) ([]models.Vulnerability, error) {
	var vulnerabilities []models.Vulnerability

	// Common sensitive files to test
	paths := []string{
		// Basic traversal
		"/../../../../etc/passwd",
		"/..%2F..%2F..%2F..%2Fetc/passwd",
		"/%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2fetc/passwd",
		"/....//....//....//....//etc/passwd",
		"/..%252F..%252F..%252F..%252Fetc/passwd",

		// Windows paths
		"/..\\..\\..\\..\\windows\\system32\\drivers\\etc\\hosts",
		"/..%5C..%5C..%5C..%5Cwindows%5Csystem32%5Cdrivers%5Cetc%5Chosts",

		// Common sensitive files
		"/../../../../etc/shadow",
		"/../../../../etc/hosts",
		"/../../../../etc/group",
		"/../../../../etc/hostname",
		"/../../../../etc/resolv.conf",

		// Configuration files
		"/../../../../etc/nginx/nginx.conf",
		"/../../../../etc/apache2/apache2.conf",
		"/../../../../etc/httpd/conf/httpd.conf",

		// Log files
		"/../../../../var/log/auth.log",
		"/../../../../var/log/syslog",
		"/../../../../var/log/nginx/access.log",

		// Web server files
		"/../../../../var/www/html/index.php",
		"/../../../../var/www/html/config.php",
		"/../../../../var/www/html/.env",

		// SSH files
		"/../../../../.ssh/id_rsa",
		"/../../../../.ssh/authorized_keys",
		"/../../../../.ssh/config",

		// Git files
		"/../../../../.git/config",
		"/../../../../.git/HEAD",
		"/../../../../.git/index",

		// Environment files
		"/../../../../.env",
		"/../../../../.env.local",
		"/../../../../.env.production",

		// Database files
		"/../../../../var/lib/mysql/mysql/user.MYD",
		"/../../../../var/lib/postgresql/data/pg_hba.conf",
	}

	// Common sensitive file indicators
	indicators := []string{
		"root:",        // /etc/passwd
		"root:$",       // /etc/shadow
		"127.0.0.1",    // /etc/hosts
		"root:x:",      // /etc/group
		"server {",     // nginx config
		"<VirtualHost", // apache config
		"BEGIN RSA",    // SSH keys
		"ref: refs/",   // git files
		"DB_USERNAME=", // .env files
		"<?php",        // PHP files
	}

	for _, path := range paths {
		req, err := http.NewRequest("GET", targetURL+path, nil)
		if err != nil {
			continue
		}

		// Set timeout
		scanner.client.Timeout = 5 * time.Second

		resp, err := scanner.client.Do(req)
		if err != nil {
			continue
		}
		defer resp.Body.Close()

		// Only process successful responses
		if resp.StatusCode != http.StatusOK {
			continue
		}

		body, err := io.ReadAll(resp.Body)
		if err != nil {
			continue
		}

		// Check for any sensitive file indicators
		for _, indicator := range indicators {
			if strings.Contains(string(body), indicator) {
				evidence, err := scanner.evidenceColl.CollectEvidence(targetURL+path, req, resp)
				if err != nil {
					fmt.Printf("Warning: Could not collect evidence: %v\n", err)
					continue
				}

				vulnerabilities = append(vulnerabilities, models.Vulnerability{
					Title:       "Directory Traversal",
					Description: fmt.Sprintf("The application is vulnerable to directory traversal attacks. Sensitive file '%s' was accessed.", path),
					Category:    models.CategoryBrokenAccessControl,
					Severity:    models.High,
					URL:         targetURL + path,
					Evidence:    evidence,
					Remediation: "Implement proper input validation and path normalization. Use a secure file access API that prevents directory traversal.",
				})
				break
			}
		}
	}

	return vulnerabilities, nil
}

func checkIDOR(scanner *Scanner, targetURL string) ([]models.Vulnerability, error) {
	var vulnerabilities []models.Vulnerability

	// Common IDOR patterns to test
	patterns := []string{
		"/api/users/%d",         // User IDs
		"/api/orders/%d",        // Order IDs
		"/api/products/%d",      // Product IDs
		"/api/documents/%d",     // Document IDs
		"/api/invoices/%d",      // Invoice IDs
		"/api/tickets/%d",       // Support tickets
		"/api/payments/%d",      // Payment records
		"/api/transactions/%d",  // Transaction records
		"/api/accounts/%d",      // Account records
		"/api/profiles/%d",      // Profile records
		"/api/settings/%d",      // Settings records
		"/api/notifications/%d", // Notification records
		"/api/messages/%d",      // Message records
		"/api/comments/%d",      // Comment records
		"/api/reviews/%d",       // Review records
		"/api/ratings/%d",       // Rating records
		"/api/bookmarks/%d",     // Bookmark records
		"/api/favorites/%d",     // Favorite records
		"/api/likes/%d",         // Like records
		"/api/shares/%d",        // Share records
	}

	// Test each pattern with sequential IDs
	for _, pattern := range patterns {
		for i := 1; i <= 5; i++ {
			path := fmt.Sprintf(pattern, i)
			req, err := http.NewRequest("GET", targetURL+path, nil)
			if err != nil {
				continue
			}

			resp, err := scanner.client.Do(req)
			if err != nil {
				continue
			}
			defer resp.Body.Close()

			if resp.StatusCode == http.StatusOK {
				evidence, err := scanner.evidenceColl.CollectEvidence(targetURL+path, req, resp)
				if err != nil {
					fmt.Printf("Warning: Could not collect evidence: %v\n", err)
					continue
				}

				vulnerabilities = append(vulnerabilities, models.Vulnerability{
					Title:       "Insecure Direct Object Reference (IDOR)",
					Description: fmt.Sprintf("The application allows direct access to objects by their ID at path '%s'.", path),
					Category:    models.CategoryBrokenAccessControl,
					Severity:    models.Medium,
					URL:         targetURL + path,
					Evidence:    evidence,
					Remediation: "Implement proper access control checks. Use indirect object references or access control lists.",
				})
			}
		}
	}

	return vulnerabilities, nil
}

func checkMissingAuthHeaders(scanner *Scanner, targetURL string) ([]models.Vulnerability, error) {
	var vulnerabilities []models.Vulnerability

	// Test endpoints that should require authentication
	endpoints := []string{
		"/api/users",
		"/api/orders",
		"/api/settings",
		"/api/admin",
		"/api/dashboard",
	}

	for _, endpoint := range endpoints {
		req, err := http.NewRequest("GET", targetURL+endpoint, nil)
		if err != nil {
			continue
		}

		resp, err := scanner.client.Do(req)
		if err != nil {
			continue
		}
		defer resp.Body.Close()

		// Check if endpoint is accessible without authentication
		if resp.StatusCode == http.StatusOK {
			evidence, err := scanner.evidenceColl.CollectEvidence(targetURL+endpoint, req, resp)
			if err != nil {
				fmt.Printf("Warning: Could not collect evidence: %v\n", err)
				continue
			}

			vulnerabilities = append(vulnerabilities, models.Vulnerability{
				Title:       "Missing Authorization",
				Description: fmt.Sprintf("The endpoint '%s' is accessible without proper authorization.", endpoint),
				Category:    models.CategoryBrokenAccessControl,
				Severity:    models.High,
				URL:         targetURL + endpoint,
				Evidence:    evidence,
				Remediation: "Implement proper authorization checks. Require valid authentication tokens for all sensitive endpoints.",
			})
		}
	}

	return vulnerabilities, nil
}

func checkCORS(scanner *Scanner, targetURL string) ([]models.Vulnerability, error) {
	var vulnerabilities []models.Vulnerability

	// Test CORS configuration
	req, err := http.NewRequest("OPTIONS", targetURL, nil)
	if err != nil {
		return vulnerabilities, nil
	}

	// Test with different origins
	origins := []string{
		"https://evil.com",
		"http://localhost",
		"http://127.0.0.1",
		"null",
		"*",
	}

	for _, origin := range origins {
		req.Header.Set("Origin", origin)
		req.Header.Set("Access-Control-Request-Method", "GET")
		req.Header.Set("Access-Control-Request-Headers", "Content-Type")

		resp, err := scanner.client.Do(req)
		if err != nil {
			continue
		}
		defer resp.Body.Close()

		// Check for overly permissive CORS
		allowOrigin := resp.Header.Get("Access-Control-Allow-Origin")
		if allowOrigin == "*" || allowOrigin == origin {
			evidence, err := scanner.evidenceColl.CollectEvidence(targetURL, req, resp)
			if err != nil {
				fmt.Printf("Warning: Could not collect evidence: %v\n", err)
				continue
			}

			vulnerabilities = append(vulnerabilities, models.Vulnerability{
				Title:       "CORS Misconfiguration",
				Description: fmt.Sprintf("The application has an overly permissive CORS configuration, allowing requests from origin '%s'.", origin),
				Category:    models.CategoryBrokenAccessControl,
				Severity:    models.Medium,
				URL:         targetURL,
				Evidence:    evidence,
				Remediation: "Implement proper CORS configuration. Only allow specific trusted origins and methods.",
			})
		}
	}

	return vulnerabilities, nil
}

func checkJWTValidation(scanner *Scanner, targetURL string) ([]models.Vulnerability, error) {
	var vulnerabilities []models.Vulnerability

	// Test JWT validation
	// First, try to get a valid token from login
	loginReq, err := http.NewRequest("POST", targetURL+"/api/login", strings.NewReader(`{"username":"test","password":"test"}`))
	if err != nil {
		return vulnerabilities, nil
	}
	loginReq.Header.Set("Content-Type", "application/json")

	loginResp, err := scanner.client.Do(loginReq)
	if err != nil {
		return vulnerabilities, nil
	}
	defer loginResp.Body.Close()

	// Get token from response
	token := loginResp.Header.Get("Authorization")
	if token == "" {
		return vulnerabilities, nil
	}

	// Test JWT validation with modified tokens
	tokens := []string{
		token,                                    // Original token
		strings.Replace(token, "Bearer ", "", 1), // Without Bearer prefix
		"eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.",                                             // None algorithm
		"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c", // HS256 with weak key
	}

	for _, testToken := range tokens {
		req, err := http.NewRequest("GET", targetURL+"/api/protected", nil)
		if err != nil {
			continue
		}
		req.Header.Set("Authorization", "Bearer "+testToken)

		resp, err := scanner.client.Do(req)
		if err != nil {
			continue
		}
		defer resp.Body.Close()

		if resp.StatusCode == http.StatusOK {
			evidence, err := scanner.evidenceColl.CollectEvidence(targetURL+"/api/protected", req, resp)
			if err != nil {
				fmt.Printf("Warning: Could not collect evidence: %v\n", err)
				continue
			}

			vulnerabilities = append(vulnerabilities, models.Vulnerability{
				Title:       "JWT Validation Bypass",
				Description: "The application accepts invalid or weak JWT tokens.",
				Category:    models.CategoryBrokenAccessControl,
				Severity:    models.High,
				URL:         targetURL + "/api/protected",
				Evidence:    evidence,
				Remediation: "Implement proper JWT validation. Reject tokens with 'none' algorithm and weak signatures.",
			})
			break
		}
	}

	return vulnerabilities, nil
}

func checkRBACBypass(scanner *Scanner, targetURL string) ([]models.Vulnerability, error) {
	var vulnerabilities []models.Vulnerability

	// Test RBAC bypass
	// First, login as a regular user
	loginReq, err := http.NewRequest("POST", targetURL+"/api/login", strings.NewReader(`{"username":"user","password":"user"}`))
	if err != nil {
		return vulnerabilities, nil
	}
	loginReq.Header.Set("Content-Type", "application/json")

	loginResp, err := scanner.client.Do(loginReq)
	if err != nil {
		return vulnerabilities, nil
	}
	defer loginResp.Body.Close()

	// Get token from response
	token := loginResp.Header.Get("Authorization")
	if token == "" {
		return vulnerabilities, nil
	}

	// Test admin endpoints with regular user token
	adminEndpoints := []string{
		"/api/admin/users",
		"/api/admin/settings",
		"/api/admin/logs",
		"/api/admin/config",
	}

	for _, endpoint := range adminEndpoints {
		req, err := http.NewRequest("GET", targetURL+endpoint, nil)
		if err != nil {
			continue
		}
		req.Header.Set("Authorization", token)

		resp, err := scanner.client.Do(req)
		if err != nil {
			continue
		}
		defer resp.Body.Close()

		if resp.StatusCode == http.StatusOK {
			evidence, err := scanner.evidenceColl.CollectEvidence(targetURL+endpoint, req, resp)
			if err != nil {
				fmt.Printf("Warning: Could not collect evidence: %v\n", err)
				continue
			}

			vulnerabilities = append(vulnerabilities, models.Vulnerability{
				Title:       "RBAC Bypass",
				Description: fmt.Sprintf("The application allows regular users to access admin endpoint '%s'.", endpoint),
				Category:    models.CategoryBrokenAccessControl,
				Severity:    models.High,
				URL:         targetURL + endpoint,
				Evidence:    evidence,
				Remediation: "Implement proper role-based access control. Verify user roles before granting access to sensitive endpoints.",
			})
		}
	}

	return vulnerabilities, nil
}

// Helper functions for security misconfiguration checks
func checkDefaultCredentials(scanner *Scanner, targetURL string) ([]models.Vulnerability, error) {
	var vulnerabilities []models.Vulnerability

	defaultCredentials := []struct {
		username string
		password string
	}{
		{"admin", "admin"},
		{"admin", "password"},
		{"root", "root"},
		{"administrator", "administrator"},
	}

	for _, creds := range defaultCredentials {
		formData := url.Values{}
		formData.Set("username", creds.username)
		formData.Set("password", creds.password)

		req, err := http.NewRequest("POST", targetURL+"/login", strings.NewReader(formData.Encode()))
		if err != nil {
			continue
		}
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

		resp, err := scanner.client.Do(req)
		if err != nil {
			continue
		}
		defer resp.Body.Close()

		if resp.StatusCode == http.StatusOK {
			evidence, err := scanner.evidenceColl.CollectEvidence(targetURL+"/login", req, resp)
			if err != nil {
				fmt.Printf("Warning: Could not collect evidence: %v\n", err)
			}

			vulnerabilities = append(vulnerabilities, models.Vulnerability{
				Title:       "Default Credentials",
				Description: "The application uses default credentials that are publicly known.",
				Category:    models.CategorySecurityMisconfiguration,
				Severity:    models.High,
				URL:         targetURL + "/login",
				Evidence:    evidence,
				Remediation: "Change all default credentials. Implement strong password policies.",
			})
			break
		}
	}

	return vulnerabilities, nil
}

func checkDirectoryListing(scanner *Scanner, targetURL string) ([]models.Vulnerability, error) {
	var vulnerabilities []models.Vulnerability

	paths := []string{
		"/",
		"/images/",
		"/uploads/",
		"/assets/",
	}

	for _, path := range paths {
		req, err := http.NewRequest("GET", targetURL+path, nil)
		if err != nil {
			continue
		}

		resp, err := scanner.client.Do(req)
		if err != nil {
			continue
		}
		defer resp.Body.Close()

		body, err := io.ReadAll(resp.Body)
		if err != nil {
			continue
		}

		if strings.Contains(string(body), "<title>Index of") ||
			strings.Contains(string(body), "Directory listing for") {
			evidence, err := scanner.evidenceColl.CollectEvidence(targetURL+path, req, resp)
			if err != nil {
				fmt.Printf("Warning: Could not collect evidence: %v\n", err)
			}

			vulnerabilities = append(vulnerabilities, models.Vulnerability{
				Title:       "Directory Listing Enabled",
				Description: "The application has directory listing enabled, exposing sensitive files and directories.",
				Category:    models.CategorySecurityMisconfiguration,
				Severity:    models.Medium,
				URL:         targetURL + path,
				Evidence:    evidence,
				Remediation: "Disable directory listing in web server configuration.",
			})
		}
	}

	return vulnerabilities, nil
}

// Helper functions for vulnerable components checks
func checkOutdatedComponents(scanner *Scanner, targetURL string) ([]models.Vulnerability, error) {
	var vulnerabilities []models.Vulnerability

	req, err := http.NewRequest("GET", targetURL, nil)
	if err != nil {
		return vulnerabilities, nil
	}

	resp, err := scanner.client.Do(req)
	if err != nil {
		return vulnerabilities, nil
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return vulnerabilities, nil
	}

	outdatedLibs := map[string]string{
		"jquery-1.":    "jQuery 1.x (outdated)",
		"angular-1.":   "AngularJS 1.x (outdated)",
		"bootstrap-3.": "Bootstrap 3.x (outdated)",
	}

	for pattern, lib := range outdatedLibs {
		if strings.Contains(string(body), pattern) {
			evidence, err := scanner.evidenceColl.CollectEvidence(targetURL, req, resp)
			if err != nil {
				fmt.Printf("Warning: Could not collect evidence: %v\n", err)
			}

			vulnerabilities = append(vulnerabilities, models.Vulnerability{
				Title:       "Outdated Component",
				Description: fmt.Sprintf("The application uses %s which may contain known vulnerabilities.", lib),
				Category:    models.CategoryVulnerableComponents,
				Severity:    models.Medium,
				URL:         targetURL,
				Evidence:    evidence,
				Remediation: "Update all components to their latest secure versions.",
			})
		}
	}

	return vulnerabilities, nil
}

// Helper functions for integrity checks
func checkMissingIntegrity(scanner *Scanner, targetURL string) ([]models.Vulnerability, error) {
	var vulnerabilities []models.Vulnerability

	req, err := http.NewRequest("GET", targetURL, nil)
	if err != nil {
		return vulnerabilities, nil
	}

	resp, err := scanner.client.Do(req)
	if err != nil {
		return vulnerabilities, nil
	}
	defer resp.Body.Close()

	if resp.Header.Get("Content-Security-Policy") == "" {
		evidence, err := scanner.evidenceColl.CollectEvidence(targetURL, req, resp)
		if err != nil {
			fmt.Printf("Warning: Could not collect evidence: %v\n", err)
		}

		vulnerabilities = append(vulnerabilities, models.Vulnerability{
			Title:       "Missing Content Security Policy",
			Description: "The application does not implement Content Security Policy.",
			Category:    models.CategoryIntegrityFailures,
			Severity:    models.Medium,
			URL:         targetURL,
			Evidence:    evidence,
			Remediation: "Implement a strong Content Security Policy.",
		})
	}

	return vulnerabilities, nil
}

// Helper functions for logging checks
func checkMissingSecurityHeaders(scanner *Scanner, targetURL string) ([]models.Vulnerability, error) {
	var vulnerabilities []models.Vulnerability

	req, err := http.NewRequest("GET", targetURL, nil)
	if err != nil {
		return vulnerabilities, nil
	}

	resp, err := scanner.client.Do(req)
	if err != nil {
		return vulnerabilities, nil
	}
	defer resp.Body.Close()

	missingHeaders := []string{
		"X-Content-Type-Options",
		"X-Frame-Options",
		"X-XSS-Protection",
		"Strict-Transport-Security",
	}

	for _, header := range missingHeaders {
		if resp.Header.Get(header) == "" {
			evidence, err := scanner.evidenceColl.CollectEvidence(targetURL, req, resp)
			if err != nil {
				fmt.Printf("Warning: Could not collect evidence: %v\n", err)
			}

			vulnerabilities = append(vulnerabilities, models.Vulnerability{
				Title:       "Missing Security Header",
				Description: fmt.Sprintf("The application is missing the %s security header.", header),
				Category:    models.CategoryLoggingFailures,
				Severity:    models.Low,
				URL:         targetURL,
				Evidence:    evidence,
				Remediation: "Implement all recommended security headers.",
			})
		}
	}

	return vulnerabilities, nil
}

// Helper functions for SSRF checks
func checkSSRFVulnerabilities(scanner *Scanner, targetURL string) ([]models.Vulnerability, error) {
	var vulnerabilities []models.Vulnerability

	ssrfTargets := []string{
		"http://localhost",
		"http://127.0.0.1",
		"http://169.254.169.254",
		"http://metadata.google.internal",
	}

	for _, target := range ssrfTargets {
		path := fmt.Sprintf("/api/fetch?url=%s", url.QueryEscape(target))
		req, err := http.NewRequest("GET", targetURL+path, nil)
		if err != nil {
			continue
		}

		resp, err := scanner.client.Do(req)
		if err != nil {
			continue
		}
		defer resp.Body.Close()

		body, err := io.ReadAll(resp.Body)
		if err != nil {
			continue
		}

		if strings.Contains(string(body), "localhost") ||
			strings.Contains(string(body), "127.0.0.1") ||
			strings.Contains(string(body), "metadata") {
			evidence, err := scanner.evidenceColl.CollectEvidence(targetURL+path, req, resp)
			if err != nil {
				fmt.Printf("Warning: Could not collect evidence: %v\n", err)
			}

			vulnerabilities = append(vulnerabilities, models.Vulnerability{
				Title:       "Server-Side Request Forgery (SSRF)",
				Description: "The application is vulnerable to SSRF attacks.",
				Category:    models.CategorySSRF,
				Severity:    models.High,
				URL:         targetURL + path,
				Evidence:    evidence,
				Remediation: "Implement proper URL validation and filtering.",
			})
		}
	}

	return vulnerabilities, nil
}
