package scanner

import (
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/gleicon/sonnel/internal/evidence"
	"github.com/gleicon/sonnel/internal/models"
)

// Common route patterns for different types of endpoints
var (
	// Auth & Session routes
	// TODO: use a wordlist for common endpoints
	authRoutes = []string{
		"/login", "/signin", "/auth", "/authenticate",
		"/register", "/signup", "/create-account",
		"/logout", "/signout",
		"/reset-password", "/forgot-password", "/password-reset",
		"/auth/token", "/oauth/token", "/api/auth",
	}

	// Payment & Checkout routes
	paymentRoutes = []string{
		"/checkout", "/cart/checkout",
		"/cart/add", "/cart/remove", "/cart/update",
		"/payment", "/pay", "/process-payment",
		"/order/confirm", "/order/complete",
		"/billing", "/subscription",
	}

	// Account & Profile routes
	accountRoutes = []string{
		"/account", "/profile", "/user",
		"/account/settings", "/profile/settings",
		"/user/:id", "/users/:id",
		"/api/v1/users", "/api/v1/account",
		"/api/v1/profile",
	}

	// Admin & Configuration routes
	adminRoutes = []string{
		"/admin", "/administrator",
		"/config", "/configuration",
		"/debug", "/test",
		"/hidden", "/private",
		"/api/admin", "/api/v1/admin",
	}

	// Content & Search routes
	contentRoutes = []string{
		"/products", "/items", "/listings",
		"/search", "/find", "/query",
		"/list", "/catalog", "/inventory",
		"/api/products", "/api/items",
	}

	// API version patterns
	apiVersionPatterns = []string{
		"/api/v1", "/api/v2", "/api/v3",
		"/v1/api", "/v2/api", "/v3/api",
		"/api/1.0", "/api/2.0", "/api/3.0",
		"/v1", "v2",
	}
)

// CheckCarding checks for card testing attempts (OAT-001)
func CheckCarding(target string) []models.Vulnerability {
	var vulns []models.Vulnerability
	fmt.Println("Checking for carding attempts...")

	// Create evidence collector
	evidenceColl, err := evidence.NewEvidenceCollector("evidence")
	if err != nil {
		fmt.Printf("Warning: Could not create evidence collector: %v\n", err)
		return vulns
	}

	// Test payment endpoints
	for _, path := range paymentRoutes {
		// Test with known BIN patterns
		payloads := []string{
			`{"card_number":"4111111111111111","expiry":"12/25","cvv":"123"}`,
			`{"card_number":"4242424242424242","expiry":"12/25","cvv":"123"}`,
			`{"card_number":"5555555555554444","expiry":"12/25","cvv":"123"}`,
		}

		for _, payload := range payloads {
			req, err := http.NewRequest("POST", target+path, strings.NewReader(payload))
			if err != nil {
				continue
			}
			req.Header.Set("Content-Type", "application/json")

			client := &http.Client{}
			resp, err := client.Do(req)
			if err != nil {
				continue
			}
			defer resp.Body.Close()

			// Check for rate limiting or suspicious responses
			if resp.StatusCode == 429 || resp.StatusCode == 403 {
				evidence, err := evidenceColl.CollectEvidence(target+path, req, resp)
				if err != nil {
					fmt.Printf("Warning: Could not collect evidence: %v\n", err)
				}

				vulns = append(vulns, models.Vulnerability{
					Title:       "Potential Carding Attempt Detected",
					Description: "Rate limiting or suspicious response detected on payment endpoint",
					Category:    models.CategoryCarding,
					Severity:    models.High,
					URL:         target + path,
					Evidence:    evidence,
					Remediation: "Endpoint found but target implemented rate limiting, CAPTCHA. Make sure it has card validation checks",
				})
			} else if resp.StatusCode >= 200 && resp.StatusCode < 300 {
				evidence, err := evidenceColl.CollectEvidence(target+path, req, resp)
				if err != nil {
					fmt.Printf("Warning: Could not collect evidence: %v\n", err)
				}

				vulns = append(vulns, models.Vulnerability{
					Title:       "Potential Carding Attempt Detected",
					Description: "Rate limiting or suspicious response detected on payment endpoint",
					Category:    models.CategoryCarding,
					Severity:    models.High,
					URL:         target + path,
					Evidence:    evidence,
					Remediation: "Target should implement rate limiting, CAPTCHA. Make sure it has card validation checks",
				})
			}
		}
	}

	return vulns
}

// CheckTokenCracking checks for token brute-forcing (OAT-002)
func CheckTokenCracking(target string) []models.Vulnerability {
	var vulns []models.Vulnerability
	fmt.Println("Checking for token cracking attempts...")

	// Create evidence collector
	evidenceColl, err := evidence.NewEvidenceCollector("evidence")
	if err != nil {
		fmt.Printf("Warning: Could not create evidence collector: %v\n", err)
		return vulns
	}

	// Common token endpoints
	tokenEndpoints := []string{
		"/redeem", "/verify", "/activate",
		"/reset-password", "/confirm-email",
	}

	for _, path := range tokenEndpoints {
		// Test with sequential tokens
		for i := 0; i < 5; i++ {
			token := fmt.Sprintf("TEST%d", i)
			req, err := http.NewRequest("GET", target+path+"?code="+token, nil)
			if err != nil {
				continue
			}

			client := &http.Client{}
			resp, err := client.Do(req)
			if err != nil {
				continue
			}
			defer resp.Body.Close()

			// Check for rate limiting or suspicious responses
			if resp.StatusCode == 429 || resp.StatusCode == 403 {
				evidence, err := evidenceColl.CollectEvidence(target+path, req, resp)
				if err != nil {
					fmt.Printf("Warning: Could not collect evidence: %v\n", err)
				}

				vulns = append(vulns, models.Vulnerability{
					Title:       "Potential Token Cracking Attempt Detected",
					Description: "Rate limiting or suspicious response detected on token endpoint",
					Category:    models.CategoryTokenCracking,
					Severity:    models.High,
					URL:         target + path,
					Evidence:    evidence,
					Remediation: "Target implemented rate limiting, CAPTCHA, or token validation checks",
				})
			} else if resp.StatusCode >= 200 && resp.StatusCode < 300 {
				evidence, err := evidenceColl.CollectEvidence(target+path, req, resp)
				if err != nil {
					fmt.Printf("Warning: Could not collect evidence: %v\n", err)
				}

				vulns = append(vulns, models.Vulnerability{
					Title:       "Potential Token Cracking Attempt Detected",
					Description: "Rate limiting or suspicious response detected on token endpoint",
					Category:    models.CategoryTokenCracking,
					Severity:    models.High,
					URL:         target + path,
					Evidence:    evidence,
					Remediation: "Implement rate limiting, CAPTCHA, and token validation checks",
				})
			}
		}
	}

	return vulns
}

// CheckCredentialCracking checks for password brute-forcing (OAT-007)
func CheckCredentialCracking(target string) []models.Vulnerability {
	var vulns []models.Vulnerability
	fmt.Println("Checking for credential cracking attempts...")

	// Create evidence collector
	evidenceColl, err := evidence.NewEvidenceCollector("evidence")
	if err != nil {
		fmt.Printf("Warning: Could not create evidence collector: %v\n", err)
		return vulns
	}

	// Test login endpoints
	for _, path := range authRoutes {
		// Common password list
		// TODO: implement a wordlist
		passwords := []string{
			"password", "123456", "admin", "test",
			"qwerty", "letmein", "welcome",
		}

		for _, password := range passwords {
			payload := fmt.Sprintf(`{"username":"admin","password":"%s"}`, password)
			req, err := http.NewRequest("POST", target+path, strings.NewReader(payload))
			if err != nil {
				continue
			}
			req.Header.Set("Content-Type", "application/json")

			client := &http.Client{}
			resp, err := client.Do(req)
			if err != nil {
				continue
			}
			defer resp.Body.Close()

			// Check for rate limiting or suspicious responses
			if resp.StatusCode == 429 || resp.StatusCode == 403 {
				evidence, err := evidenceColl.CollectEvidence(target+path, req, resp)
				if err != nil {
					fmt.Printf("Warning: Could not collect evidence: %v\n", err)
				}

				vulns = append(vulns, models.Vulnerability{
					Title:       "Potential Credential Cracking Attempt Detected",
					Description: "Rate limiting or suspicious response detected on login endpoint",
					Category:    models.CategoryCredentialCracking,
					Severity:    models.High,
					URL:         target + path,
					Evidence:    evidence,
					Remediation: "Target imeplemented rate limiting or CAPTCHA",
				})
			} else if resp.StatusCode >= 200 && resp.StatusCode < 300 {
				evidence, err := evidenceColl.CollectEvidence(target+path, req, resp)
				if err != nil {
					fmt.Printf("Warning: Could not collect evidence: %v\n", err)
				}

				vulns = append(vulns, models.Vulnerability{
					Title:       "Potential Credential Cracking Attempt Detected",
					Description: "No rate limit detected, credentials easily cracked",
					Category:    models.CategoryCredentialCracking,
					Severity:    models.High,
					URL:         target + path,
					Evidence:    evidence,
					Remediation: "Implement rate limiting, CAPTCHA, and account lockout",
				})
			}
		}
	}

	return vulns
}

// CheckScraping checks for content scraping attempts (OAT-011)
func CheckScraping(target string) []models.Vulnerability {
	var vulns []models.Vulnerability
	fmt.Println("Checking for scraping attempts...")

	// Create evidence collector
	evidenceColl, err := evidence.NewEvidenceCollector("evidence")
	if err != nil {
		fmt.Printf("Warning: Could not create evidence collector: %v\n", err)
		return vulns
	}

	// Test content endpoints
	for _, path := range contentRoutes {
		// Test with different user agents
		userAgents := []string{
			"", // Empty user agent
			"curl/7.64.1",
			"python-requests/2.25.1",
			"Go-http-client/1.1",
		}

		for _, ua := range userAgents {
			req, err := http.NewRequest("GET", target+path, nil)
			if err != nil {
				continue
			}
			if ua != "" {
				req.Header.Set("User-Agent", ua)
			}

			client := &http.Client{}
			resp, err := client.Do(req)
			if err != nil {
				continue
			}
			defer resp.Body.Close()

			// Check for scraping protection
			if resp.StatusCode == 400 || resp.StatusCode == 401 || resp.StatusCode == 403 || resp.StatusCode == 429 {
				evidence, err := evidenceColl.CollectEvidence(target+path, req, resp)
				if err != nil {
					fmt.Printf("Warning: Could not collect evidence: %v\n", err)
				}

				vulns = append(vulns, models.Vulnerability{
					Title:       "Potential Scraping Attempt Detected",
					Description: "Scraping protection detected on content endpoint",
					Category:    models.CategoryScraping,
					Severity:    models.Medium,
					URL:         target + path,
					Evidence:    evidence,
					Remediation: "Target implemented rate limiting, CAPTCHA, or user agent validation",
				})
			} else if resp.StatusCode >= 200 && resp.StatusCode < 300 {
				evidence, err := evidenceColl.CollectEvidence(target+path, req, resp)
				if err != nil {
					fmt.Printf("Warning: Could not collect evidence: %v\n", err)
				}

				vulns = append(vulns, models.Vulnerability{
					Title:       "Potential Scraping Attempt Detected",
					Description: "No scraping protection detected on content endpoint",
					Category:    models.CategoryScraping,
					Severity:    models.Medium,
					URL:         target + path,
					Evidence:    evidence,
					Remediation: "Implement rate limiting, CAPTCHA, and user agent validation",
				})
			}
		}
	}

	return vulns
}

// CheckVulnerabilityScanning checks for automated vulnerability scanning (OAT-014)
func CheckVulnerabilityScanning(target string) []models.Vulnerability {
	var vulns []models.Vulnerability
	fmt.Println("Checking for vulnerability scanning attempts...")

	// Create evidence collector
	evidenceColl, err := evidence.NewEvidenceCollector("evidence")
	if err != nil {
		fmt.Printf("Warning: Could not create evidence collector: %v\n", err)
		return vulns
	}

	// Common vulnerability scanning patterns
	// TODO: implement a wordlist
	patterns := []string{
		"../../etc/passwd",
		"' OR '1'='1",
		"<script>alert(1)</script>",
		"${jndi:ldap://",
		"../",
		"<!--#exec",
	}

	for _, path := range append(authRoutes, adminRoutes...) {
		for _, pattern := range patterns {
			req, err := http.NewRequest("GET", target+path+"?test="+pattern, nil)
			if err != nil {
				continue
			}

			client := &http.Client{}
			resp, err := client.Do(req)
			if err != nil {
				continue
			}
			defer resp.Body.Close()

			// Check for rate limiting or suspicious responses
			if resp.StatusCode == 429 || resp.StatusCode == 403 {
				evidence, err := evidenceColl.CollectEvidence(target+path, req, resp)
				if err != nil {
					fmt.Printf("Warning: Could not collect evidence: %v\n", err)
				}

				vulns = append(vulns, models.Vulnerability{
					Title:       "Potential Vulnerability Scanning Attempt Detected",
					Description: "Rate limiting or suspicious response detected on endpoint",
					Category:    models.CategoryVulnerabilityScanning,
					Severity:    models.High,
					URL:         target + path,
					Evidence:    evidence,
					Remediation: "Target implements some form of rate limiting, CAPTCHA, and input validation",
				})
			} else if resp.StatusCode >= 200 && resp.StatusCode < 300 {
				evidence, err := evidenceColl.CollectEvidence(target+path, req, resp)
				if err != nil {
					fmt.Printf("Warning: Could not collect evidence: %v\n", err)
				}

				vulns = append(vulns, models.Vulnerability{
					Title:       "Potential Vulnerability Scanning Attempt Detected",
					Description: "No rate limiting or suspicious response protection detected on endpoint",
					Category:    models.CategoryVulnerabilityScanning,
					Severity:    models.High,
					URL:         target + path,
					Evidence:    evidence,
					Remediation: "Implement some form of rate limiting, CAPTCHA, and input validation",
				})
			}
		}
	}

	return vulns
}

// CheckDenialOfService checks for DoS attempts (OAT-015)
func CheckDenialOfService(target string) []models.Vulnerability {
	var vulns []models.Vulnerability
	fmt.Println("Checking for denial of service attempts...")

	// Create evidence collector
	evidenceColl, err := evidence.NewEvidenceCollector("evidence")
	if err != nil {
		fmt.Printf("Warning: Could not create evidence collector: %v\n", err)
		return vulns
	}

	// Test endpoints with large payloads
	for _, path := range append(authRoutes, contentRoutes...) {
		// Create a large payload
		payload := strings.Repeat("A", 1024*1024) // 1MB payload

		req, err := http.NewRequest("POST", target+path, strings.NewReader(payload))
		if err != nil {
			continue
		}
		req.Header.Set("Content-Type", "application/json")

		client := &http.Client{}
		resp, err := client.Do(req)
		if err != nil {
			continue
		}
		defer resp.Body.Close()

		// Check for rate limiting or suspicious responses
		if resp.StatusCode == 429 || resp.StatusCode == 403 {
			evidence, err := evidenceColl.CollectEvidence(target+path, req, resp)
			if err != nil {
				fmt.Printf("Warning: Could not collect evidence: %v\n", err)
			}

			vulns = append(vulns, models.Vulnerability{
				Title:       "Potential Denial of Service Attempt Detected",
				Description: "Rate limiting or suspicious response protection detected on endpoint",
				Category:    models.CategoryDenialOfService,
				Severity:    models.High,
				URL:         target + path,
				Evidence:    evidence,
				Remediation: "Target implements rate limiting, request size limits, and DoS protection",
			})
		} else if resp.StatusCode >= 200 && resp.StatusCode < 300 {
			evidence, err := evidenceColl.CollectEvidence(target+path, req, resp)
			if err != nil {
				fmt.Printf("Warning: Could not collect evidence: %v\n", err)
			}

			vulns = append(vulns, models.Vulnerability{
				Title:       "Potential Denial of Service Attempt Detected",
				Description: "Rate limiting or suspicious response not detected on endpoint",
				Category:    models.CategoryDenialOfService,
				Severity:    models.High,
				URL:         target + path,
				Evidence:    evidence,
				Remediation: "Implement rate limiting, request size limits, and DoS protection",
			})
		}
	}

	return vulns
}

// CheckAccountCreation checks for automated account creation (OAT-019)
func CheckAccountCreation(target string) []models.Vulnerability {
	var vulns []models.Vulnerability
	fmt.Println("Checking for automated account creation attempts...")

	// Create evidence collector
	evidenceColl, err := evidence.NewEvidenceCollector("evidence")
	if err != nil {
		fmt.Printf("Warning: Could not create evidence collector: %v\n", err)
		return vulns
	}

	// Test registration endpoints
	for _, path := range authRoutes {
		// Test with sequential usernames
		for i := 0; i < 5; i++ {
			payload := fmt.Sprintf(`{"username":"test%d","password":"test123"}`, i)
			req, err := http.NewRequest("POST", target+path, strings.NewReader(payload))
			if err != nil {
				continue
			}
			req.Header.Set("Content-Type", "application/json")

			client := &http.Client{}
			resp, err := client.Do(req)
			if err != nil {
				continue
			}
			defer resp.Body.Close()

			// Check for rate limiting or suspicious responses
			if resp.StatusCode == 429 || resp.StatusCode == 403 {
				evidence, err := evidenceColl.CollectEvidence(target+path, req, resp)
				if err != nil {
					fmt.Printf("Warning: Could not collect evidence: %v\n", err)
				}

				vulns = append(vulns, models.Vulnerability{
					Title:       "Potential Automated Account Creation Attempt Detected",
					Description: "Rate limiting or suspicious response detected on registration endpoint",
					Category:    models.CategoryAccountCreation,
					Severity:    models.High,
					URL:         target + path,
					Evidence:    evidence,
					Remediation: "Implement rate limiting, CAPTCHA, and account creation validation",
				})
			} else if resp.StatusCode >= 200 && resp.StatusCode < 300 {
				evidence, err := evidenceColl.CollectEvidence(target+path, req, resp)
				if err != nil {
					fmt.Printf("Warning: Could not collect evidence: %v\n", err)
				}

				vulns = append(vulns, models.Vulnerability{
					Title:       "Potential Automated Account Creation Attempt Detected",
					Description: "Account creation allowed, no rate limiting or suspicious response not detected on endpoint",
					Category:    models.CategoryAccountCreation,
					Severity:    models.High,
					URL:         target + path,
					Evidence:    evidence,
					Remediation: "Implement mass account creating protection, rate limiting, request size limits, and DoS protection",
				})
			}
		}
	}

	return vulns
}

// CheckAdFraud checks for ad fraud attempts (OAT-003)
func CheckAdFraud(target string) []models.Vulnerability {
	var vulns []models.Vulnerability
	fmt.Println("Checking for ad fraud attempts...")

	// Create evidence collector
	evidenceColl, err := evidence.NewEvidenceCollector("evidence")
	if err != nil {
		fmt.Printf("Warning: Could not create evidence collector: %v\n", err)
		return vulns
	}

	// Common ad-related endpoints
	adEndpoints := []string{
		"/ads", "/advertisements", "/banners",
		"/tracking", "/analytics", "/pixel",
		"/impression", "/click", "/conversion",
	}

	for _, path := range adEndpoints {
		// Test with suspicious user agents and IPs
		userAgents := []string{
			"", // Empty user agent
			"curl/7.64.1",
			"python-requests/2.25.1",
			"Go-http-client/1.1",
		}

		for _, ua := range userAgents {
			req, err := http.NewRequest("GET", target+path, nil)
			if err != nil {
				continue
			}
			if ua != "" {
				req.Header.Set("User-Agent", ua)
			}

			// Add suspicious headers
			req.Header.Set("X-Forwarded-For", "1.1.1.1")
			req.Header.Set("X-Real-IP", "1.1.1.1")
			req.Header.Set("CF-Connecting-IP", "1.1.1.1")

			client := &http.Client{}
			resp, err := client.Do(req)
			if err != nil {
				continue
			}
			defer resp.Body.Close()

			// Check for ad fraud protection
			if resp.StatusCode == 400 || resp.StatusCode == 401 || resp.StatusCode == 403 || resp.StatusCode == 429 {
				evidence, err := evidenceColl.CollectEvidence(target+path, req, resp)
				if err != nil {
					fmt.Printf("Warning: Could not collect evidence: %v\n", err)
				}

				vulns = append(vulns, models.Vulnerability{
					Title:       "Potential Ad Fraud Attempt Detected",
					Description: "Ad fraud protection detected on ad endpoint",
					Category:    models.CategoryAdFraud,
					Severity:    models.High,
					URL:         target + path,
					Evidence:    evidence,
					Remediation: "Implement ad fraud detection, rate limiting, and user agent validation",
				})
			} else if resp.StatusCode >= 200 && resp.StatusCode < 300 {
				evidence, err := evidenceColl.CollectEvidence(target+path, req, resp)
				if err != nil {
					fmt.Printf("Warning: Could not collect evidence: %v\n", err)
				}

				vulns = append(vulns, models.Vulnerability{
					Title:       "Potential Ad Fraud Attempt Detected",
					Description: "No Ad fraude protection detected on ad endpoint",
					Category:    models.CategoryAdFraud,
					Severity:    models.High,
					URL:         target + path,
					Evidence:    evidence,
					Remediation: "Implement ad fraud detection, rate limiting, request size limits, and user agent validation",
				})
			}
		}
	}

	return vulns
}

// CheckFingerprinting checks for fingerprinting attempts (OAT-004)
func CheckFingerprinting(target string) []models.Vulnerability {
	var vulns []models.Vulnerability
	fmt.Println("Checking for fingerprinting attempts...")

	// Create evidence collector
	evidenceColl, err := evidence.NewEvidenceCollector("evidence")
	if err != nil {
		fmt.Printf("Warning: Could not create evidence collector: %v\n", err)
		return vulns
	}

	// Common fingerprinting endpoints
	fingerprintingEndpoints := []string{
		"/", "/robots.txt", "/sitemap.xml",
		"/.git/", "/.env", "/wp-config.php",
		"/server-status", "/phpinfo.php",
		"/admin", "/administrator",
	}

	for _, path := range fingerprintingEndpoints {
		// Test with different HTTP methods
		methods := []string{"GET", "HEAD", "OPTIONS", "TRACE"}

		for _, method := range methods {
			req, err := http.NewRequest(method, target+path, nil)
			if err != nil {
				continue
			}

			// Add suspicious headers
			req.Header.Set("X-Forwarded-For", "1.1.1.1")
			req.Header.Set("X-Real-IP", "1.1.1.1")
			req.Header.Set("CF-Connecting-IP", "1.1.1.1")

			client := &http.Client{}
			resp, err := client.Do(req)
			if err != nil {
				continue
			}
			defer resp.Body.Close()

			// Check for fingerprinting protection
			if resp.StatusCode == 400 || resp.StatusCode == 401 || resp.StatusCode == 403 || resp.StatusCode == 429 {
				evidence, err := evidenceColl.CollectEvidence(target+path, req, resp)
				if err != nil {
					fmt.Printf("Warning: Could not collect evidence: %v\n", err)
				}

				vulns = append(vulns, models.Vulnerability{
					Title:       "Potential Fingerprinting Attempt Detected",
					Description: "Fingerprinting protection detected on endpoint",
					Category:    models.CategoryFingerprinting,
					Severity:    models.Medium,
					URL:         target + path,
					Evidence:    evidence,
					Remediation: "Endpoint implements fingerprinting protection, rate limiting, and request validation",
				})
			} else if resp.StatusCode >= 200 || resp.StatusCode < 300 {
				evidence, err := evidenceColl.CollectEvidence(target+path, req, resp)
				if err != nil {
					fmt.Printf("Warning: Could not collect evidence: %v\n", err)
				}

				vulns = append(vulns, models.Vulnerability{
					Title:       "Potential Fingerprinting Attempt Detected",
					Description: "No fingerprinting protection detected on endpoint",
					Category:    models.CategoryFingerprinting,
					Severity:    models.Medium,
					URL:         target + path,
					Evidence:    evidence,
					Remediation: "Implement fingerprinting protection, rate limiting, and request validation",
				})
			}
		}
	}

	return vulns
}

// CheckScalping checks for scalping attempts (OAT-005)
func CheckScalping(target string) []models.Vulnerability {
	var vulns []models.Vulnerability
	fmt.Println("Checking for scalping attempts...")

	// Create evidence collector
	evidenceColl, err := evidence.NewEvidenceCollector("evidence")
	if err != nil {
		fmt.Printf("Warning: Could not create evidence collector: %v\n", err)
		return vulns
	}

	// Common scalping endpoints
	// TODO: implement wordlists
	scalpingEndpoints := []string{
		"/products", "/tickets", "/events",
		"/inventory", "/stock", "/availability",
		"/checkout", "/cart", "/basket",
	}

	for _, path := range scalpingEndpoints {
		// Test with rapid requests
		for i := 0; i < 5; i++ {
			req, err := http.NewRequest("GET", target+path, nil)
			if err != nil {
				continue
			}

			// Add suspicious headers
			req.Header.Set("X-Forwarded-For", "1.1.1.1")
			req.Header.Set("X-Real-IP", "1.1.1.1")
			req.Header.Set("CF-Connecting-IP", "1.1.1.1")

			client := &http.Client{}
			resp, err := client.Do(req)
			if err != nil {
				continue
			}
			defer resp.Body.Close()

			// Check for scalping protection
			if resp.StatusCode == 400 || resp.StatusCode == 401 || resp.StatusCode == 403 || resp.StatusCode == 429 {
				evidence, err := evidenceColl.CollectEvidence(target+path, req, resp)
				if err != nil {
					fmt.Printf("Warning: Could not collect evidence: %v\n", err)
				}

				vulns = append(vulns, models.Vulnerability{
					Title:       "Potential Scalping Attempt Detected",
					Description: "Scalping protection detected on endpoint",
					Category:    models.CategoryScalping,
					Severity:    models.High,
					URL:         target + path,
					Evidence:    evidence,
					Remediation: "Endpoint implements scalping protection, rate limiting, and purchase limits",
				})
			} else if resp.StatusCode >= 200 || resp.StatusCode < 300 {
				evidence, err := evidenceColl.CollectEvidence(target+path, req, resp)
				if err != nil {
					fmt.Printf("Warning: Could not collect evidence: %v\n", err)
				}

				vulns = append(vulns, models.Vulnerability{
					Title:       "Potential Scalping Attempt Detected",
					Description: "No scalping protection detected on endpoint",
					Category:    models.CategoryScalping,
					Severity:    models.High,
					URL:         target + path,
					Evidence:    evidence,
					Remediation: "Implement scalping protection, rate limiting, and purchase limits",
				})
			}

			// Add a small delay between requests
			time.Sleep(100 * time.Millisecond)
		}
	}

	return vulns
}

// CheckExpediting checks for expediting attempts (OAT-006)
func CheckExpediting(target string) []models.Vulnerability {
	var vulns []models.Vulnerability
	fmt.Println("Checking for expediting attempts...")

	// Create evidence collector
	evidenceColl, err := evidence.NewEvidenceCollector("evidence")
	if err != nil {
		fmt.Printf("Warning: Could not create evidence collector: %v\n", err)
		return vulns
	}

	// Common expediting endpoints
	expeditingEndpoints := []string{
		"/checkout", "/cart", "/basket",
		"/shipping", "/delivery", "/express",
		"/priority", "/rush", "/fast-track",
	}

	for _, path := range expeditingEndpoints {
		// Test with different shipping methods
		shippingMethods := []string{
			"express", "priority", "rush",
			"overnight", "same-day", "fast-track",
		}

		for _, method := range shippingMethods {
			payload := fmt.Sprintf(`{"shipping_method":"%s"}`, method)
			req, err := http.NewRequest("POST", target+path, strings.NewReader(payload))
			if err != nil {
				continue
			}
			req.Header.Set("Content-Type", "application/json")

			// Add suspicious headers
			req.Header.Set("X-Forwarded-For", "1.1.1.1")
			req.Header.Set("X-Real-IP", "1.1.1.1")
			req.Header.Set("CF-Connecting-IP", "1.1.1.1")

			client := &http.Client{}
			resp, err := client.Do(req)
			if err != nil {
				continue
			}
			defer resp.Body.Close()

			// Check for expediting protection
			if resp.StatusCode == 400 || resp.StatusCode == 401 || resp.StatusCode == 403 || resp.StatusCode == 429 {
				evidence, err := evidenceColl.CollectEvidence(target+path, req, resp)
				if err != nil {
					fmt.Printf("Warning: Could not collect evidence: %v\n", err)
				}

				vulns = append(vulns, models.Vulnerability{
					Title:       "Potential Expediting Attempt Detected",
					Description: "Expediting protection detected on endpoint",
					Category:    models.CategoryExpediting,
					Severity:    models.Medium,
					URL:         target + path,
					Evidence:    evidence,
					Remediation: "Endpoint implements expediting protection, rate limiting, and shipping method validation",
				})
			} else if resp.StatusCode >= 403 || resp.StatusCode < 300 {
				evidence, err := evidenceColl.CollectEvidence(target+path, req, resp)
				if err != nil {
					fmt.Printf("Warning: Could not collect evidence: %v\n", err)
				}

				vulns = append(vulns, models.Vulnerability{
					Title:       "Potential Expediting Attempt Detected",
					Description: "No Expediting protection detected on endpoint",
					Category:    models.CategoryExpediting,
					Severity:    models.Medium,
					URL:         target + path,
					Evidence:    evidence,
					Remediation: "Implement expediting protection, rate limiting, and shipping method validation",
				})
			}

			// Add a small delay between requests
			time.Sleep(100 * time.Millisecond)
		}
	}

	return vulns
}

// CheckCredentialStuffing checks for credential stuffing attempts (OAT-008)
func CheckCredentialStuffing(target string) []models.Vulnerability {
	var vulns []models.Vulnerability
	fmt.Println("Checking for credential stuffing attempts...")

	// Create evidence collector
	evidenceColl, err := evidence.NewEvidenceCollector("evidence")
	if err != nil {
		fmt.Printf("Warning: Could not create evidence collector: %v\n", err)
		return vulns
	}

	// Test login endpoints
	// TODO: implement wordlist for endpoints and user/pass pairs
	for _, path := range authRoutes {
		// Common credential pairs from known breaches
		credentials := []struct {
			username string
			password string
		}{
			{"admin", "admin"},
			{"admin", "password"},
			{"admin", "123456"},
			{"admin", "qwerty"},
			{"admin", "letmein"},
			{"admin", "welcome"},
			{"admin", "admin123"},
			{"admin", "password123"},
			{"admin", "admin1234"},
			{"admin", "admin12345"},
		}

		for _, cred := range credentials {
			payload := fmt.Sprintf(`{"username":"%s","password":"%s"}`, cred.username, cred.password)
			req, err := http.NewRequest("POST", target+path, strings.NewReader(payload))
			if err != nil {
				continue
			}
			req.Header.Set("Content-Type", "application/json")

			// Add suspicious headers
			req.Header.Set("X-Forwarded-For", "1.1.1.1")
			req.Header.Set("X-Real-IP", "1.1.1.1")
			req.Header.Set("CF-Connecting-IP", "1.1.1.1")

			client := &http.Client{}
			resp, err := client.Do(req)
			if err != nil {
				continue
			}
			defer resp.Body.Close()

			// Check for credential stuffing protection
			if resp.StatusCode == 400 || resp.StatusCode == 401 || resp.StatusCode == 403 || resp.StatusCode == 429 {
				evidence, err := evidenceColl.CollectEvidence(target+path, req, resp)
				if err != nil {
					fmt.Printf("Warning: Could not collect evidence: %v\n", err)
				}

				vulns = append(vulns, models.Vulnerability{
					Title:       "Potential Credential Stuffing Attempt Detected",
					Description: "Credential stuffing protection detected on login endpoint",
					Category:    models.CategoryCredentialStuffing,
					Severity:    models.High,
					URL:         target + path,
					Evidence:    evidence,
					Remediation: "Endpoint implements credential stuffing protection, rate limiting, and account lockout",
				})
			} else if resp.StatusCode >= 200 || resp.StatusCode < 300 {
				evidence, err := evidenceColl.CollectEvidence(target+path, req, resp)
				if err != nil {
					fmt.Printf("Warning: Could not collect evidence: %v\n", err)
				}

				vulns = append(vulns, models.Vulnerability{
					Title:       "Potential Credential Stuffing Attempt Detected",
					Description: "No Credential stuffing protection detected on login endpoint",
					Category:    models.CategoryCredentialStuffing,
					Severity:    models.High,
					URL:         target + path,
					Evidence:    evidence,
					Remediation: "Implement credential stuffing protection, rate limiting, and account lockout",
				})
			}

			// Add a small delay between requests
			time.Sleep(100 * time.Millisecond)
		}
	}

	return vulns
}

// CheckCAPTCHADefeat checks for CAPTCHA defeat attempts (OAT-009)
func CheckCAPTCHADefeat(target string) []models.Vulnerability {
	var vulns []models.Vulnerability
	fmt.Println("Checking for CAPTCHA defeat attempts...")

	// Create evidence collector
	evidenceColl, err := evidence.NewEvidenceCollector("evidence")
	if err != nil {
		fmt.Printf("Warning: Could not create evidence collector: %v\n", err)
		return vulns
	}

	// Common CAPTCHA endpoints
	captchaEndpoints := []string{
		"/captcha", "/verify", "/validate",
		"/recaptcha", "/hcaptcha", "/turnstile",
	}

	for _, path := range captchaEndpoints {
		// Test with different CAPTCHA bypass techniques
		bypassTechniques := []string{
			"",         // Empty CAPTCHA
			"1234",     // Simple numeric
			"test",     // Simple text
			"bypass",   // Common bypass word
			"captcha",  // Common bypass word
			"verify",   // Common bypass word
			"validate", // Common bypass word
		}

		for _, technique := range bypassTechniques {
			payload := fmt.Sprintf(`{"captcha":"%s"}`, technique)
			req, err := http.NewRequest("POST", target+path, strings.NewReader(payload))
			if err != nil {
				continue
			}
			req.Header.Set("Content-Type", "application/json")

			// Add suspicious headers
			req.Header.Set("X-Forwarded-For", "1.1.1.1")
			req.Header.Set("X-Real-IP", "1.1.1.1")
			req.Header.Set("CF-Connecting-IP", "1.1.1.1")

			client := &http.Client{}
			resp, err := client.Do(req)
			if err != nil {
				continue
			}
			defer resp.Body.Close()

			// Check for CAPTCHA defeat protection
			if resp.StatusCode == 400 || resp.StatusCode == 401 || resp.StatusCode == 403 || resp.StatusCode == 429 {
				evidence, err := evidenceColl.CollectEvidence(target+path, req, resp)
				if err != nil {
					fmt.Printf("Warning: Could not collect evidence: %v\n", err)
				}

				vulns = append(vulns, models.Vulnerability{
					Title:       "Potential CAPTCHA Defeat Attempt Detected",
					Description: "CAPTCHA defeat protection detected on endpoint",
					Category:    models.CategoryCAPTCHADefeat,
					Severity:    models.High,
					URL:         target + path,
					Evidence:    evidence,
					Remediation: "Endpoint implements CAPTCHA defeat protection, rate limiting, and CAPTCHA validation",
				})
			} else if resp.StatusCode >= 200 || resp.StatusCode < 300 {
				evidence, err := evidenceColl.CollectEvidence(target+path, req, resp)
				if err != nil {
					fmt.Printf("Warning: Could not collect evidence: %v\n", err)
				}

				vulns = append(vulns, models.Vulnerability{
					Title:       "Potential CAPTCHA Defeat Attempt Detected",
					Description: "No CAPTCHA defeat protection detected on endpoint",
					Category:    models.CategoryCAPTCHADefeat,
					Severity:    models.High,
					URL:         target + path,
					Evidence:    evidence,
					Remediation: "Implement CAPTCHA defeat protection, rate limiting, and CAPTCHA validation",
				})
			}

			// Add a small delay between requests
			time.Sleep(100 * time.Millisecond)
		}
	}

	return vulns
}

// CheckCardCracking checks for card cracking attempts (OAT-010)
func CheckCardCracking(target string) []models.Vulnerability {
	var vulns []models.Vulnerability
	fmt.Println("Checking for card cracking attempts...")

	// Create evidence collector
	evidenceColl, err := evidence.NewEvidenceCollector("evidence")
	if err != nil {
		fmt.Printf("Warning: Could not create evidence collector: %v\n", err)
		return vulns
	}

	// Test payment endpoints
	for _, path := range paymentRoutes {
		// Test with known BIN patterns and sequential CVVs
		binPatterns := []string{
			"4111111111111111", // Visa
			"4242424242424242", // Visa
			"5555555555554444", // Mastercard
			"378282246310005",  // Amex
			"371449635398431",  // Amex
		}

		for _, bin := range binPatterns {
			// Test with sequential CVVs
			for cvv := 100; cvv < 105; cvv++ {
				payload := fmt.Sprintf(`{"card_number":"%s","expiry":"12/25","cvv":"%d"}`, bin, cvv)
				req, err := http.NewRequest("POST", target+path, strings.NewReader(payload))
				if err != nil {
					continue
				}
				req.Header.Set("Content-Type", "application/json")

				// Add suspicious headers
				req.Header.Set("X-Forwarded-For", "1.1.1.1")
				req.Header.Set("X-Real-IP", "1.1.1.1")
				req.Header.Set("CF-Connecting-IP", "1.1.1.1")

				client := &http.Client{}
				resp, err := client.Do(req)
				if err != nil {
					continue
				}
				defer resp.Body.Close()

				// Check for card cracking protection
				if resp.StatusCode == 400 || resp.StatusCode == 401 || resp.StatusCode == 403 || resp.StatusCode == 429 {
					evidence, err := evidenceColl.CollectEvidence(target+path, req, resp)
					if err != nil {
						fmt.Printf("Warning: Could not collect evidence: %v\n", err)
					}

					vulns = append(vulns, models.Vulnerability{
						Title:       "Potential Card Cracking Attempt Detected",
						Description: "Card cracking protection detected on payment endpoint",
						Category:    models.CategoryCardCracking,
						Severity:    models.High,
						URL:         target + path,
						Evidence:    evidence,
						Remediation: "Endpoint implements card cracking protection, rate limiting, and card validation checks",
					})
				} else if resp.StatusCode >= 200 || resp.StatusCode < 300 {
					evidence, err := evidenceColl.CollectEvidence(target+path, req, resp)
					if err != nil {
						fmt.Printf("Warning: Could not collect evidence: %v\n", err)
					}

					vulns = append(vulns, models.Vulnerability{
						Title:       "Potential Card Cracking Attempt Detected",
						Description: "No card cracking protection detected on payment endpoint",
						Category:    models.CategoryCardCracking,
						Severity:    models.High,
						URL:         target + path,
						Evidence:    evidence,
						Remediation: "Implement card cracking protection, rate limiting, and card validation checks",
					})
				}

				// Add a small delay between requests
				time.Sleep(100 * time.Millisecond)
			}
		}
	}

	return vulns
}

// CheckCashingOut checks for cashing out attempts (OAT-012)
func CheckCashingOut(target string) []models.Vulnerability {
	var vulns []models.Vulnerability
	fmt.Println("Checking for cashing out attempts...")

	// Create evidence collector
	evidenceColl, err := evidence.NewEvidenceCollector("evidence")
	if err != nil {
		fmt.Printf("Warning: Could not create evidence collector: %v\n", err)
		return vulns
	}

	// Common cashing out endpoints
	// TODO: implement wordlist
	cashingOutEndpoints := []string{
		"/withdraw", "/cashout", "/payout",
		"/transfer", "/send", "/withdrawal",
		"/redeem", "/convert", "/exchange",
	}

	for _, path := range cashingOutEndpoints {
		// Test with different amounts and currencies
		amounts := []string{
			"1000", "5000", "10000",
			"50000", "100000", "500000",
		}

		currencies := []string{
			"USD", "EUR", "GBP",
			"JPY", "AUD", "CAD",
			"BRL", "BTC",
		}

		for _, amount := range amounts {
			for _, currency := range currencies {
				payload := fmt.Sprintf(`{"amount":"%s","currency":"%s"}`, amount, currency)
				req, err := http.NewRequest("POST", target+path, strings.NewReader(payload))
				if err != nil {
					continue
				}
				req.Header.Set("Content-Type", "application/json")

				// Add suspicious headers
				req.Header.Set("X-Forwarded-For", "1.1.1.1")
				req.Header.Set("X-Real-IP", "1.1.1.1")
				req.Header.Set("CF-Connecting-IP", "1.1.1.1")

				client := &http.Client{}
				resp, err := client.Do(req)
				if err != nil {
					continue
				}
				defer resp.Body.Close()

				// Check for cashing out protection
				if resp.StatusCode == 400 || resp.StatusCode == 401 || resp.StatusCode == 403 || resp.StatusCode == 429 {
					evidence, err := evidenceColl.CollectEvidence(target+path, req, resp)
					if err != nil {
						fmt.Printf("Warning: Could not collect evidence: %v\n", err)
					}

					vulns = append(vulns, models.Vulnerability{
						Title:       "Potential Cashing Out Attempt Detected",
						Description: "Cashing out protection detected on endpoint",
						Category:    models.CategoryCashingOut,
						Severity:    models.High,
						URL:         target + path,
						Evidence:    evidence,
						Remediation: "Endpoint implements cashing out protection, rate limiting, and amount validation",
					})
				} else if resp.StatusCode >= 200 || resp.StatusCode < 300 {
					evidence, err := evidenceColl.CollectEvidence(target+path, req, resp)
					if err != nil {
						fmt.Printf("Warning: Could not collect evidence: %v\n", err)
					}

					vulns = append(vulns, models.Vulnerability{
						Title:       "Potential Cashing Out Attempt Detected",
						Description: "No cashing out protection detected on endpoint",
						Category:    models.CategoryCashingOut,
						Severity:    models.High,
						URL:         target + path,
						Evidence:    evidence,
						Remediation: "Implement cashing out protection, rate limiting, and amount validation",
					})
				}

				// Add a small delay between requests
				time.Sleep(100 * time.Millisecond)
			}
		}
	}

	return vulns
}

// CheckSniping checks for sniping attempts (OAT-013)
func CheckSniping(target string) []models.Vulnerability {
	var vulns []models.Vulnerability
	fmt.Println("Checking for sniping attempts...")

	// Create evidence collector
	evidenceColl, err := evidence.NewEvidenceCollector("evidence")
	if err != nil {
		fmt.Printf("Warning: Could not create evidence collector: %v\n", err)
		return vulns
	}

	// Common sniping endpoints
	snipingEndpoints := []string{
		"/auctions", "/bids", "/offers",
		"/listings", "/items", "/products",
		"/buy", "/purchase", "/checkout",
	}

	for _, path := range snipingEndpoints {
		// Test with rapid requests
		for i := 0; i < 5; i++ {
			// Test with different bid amounts
			amounts := []string{
				"100", "200", "300",
				"400", "500", "600",
			}

			for _, amount := range amounts {
				payload := fmt.Sprintf(`{"amount":"%s"}`, amount)
				req, err := http.NewRequest("POST", target+path, strings.NewReader(payload))
				if err != nil {
					continue
				}
				req.Header.Set("Content-Type", "application/json")

				// Add suspicious headers
				req.Header.Set("X-Forwarded-For", "1.1.1.1")
				req.Header.Set("X-Real-IP", "1.1.1.1")
				req.Header.Set("CF-Connecting-IP", "1.1.1.1")

				client := &http.Client{}
				resp, err := client.Do(req)
				if err != nil {
					continue
				}
				defer resp.Body.Close()

				// Check for sniping protection
				if resp.StatusCode == 400 || resp.StatusCode == 401 || resp.StatusCode == 403 || resp.StatusCode == 429 {
					evidence, err := evidenceColl.CollectEvidence(target+path, req, resp)
					if err != nil {
						fmt.Printf("Warning: Could not collect evidence: %v\n", err)
					}

					vulns = append(vulns, models.Vulnerability{
						Title:       "Potential Sniping Attempt Detected",
						Description: "Sniping protection detected on endpoint",
						Category:    models.CategorySniping,
						Severity:    models.High,
						URL:         target + path,
						Evidence:    evidence,
						Remediation: "Endpoint implements sniping protection, rate limiting, and bid validation",
					})
				} else if resp.StatusCode >= 200 || resp.StatusCode < 300 {
					evidence, err := evidenceColl.CollectEvidence(target+path, req, resp)
					if err != nil {
						fmt.Printf("Warning: Could not collect evidence: %v\n", err)
					}

					vulns = append(vulns, models.Vulnerability{
						Title:       "Potential Sniping Attempt Detected",
						Description: "No sniping protection detected on endpoint",
						Category:    models.CategorySniping,
						Severity:    models.High,
						URL:         target + path,
						Evidence:    evidence,
						Remediation: "Implement sniping protection, rate limiting, and bid validation",
					})
				}

				// Add a small delay between requests
				time.Sleep(100 * time.Millisecond)
			}
		}
	}

	return vulns
}

// CheckSkewing checks for skewing attempts (OAT-016)
func CheckSkewing(target string) []models.Vulnerability {
	var vulns []models.Vulnerability
	fmt.Println("Checking for skewing attempts...")

	// Create evidence collector
	evidenceColl, err := evidence.NewEvidenceCollector("evidence")
	if err != nil {
		fmt.Printf("Warning: Could not create evidence collector: %v\n", err)
		return vulns
	}

	// Common skewing endpoints
	skewingEndpoints := []string{
		"/ratings", "/reviews", "/feedback",
		"/comments", "/votes", "/likes",
		"/stars", "/score", "/rating",
	}

	for _, path := range skewingEndpoints {
		// Test with different ratings
		ratings := []string{
			"1", "2", "3", "4", "5",
			"10", "20", "30", "40", "50",
		}

		for _, rating := range ratings {
			payload := fmt.Sprintf(`{"rating":"%s"}`, rating)
			req, err := http.NewRequest("POST", target+path, strings.NewReader(payload))
			if err != nil {
				continue
			}
			req.Header.Set("Content-Type", "application/json")

			// Add suspicious headers
			req.Header.Set("X-Forwarded-For", "1.1.1.1")
			req.Header.Set("X-Real-IP", "1.1.1.1")
			req.Header.Set("CF-Connecting-IP", "1.1.1.1")

			client := &http.Client{}
			resp, err := client.Do(req)
			if err != nil {
				continue
			}
			defer resp.Body.Close()

			// Check for skewing protection
			if resp.StatusCode == 400 || resp.StatusCode == 401 || resp.StatusCode == 403 || resp.StatusCode == 429 {
				evidence, err := evidenceColl.CollectEvidence(target+path, req, resp)
				if err != nil {
					fmt.Printf("Warning: Could not collect evidence: %v\n", err)
				}

				vulns = append(vulns, models.Vulnerability{
					Title:       "Potential Skewing Attempt Detected",
					Description: "Skewing protection detected on endpoint",
					Category:    models.CategorySkewing,
					Severity:    models.Medium,
					URL:         target + path,
					Evidence:    evidence,
					Remediation: "Endpoint implements skewing protection, rate limiting, and rating validation",
				})
			} else if resp.StatusCode >= 200 || resp.StatusCode < 300 {
				evidence, err := evidenceColl.CollectEvidence(target+path, req, resp)
				if err != nil {
					fmt.Printf("Warning: Could not collect evidence: %v\n", err)
				}

				vulns = append(vulns, models.Vulnerability{
					Title:       "Potential Skewing Attempt Detected",
					Description: "No skewing protection detected on endpoint",
					Category:    models.CategorySkewing,
					Severity:    models.Medium,
					URL:         target + path,
					Evidence:    evidence,
					Remediation: "Implement skewing protection, rate limiting, and rating validation",
				})
			}

			// Add a small delay between requests
			time.Sleep(100 * time.Millisecond)
		}
	}

	return vulns
}

// CheckSpamming checks for spamming attempts (OAT-017)
func CheckSpamming(target string) []models.Vulnerability {
	var vulns []models.Vulnerability
	fmt.Println("Checking for spamming attempts...")

	// Create evidence collector
	evidenceColl, err := evidence.NewEvidenceCollector("evidence")
	if err != nil {
		fmt.Printf("Warning: Could not create evidence collector: %v\n", err)
		return vulns
	}

	// Common spamming endpoints
	spammingEndpoints := []string{
		"/contact", "/feedback", "/support",
		"/message", "/comment", "/post",
		"/submit", "/form", "/survey",
	}

	for _, path := range spammingEndpoints {
		// Test with different spam content
		spamContent := []string{
			"Buy cheap viagra", "Make money fast",
			"Free iphone", "Win lottery",
			"Click here", "Special offer",
			"Limited time", "Act now",
			"Urgent", "Important",
		}

		for _, content := range spamContent {
			payload := fmt.Sprintf(`{"message":"%s"}`, content)
			req, err := http.NewRequest("POST", target+path, strings.NewReader(payload))
			if err != nil {
				continue
			}
			req.Header.Set("Content-Type", "application/json")

			// Add suspicious headers
			req.Header.Set("X-Forwarded-For", "1.1.1.1")
			req.Header.Set("X-Real-IP", "1.1.1.1")
			req.Header.Set("CF-Connecting-IP", "1.1.1.1")

			client := &http.Client{}
			resp, err := client.Do(req)
			if err != nil {
				continue
			}
			defer resp.Body.Close()

			// Check for spamming protection
			if resp.StatusCode == 400 || resp.StatusCode == 401 || resp.StatusCode == 403 || resp.StatusCode == 429 {
				evidence, err := evidenceColl.CollectEvidence(target+path, req, resp)
				if err != nil {
					fmt.Printf("Warning: Could not collect evidence: %v\n", err)
				}

				vulns = append(vulns, models.Vulnerability{
					Title:       "Potential Spamming Attempt Detected",
					Description: "Spamming protection detected on endpoint",
					Category:    models.CategorySpamming,
					Severity:    models.Medium,
					URL:         target + path,
					Evidence:    evidence,
					Remediation: "Endpoint implements spamming protection, rate limiting, and content validation",
				})
			} else if resp.StatusCode >= 200 || resp.StatusCode < 300 {
				evidence, err := evidenceColl.CollectEvidence(target+path, req, resp)
				if err != nil {
					fmt.Printf("Warning: Could not collect evidence: %v\n", err)
				}

				vulns = append(vulns, models.Vulnerability{
					Title:       "Potential Spamming Attempt Detected",
					Description: "No spamming protection detected on endpoint",
					Category:    models.CategorySpamming,
					Severity:    models.Medium,
					URL:         target + path,
					Evidence:    evidence,
					Remediation: "Implement spamming protection, rate limiting, and content validation",
				})
			}

			// Add a small delay between requests
			time.Sleep(100 * time.Millisecond)
		}
	}

	return vulns
}

// CheckFootprinting checks for footprinting attempts (OAT-018)
func CheckFootprinting(target string) []models.Vulnerability {
	var vulns []models.Vulnerability
	fmt.Println("Checking for footprinting attempts...")

	// Create evidence collector
	evidenceColl, err := evidence.NewEvidenceCollector("evidence")
	if err != nil {
		fmt.Printf("Warning: Could not create evidence collector: %v\n", err)
		return vulns
	}

	// Common footprinting endpoints
	footprintingEndpoints := []string{
		"/", "/robots.txt", "/sitemap.xml",
		"/.git/", "/.env", "/wp-config.php",
		"/server-status", "/phpinfo.php",
		"/admin", "/administrator",
		"/api", "/api/v1", "/api/v2",
		"/swagger", "/swagger-ui", "/docs",
		"/graphql", "/graphiql", "/playground",
	}

	for _, path := range footprintingEndpoints {
		// Test with different HTTP methods
		methods := []string{"GET", "HEAD", "OPTIONS", "TRACE"}

		for _, method := range methods {
			req, err := http.NewRequest(method, target+path, nil)
			if err != nil {
				continue
			}

			// Add suspicious headers
			req.Header.Set("X-Forwarded-For", "1.1.1.1")
			req.Header.Set("X-Real-IP", "1.1.1.1")
			req.Header.Set("CF-Connecting-IP", "1.1.1.1")

			client := &http.Client{}
			resp, err := client.Do(req)
			if err != nil {
				continue
			}
			defer resp.Body.Close()

			// Check for footprinting protection
			if resp.StatusCode == 400 || resp.StatusCode == 401 || resp.StatusCode == 403 || resp.StatusCode == 429 {
				evidence, err := evidenceColl.CollectEvidence(target+path, req, resp)
				if err != nil {
					fmt.Printf("Warning: Could not collect evidence: %v\n", err)
				}

				vulns = append(vulns, models.Vulnerability{
					Title:       "Potential Footprinting Attempt Detected",
					Description: "Footprinting protection detected on endpoint",
					Category:    models.CategoryFootprinting,
					Severity:    models.Medium,
					URL:         target + path,
					Evidence:    evidence,
					Remediation: "Endpoint implements footprinting protection, rate limiting, and request validation",
				})
			} else if resp.StatusCode >= 200 || resp.StatusCode < 300 {
				evidence, err := evidenceColl.CollectEvidence(target+path, req, resp)
				if err != nil {
					fmt.Printf("Warning: Could not collect evidence: %v\n", err)
				}

				vulns = append(vulns, models.Vulnerability{
					Title:       "Potential Footprinting Attempt Detected",
					Description: "No footprinting protection detected on endpoint",
					Category:    models.CategoryFootprinting,
					Severity:    models.Medium,
					URL:         target + path,
					Evidence:    evidence,
					Remediation: "Implement footprinting protection, rate limiting, and request validation",
				})
			}

			// Add a small delay between requests
			time.Sleep(100 * time.Millisecond)
		}
	}

	return vulns
}

// CheckAccountAggregation checks for account aggregation attempts (OAT-020)
func CheckAccountAggregation(target string) []models.Vulnerability {
	var vulns []models.Vulnerability
	fmt.Println("Checking for account aggregation attempts...")

	// Create evidence collector
	evidenceColl, err := evidence.NewEvidenceCollector("evidence")
	if err != nil {
		fmt.Printf("Warning: Could not create evidence collector: %v\n", err)
		return vulns
	}

	// Common account aggregation endpoints
	accountAggregationEndpoints := []string{
		"/accounts", "/users", "/profiles",
		"/members", "/customers", "/clients",
		"/api/accounts", "/api/users", "/api/profiles",
	}

	for _, path := range accountAggregationEndpoints {
		// Test with different query parameters
		queryParams := []string{
			"limit=100", "limit=1000", "limit=10000",
			"offset=0", "offset=100", "offset=1000",
			"page=1", "page=2", "page=3",
		}

		for _, param := range queryParams {
			req, err := http.NewRequest("GET", target+path+"?"+param, nil)
			if err != nil {
				continue
			}

			// Add suspicious headers
			req.Header.Set("X-Forwarded-For", "1.1.1.1")
			req.Header.Set("X-Real-IP", "1.1.1.1")
			req.Header.Set("CF-Connecting-IP", "1.1.1.1")

			client := &http.Client{}
			resp, err := client.Do(req)
			if err != nil {
				continue
			}
			defer resp.Body.Close()

			// Check for account aggregation protection
			if resp.StatusCode == 400 || resp.StatusCode == 401 || resp.StatusCode == 403 || resp.StatusCode == 429 {
				evidence, err := evidenceColl.CollectEvidence(target+path, req, resp)
				if err != nil {
					fmt.Printf("Warning: Could not collect evidence: %v\n", err)
				}

				vulns = append(vulns, models.Vulnerability{
					Title:       "Potential Account Aggregation Attempt Detected",
					Description: "Account aggregation protection detected on endpoint",
					Category:    models.CategoryAccountAggregation,
					Severity:    models.High,
					URL:         target + path,
					Evidence:    evidence,
					Remediation: "Endpoint implements account aggregation protection, rate limiting, and access control",
				})
			} else if resp.StatusCode >= 200 || resp.StatusCode < 300 {
				evidence, err := evidenceColl.CollectEvidence(target+path, req, resp)
				if err != nil {
					fmt.Printf("Warning: Could not collect evidence: %v\n", err)
				}

				vulns = append(vulns, models.Vulnerability{
					Title:       "Potential Account Aggregation Attempt Detected",
					Description: "No account aggregation protection detected on endpoint",
					Category:    models.CategoryAccountAggregation,
					Severity:    models.High,
					URL:         target + path,
					Evidence:    evidence,
					Remediation: "Implement account aggregation protection, rate limiting, and access control",
				})
			}

			// Add a small delay between requests
			time.Sleep(100 * time.Millisecond)
		}
	}

	return vulns
}

// CheckDenialOfInventory checks for denial of inventory attempts (OAT-021)
func CheckDenialOfInventory(target string) []models.Vulnerability {
	var vulns []models.Vulnerability
	fmt.Println("Checking for denial of inventory attempts...")

	// Create evidence collector
	evidenceColl, err := evidence.NewEvidenceCollector("evidence")
	if err != nil {
		fmt.Printf("Warning: Could not create evidence collector: %v\n", err)
		return vulns
	}

	// Common inventory endpoints
	inventoryEndpoints := []string{
		"/products", "/items", "/inventory",
		"/stock", "/availability", "/quantity",
		"/reserve", "/hold", "/book",
	}

	for _, path := range inventoryEndpoints {
		// Test with different quantities
		quantities := []string{
			"100", "1000", "10000",
			"50000", "100000", "500000",
		}

		for _, quantity := range quantities {
			payload := fmt.Sprintf(`{"quantity":"%s"}`, quantity)
			req, err := http.NewRequest("POST", target+path, strings.NewReader(payload))
			if err != nil {
				continue
			}
			req.Header.Set("Content-Type", "application/json")

			// Add suspicious headers
			req.Header.Set("X-Forwarded-For", "1.1.1.1")
			req.Header.Set("X-Real-IP", "1.1.1.1")
			req.Header.Set("CF-Connecting-IP", "1.1.1.1")

			client := &http.Client{}
			resp, err := client.Do(req)
			if err != nil {
				continue
			}
			defer resp.Body.Close()

			// Check for denial of inventory protection
			if resp.StatusCode == 400 || resp.StatusCode == 401 || resp.StatusCode == 403 || resp.StatusCode == 429 {
				evidence, err := evidenceColl.CollectEvidence(target+path, req, resp)
				if err != nil {
					fmt.Printf("Warning: Could not collect evidence: %v\n", err)
				}

				vulns = append(vulns, models.Vulnerability{
					Title:       "Potential Denial of Inventory Attempt Detected",
					Description: "Denial of inventory protection detected on endpoint",
					Category:    models.CategoryDenialOfInventory,
					Severity:    models.High,
					URL:         target + path,
					Evidence:    evidence,
					Remediation: "Endpoint implements denial of inventory protection, rate limiting, and quantity validation",
				})
			} else if resp.StatusCode >= 200 && resp.StatusCode < 300 {
				evidence, err := evidenceColl.CollectEvidence(target+path, req, resp)
				if err != nil {
					fmt.Printf("Warning: Could not collect evidence: %v\n", err)
				}

				vulns = append(vulns, models.Vulnerability{
					Title:       "Potential Denial of Inventory Attempt Detected",
					Description: "Denial of inventory protection detected on endpoint",
					Category:    models.CategoryDenialOfInventory,
					Severity:    models.High,
					URL:         target + path,
					Evidence:    evidence,
					Remediation: "Implement denial of inventory protection, rate limiting, and quantity validation",
				})
			}

			// Add a small delay between requests
			time.Sleep(100 * time.Millisecond)
		}
	}

	return vulns
}
