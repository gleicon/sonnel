package scanner

import (
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strings"

	"github.com/gleicon/browserhttp"
	"github.com/gleicon/sonnel/internal/models"
)

// NativeScanner provides security checks using only Go standard libraries
type NativeScanner struct {
	scanner *Scanner
	client  *browserhttp.BrowserClient
}

// NewNativeScanner creates a new NativeScanner instance
func NewNativeScanner(scanner *Scanner) *NativeScanner {

	return &NativeScanner{
		scanner: scanner,
		client:  scanner.client,
	}
}

// CheckNativeFuzzing performs basic fuzzing using Go standard libraries
func (ns *NativeScanner) CheckNativeFuzzing(target string) ([]models.Vulnerability, error) {
	// Common paths to check
	// TODO: use a wordlist
	paths := []string{
		"/", "/admin", "/api", "/backup", "/config", "/db", "/dev",
		"/doc", "/docs", "/git", "/logs", "/old", "/src", "/test",
		"/tmp", "/vendor", "/www", "/.git", "/.env", "/.svn",
	}

	var vulnerabilities []models.Vulnerability
	evidenceColl := ns.scanner.evidenceColl

	for _, path := range paths {
		u, err := url.Parse(target)
		if err != nil {
			continue
		}
		u.Path = path

		req, err := http.NewRequest("GET", u.String(), nil)
		if err != nil {
			continue
		}

		// Add common headers
		req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36")
		req.Header.Set("Accept", "*/*")
		req.Header.Set("Accept-Language", "en-US,en;q=0.9")

		resp, err := ns.client.Do(req)
		if err != nil {
			continue
		}
		defer resp.Body.Close()

		if resp.StatusCode == 200 || resp.StatusCode == 301 || resp.StatusCode == 302 {
			ev, err := evidenceColl.CollectEvidence(u.String(), req, resp)
			if err == nil {
				vulnerabilities = append(vulnerabilities, models.Vulnerability{
					Title:       "Directory/File Discovery",
					Description: "Potential sensitive directories or files discovered through basic fuzzing",
					Severity:    models.Medium,
					Category:    models.CategorySecurityMisconfiguration,
					URL:         u.String(),
					Evidence:    ev,
					Remediation: "Review and restrict access to discovered endpoints. Implement proper access controls.",
				})
			}
		}
	}

	return vulnerabilities, nil
}

// CheckNativeSubdomain performs basic subdomain enumeration using Go standard libraries
func (ns *NativeScanner) CheckNativeSubdomain(target string) ([]models.Vulnerability, error) {
	u, err := url.Parse(target)
	if err != nil {
		return nil, err
	}

	domain := u.Hostname()
	if strings.Contains(domain, ":") {
		domain = strings.Split(domain, ":")[0]
	}

	// Common subdomain prefixes
	prefixes := []string{
		"www", "mail", "ftp", "localhost", "webmail", "smtp", "pop", "ns1", "ns2",
		"test", "dev", "staging", "api", "admin", "blog", "shop", "store", "app",
	}

	var vulnerabilities []models.Vulnerability
	evidenceColl := ns.scanner.evidenceColl

	for _, prefix := range prefixes {
		subdomain := fmt.Sprintf("%s.%s", prefix, domain)
		ips, err := net.LookupIP(subdomain)
		if err == nil && len(ips) > 0 {
			subdomainURL := fmt.Sprintf("http://%s", subdomain)
			req, err := http.NewRequest("GET", subdomainURL, nil)
			if err != nil {
				continue
			}

			resp, err := ns.client.Do(req)
			if err != nil {
				continue
			}
			defer resp.Body.Close()

			ev, err := evidenceColl.CollectEvidence(subdomainURL, req, resp)
			if err == nil {
				vulnerabilities = append(vulnerabilities, models.Vulnerability{
					Title:       "Subdomain Enumeration",
					Description: "Subdomains discovered through basic enumeration",
					Severity:    models.Low,
					Category:    models.CategorySecurityMisconfiguration,
					URL:         subdomainURL,
					Evidence:    ev,
					Remediation: "Review discovered subdomains and ensure they are properly secured.",
				})
			}
		}
	}

	return vulnerabilities, nil
}

// CheckNativeHTTP performs basic HTTP probing using Go standard libraries
func (ns *NativeScanner) CheckNativeHTTP(target string) ([]models.Vulnerability, error) {
	var vulnerabilities []models.Vulnerability
	evidenceColl := ns.scanner.evidenceColl

	// Check HTTP/1.1
	req, err := http.NewRequest("GET", target, nil)
	if err != nil {
		return nil, err
	}

	resp, err := ns.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	// Collect evidence
	ev, err := evidenceColl.CollectEvidence(target, req, resp)
	if err != nil {
		return nil, fmt.Errorf("failed to collect evidence: %v", err)
	}

	// Check security headers
	securityHeaders := map[string]string{
		"X-Content-Type-Options":    "nosniff",
		"X-Frame-Options":           "DENY",
		"X-XSS-Protection":          "1; mode=block",
		"Content-Security-Policy":   "default-src 'self'",
		"Strict-Transport-Security": "max-age=31536000; includeSubDomains",
	}

	missingHeaders := make([]string, 0)
	insecureHeaders := make([]string, 0)

	for header, expected := range securityHeaders {
		value := resp.Header.Get(header)
		if value == "" {
			missingHeaders = append(missingHeaders, header)
		} else if value != expected {
			insecureHeaders = append(insecureHeaders, fmt.Sprintf("%s: %s", header, value))
		}
	}

	if len(missingHeaders) > 0 || len(insecureHeaders) > 0 {
		details := make(map[string]string)
		if len(missingHeaders) > 0 {
			details["Missing Headers"] = strings.Join(missingHeaders, ", ")
		}
		if len(insecureHeaders) > 0 {
			details["Insecure Headers"] = strings.Join(insecureHeaders, ", ")
		}

		vulnerabilities = append(vulnerabilities, models.Vulnerability{
			Title:       "HTTP Service Information",
			Description: "Detailed HTTP service information and security headers",
			Severity:    models.Info,
			Category:    models.CategorySecurityMisconfiguration,
			Details:     details,
			URL:         target,
			Evidence:    ev,
			Remediation: "Review and secure exposed HTTP services. Implement missing security headers.",
		})
	}

	return vulnerabilities, nil
}
