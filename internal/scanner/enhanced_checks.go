package scanner

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"

	"github.com/gleicon/sonnel/internal/evidence"
	"github.com/gleicon/sonnel/internal/models"
)

// EnhancedScanner provides additional scanning capabilities using external tools
type EnhancedScanner struct {
	toolManager *ToolManager
	scanner     *Scanner
}

// NewEnhancedScanner creates a new EnhancedScanner instance
func NewEnhancedScanner(scanner *Scanner) *EnhancedScanner {
	return &EnhancedScanner{
		toolManager: NewToolManager(),
		scanner:     scanner,
	}
}

// CheckFuzzing performs fuzzing tests using ffuf
func (es *EnhancedScanner) CheckFuzzing(target string) ([]models.Vulnerability, error) {
	if !es.toolManager.IsToolAvailable("ffuf") {
		return nil, fmt.Errorf("ffuf is not available")
	}

	// Parse target URL
	_, err := url.Parse(target)
	if err != nil {
		return nil, err
	}

	// Common wordlists for fuzzing
	wordlists := []string{
		"/usr/share/wordlists/dirb/common.txt",
		"/usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt",
	}

	var vulnerabilities []models.Vulnerability
	evidenceColl, err := evidence.NewEvidenceCollector("evidence")
	if err != nil {
		return nil, fmt.Errorf("failed to create evidence collector: %v", err)
	}

	for _, wordlist := range wordlists {
		// Run ffuf with the wordlist
		args := []string{
			"-u", fmt.Sprintf("%s/FUZZ", target),
			"-w", wordlist,
			"-o", "json",
			"-of", "json",
		}

		output, err := es.toolManager.ExecuteTool("ffuf", args)
		if err != nil {
			fmt.Printf("Error running ffuf: %v\n", err)
			continue
		}

		// Parse ffuf output
		var results []struct {
			URL    string `json:"url"`
			Status int    `json:"status"`
			Length int    `json:"length"`
		}

		if err := json.Unmarshal([]byte(output), &results); err != nil {
			fmt.Printf("Error parsing ffuf output: %v\n", err)
			continue
		}

		// Analyze results
		for _, result := range results {
			if result.Status == 200 || result.Status == 301 || result.Status == 302 {
				req, err := http.NewRequest("GET", result.URL, nil)
				if err != nil {
					continue
				}

				resp, err := es.scanner.client.Do(req)
				if err != nil {
					continue
				}
				defer resp.Body.Close()

				ev, err := evidenceColl.CollectEvidence(result.URL, req, resp)
				if err == nil {
					vulnerabilities = append(vulnerabilities, models.Vulnerability{
						Title:       "Directory/File Discovery",
						Description: "Potential sensitive directories or files discovered through fuzzing",
						Severity:    models.Medium,
						Category:    models.CategorySecurityMisconfiguration,
						URL:         result.URL,
						Evidence:    ev,
						Remediation: "Review discovered directories and files for sensitive information. Implement proper access controls.",
					})
				}
			}
		}
	}

	return vulnerabilities, nil
}

// CheckSubdomainEnumeration performs subdomain enumeration using amass
func (es *EnhancedScanner) CheckSubdomainEnumeration(target string) ([]models.Vulnerability, error) {
	if !es.toolManager.IsToolAvailable("amass") {
		return nil, fmt.Errorf("amass is not available")
	}

	// Parse target URL to get domain
	parsedURL, err := url.Parse(target)
	if err != nil {
		return nil, err
	}

	domain := parsedURL.Hostname()
	if strings.Contains(domain, ":") {
		domain = strings.Split(domain, ":")[0]
	}

	var vulnerabilities []models.Vulnerability
	evidenceColl, err := evidence.NewEvidenceCollector("evidence")
	if err != nil {
		return nil, fmt.Errorf("failed to create evidence collector: %v", err)
	}

	// Run amass with passive enumeration
	args := []string{
		"enum",
		"-passive",
		"-d", domain,
		"-json", "amass_output.json",
	}

	output, err := es.toolManager.ExecuteTool("amass", args)
	if err != nil {
		return nil, fmt.Errorf("error running amass: %v", err)
	}

	// Parse amass output
	var results []struct {
		Name      string `json:"name"`
		Domain    string `json:"domain"`
		Addresses []struct {
			IP string `json:"ip"`
		} `json:"addresses"`
	}

	if err := json.Unmarshal([]byte(output), &results); err != nil {
		return nil, fmt.Errorf("error parsing amass output: %v", err)
	}

	// Analyze results
	for _, result := range results {
		subdomainURL := fmt.Sprintf("https://%s", result.Name)
		req, err := http.NewRequest("GET", subdomainURL, nil)
		if err != nil {
			continue
		}

		resp, err := es.scanner.client.Do(req)
		if err != nil {
			continue
		}
		defer resp.Body.Close()

		ev, err := evidenceColl.CollectEvidence(subdomainURL, req, resp)
		if err == nil {
			vulnerabilities = append(vulnerabilities, models.Vulnerability{
				Title:       "Subdomain Discovery",
				Description: fmt.Sprintf("Discovered subdomain: %s", result.Name),
				Severity:    models.Medium,
				Category:    models.CategorySecurityMisconfiguration,
				URL:         subdomainURL,
				Evidence:    ev,
				Remediation: "Review discovered subdomains and ensure they are properly secured.",
			})
		}
	}

	return vulnerabilities, nil
}

// CheckHTTPProbing performs HTTP probing using httpx
func (es *EnhancedScanner) CheckHTTPProbing(target string) ([]models.Vulnerability, error) {
	if !es.toolManager.IsToolAvailable("httpx") {
		return nil, fmt.Errorf("httpx is not available")
	}

	var vulnerabilities []models.Vulnerability
	evidenceColl, err := evidence.NewEvidenceCollector("evidence")
	if err != nil {
		return nil, fmt.Errorf("failed to create evidence collector: %v", err)
	}

	// Run httpx with various probes
	args := []string{
		"-u", target,
		"-title",
		"-status-code",
		"-tech-detect",
		"-json",
	}

	output, err := es.toolManager.ExecuteTool("httpx", args)
	if err != nil {
		return nil, fmt.Errorf("error running httpx: %v", err)
	}

	// Parse httpx output
	var results []struct {
		URL          string   `json:"url"`
		StatusCode   int      `json:"status_code"`
		Title        string   `json:"title"`
		Technologies []string `json:"technologies"`
	}

	if err := json.Unmarshal([]byte(output), &results); err != nil {
		return nil, fmt.Errorf("error parsing httpx output: %v", err)
	}

	// Analyze results
	for _, result := range results {
		req, err := http.NewRequest("GET", result.URL, nil)
		if err != nil {
			continue
		}

		resp, err := es.scanner.client.Do(req)
		if err != nil {
			continue
		}
		defer resp.Body.Close()

		ev, err := evidenceColl.CollectEvidence(result.URL, req, resp)
		if err == nil {
			vulnerabilities = append(vulnerabilities, models.Vulnerability{
				Title:       "HTTP Service Information",
				Description: fmt.Sprintf("Discovered HTTP service with status code %d and technologies: %v", result.StatusCode, result.Technologies),
				Severity:    models.Info,
				Category:    models.CategorySecurityMisconfiguration,
				URL:         result.URL,
				Evidence:    ev,
				Remediation: "Review exposed services and ensure they are properly configured and secured.",
			})
		}
	}

	return vulnerabilities, nil
}

// CheckNucleiScan performs vulnerability scanning using nuclei
func (es *EnhancedScanner) CheckNucleiScan(target string) ([]models.Vulnerability, error) {
	if !es.toolManager.IsToolAvailable("nuclei") {
		return nil, fmt.Errorf("nuclei is not available")
	}

	var vulnerabilities []models.Vulnerability
	evidenceColl, err := evidence.NewEvidenceCollector("evidence")
	if err != nil {
		return nil, fmt.Errorf("failed to create evidence collector: %v", err)
	}

	// Get user's home directory
	homeDir, err := os.UserHomeDir()
	if err != nil {
		return nil, fmt.Errorf("failed to get home directory: %v", err)
	}

	// Run nuclei with various templates
	args := []string{
		"-u", target,
		"-severity", "critical,high,medium",
		"-jsonl",
		"-rate-limit", "50",
		"-timeout", "10",
		"-retries", "2",
		"-silent",
		"-templates", filepath.Join(homeDir, "nuclei-templates", "cves"),
		"-templates", filepath.Join(homeDir, "nuclei-templates", "vulnerabilities"),
		"-templates", filepath.Join(homeDir, "nuclei-templates", "misconfiguration"),
	}

	output, err := es.toolManager.ExecuteTool("nuclei", args)
	if err != nil {
		// Check if the error is due to missing templates
		if strings.Contains(err.Error(), "no templates were found") {
			fmt.Println("Warning: No nuclei templates found. Please ensure templates are installed in ~/nuclei-templates")
			return nil, fmt.Errorf("nuclei templates not found: %v", err)
		}
		return nil, fmt.Errorf("error running nuclei: %v", err)
	}

	// Parse nuclei output
	var results []struct {
		TemplateID string `json:"template-id"`
		Info       struct {
			Name        string `json:"name"`
			Severity    string `json:"severity"`
			Description string `json:"description"`
		} `json:"info"`
		MatchedAt string `json:"matched-at"`
	}

	if err := json.Unmarshal([]byte(output), &results); err != nil {
		return nil, fmt.Errorf("error parsing nuclei output: %v", err)
	}

	// Analyze results
	for _, result := range results {
		req, err := http.NewRequest("GET", result.MatchedAt, nil)
		if err != nil {
			continue
		}

		resp, err := es.scanner.client.Do(req)
		if err != nil {
			continue
		}
		defer resp.Body.Close()

		ev, err := evidenceColl.CollectEvidence(result.MatchedAt, req, resp)
		if err == nil {
			severity := models.SeverityFromString(result.Info.Severity)
			vulnerabilities = append(vulnerabilities, models.Vulnerability{
				Title:       result.Info.Name,
				Description: result.Info.Description,
				Severity:    severity,
				Category:    models.CategoryVulnerableComponents,
				URL:         result.MatchedAt,
				Evidence:    ev,
				Remediation: "Update or patch the vulnerable component.",
			})
		}
	}

	return vulnerabilities, nil
}
