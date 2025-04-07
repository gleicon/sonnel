package scanner

import (
	"fmt"
	"net/url"
	"time"

	"github.com/gleicon/browserhttp"
	"github.com/gleicon/sonnel/internal/evidence"
	"github.com/gleicon/sonnel/internal/models"
)

// Scanner performs security scans on web applications
type Scanner struct {
	client        *browserhttp.BrowserClient
	evidenceDir   string
	evidenceColl  *evidence.EvidenceCollector
	targetURL     string
	verbose       bool
	screenshotDir string
}

// ScanResult represents the results of a security scan
type ScanResult struct {
	Target          string
	StartTime       time.Time
	EndTime         time.Time
	Vulnerabilities []models.Vulnerability
	Summary         map[models.OWASPCategory]int
	SeverityCount   map[models.SeverityLevel]int
}

// NewScanner creates a new scanner instance
func NewScanner(targetURL string, evidenceDir string) (*Scanner, error) {
	// Create evidence collector
	evidenceColl, err := evidence.NewEvidenceCollector(evidenceDir)
	if err != nil {
		return nil, fmt.Errorf("failed to create evidence collector: %v", err)
	}
	client := browserhttp.NewClient(15 * time.Second) //TODO: make timeout configurable

	return &Scanner{
		targetURL:     targetURL,
		evidenceDir:   evidenceDir,
		evidenceColl:  evidenceColl,
		screenshotDir: evidenceDir, // store evidence and screenshots in the same place
		client:        client,
	}, nil
}

// SetVerbose sets the verbose mode for the scanner
func (s *Scanner) SetVerbose(verbose bool) {
	s.verbose = verbose
}

// Scan performs a security scan on the target URL
func (s *Scanner) Scan(targetURL string) ([]models.Vulnerability, error) {
	// setup browserclient and chrome persistent tab usage to save memory and improve latency
	s.client.UsePersistentTabs(true)
	s.client.EnableScreenshots(s.screenshotDir)
	s.client.Init()

	if s.verbose {
		s.client.EnableVerbose()
	}
	defer s.client.Close()

	// Validate URL
	parsedURL, err := url.Parse(targetURL)
	if err != nil {
		return nil, fmt.Errorf("invalid URL: %v", err)
	}
	if parsedURL.Scheme == "" || parsedURL.Host == "" {
		return nil, fmt.Errorf("invalid URL: missing scheme or host")
	}

	if s.verbose {
		fmt.Println("\n=== Starting Security Scan ===")
		fmt.Printf("Target URL: %s\n", targetURL)
		fmt.Printf("Evidence Directory: %s\n", s.evidenceDir)
		fmt.Println("----------------------------------------")
	}

	var vulnerabilities []models.Vulnerability

	// Define all OWASP Top 10 checks with their names and descriptions
	checks := []struct {
		name        models.OWASPCategory
		description string
		check       func(*Scanner, string) ([]models.Vulnerability, error)
	}{
		{
			name:        models.CategoryBrokenAccessControl,
			description: "Checks for broken access control vulnerabilities",
			check:       CheckBrokenAccessControl,
		},
		{
			name:        models.CategoryCryptographicFailures,
			description: "Checks for cryptographic failures",
			check:       CheckSensitiveDataExposure,
		},
		{
			name:        models.CategoryInjection,
			description: "Checks for injection vulnerabilities",
			check:       CheckInjection,
		},
		{
			name:        models.CategoryInsecureDesign,
			description: "Checks for insecure design flaws",
			check:       CheckInsecureDesign,
		},
		{
			name:        models.CategorySecurityMisconfiguration,
			description: "Checks for security misconfigurations",
			check:       CheckSecurityMisconfiguration,
		},
		{
			name:        models.CategoryVulnerableComponents,
			description: "Checks for vulnerable components",
			check:       CheckVulnerableComponents,
		},
		{
			name:        models.CategoryIntegrityFailures,
			description: "Checks for identification and authentication failures",
			check:       CheckBrokenAuth,
		},
		{
			name:        models.CategoryIntegrityFailures,
			description: "Checks for integrity failures",
			check:       CheckIntegrityFailures,
		},
		{
			name:        models.CategoryLoggingFailures,
			description: "Checks for logging failures",
			check:       CheckLoggingFailures,
		},
		{
			name:        models.CategorySSRF,
			description: "Checks for SSRF vulnerabilities",
			check:       CheckSSRF,
		},
		// LLM Security Checks
		{
			name:        models.CategoryLLMPromptInjection,
			description: "Checks for vulnerabilities that allow attackers to inject malicious prompts",
			check:       CheckLLMPromptInjection,
		},
		{
			name:        models.CategoryLLMDataLeakage,
			description: "Checks for sensitive data exposure through LLM responses",
			check:       CheckLLMDataLeakage,
		},
		{
			name:        models.CategoryLLMContextManipulation,
			description: "Checks for vulnerabilities in LLM context handling",
			check:       CheckLLMContextManipulation,
		},
	}

	// Test basic connectivity first
	if s.verbose {
		fmt.Println("\n[1/4] Testing basic connectivity...")
	}
	_, err = s.client.Get(targetURL)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to target: %v", err)
	}
	if s.verbose {
		fmt.Println("✓ Target is accessible")
	}

	// Run vulnerability checks
	if s.verbose {
		fmt.Println("\n[2/4] Running vulnerability checks...")
	}
	for i, check := range checks {
		if s.verbose {
			fmt.Printf("\n[%d/%d] Running %s check...\n", i+1, len(checks), check.name)
			fmt.Printf("Description: %s\n", check.description)
		}
		vulns, err := check.check(s, targetURL)
		if err != nil {
			if s.verbose {
				fmt.Printf("✗ Error in %s check: %v\n", check.name, err)
			}
			continue
		}
		if s.verbose {
			if len(vulns) > 0 {
				fmt.Printf("✓ Found %d vulnerabilities in %s check:\n", len(vulns), check.name)
				for _, vuln := range vulns {
					fmt.Printf("  - %s (%s)\n", vuln.Title, vuln.Severity)
					fmt.Printf("    Description: %s\n", vuln.Description)
					fmt.Printf("    URL: %s\n", vuln.URL)
					if vuln.Evidence != nil {
						fmt.Printf("    Evidence: %s\n", vuln.Evidence.URL)
					}
				}
			} else {
				fmt.Printf("✓ No vulnerabilities found in %s check\n", check.name)
			}
		}
		vulnerabilities = append(vulnerabilities, vulns...)
	}

	// Print summary
	if s.verbose {
		fmt.Println("\n[3/4] Scan Summary:")
		fmt.Println("----------------------------------------")
		fmt.Printf("Total Vulnerabilities Found: %d\n", len(vulnerabilities))

		// Count by severity
		severityCount := make(map[models.SeverityLevel]int)
		for _, vuln := range vulnerabilities {
			severityCount[vuln.Severity]++
		}

		fmt.Println("\nVulnerabilities by Severity:")
		for severity, count := range severityCount {
			fmt.Printf("  %s: %d\n", severity, count)
		}

		// Count by category
		categoryCount := make(map[models.OWASPCategory]int)
		for _, vuln := range vulnerabilities {
			categoryCount[vuln.Category]++
		}

		fmt.Println("\nVulnerabilities by Category:")
		for category, count := range categoryCount {
			fmt.Printf("  %s: %d\n", category, count)
		}

		// Print OWASP Top 10 and LLM Security table
		fmt.Println("\n[4/4] Security Summary:")
		fmt.Println("----------------------------------------")
		fmt.Println("| Category | Description | Vulnerabilities Found |")
		fmt.Println("|----------|-------------|----------------------|")
		for _, check := range checks {
			count := 0
			for _, vuln := range vulnerabilities {
				if vuln.Category == check.name {
					count++
				}
			}
			fmt.Printf("| %-8s | %-11s | %-20d |\n", check.name, check.description, count)
		}

		fmt.Println("\n=== Scan Completed ===")
	}

	return vulnerabilities, nil
}

// RunScan performs a comprehensive security scan
func (s *Scanner) RunScan(target string) ScanResult {
	result := ScanResult{
		Target:    target,
		StartTime: time.Now(),
	}

	// Create scanner instance
	scanner, err := NewScanner(target, "verbose")
	if err != nil {
		fmt.Printf("Error creating scanner: %v\n", err)
		return result
	}

	// Run OWASP Top 10 checks
	if vulns, err := CheckBrokenAccessControl(scanner, target); err == nil {
		result.Vulnerabilities = append(result.Vulnerabilities, vulns...)
	}
	if vulns, err := CheckSensitiveDataExposure(scanner, target); err == nil {
		result.Vulnerabilities = append(result.Vulnerabilities, vulns...)
	}
	if vulns, err := CheckInjection(scanner, target); err == nil {
		result.Vulnerabilities = append(result.Vulnerabilities, vulns...)
	}
	if vulns, err := CheckInsecureDesign(scanner, target); err == nil {
		result.Vulnerabilities = append(result.Vulnerabilities, vulns...)
	}
	if vulns, err := CheckSecurityMisconfiguration(scanner, target); err == nil {
		result.Vulnerabilities = append(result.Vulnerabilities, vulns...)
	}
	if vulns, err := CheckVulnerableComponents(scanner, target); err == nil {
		result.Vulnerabilities = append(result.Vulnerabilities, vulns...)
	}
	if vulns, err := CheckIntegrityFailures(scanner, target); err == nil {
		result.Vulnerabilities = append(result.Vulnerabilities, vulns...)
	}
	if vulns, err := CheckLoggingFailures(scanner, target); err == nil {
		result.Vulnerabilities = append(result.Vulnerabilities, vulns...)
	}
	if vulns, err := CheckSSRF(scanner, target); err == nil {
		result.Vulnerabilities = append(result.Vulnerabilities, vulns...)
	}

	oat := newOAT(s)
	// Run OAT checks
	if vulns := oat.CheckCarding(target); len(vulns) > 0 {
		result.Vulnerabilities = append(result.Vulnerabilities, vulns...)
	}
	if vulns := oat.CheckTokenCracking(target); len(vulns) > 0 {
		result.Vulnerabilities = append(result.Vulnerabilities, vulns...)
	}
	if vulns := oat.CheckAdFraud(target); len(vulns) > 0 {
		result.Vulnerabilities = append(result.Vulnerabilities, vulns...)
	}
	if vulns := oat.CheckFingerprinting(target); len(vulns) > 0 {
		result.Vulnerabilities = append(result.Vulnerabilities, vulns...)
	}
	if vulns := oat.CheckScalping(target); len(vulns) > 0 {
		result.Vulnerabilities = append(result.Vulnerabilities, vulns...)
	}
	if vulns := oat.CheckExpediting(target); len(vulns) > 0 {
		result.Vulnerabilities = append(result.Vulnerabilities, vulns...)
	}
	if vulns := oat.CheckCredentialCracking(target); len(vulns) > 0 {
		result.Vulnerabilities = append(result.Vulnerabilities, vulns...)
	}
	if vulns := oat.CheckCredentialStuffing(target); len(vulns) > 0 {
		result.Vulnerabilities = append(result.Vulnerabilities, vulns...)
	}
	if vulns := oat.CheckCAPTCHADefeat(target); len(vulns) > 0 {
		result.Vulnerabilities = append(result.Vulnerabilities, vulns...)
	}
	if vulns := oat.CheckCardCracking(target); len(vulns) > 0 {
		result.Vulnerabilities = append(result.Vulnerabilities, vulns...)
	}
	if vulns := oat.CheckScraping(target); len(vulns) > 0 {
		result.Vulnerabilities = append(result.Vulnerabilities, vulns...)
	}
	if vulns := oat.CheckCashingOut(target); len(vulns) > 0 {
		result.Vulnerabilities = append(result.Vulnerabilities, vulns...)
	}
	if vulns := oat.CheckSniping(target); len(vulns) > 0 {
		result.Vulnerabilities = append(result.Vulnerabilities, vulns...)
	}
	if vulns := oat.CheckVulnerabilityScanning(target); len(vulns) > 0 {
		result.Vulnerabilities = append(result.Vulnerabilities, vulns...)
	}
	if vulns := oat.CheckDenialOfService(target); len(vulns) > 0 {
		result.Vulnerabilities = append(result.Vulnerabilities, vulns...)
	}
	if vulns := oat.CheckSkewing(target); len(vulns) > 0 {
		result.Vulnerabilities = append(result.Vulnerabilities, vulns...)
	}
	if vulns := oat.CheckSpamming(target); len(vulns) > 0 {
		result.Vulnerabilities = append(result.Vulnerabilities, vulns...)
	}
	if vulns := oat.CheckFootprinting(target); len(vulns) > 0 {
		result.Vulnerabilities = append(result.Vulnerabilities, vulns...)
	}
	if vulns := oat.CheckAccountCreation(target); len(vulns) > 0 {
		result.Vulnerabilities = append(result.Vulnerabilities, vulns...)
	}
	if vulns := oat.CheckAccountAggregation(target); len(vulns) > 0 {
		result.Vulnerabilities = append(result.Vulnerabilities, vulns...)
	}
	if vulns := oat.CheckDenialOfInventory(target); len(vulns) > 0 {
		result.Vulnerabilities = append(result.Vulnerabilities, vulns...)
	}

	// Run LLM checks
	if vulns, err := CheckLLMPromptInjection(scanner, target); err == nil {
		result.Vulnerabilities = append(result.Vulnerabilities, vulns...)
	}
	if vulns, err := CheckLLMDataLeakage(scanner, target); err == nil {
		result.Vulnerabilities = append(result.Vulnerabilities, vulns...)
	}
	if vulns, err := CheckLLMContextManipulation(scanner, target); err == nil {
		result.Vulnerabilities = append(result.Vulnerabilities, vulns...)
	}

	// Calculate summary
	result.Summary = make(map[models.OWASPCategory]int)
	result.SeverityCount = make(map[models.SeverityLevel]int)

	for _, vuln := range result.Vulnerabilities {
		result.Summary[vuln.Category]++
		result.SeverityCount[vuln.Severity]++
	}

	result.EndTime = time.Now()
	return result
}

// PrintResults prints the scan results in a formatted table
func PrintResults(result ScanResult) {
	fmt.Println("\nSecurity Scan Results")
	fmt.Println("====================")
	fmt.Printf("Target: %s\n", result.Target)
	fmt.Printf("Duration: %v\n", result.EndTime.Sub(result.StartTime))
	fmt.Println("\nVulnerabilities Found:")
	fmt.Println("---------------------")

	// Group vulnerabilities by category
	vulnsByCategory := make(map[models.OWASPCategory][]models.Vulnerability)
	for _, vuln := range result.Vulnerabilities {
		vulnsByCategory[vuln.Category] = append(vulnsByCategory[vuln.Category], vuln)
	}

	// Print summary table
	fmt.Println("\nSummary:")
	fmt.Println("--------")
	fmt.Printf("%-40s %-10s %s\n", "Category", "Count", "Severity")
	fmt.Println("----------------------------------------")
	for category, vulns := range vulnsByCategory {
		severity := "Low"
		for _, vuln := range vulns {
			if vuln.Severity == "High" {
				severity = "High"
				break
			} else if vuln.Severity == "Medium" && severity != "High" {
				severity = "Medium"
			}
		}
		fmt.Printf("%-40s %-10d %s\n", category, len(vulns), severity)
	}

	// Print detailed findings
	fmt.Println("\nDetailed Findings:")
	fmt.Println("-----------------")
	for category, vulns := range vulnsByCategory {
		fmt.Printf("\n%s:\n", category)
		for _, vuln := range vulns {
			fmt.Printf("  - %s (%s)\n", vuln.Title, vuln.Severity)
			fmt.Printf("    URL: %s\n", vuln.URL)
			fmt.Printf("    Evidence: %s\n", vuln.Evidence)
			fmt.Printf("    Remediation: %s\n", vuln.Remediation)
		}
	}
}
