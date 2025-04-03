package reporter

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/gleicon/sonnel/internal/models"
	"github.com/jung-kurt/gofpdf"
)

// OWASPInfo contains information about OWASP Top 10 categories
var OWASPInfo = map[models.OWASPCategory]struct {
	Title       string
	Description string
	Link        string
}{
	models.CategoryBrokenAccessControl: {
		Title:       "A1: Broken Access Control",
		Description: "Access control enforces policy such that users cannot act outside of their intended permissions. Failures typically lead to unauthorized information disclosure, modification, or destruction of all data or performing a business function outside the user's limits.",
		Link:        "https://owasp.org/Top10/A01_2021-Broken_Access_Control/",
	},
	models.CategoryCryptographicFailures: {
		Title:       "A2: Cryptographic Failures",
		Description: "Previously known as 'Sensitive Data Exposure', this category focuses on failures related to cryptography which often lead to exposure of sensitive data.",
		Link:        "https://owasp.org/Top10/A02_2021-Cryptographic_Failures/",
	},
	models.CategoryInjection: {
		Title:       "A3: Injection",
		Description: "Injection flaws, such as SQL, NoSQL, OS, and LDAP injection, occur when untrusted data is sent to an interpreter as part of a command or query. The attacker's hostile data can trick the interpreter into executing unintended commands or accessing data without proper authorization.",
		Link:        "https://owasp.org/Top10/A03_2021-Injection/",
	},
	models.CategoryInsecureDesign: {
		Title:       "A4: Insecure Design",
		Description: "Insecure design is a broad category representing different weaknesses, expressed as 'missing or ineffective control design'. This category focuses on risks related to design and architectural flaws.",
		Link:        "https://owasp.org/Top10/A04_2021-Insecure_Design/",
	},
	models.CategorySecurityMisconfiguration: {
		Title:       "A5: Security Misconfiguration",
		Description: "Security misconfiguration is the most commonly seen issue. This is commonly a result of insecure default configurations, incomplete or ad hoc configurations, open cloud storage, misconfigured HTTP headers, and verbose error messages containing sensitive information.",
		Link:        "https://owasp.org/Top10/A05_2021-Security_Misconfiguration/",
	},
	models.CategoryVulnerableComponents: {
		Title:       "A6: Vulnerable and Outdated Components",
		Description: "Components, such as libraries, frameworks, and other software modules, run with the same privileges as the application. If a vulnerable component is exploited, such an attack can facilitate serious data loss or server takeover.",
		Link:        "https://owasp.org/Top10/A06_2021-Vulnerable_and_Outdated_Components/",
	},
	models.CategoryIntegrityFailures: {
		Title:       "A7: Identification and Authentication Failures",
		Description: "Confirmation of the user's identity, authentication, and session management is critical to protect against authentication-related attacks.",
		Link:        "https://owasp.org/Top10/A07_2021-Identification_and_Authentication_Failures/",
	},
	models.CategoryLoggingFailures: {
		Title:       "A8: Software and Data Integrity Failures",
		Description: "Software and data integrity failures relate to code and infrastructure that does not protect against integrity violations.",
		Link:        "https://owasp.org/Top10/A08_2021-Software_and_Data_Integrity_Failures/",
	},
	models.CategorySSRF: {
		Title:       "A9: Security Logging and Monitoring Failures",
		Description: "This category is to help detect, escalate, and respond to active breaches. Without logging and monitoring, breaches cannot be detected.",
		Link:        "https://owasp.org/Top10/A09_2021-Security_Logging_and_Monitoring_Failures/",
	},
	models.CategoryServerSideRequestForgery: {
		Title:       "A10: Server-Side Request Forgery",
		Description: "SSRF flaws occur whenever a web application is fetching a remote resource without validating the user-supplied URL. It allows an attacker to coerce the application to send a crafted request to an unexpected destination.",
		Link:        "https://owasp.org/Top10/A10_2021-Server-Side_Request_Forgery/",
	},
	models.CategoryLLMPromptInjection: {
		Title:       "LLM1: Prompt Injection",
		Description: "Prompt injection vulnerabilities allow attackers to manipulate LLM behavior by injecting malicious prompts.",
		Link:        "https://owasp.org/Top10/LLM01_2023-Prompt_Injection/",
	},
	models.CategoryLLMDataLeakage: {
		Title:       "LLM2: Data Leakage",
		Description: "Data leakage vulnerabilities expose sensitive information through LLM responses.",
		Link:        "https://owasp.org/Top10/LLM02_2023-Data_Leakage/",
	},
	models.CategoryLLMContextManipulation: {
		Title:       "LLM3: Context Manipulation",
		Description: "Context manipulation vulnerabilities allow attackers to modify LLM context to influence responses.",
		Link:        "https://owasp.org/Top10/LLM03_2023-Context_Manipulation/",
	},
}

// GenerateReport generates a report from the scan results
func GenerateReport(result *models.ScanResult) string {
	var report strings.Builder

	report.WriteString("=== Security Scan Report ===\n\n")
	report.WriteString(fmt.Sprintf("Target: %s\n", result.Target))
	report.WriteString(fmt.Sprintf("Timestamp: %s\n\n", result.Timestamp))

	// OWASP Top 10 Summary
	report.WriteString("OWASP Top 10 Summary:\n")
	report.WriteString("--------------------\n")
	report.WriteString(fmt.Sprintf("%s: %d vulnerabilities\n", models.CategoryBrokenAccessControl, result.Summary[models.CategoryBrokenAccessControl]))
	report.WriteString(fmt.Sprintf("%s: %d vulnerabilities\n", models.CategoryCryptographicFailures, result.Summary[models.CategoryCryptographicFailures]))
	report.WriteString(fmt.Sprintf("%s: %d vulnerabilities\n", models.CategoryInjection, result.Summary[models.CategoryInjection]))
	report.WriteString(fmt.Sprintf("%s: %d vulnerabilities\n", models.CategoryInsecureDesign, result.Summary[models.CategoryInsecureDesign]))
	report.WriteString(fmt.Sprintf("%s: %d vulnerabilities\n", models.CategorySecurityMisconfiguration, result.Summary[models.CategorySecurityMisconfiguration]))
	report.WriteString(fmt.Sprintf("%s: %d vulnerabilities\n", models.CategoryVulnerableComponents, result.Summary[models.CategoryVulnerableComponents]))
	report.WriteString(fmt.Sprintf("%s: %d vulnerabilities\n", models.CategoryIntegrityFailures, result.Summary[models.CategoryIntegrityFailures]))
	report.WriteString(fmt.Sprintf("%s: %d vulnerabilities\n", models.CategoryLoggingFailures, result.Summary[models.CategoryLoggingFailures]))
	report.WriteString(fmt.Sprintf("%s: %d vulnerabilities\n", models.CategorySSRF, result.Summary[models.CategorySSRF]))
	report.WriteString(fmt.Sprintf("%s: %d vulnerabilities\n", models.CategoryServerSideRequestForgery, result.Summary[models.CategoryServerSideRequestForgery]))

	// OAT Summary
	report.WriteString("\nOWASP Automated Threats Summary:\n")
	report.WriteString("-----------------------------\n")
	report.WriteString(fmt.Sprintf("%s: %d vulnerabilities\n", models.CategoryCarding, result.Summary[models.CategoryCarding]))
	report.WriteString(fmt.Sprintf("%s: %d vulnerabilities\n", models.CategoryTokenCracking, result.Summary[models.CategoryTokenCracking]))
	report.WriteString(fmt.Sprintf("%s: %d vulnerabilities\n", models.CategoryAdFraud, result.Summary[models.CategoryAdFraud]))
	report.WriteString(fmt.Sprintf("%s: %d vulnerabilities\n", models.CategoryFingerprinting, result.Summary[models.CategoryFingerprinting]))
	report.WriteString(fmt.Sprintf("%s: %d vulnerabilities\n", models.CategoryScalping, result.Summary[models.CategoryScalping]))
	report.WriteString(fmt.Sprintf("%s: %d vulnerabilities\n", models.CategoryExpediting, result.Summary[models.CategoryExpediting]))
	report.WriteString(fmt.Sprintf("%s: %d vulnerabilities\n", models.CategoryCredentialCracking, result.Summary[models.CategoryCredentialCracking]))
	report.WriteString(fmt.Sprintf("%s: %d vulnerabilities\n", models.CategoryCredentialStuffing, result.Summary[models.CategoryCredentialStuffing]))
	report.WriteString(fmt.Sprintf("%s: %d vulnerabilities\n", models.CategoryCAPTCHADefeat, result.Summary[models.CategoryCAPTCHADefeat]))
	report.WriteString(fmt.Sprintf("%s: %d vulnerabilities\n", models.CategoryCardCracking, result.Summary[models.CategoryCardCracking]))
	report.WriteString(fmt.Sprintf("%s: %d vulnerabilities\n", models.CategoryScraping, result.Summary[models.CategoryScraping]))
	report.WriteString(fmt.Sprintf("%s: %d vulnerabilities\n", models.CategoryCashingOut, result.Summary[models.CategoryCashingOut]))
	report.WriteString(fmt.Sprintf("%s: %d vulnerabilities\n", models.CategorySniping, result.Summary[models.CategorySniping]))
	report.WriteString(fmt.Sprintf("%s: %d vulnerabilities\n", models.CategoryVulnerabilityScanning, result.Summary[models.CategoryVulnerabilityScanning]))
	report.WriteString(fmt.Sprintf("%s: %d vulnerabilities\n", models.CategoryDenialOfService, result.Summary[models.CategoryDenialOfService]))
	report.WriteString(fmt.Sprintf("%s: %d vulnerabilities\n", models.CategorySkewing, result.Summary[models.CategorySkewing]))
	report.WriteString(fmt.Sprintf("%s: %d vulnerabilities\n", models.CategorySpamming, result.Summary[models.CategorySpamming]))
	report.WriteString(fmt.Sprintf("%s: %d vulnerabilities\n", models.CategoryFootprinting, result.Summary[models.CategoryFootprinting]))
	report.WriteString(fmt.Sprintf("%s: %d vulnerabilities\n", models.CategoryAccountCreation, result.Summary[models.CategoryAccountCreation]))
	report.WriteString(fmt.Sprintf("%s: %d vulnerabilities\n", models.CategoryAccountAggregation, result.Summary[models.CategoryAccountAggregation]))
	report.WriteString(fmt.Sprintf("%s: %d vulnerabilities\n", models.CategoryDenialOfInventory, result.Summary[models.CategoryDenialOfInventory]))

	// LLM Security Summary
	report.WriteString("\nLLM Security Summary:\n")
	report.WriteString("--------------------\n")
	report.WriteString(fmt.Sprintf("%s: %d vulnerabilities\n", models.CategoryLLMPromptInjection, result.Summary[models.CategoryLLMPromptInjection]))
	report.WriteString(fmt.Sprintf("%s: %d vulnerabilities\n", models.CategoryLLMDataLeakage, result.Summary[models.CategoryLLMDataLeakage]))
	report.WriteString(fmt.Sprintf("%s: %d vulnerabilities\n", models.CategoryLLMContextManipulation, result.Summary[models.CategoryLLMContextManipulation]))

	// Detailed Findings
	report.WriteString("\nDetailed Findings:\n")
	report.WriteString("-----------------\n")
	for _, vuln := range result.Vulnerabilities {
		report.WriteString(fmt.Sprintf("\nTitle: %s\n", vuln.Title))
		report.WriteString(fmt.Sprintf("Category: %s\n", vuln.Category))
		report.WriteString(fmt.Sprintf("Severity: %s\n", vuln.Severity))
		report.WriteString(fmt.Sprintf("Description: %s\n", vuln.Description))
		report.WriteString(fmt.Sprintf("URL: %s\n", vuln.URL))
		if vuln.Evidence != nil {
			report.WriteString(fmt.Sprintf("Evidence: %s\n", vuln.Evidence.URL))
		}
		report.WriteString(fmt.Sprintf("Remediation: %s\n", vuln.Remediation))
	}

	return report.String()
}

// GenerateReport creates a PDF report with the scan results
func GenerateReportPDF(vulnerabilities []models.Vulnerability, outputPath string, evidenceDir string) error {
	// Create output directory if it doesn't exist
	if err := os.MkdirAll(filepath.Dir(outputPath), 0755); err != nil {
		return fmt.Errorf("failed to create output directory: %v", err)
	}

	// Create PDF document
	pdf := gofpdf.New("P", "mm", "A4", "")
	pdf.SetTitle("Sonnel Security Report", false)
	pdf.SetAuthor("Sonnel Security Scanner", false)
	pdf.SetCreator("Sonnel", false)

	// Set default font (using built-in core font)
	pdf.SetFont("Courier", "", 12)

	// Add first page
	pdf.AddPage()

	// Title
	pdf.SetFont("Courier", "B", 24)
	pdf.Cell(0, 20, "Sonnel Security Report")
	pdf.Ln(20)

	// Summary section
	pdf.SetFont("Courier", "B", 16)
	pdf.Cell(0, 10, "Summary")
	pdf.Ln(10)

	pdf.SetFont("Courier", "", 12)
	pdf.Cell(0, 10, fmt.Sprintf("Total Vulnerabilities Found: %d", len(vulnerabilities)))
	pdf.Ln(10)

	// Create a table for vulnerability summary
	colWidths := []float64{40, 30, 30}
	headers := []string{"Category", "Count", "Severity"}

	// Table header
	pdf.SetFont("Courier", "B", 12)
	for i, header := range headers {
		pdf.CellFormat(colWidths[i], 10, header, "1", 0, "C", false, 0, "")
	}
	pdf.Ln(10)

	// Count vulnerabilities by category
	categoryCounts := make(map[models.OWASPCategory]int)
	categorySeverity := make(map[models.OWASPCategory]models.SeverityLevel)
	for _, vuln := range vulnerabilities {
		categoryCounts[vuln.Category]++
		if severity, exists := categorySeverity[vuln.Category]; !exists ||
			(severity == "Low" && vuln.Severity != "Low") ||
			(severity == "Medium" && vuln.Severity == "High") {
			categorySeverity[vuln.Category] = vuln.Severity
		}
	}

	// Table rows
	pdf.SetFont("Courier", "", 12)
	for category, count := range categoryCounts {
		owaspInfo := OWASPInfo[category]
		pdf.CellFormat(colWidths[0], 10, owaspInfo.Title, "1", 0, "L", false, 0, "")
		pdf.CellFormat(colWidths[1], 10, fmt.Sprintf("%d", count), "1", 0, "C", false, 0, "")
		pdf.CellFormat(colWidths[2], 10, string(categorySeverity[category]), "1", 0, "C", false, 0, "")
		pdf.Ln(10)
	}
	pdf.Ln(10)

	// Detailed Findings section
	pdf.SetFont("Courier", "B", 16)
	pdf.Cell(0, 10, "Detailed Findings")
	pdf.Ln(10)

	// Add each vulnerability
	for i, vuln := range vulnerabilities {
		if i > 0 {
			pdf.AddPage()
		}

		// Vulnerability title
		pdf.SetFont("Courier", "B", 14)
		pdf.Cell(0, 10, fmt.Sprintf("Vulnerability %d: %s", i+1, vuln.Title))
		pdf.Ln(10)

		// Category and severity
		pdf.SetFont("Courier", "B", 12)
		pdf.Cell(40, 10, "Category:")
		pdf.SetFont("Courier", "", 12)
		owaspInfo := OWASPInfo[vuln.Category]
		pdf.Cell(0, 10, owaspInfo.Title)
		pdf.Ln(10)

		pdf.SetFont("Courier", "B", 12)
		pdf.Cell(40, 10, "Severity:")
		pdf.SetFont("Courier", "", 12)
		pdf.Cell(0, 10, string(vuln.Severity))
		pdf.Ln(10)

		// Description
		pdf.SetFont("Courier", "B", 12)
		pdf.Cell(0, 10, "Description:")
		pdf.Ln(10)
		pdf.SetFont("Courier", "", 12)
		pdf.MultiCell(0, 10, vuln.Description, "", "", false)
		pdf.Ln(5)

		// Impact
		pdf.SetFont("Courier", "B", 12)
		pdf.Cell(0, 10, "Impact:")
		pdf.Ln(10)
		pdf.SetFont("Courier", "", 12)
		pdf.MultiCell(0, 10, owaspInfo.Description, "", "", false)
		pdf.Ln(5)

		// Recommendation
		pdf.SetFont("Courier", "B", 12)
		pdf.Cell(0, 10, "Recommendation:")
		pdf.Ln(10)
		pdf.SetFont("Courier", "", 12)
		pdf.MultiCell(0, 10, vuln.Remediation, "", "", false)
		pdf.Ln(5)

		// Evidence section
		if vuln.Evidence != nil {
			pdf.SetFont("Courier", "B", 12)
			pdf.Cell(0, 10, "Evidence:")
			pdf.Ln(10)

			// URL
			pdf.SetFont("Courier", "B", 12)
			pdf.Cell(30, 10, "URL:")
			pdf.SetFont("Courier", "", 12)
			pdf.Cell(0, 10, vuln.Evidence.URL)
			pdf.Ln(10)

			// Curl command
			if vuln.Evidence.CurlCommand != "" {
				pdf.SetFont("Courier", "B", 12)
				pdf.Cell(30, 10, "Curl Command:")
				pdf.Ln(10)
				pdf.SetFont("Courier", "", 12)
				pdf.MultiCell(0, 10, vuln.Evidence.CurlCommand, "", "", false)
				pdf.Ln(5)
			}

			// Screenshot
			if vuln.Evidence.ScreenshotPath != "" {
				pdf.SetFont("Courier", "B", 12)
				pdf.Cell(0, 10, "Screenshot:")
				pdf.Ln(10)

				// Add screenshot if it exists
				if _, err := os.Stat(vuln.Evidence.ScreenshotPath); err == nil {
					// Get image dimensions
					imgInfo := pdf.RegisterImage(vuln.Evidence.ScreenshotPath, "")
					if imgInfo != nil {
						imgWidth, imgHeight := imgInfo.Extent()
						// Scale image to fit page width while maintaining aspect ratio
						pageWidth := 190.0 // A4 width (210mm) minus margins
						scale := pageWidth / imgWidth
						pdf.Image(vuln.Evidence.ScreenshotPath, 10, pdf.GetY(), pageWidth, imgHeight*scale, false, "", 0, "")
						pdf.Ln(imgHeight*scale + 10)
					}
				}
			}

			// Log file reference
			if vuln.Evidence.LogPath != "" {
				pdf.SetFont("Courier", "B", 12)
				pdf.Cell(30, 10, "Log File:")
				pdf.SetFont("Courier", "", 12)
				pdf.Cell(0, 10, filepath.Base(vuln.Evidence.LogPath))
				pdf.Ln(10)
			}
		}

		// Add page break if not the last vulnerability
		if i < len(vulnerabilities)-1 {
			pdf.AddPage()
		}
	}

	// Save the PDF
	if err := pdf.OutputFileAndClose(outputPath); err != nil {
		return fmt.Errorf("failed to save PDF: %v", err)
	}

	return nil
}
