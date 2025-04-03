package reporter

import (
	"strings"
	"testing"

	"github.com/gleicon/sonnel/internal/models"
)

func TestGenerateReport(t *testing.T) {
	scanResult := &models.ScanResult{
		Target:    "http://example.com",
		Timestamp: "2024-03-21T12:00:00Z",
		Vulnerabilities: []models.Vulnerability{
			{
				Title:       "Test Vulnerability",
				Description: "This is a test vulnerability",
				Severity:    models.High,
				Category:    models.CategoryBrokenAccessControl,
				URL:         "http://example.com/test",
				Remediation: "Fix the vulnerability",
			},
		},
		Summary: map[models.OWASPCategory]int{
			models.CategoryBrokenAccessControl: 1,
		},
		SeverityCount: map[models.SeverityLevel]int{
			models.High: 1,
		},
	}

	report := GenerateReport(scanResult)
	if !strings.Contains(report, "Test Vulnerability") {
		t.Error("Report should contain the vulnerability title")
	}
	if !strings.Contains(report, "This is a test vulnerability") {
		t.Error("Report should contain the vulnerability description")
	}
	if !strings.Contains(report, "High") {
		t.Error("Report should contain the vulnerability severity")
	}
	if !strings.Contains(report, "Fix the vulnerability") {
		t.Error("Report should contain the vulnerability remediation")
	}
}
