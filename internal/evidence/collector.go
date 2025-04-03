package evidence

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/chromedp/chromedp"
)

// EvidenceCollector handles gathering evidence for vulnerabilities
type EvidenceCollector struct {
	outputDir string
}

// NewEvidenceCollector creates a new evidence collector
func NewEvidenceCollector(outputDir string) (*EvidenceCollector, error) {
	// Create output directory if it doesn't exist
	if err := os.MkdirAll(outputDir, 0755); err != nil {
		return nil, fmt.Errorf("failed to create output directory: %v", err)
	}

	return &EvidenceCollector{
		outputDir: outputDir,
	}, nil
}

// CollectEvidence gathers all available evidence for a vulnerability
func (ec *EvidenceCollector) CollectEvidence(targetURL string, req *http.Request, resp *http.Response) (*Evidence, error) {
	evidence := &Evidence{
		URL: targetURL,
	}

	// Generate curl command without cookies
	evidence.CurlCommand = ec.generateCurlCommand(req)

	// Save request/response logs first (as it's more reliable)
	logPath, err := ec.saveRequestResponseLogs(req, resp)
	if err != nil {
		fmt.Printf("Warning: Could not save request/response logs: %v\n", err)
	} else {
		evidence.LogPath = logPath
	}

	// Try to capture screenshot, but don't fail if it doesn't work
	screenshotPath, err := ec.captureScreenshot(targetURL)
	if err != nil {
		fmt.Printf("Warning: Could not capture screenshot: %v\n", err)
	} else {
		evidence.ScreenshotPath = screenshotPath
	}

	return evidence, nil
}

// Evidence contains all gathered evidence for a vulnerability
type Evidence struct {
	URL            string
	CurlCommand    string
	ScreenshotPath string
	LogPath        string
}

// generateCurlCommand creates a curl command that reproduces the request
func (ec *EvidenceCollector) generateCurlCommand(req *http.Request) string {
	var cmd strings.Builder
	cmd.WriteString("curl -X " + req.Method)

	// Add headers, explicitly skipping cookies
	for key, values := range req.Header {
		if key == "Cookie" || key == "Set-Cookie" {
			continue
		}
		for _, value := range values {
			cmd.WriteString(fmt.Sprintf(" -H '%s: %s'", key, value))
		}
	}

	// Add body if present
	if req.Body != nil {
		body, _ := io.ReadAll(req.Body)
		req.Body = io.NopCloser(bytes.NewBuffer(body))
		if len(body) > 0 {
			cmd.WriteString(fmt.Sprintf(" -d '%s'", string(body)))
		}
	}

	cmd.WriteString(" '" + req.URL.String() + "'")
	return cmd.String()
}

// captureScreenshot takes a screenshot of the target URL
func (ec *EvidenceCollector) captureScreenshot(targetURL string) (string, error) {
	// Generate unique filename
	filename := fmt.Sprintf("screenshot_%s_%d.png",
		strings.ReplaceAll(url.QueryEscape(targetURL), "%", "_"),
		time.Now().Unix())
	path := filepath.Join(ec.outputDir, filename)

	// Create context with options to handle cookie errors and disable cookies
	opts := append(chromedp.DefaultExecAllocatorOptions[:],
		chromedp.Flag("ignore-certificate-errors", true),
		chromedp.Flag("disable-web-security", true),
		chromedp.Flag("disable-cookies", true),
		chromedp.Flag("disable-storage-reset", true),
		chromedp.Flag("disable-application-cache", true),
		chromedp.Flag("disable-local-storage", true),
		chromedp.Flag("disable-session-storage", true),
		chromedp.Flag("disable-extensions", true),
		chromedp.Flag("disable-popup-blocking", true),
		chromedp.Flag("disable-background-networking", true),
		chromedp.Flag("disable-background-timer-throttling", true),
		chromedp.Flag("disable-backgrounding-occluded-windows", true),
		chromedp.Flag("disable-breakpad", true),
		chromedp.Flag("disable-component-extensions-with-background-pages", true),
		chromedp.Flag("disable-default-apps", true),
		chromedp.Flag("disable-dev-shm-usage", true),
		chromedp.Flag("disable-features", "site-per-process,TranslateUI,BlinkGenPropertyTrees"),
		chromedp.Flag("disable-hang-monitor", true),
		chromedp.Flag("disable-ipc-flooding-protection", true),
		chromedp.Flag("disable-notifications", true),
		chromedp.Flag("disable-prompt-on-repost", true),
		chromedp.Flag("disable-renderer-backgrounding", true),
		chromedp.Flag("disable-sync", true),
		chromedp.Flag("force-color-profile", "srgb"),
		chromedp.Flag("metrics-recording-only", true),
		chromedp.Flag("safebrowsing-disable-auto-update", true),
		chromedp.Flag("enable-automation", true),
		chromedp.Flag("password-store", "basic"),
		chromedp.Flag("use-mock-keychain", true),
		chromedp.Flag("no-sandbox", true),
		chromedp.Flag("disable-gpu", true),
		chromedp.Flag("disable-software-rasterizer", true),
		chromedp.Flag("disable-dev-tools", true),
		chromedp.Flag("disable-logging", true),
		chromedp.Flag("log-level", "0"),
		chromedp.Flag("silent", true),
	)
	allocCtx, cancel := chromedp.NewExecAllocator(context.Background(), opts...)
	defer cancel()

	ctx, cancel := chromedp.NewContext(allocCtx)
	defer cancel()

	// Set a timeout for the screenshot operation
	ctx, cancel = context.WithTimeout(ctx, 30*time.Second)
	defer cancel()

	// Capture screenshot with error handling
	var buf []byte
	if err := chromedp.Run(ctx,
		chromedp.Navigate(targetURL),
		chromedp.Sleep(2*time.Second), // Wait for page to load
		chromedp.CaptureScreenshot(&buf),
	); err != nil {
		return "", fmt.Errorf("screenshot capture failed: %v", err)
	}

	// Save screenshot
	if err := os.WriteFile(path, buf, 0644); err != nil {
		return "", fmt.Errorf("failed to save screenshot: %v", err)
	}

	return path, nil
}

// saveRequestResponseLogs saves the request and response details
func (ec *EvidenceCollector) saveRequestResponseLogs(req *http.Request, resp *http.Response) (string, error) {
	// Generate unique filename
	filename := fmt.Sprintf("logs_%s_%d.txt",
		strings.ReplaceAll(url.QueryEscape(req.URL.String()), "%", "_"),
		time.Now().Unix())
	path := filepath.Join(ec.outputDir, filename)

	// Create log content
	var logContent strings.Builder
	logContent.WriteString("=== REQUEST ===\n")
	logContent.WriteString(fmt.Sprintf("%s %s %s\n", req.Method, req.URL.String(), req.Proto))

	// Log headers, explicitly skipping cookies
	for key, values := range req.Header {
		if key == "Cookie" || key == "Set-Cookie" {
			continue
		}
		for _, value := range values {
			logContent.WriteString(fmt.Sprintf("%s: %s\n", key, value))
		}
	}
	logContent.WriteString("\n")

	if req.Body != nil {
		body, _ := io.ReadAll(req.Body)
		req.Body = io.NopCloser(bytes.NewBuffer(body))
		if len(body) > 0 {
			logContent.WriteString("Request Body:\n")
			logContent.WriteString(string(body))
			logContent.WriteString("\n\n")
		}
	}

	logContent.WriteString("=== RESPONSE ===\n")
	logContent.WriteString(fmt.Sprintf("%s %s\n", resp.Proto, resp.Status))
	for key, values := range resp.Header {
		if key == "Cookie" || key == "Set-Cookie" {
			continue
		}
		for _, value := range values {
			logContent.WriteString(fmt.Sprintf("%s: %s\n", key, value))
		}
	}
	logContent.WriteString("\n")

	if resp.Body != nil {
		body, _ := io.ReadAll(resp.Body)
		resp.Body = io.NopCloser(bytes.NewBuffer(body))
		if len(body) > 0 {
			logContent.WriteString("Response Body:\n")
			logContent.WriteString(string(body))
		}
	}

	// Save log file
	if err := os.WriteFile(path, []byte(logContent.String()), 0644); err != nil {
		return "", fmt.Errorf("failed to save log file: %v", err)
	}

	return path, nil
}
