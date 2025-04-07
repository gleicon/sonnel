package evidence

import (
	"bytes"
	"fmt"
	"io"
	"net/http"
	"strings"
)

// NewEvidence creates a new Evidence instance
func NewEvidence(req *http.Request, resp *http.Response) *Evidence {
	// Read request body
	var reqBody []byte
	if req.Body != nil {
		reqBody, _ = io.ReadAll(req.Body)
		req.Body = io.NopCloser(bytes.NewBuffer(reqBody))
	}

	// Read response body
	var respBody []byte
	if resp.Body != nil {
		respBody, _ = io.ReadAll(resp.Body)
		resp.Body = io.NopCloser(bytes.NewBuffer(respBody))
	}

	return &Evidence{
		URL:            req.URL.String(),
		CurlCommand:    generateCurlCommand(req),
		ScreenshotPath: "",
		LogPath:        "",
	}
}

// generateCurlCommand creates a curl command from the request
func generateCurlCommand(req *http.Request) string {
	var cmd strings.Builder
	cmd.WriteString("curl -X " + req.Method)

	// Add headers
	for key, values := range req.Header {
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
