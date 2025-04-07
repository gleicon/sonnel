package scanner

import (
	"fmt"
	"os/exec"
	"strings"
)

// Tool represents an external security tool
type Tool struct {
	Name        string
	Command     string
	Version     string
	IsAvailable bool
	Path        string
}

// ToolManager handles external tool availability and execution
type ToolManager struct {
	tools map[string]*Tool
}

// NewToolManager creates a new ToolManager instance
func NewToolManager() *ToolManager {
	tm := &ToolManager{
		tools: make(map[string]*Tool),
	}
	tm.initTools()
	return tm
}

// initTools initializes the available tools
func (tm *ToolManager) initTools() {
	tools := []*Tool{
		{
			Name:    "ffuf",
			Command: "ffuf",
		},
		{
			Name:    "amass",
			Command: "amass",
		},
		{
			Name:    "httpx",
			Command: "httpx",
		},
		{
			Name:    "nuclei",
			Command: "nuclei",
		},
	}

	for _, tool := range tools {
		tm.tools[tool.Name] = tool
		tm.checkToolAvailability(tool)
	}
}

// checkToolAvailability checks if a tool is available in the system
func (tm *ToolManager) checkToolAvailability(tool *Tool) {
	path, err := exec.LookPath(tool.Command)
	if err != nil {
		tool.IsAvailable = false
		return
	}

	tool.IsAvailable = true
	tool.Path = path

	// Get version if possible
	cmd := exec.Command(path, "--version")
	output, err := cmd.Output()
	if err == nil {
		tool.Version = strings.TrimSpace(string(output))
	}
}

// IsToolAvailable checks if a specific tool is available
func (tm *ToolManager) IsToolAvailable(toolName string) bool {
	tool, exists := tm.tools[toolName]
	if !exists {
		return false
	}
	return tool.IsAvailable
}

// GetTool returns a tool by name
func (tm *ToolManager) GetTool(toolName string) (*Tool, error) {
	tool, exists := tm.tools[toolName]
	if !exists {
		return nil, fmt.Errorf("tool %s not found", toolName)
	}
	return tool, nil
}

// ExecuteTool runs a tool with the given arguments
func (tm *ToolManager) ExecuteTool(toolName string, args []string) (string, error) {
	tool, err := tm.GetTool(toolName)
	if err != nil {
		return "", err
	}

	if !tool.IsAvailable {
		return "", fmt.Errorf("tool %s is not available", toolName)
	}

	// Print command being executed
	fmt.Printf("\nExecuting %s with arguments: %v\n", toolName, args)

	cmd := exec.Command(tool.Path, args...)
	output, err := cmd.CombinedOutput()
	if err != nil {
		fmt.Printf("Error executing %s: %v\n", toolName, err)
		fmt.Printf("Output: %s\n", string(output))
		// Check if the error is due to non-zero exit code but we still got output
		if len(output) > 0 {
			// Try to sanitize the output by removing problematic cookie data
			outputStr := string(output)
			if strings.Contains(outputStr, "cookiePart") {
				// Remove cookie-related data that might cause JSON parsing issues
				lines := strings.Split(outputStr, "\n")
				var sanitizedLines []string
				for _, line := range lines {
					if !strings.Contains(line, "cookiePart") && !strings.Contains(line, "Set-Cookie") {
						sanitizedLines = append(sanitizedLines, line)
					}
				}
				outputStr = strings.Join(sanitizedLines, "\n")
				return outputStr, nil
			}
			return string(output), nil
		}
		return "", fmt.Errorf("error executing %s: %v", toolName, err)
	}

	// Print tool output
	fmt.Printf("%s output:\n%s\n", toolName, string(output))

	// Sanitize output if it contains cookie data
	outputStr := string(output)
	if strings.Contains(outputStr, "cookiePart") {
		// Remove cookie-related data that might cause JSON parsing issues
		lines := strings.Split(outputStr, "\n")
		var sanitizedLines []string
		for _, line := range lines {
			if !strings.Contains(line, "cookiePart") && !strings.Contains(line, "Set-Cookie") {
				sanitizedLines = append(sanitizedLines, line)
			}
		}
		outputStr = strings.Join(sanitizedLines, "\n")
	}

	return outputStr, nil
}

// GetAvailableTools returns a list of available tools
func (tm *ToolManager) GetAvailableTools() []string {
	var available []string
	for name, tool := range tm.tools {
		if tool.IsAvailable {
			available = append(available, name)
		}
	}
	return available
}
