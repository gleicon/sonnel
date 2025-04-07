package models

import "strings"

// SeverityFromString converts a severity string to a SeverityLevel
func SeverityFromString(severity string) SeverityLevel {
	switch strings.ToLower(severity) {
	case "critical":
		return Critical
	case "high":
		return High
	case "medium":
		return Medium
	case "low":
		return Low
	default:
		return Info
	}
}
