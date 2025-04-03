# Sonnel - OWASP Top 10 Security Scanner

Sonnel is a command-line tool for scanning web applications for OWASP Top 10 vulnerabilities. It performs automated security testing and generates detailed PDF reports with evidence and remediation recommendations.

## Features

- Automated scanning for OWASP Top 10 vulnerabilities
- Detailed PDF reports with evidence
- Support for screenshots and request/response logs
- Command-line interface for easy integration
- Example scans against OWASP Juice Shop

## Installation

1. Clone the repository:
```bash
git clone https://github.com/gleicon/sonnel.git
cd sonnel
```

2. Build the tool:
```bash
make build
```

## Usage

### Basic Commands

```bash
# Initialize directories
make init

# Build the tool
make build

# Run tests
make test

# Clean build artifacts
make clean
```

### Scanning Commands

```bash
# Scan OWASP Juice Shop (example)
make scan-juiceshop

# Generate PDF report for Juice Shop
make scan-juiceshop-report

# Scan any target URL
make scan TARGET=https://example.com VERBOSE=true

# Generate PDF report for any target
make scan-report TARGET=https://example.com
```

### Directory Structure

- `sonnel_output/` - Main output directory
  - `evidence/` - Contains screenshots, logs, and other evidence
  - `reports/` - Contains generated PDF reports

## OWASP Top 10 Categories

Sonnel checks for the following OWASP Top 10 vulnerabilities:

1. A1: Broken Access Control
2. A2: Cryptographic Failures
3. A3: Injection
4. A4: Insecure Design
5. A5: Security Misconfiguration
6. A6: Vulnerable and Outdated Components
7. A7: Identification and Authentication Failures
8. A8: Software and Data Integrity Failures
9. A9: Security Logging and Monitoring Failures
10. A10: Server-Side Request Forgery

## Report Contents

The generated PDF reports include:

- Executive summary
- Vulnerability summary table
- Detailed findings for each vulnerability
- OWASP category information and documentation links
- Evidence (curl commands, screenshots, logs)
- Remediation recommendations

## Example: Juice Shop Report

To generate a sample report using the OWASP Juice Shop:

```bash
make scan-juiceshop-report
```

This will create a comprehensive report in `sonnel_output/reports/` that demonstrates all OWASP Top 10 vulnerabilities.

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Acknowledgments

- OWASP Top 10 Project
- OWASP Juice Shop Project
- All contributors and maintainers 