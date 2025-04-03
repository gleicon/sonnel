.PHONY: build test clean scan-juiceshop scan-juiceshop-report scan-report help init

# Initialize directories
init:
	mkdir -p sonnel_output/evidence
	mkdir -p sonnel_output/reports

# Build commands
build: init
	go build -o sonnel ./cmd/sonnel

test:
	go test ./... -v

clean:
	rm -f sonnel
	rm -rf sonnel_output
	rm -f *.pdf

# Scan commands
scan-juiceshop: build
	./sonnel scan https://juice-shop.herokuapp.com --verbose

scan-juiceshop-report: build
	./sonnel report https://juice-shop.herokuapp.com

# General scan and report commands
scan-report: build
	@echo "Usage: make scan-report TARGET=<url>"
	@echo "Example: make scan-report TARGET=https://example.com"
	@if [ -z "$(TARGET)" ]; then echo "Error: TARGET is required"; exit 1; fi
	./sonnel report $(TARGET)

scan: build
	@echo "Usage: make scan TARGET=<url> VERBOSE=<true|false>"
	@echo "Example: make scan TARGET=https://example.com VERBOSE=true"
	@if [ -z "$(TARGET)" ]; then echo "Error: TARGET is required"; exit 1; fi
	@if [ "$(VERBOSE)" = "true" ]; then \
		./sonnel scan $(TARGET) --verbose; \
	else \
		./sonnel scan $(TARGET); \
	fi

# Help command
help:
	@echo "Available commands:"
	@echo "  make init                  - Initialize required directories"
	@echo "  make build                 - Build the sonnel binary"
	@echo "  make test                  - Run all tests"
	@echo "  make clean                 - Clean build artifacts and reports"
	@echo "  make scan-juiceshop        - Scan OWASP Juice Shop with verbose output"
	@echo "  make scan-juiceshop-report - Generate PDF report for OWASP Juice Shop"
	@echo "  make scan-report           - Generate PDF report for a target URL (requires TARGET)"
	@echo "  make scan                  - Run scan on a target URL (requires TARGET, optional VERBOSE)"
	@echo ""
	@echo "Examples:"
	@echo "  make scan-report TARGET=https://example.com"
	@echo "  make scan TARGET=https://example.com VERBOSE=true" 