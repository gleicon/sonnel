package scanner

import (
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
)

// RunFullReconPipeline orchestrates the Amass → Httpx → Nuclei pipeline
func RunFullReconPipeline(domain string, save bool) error {
	tm := NewToolManager()

	// Step 1: Run Amass
	subdomainsFile, err := ioutil.TempFile("", "subdomains.txt")
	if err != nil {
		return fmt.Errorf("failed to create temp file for subdomains: %v", err)
	}
	defer os.Remove(subdomainsFile.Name())

	amassArgs := []string{"enum", "-passive", "-norecursive", "-d", domain, "-o", subdomainsFile.Name()}
	_, err = tm.ExecuteTool("amass", amassArgs)
	if err != nil {
		return fmt.Errorf("failed to run Amass: %v", err)
	}

	// Step 2: Run Httpx
	liveHostsFile, err := ioutil.TempFile("", "live.txt")
	if err != nil {
		return fmt.Errorf("failed to create temp file for live hosts: %v", err)
	}
	defer os.Remove(liveHostsFile.Name())

	httpxArgs := []string{"-l", subdomainsFile.Name(), "-silent", "-threads", "10"}
	httpxOutput, err := tm.ExecuteTool("httpx", httpxArgs)
	if err != nil {
		return fmt.Errorf("failed to run Httpx: %v", err)
	}
	if _, err := liveHostsFile.WriteString(httpxOutput); err != nil {
		return fmt.Errorf("failed to write live hosts: %v", err)
	}

	// Step 3: Run Nuclei
	resultsFile, err := ioutil.TempFile("", "result.txt")
	if err != nil {
		return fmt.Errorf("failed to create temp file for results: %v", err)
	}
	defer os.Remove(resultsFile.Name())

	nucleiArgs := []string{"-l", liveHostsFile.Name(), "-o", resultsFile.Name(), "-timeout", "30"}
	_, err = tm.ExecuteTool("nuclei", nucleiArgs)
	if err != nil {
		return fmt.Errorf("failed to run Nuclei: %v", err)
	}

	// Output results
	fmt.Println("## Subdomains Discovered")
	fmt.Println(httpxOutput)

	fmt.Println("## Live Hosts")
	liveHosts, _ := ioutil.ReadFile(liveHostsFile.Name())
	fmt.Println(string(liveHosts))

	fmt.Println("## Vulnerabilities")
	vulnerabilities, _ := ioutil.ReadFile(resultsFile.Name())
	fmt.Println(string(vulnerabilities))

	// Save raw files if requested
	if save {
		outputDir := filepath.Join("scan_output", domain)
		os.MkdirAll(outputDir, 0755)
		os.Rename(subdomainsFile.Name(), filepath.Join(outputDir, "subdomains.txt"))
		os.Rename(liveHostsFile.Name(), filepath.Join(outputDir, "live.txt"))
		os.Rename(resultsFile.Name(), filepath.Join(outputDir, "result.txt"))
	}

	return nil
}
