// Purpose: Implements a CI/CD pipeline deployment security gate. Parses vulnerability reports and fails the build (exit code 1) if security thresholds (e.g. any Criticals, > 2 Highs, or hardcoded secrets) are violated.
package main

import (
	"encoding/json"
	"fmt"
	"os"
)

// SecurityMetrics represents aggregate scan findings from different scanners.
type SecurityMetrics struct {
	BuildID        string          `json:"build_id"`
	SASTScan       VulnerabilitySet `json:"sast_scan"`
	DependencyScan VulnerabilitySet `json:"dependency_scan"`
	SecretScan     SecretFindings   `json:"secret_scan"`
	LicenseScan    LicenseFindings  `json:"license_scan"`
}

// VulnerabilitySet tracks severity counts.
type VulnerabilitySet struct {
	Critical int `json:"critical"`
	High     int `json:"high"`
	Medium   int `json:"medium"`
	Low      int `json:"low"`
}

// SecretFindings tracks detected secrets count.
type SecretFindings struct {
	LeakedSecrets int `json:"leaked_secrets"`
}

// LicenseFindings tracks copyleft license counts.
type LicenseFindings struct {
	CopyleftLicenses int `json:"copyleft_licenses"`
}

// GatePolicy defines the threshold limits for passing the build.
type GatePolicy struct {
	AllowCritical     bool
	MaxAllowedHighs   int
	BlockSecrets      bool
	BlockCopyleft     bool
}

// EvaluateGate checks metrics against the defined policy.
func EvaluateGate(metrics SecurityMetrics, policy GatePolicy) (bool, []string) {
	var failures []string

	// 1. Critical vulnerabilities check
	if !policy.AllowCritical {
		if metrics.SASTScan.Critical > 0 {
			failures = append(failures, fmt.Sprintf("SAST Scan contains %d CRITICAL vulnerability findings (Threshold: 0)", metrics.SASTScan.Critical))
		}
		if metrics.DependencyScan.Critical > 0 {
			failures = append(failures, fmt.Sprintf("Dependency Scan contains %d CRITICAL vulnerability findings (Threshold: 0)", metrics.DependencyScan.Critical))
		}
	}

	// 2. High vulnerabilities check
	if metrics.SASTScan.High > policy.MaxAllowedHighs {
		failures = append(failures, fmt.Sprintf("SAST Scan contains %d HIGH vulnerability findings (Threshold: %d)", metrics.SASTScan.High, policy.MaxAllowedHighs))
	}
	if metrics.DependencyScan.High > policy.MaxAllowedHighs {
		failures = append(failures, fmt.Sprintf("Dependency Scan contains %d HIGH vulnerability findings (Threshold: %d)", metrics.DependencyScan.High, policy.MaxAllowedHighs))
	}

	// 3. Secrets check
	if policy.BlockSecrets && metrics.SecretScan.LeakedSecrets > 0 {
		failures = append(failures, fmt.Sprintf("Secret Scanner detected %d hardcoded secrets in commit diff (Threshold: 0)", metrics.SecretScan.LeakedSecrets))
	}

	// 4. License check
	if policy.BlockCopyleft && metrics.LicenseScan.CopyleftLicenses > 0 {
		failures = append(failures, fmt.Sprintf("License Scanner detected %d libraries with Copyleft licenses (Threshold: 0)", metrics.LicenseScan.CopyleftLicenses))
	}

	return len(failures) == 0, failures
}

func main() {
	// Sample JSON output from scanners
	sampleReportJSON := `{
		"build_id": "job-run-849921",
		"sast_scan": {
			"critical": 0,
			"high": 3,
			"medium": 5,
			"low": 12
		},
		"dependency_scan": {
			"critical": 1,
			"high": 1,
			"medium": 4,
			"low": 8
		},
		"secret_scan": {
			"leaked_secrets": 0
		},
		"license_scan": {
			"copyleft_licenses": 1
		}
	}`

	fmt.Println("==================================================")
	fmt.Println("DevSecOps CI/CD Deployment Security Gate Engine")
	fmt.Println("==================================================")

	var metrics SecurityMetrics
	if err := json.Unmarshal([]byte(sampleReportJSON), &metrics); err != nil {
		fmt.Printf("Error unmarshaling security metrics: %v\n", err)
		os.Exit(1)
	}

	// Default Org Security Policy
	policy := GatePolicy{
		AllowCritical:   false, // Fail if any Criticals exist
		MaxAllowedHighs: 2,     // Fail if > 2 Highs exist
		BlockSecrets:    true,  // Fail if any secrets leaked
		BlockCopyleft:   true,  // Fail on GPL/AGPL software
	}

	fmt.Printf("\nEvaluating Build: %s...\n", metrics.BuildID)
	passed, violations := EvaluateGate(metrics, policy)

	if passed {
		fmt.Println("\n[PASS] All security gates successfully cleared. Continuing deployment pipeline.")
		os.Exit(0)
	} else {
		fmt.Println("\n[FAIL] Build blocked by organizational security policy gates!")
		fmt.Println("Violations:")
		for _, violation := range violations {
			fmt.Printf("   - %s\n", violation)
		}
		// In a real pipeline, we exit 1 to cause the execution job runner to halt/fail
		fmt.Println("\n[INFO] Exiting with status code 1.")
		os.Exit(1)
	}
}
