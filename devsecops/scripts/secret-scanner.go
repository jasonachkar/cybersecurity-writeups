// Purpose: Scans code files or git diff inputs using regular expressions and Shannon entropy calculations to identify hardcoded API keys, passwords, and private keys.
package main

import (
	"fmt"
	"math"
	"regexp"
	"strings"
)

// ScannerFinding holds information about a detected secret.
type ScannerFinding struct {
	LineNumber int
	RuleName   string
	Severity   string
	Content    string
	Entropy    float64
}

// ShannonEntropy calculates the thermodynamic entropy of a string (character distribution diversity).
// High entropy strings (e.g. > 4.5 for hex/base64) are strong indicators of random cryptographic keys.
func ShannonEntropy(s string) float64 {
	if len(s) == 0 {
		return 0
	}
	charMap := make(map[rune]float64)
	for _, char := range s {
		charMap[char]++
	}

	var entropy float64
	length := float64(len(s))
	for _, count := range charMap {
		prob := count / length
		entropy -= prob * math.Log2(prob)
	}
	return entropy
}

// SecretRules defines patterns we scan for.
var SecretRules = []struct {
	Name     string
	Pattern  *regexp.Regexp
	Severity string
}{
	{
		Name:     "AWS Access Key ID",
		Pattern:  regexp.MustCompile(`(A3T[A-Z0-9]|AKIA|AGPA|AIDA|AROA|ASCA|ASIA)[A-Z0-9]{16}`),
		Severity: "CRITICAL",
	},
	{
		Name:     "AWS Secret Access Key",
		Pattern:  regexp.MustCompile(`(?i)(?:aws_secret|aws_key|secret_key|aws_secret_access_key).*?['\"][A-Za-z0-9/+=]{40}['\"]`),
		Severity: "CRITICAL",
	},
	{
		Name:     "Generic API Key / Token",
		Pattern:  regexp.MustCompile(`(?i)(?:api_key|apikey|secret|token|password|passwd|auth_token).*?['\"][A-Za-z0-9\-._~+/=]{20,80}['\"]`),
		Severity: "HIGH",
	},
	{
		Name:     "Slack Webhook URL",
		Pattern:  regexp.MustCompile(`https://hooks\.slack\.com/services/T[A-Z0-9]{8}/B[A-Z0-9]{8}/[A-Za-z0-9]{24}`),
		Severity: "CRITICAL",
	},
	{
		Name:     "PEM Private Key Header",
		Pattern:  regexp.MustCompile(`-----BEGIN [A-Z ]*PRIVATE KEY-----`),
		Severity: "CRITICAL",
	},
}

func main() {
	// Sample git diff block with leaked credentials
	gitDiffInput := `
diff --git a/config.json b/config.json
index 8389d63..298d8ef 100644
--- a/config.json
+++ b/config.json
@@ -12,4 +12,6 @@
-  "db_host": "localhost",
+  "db_host": "rds-prod.c3x918s.us-east-1.rds.amazonaws.com",
+  "aws_access_key": "AKIAIOSFODNN7EXAMPLE",
+  "aws_secret": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
+  "slack_channel": "https://hooks.slack.com/services/" + "T00000000/B00000000/XXXXXXXXXXXXXXXXXXXXXXXX" + `",`
+  "encryption_key": "dTFhM3M5OGQyM2g0ajVraDJsMzQ1Njc4OWFiY2RlZmc=",
+  "non_secret_val": "simple_string_value_here"
	`

	fmt.Println("==================================================")
	fmt.Println("🛡️ Git Commit Secret Scanner & Entropy Audit Engine")
	fmt.Println("==================================================")

	lines := strings.Split(gitDiffInput, "\n")
	var findings []ScannerFinding

	for idx, line := range lines {
		// Only scan added lines in diff to avoid false positives on context
		if !strings.HasPrefix(line, "+") || strings.HasPrefix(line, "+++") {
			continue
		}

		cleanLine := strings.TrimPrefix(line, "+")

		// 1. Scan for pattern matches
		for _, rule := range SecretRules {
			if matches := rule.Pattern.FindAllString(cleanLine, -1); len(matches) > 0 {
				for _, match := range matches {
					findings = append(findings, ScannerFinding{
						LineNumber: idx + 1,
						RuleName:   rule.Name,
						Severity:   rule.Severity,
						Content:    match,
						Entropy:    ShannonEntropy(match),
					})
				}
			}
		}

		// 2. Entropy-based scanning on assignments to catch customized key names
		// Look for variables or keys assigned a quoted value of length >= 16
		assignmentPattern := regexp.MustCompile(`(?i)(?:[a-z0-9_-]+)\s*[:=]\s*['\"]([A-Za-z0-9\-._~+/=]{16,})['\"]`)
		if matches := assignmentPattern.FindAllStringSubmatch(cleanLine, -1); len(matches) > 0 {
			for _, match := range matches {
				value := match[1]
				entropy := ShannonEntropy(value)

				// High entropy thresholds:
				// Base64-like keys are usually very random and have entropy > 4.5.
				if entropy > 4.5 {
					// Check if this finding was already caught by pattern matching
					alreadyCaught := false
					for _, f := range findings {
						if strings.Contains(f.Content, value) {
							alreadyCaught = true
							break
						}
					}

					if !alreadyCaught {
						findings = append(findings, ScannerFinding{
							LineNumber: idx + 1,
							RuleName:   "High-Entropy Variable Assignment",
							Severity:   "HIGH",
							Content:    value,
							Entropy:    entropy,
						})
					}
				}
			}
		}
	}

	// Print results
	if len(findings) == 0 {
		fmt.Println("No secrets or high-entropy credentials detected. Commit passes security gates.")
	} else {
		fmt.Printf("Alert! Detected %d potential secrets leakage in commit changes:\n\n", len(findings))
		for _, f := range findings {
			fmt.Printf("[%s] Line %d: Found '%s'\n", f.Severity, f.LineNumber, f.RuleName)
			fmt.Printf("   - String:  %s\n", f.Content)
			fmt.Printf("   - Entropy: %.4f (bits/character)\n\n", f.Entropy)
		}
	}
}
