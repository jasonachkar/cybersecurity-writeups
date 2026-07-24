// Purpose: Demonstrates bounded secret-pattern and entropy checks on added diff lines.
// This educational scanner is not a replacement for a maintained secret-scanning engine.
package main

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"math"
	"regexp"
	"strings"
)

type finding struct {
	LineNumber  int
	RuleName    string
	Severity    string
	Fingerprint string
}

type secretRule struct {
	Name     string
	Pattern  *regexp.Regexp
	Severity string
}

var secretRules = []secretRule{
	{
		Name:     "AWS access-key identifier",
		Pattern:  regexp.MustCompile(`\b(?:AKIA|ASIA)[A-Z0-9]{16}\b`),
		Severity: "CRITICAL",
	},
	{
		Name: "credential-like assignment",
		Pattern: regexp.MustCompile(
			`(?i)(?:api[_-]?key|auth[_-]?token|password|secret)\s*[:=]\s*["'][^"']{12,}["']`,
		),
		Severity: "HIGH",
	},
	{
		Name:     "PEM private-key header",
		Pattern:  regexp.MustCompile(`-----BEGIN [A-Z ]*PRIVATE KEY-----`),
		Severity: "CRITICAL",
	},
}

var assignedValue = regexp.MustCompile(
	`(?i)[a-z0-9_-]+\s*[:=]\s*["']([A-Za-z0-9._~+/=-]{20,})["']`,
)

func shannonEntropy(value string) float64 {
	if len(value) == 0 {
		return 0
	}
	counts := make(map[rune]float64)
	for _, character := range value {
		counts[character]++
	}
	var entropy float64
	length := float64(len([]rune(value)))
	for _, count := range counts {
		probability := count / length
		entropy -= probability * math.Log2(probability)
	}
	return entropy
}

func fingerprint(value string) string {
	digest := sha256.Sum256([]byte(value))
	return hex.EncodeToString(digest[:])[:12]
}

func appendFinding(
	findings []finding,
	lineNumber int,
	ruleName string,
	severity string,
	matchedValue string,
) []finding {
	candidate := finding{
		LineNumber:  lineNumber,
		RuleName:    ruleName,
		Severity:    severity,
		Fingerprint: fingerprint(matchedValue),
	}
	for _, existing := range findings {
		if existing.LineNumber == candidate.LineNumber &&
			existing.Fingerprint == candidate.Fingerprint {
			return findings
		}
	}
	return append(findings, candidate)
}

func scanAddedLines(diff string) []finding {
	var findings []finding
	for index, line := range strings.Split(diff, "\n") {
		if !strings.HasPrefix(line, "+") || strings.HasPrefix(line, "+++") {
			continue
		}
		added := strings.TrimPrefix(line, "+")
		for _, rule := range secretRules {
			for _, match := range rule.Pattern.FindAllString(added, -1) {
				findings = appendFinding(
					findings,
					index+1,
					rule.Name,
					rule.Severity,
					match,
				)
			}
		}
		for _, match := range assignedValue.FindAllStringSubmatch(added, -1) {
			value := match[1]
			if shannonEntropy(value) >= 4.3 {
				findings = appendFinding(
					findings,
					index+1,
					"high-entropy assignment",
					"HIGH",
					value,
				)
			}
		}
	}
	return findings
}

func require(condition bool, message string) {
	if !condition {
		panic(message)
	}
}

func main() {
	// Construct synthetic values at runtime so the repository never contains a
	// literal that resembles a usable provider credential.
	syntheticAccessKey := "AKIA" + strings.Repeat("A", 16)
	syntheticToken := "M7xQ2vN9pR4sT8wY3zK6"
	diff := fmt.Sprintf(
		"--- a/config.env\n+++ b/config.env\n context=%s\n-OLD_TOKEN=%s\n+AWS_KEY=%s\n+AUTH_TOKEN=\"%s\"\n+MODE=test\n",
		syntheticAccessKey,
		syntheticToken,
		syntheticAccessKey,
		syntheticToken,
	)

	findings := scanAddedLines(diff)
	require(len(findings) >= 2, "expected synthetic added-line findings")
	require(
		len(scanAddedLines("+++ b/config.env\n+MODE=test\n")) == 0,
		"benign added line should pass",
	)
	for _, result := range findings {
		require(result.Fingerprint != syntheticAccessKey, "finding exposed raw access key")
		require(result.Fingerprint != syntheticToken, "finding exposed raw token")
		fmt.Printf(
			"[%s] line %d: %s (fingerprint %s)\n",
			result.Severity,
			result.LineNumber,
			result.RuleName,
			result.Fingerprint,
		)
	}
	fmt.Printf("PASS: %d redacted synthetic finding(s); removed/context lines were ignored.\n", len(findings))
}
