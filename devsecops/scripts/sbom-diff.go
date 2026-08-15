// Purpose: Parses and diffs two CycloneDX Software Bill of Materials (SBOM) files in JSON format to identify new dependencies, version upgrades/downgrades, and license compliance updates.
package main

import (
	"encoding/json"
	"fmt"
)

// CycloneDXSBOM represents a simplified CycloneDX SBOM structure.
type CycloneDXSBOM struct {
	BOMFormat    string      `json:"bomFormat"`
	SpecVersion  string      `json:"specVersion"`
	SerialNumber string      `json:"serialNumber"`
	Version      int         `json:"version"`
	Components   []Component `json:"components"`
}

// Component represents a software dependency in the SBOM.
type Component struct {
	Type       string          `json:"type"`
	Group      string          `json:"group,omitempty"`
	Name       string          `json:"name"`
	Version    string          `json:"version"`
	PURL       string          `json:"purl,omitempty"`
	Licenses   []LicenseChoice `json:"licenses,omitempty"`
}

// LicenseChoice represents license definition wrappers in CycloneDX.
type LicenseChoice struct {
	License LicenseDetails `json:"license"`
}

// LicenseDetails holds the license ID or name.
type LicenseDetails struct {
	ID   string `json:"id,omitempty"` // e.g. "MIT", "Apache-2.0", "GPL-3.0-only"
	Name string `json:"name,omitempty"`
}

// Helper to get unique key for a component.
func componentKey(c Component) string {
	group := c.Group
	if group == "" {
		group = "default"
	}
	return group + ":" + c.Name
}

func main() {
	// Simulated SBOM A (Previous version)
	sbomAJSON := `{
		"bomFormat": "CycloneDX",
		"specVersion": "1.4",
		"version": 1,
		"components": [
			{
				"type": "library",
				"group": "github.com/gin-gonic",
				"name": "gin",
				"version": "v1.8.0",
				"purl": "pkg:golang/github.com/gin-gonic/gin@v1.8.0",
				"licenses": [{"license": {"id": "MIT"}}]
			},
			{
				"type": "library",
				"group": "golang.org/x",
				"name": "crypto",
				"version": "v0.1.0",
				"purl": "pkg:golang/golang.org/x/crypto@v0.1.0",
				"licenses": [{"license": {"id": "BSD-3-Clause"}}]
			}
		]
	}`

	// Simulated SBOM B (New version introducing upgrade and new dependency)
	sbomBJSON := `{
		"bomFormat": "CycloneDX",
		"specVersion": "1.4",
		"version": 2,
		"components": [
			{
				"type": "library",
				"group": "github.com/gin-gonic",
				"name": "gin",
				"version": "v1.9.0",
				"purl": "pkg:golang/github.com/gin-gonic/gin@v1.9.0",
				"licenses": [{"license": {"id": "MIT"}}]
			},
			{
				"type": "library",
				"group": "golang.org/x",
				"name": "crypto",
				"version": "v0.1.0",
				"purl": "pkg:golang/golang.org/x/crypto@v0.1.0",
				"licenses": [{"license": {"id": "BSD-3-Clause"}}]
			},
			{
				"type": "library",
				"group": "github.com/go-gorm",
				"name": "gorm",
				"version": "v1.24.0",
				"purl": "pkg:golang/github.com/go-gorm/gorm@v1.24.0",
				"licenses": [{"license": {"id": "GPL-3.0-only"}}]
			}
		]
	}`

	fmt.Println("==================================================")
	fmt.Println("DevSecOps SBOM Diff & Dependency Audit Tool")
	fmt.Println("==================================================")

	var sbomA, sbomB CycloneDXSBOM
	if err := json.Unmarshal([]byte(sbomAJSON), &sbomA); err != nil {
		fmt.Printf("Error unmarshaling SBOM A: %v\n", err)
		return
	}
	if err := json.Unmarshal([]byte(sbomBJSON), &sbomB); err != nil {
		fmt.Printf("Error unmarshaling SBOM B: %v\n", err)
		return
	}

	// Map components in A
	mapA := make(map[string]Component)
	for _, comp := range sbomA.Components {
		mapA[componentKey(comp)] = comp
	}

	// Map components in B
	mapB := make(map[string]Component)
	for _, comp := range sbomB.Components {
		mapB[componentKey(comp)] = comp
	}

	fmt.Println("\nAnalyzing shifts between SBOM A (Baseline) -> SBOM B (Target Build)...")
	newDependencies := 0
	versionShifts := 0
	licenseAlerts := 0

	// 1. Scan for additions and version changes (B relative to A)
	for key, compB := range mapB {
		compA, exists := mapA[key]
		if !exists {
			fmt.Printf("[NEW DEPENDENCY] %s (%s) was introduced.\n", key, compB.Version)
			newDependencies++

			// Check license of new dependency
			for _, lic := range compB.Licenses {
				if lic.License.ID == "GPL-3.0-only" || lic.License.ID == "AGPL-3.0" {
					fmt.Printf("   [LICENSE ALERT] Component '%s' introduces copyleft license: %s\n", key, lic.License.ID)
					licenseAlerts++
				}
			}
		} else if compA.Version != compB.Version {
			fmt.Printf("[VERSION SHIFT] %s: %s -> %s\n", key, compA.Version, compB.Version)
			versionShifts++
		}
	}

	// 2. Scan for removals (A relative to B)
	removals := 0
	for key := range mapA {
		if _, exists := mapB[key]; !exists {
			fmt.Printf("[REMOVED DEPENDENCY] %s was removed.\n", key)
			removals++
		}
	}

	fmt.Println("\n--- Scan Results ---")
	fmt.Printf("Added Dependencies:      %d\n", newDependencies)
	fmt.Printf("Removed Dependencies:    %d\n", removals)
	fmt.Printf("Version Shifted Libs:    %d\n", versionShifts)
	fmt.Printf("High-Risk Licenses:      %d\n", licenseAlerts)
}
