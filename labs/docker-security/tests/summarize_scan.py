#!/usr/bin/env python3
"""Summarize Trivy and Syft output for the Docker lab. Usage: summarize_scan.py <outdir>

Raw finding counts are misleading: one vulnerable Go standard library appears once
per Go binary in an image, so a toolchain image reports the same CVE dozens of
times. This script therefore reports raw findings AND unique (CVE, package) pairs,
by severity and by result class, plus how many unique findings have a fixed version.
"""
import collections
import json
import pathlib
import sys


def load(path):
    try:
        return json.loads(path.read_text())
    except (FileNotFoundError, json.JSONDecodeError):
        return None


def summarize_vulns(report):
    raw = 0
    unique = {}
    by_class = collections.defaultdict(set)
    targets = 0
    for result in report.get("Results", []) or []:
        vulns = result.get("Vulnerabilities") or []
        if vulns:
            targets += 1
        for vuln in vulns:
            raw += 1
            key = (vuln["VulnerabilityID"], vuln.get("PkgName", ""))
            unique[key] = vuln
            by_class[result.get("Class", "unknown")].add(key)
    severity = collections.Counter(v["Severity"] for v in unique.values())
    return {
        "raw_findings": raw,
        "unique_cve_package_pairs": len(unique),
        "unique_by_severity": dict(sorted(severity.items())),
        "unique_by_class": {k: len(v) for k, v in sorted(by_class.items())},
        "unique_with_fixed_version": sum(1 for v in unique.values() if v.get("FixedVersion")),
        "result_targets_with_findings": targets,
    }


def summarize_config(report):
    findings = []
    for result in report.get("Results", []) or []:
        for item in result.get("Misconfigurations") or []:
            if item.get("Status") == "FAIL":
                findings.append({"id": item.get("ID"), "severity": item.get("Severity"), "title": item.get("Title")})
    return sorted(findings, key=lambda f: (f["id"] or "", f["title"] or ""))


def main():
    out = pathlib.Path(sys.argv[1])
    summary = {"images": {}, "dockerfile_misconfigurations": {}, "sbom": {}}
    version = load(out / "scan" / "trivy-version.json")
    if version:
        db = version.get("VulnerabilityDB") or {}
        summary["trivy"] = {
            "version": version.get("Version"),
            "db_updated_at": db.get("UpdatedAt"),
            "db_downloaded_at": db.get("DownloadedAt"),
        }
    else:
        summary["trivy"] = {"executed": False}
    for variant in ("insecure", "hardened"):
        report = load(out / "scan" / f"trivy-{variant}.json")
        if report:
            entry = summarize_vulns(report)
            meta_os = (report.get("Metadata") or {}).get("OS") or {}
            entry["os"] = f'{meta_os.get("Family", "none")} {meta_os.get("Name", "")}'.strip()
            summary["images"][variant] = entry
        sbom_scan = load(out / "scan" / f"trivy-sbom-{variant}.json")
        sbom_doc = load(out / "sbom" / f"{variant}.cdx.json")
        if sbom_doc:
            summary["sbom"][variant] = {
                "format": sbom_doc.get("bomFormat"),
                "spec_version": sbom_doc.get("specVersion"),
                "components": len(sbom_doc.get("components", [])),
                # Totals mislead: file-level components dominate (e.g. every zoneinfo file).
                "components_by_type": dict(sorted(collections.Counter(c.get("type") for c in sbom_doc.get("components", [])).items())),
                "unique_findings_from_sbom_only": summarize_vulns(sbom_scan)["unique_cve_package_pairs"] if sbom_scan else None,
            }
        config = load(out / "scan" / f"trivy-config-{variant}.json")
        if config:
            summary["dockerfile_misconfigurations"][variant] = summarize_config(config)
    print(json.dumps(summary, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
