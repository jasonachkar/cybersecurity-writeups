# Threat Intelligence Analysis Scripts

This section contains auditing tools written in Go to parse CloudTrail logs and analyze multi-stage attack scenarios.

---

## 1. CloudTrail Anomaly Detector (`cloudtrail-anomaly.go`)

### Purpose
Parses AWS CloudTrail events and identifies multi-stage privilege escalation sequences, console logins without MFA, and logs-tampering indicators (like CloudTrail stop logging events).

### Code Implementation
```go
--8<-- "threat-intel/scripts/cloudtrail-anomaly.go"
```
