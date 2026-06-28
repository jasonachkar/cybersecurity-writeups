// Purpose: Parses AWS CloudTrail events and identifies multi-stage privilege escalation sequences, console logins without MFA, and logs-tampering indicators.
package main

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"
)

// CloudTrailEvent represents a standard structured AWS CloudTrail log record.
type CloudTrailEvent struct {
	EventTime        string       `json:"eventTime"`
	EventName        string       `json:"eventName"`
	EventSource      string       `json:"eventSource"`
	AWSRegion        string       `json:"awsRegion"`
	SourceIPAddress  string       `json:"sourceIPAddress"`
	UserIdentity     UserIdentity `json:"userIdentity"`
	ErrorCode        string       `json:"errorCode,omitempty"`
	ErrorMessage     string       `json:"errorMessage,omitempty"`
	AdditionalFields string       `json:"additionalEventData,omitempty"`
}

// UserIdentity holds information about the caller who triggered the event.
type UserIdentity struct {
	Type           string         `json:"type"`
	PrincipalID    string         `json:"principalId"`
	ARN            string         `json:"arn"`
	AccountID      string         `json:"accountId"`
	SessionContext SessionContext `json:"sessionContext,omitempty"`
}

// SessionContext represents temporary credentials info.
type SessionContext struct {
	Attributes SessionAttributes `json:"attributes"`
}

// SessionAttributes contains MFA details.
type SessionAttributes struct {
	MFAUsed string `json:"mfaAuthenticated"`
}

// AnomalyFinding holds the suspicious patterns identified.
type AnomalyFinding struct {
	Type        string
	Description string
	ActorARN    string
	SourceIP    string
	Time        string
}

func main() {
	// Simulated CloudTrail logs representing a multi-stage attack flow:
	// 1. ConsoleLogin from a foreign IP without MFA.
	// 2. StopLogging to attempt defense evasion.
	// 3. CreateUser followed immediately by AttachUserPolicy (privilege escalation chain).
	// 4. Multiple KMS decryption Access Denied events (recon/probing).
	cloudTrailLogsJSON := `[
		{
			"eventTime": "2026-06-28T18:00:00Z",
			"eventName": "ConsoleLogin",
			"eventSource": "signin.amazonaws.com",
			"awsRegion": "us-east-1",
			"sourceIPAddress": "198.51.100.42",
			"userIdentity": {
				"type": "IAMUser",
				"arn": "arn:aws:iam::123456789012:user/dev-operator",
				"accountId": "123456789012",
				"sessionContext": {
					"attributes": {
						"mfaAuthenticated": "false"
					}
				}
			}
		},
		{
			"eventTime": "2026-06-28T18:01:05Z",
			"eventName": "StopLogging",
			"eventSource": "cloudtrail.amazonaws.com",
			"awsRegion": "us-west-2",
			"sourceIPAddress": "198.51.100.42",
			"userIdentity": {
				"type": "IAMUser",
				"arn": "arn:aws:iam::123456789012:user/dev-operator",
				"accountId": "123456789012"
			}
		},
		{
			"eventTime": "2026-06-28T18:02:15Z",
			"eventName": "CreateUser",
			"eventSource": "iam.amazonaws.com",
			"awsRegion": "us-east-1",
			"sourceIPAddress": "198.51.100.42",
			"userIdentity": {
				"type": "IAMUser",
				"arn": "arn:aws:iam::123456789012:user/dev-operator",
				"accountId": "123456789012"
			}
		},
		{
			"eventTime": "2026-06-28T18:02:30Z",
			"eventName": "AttachUserPolicy",
			"eventSource": "iam.amazonaws.com",
			"awsRegion": "us-east-1",
			"sourceIPAddress": "198.51.100.42",
			"userIdentity": {
				"type": "IAMUser",
				"arn": "arn:aws:iam::123456789012:user/dev-operator",
				"accountId": "123456789012"
			}
		},
		{
			"eventTime": "2026-06-28T18:04:10Z",
			"eventName": "Decrypt",
			"eventSource": "kms.amazonaws.com",
			"awsRegion": "us-east-1",
			"sourceIPAddress": "198.51.100.42",
			"errorCode": "AccessDenied",
			"errorMessage": "User arn:aws:iam::123456789012:user/dev-operator is not authorized to perform kms:Decrypt on resource",
			"userIdentity": {
				"type": "IAMUser",
				"arn": "arn:aws:iam::123456789012:user/dev-operator",
				"accountId": "123456789012"
			}
		}
	]`

	fmt.Println("==================================================")
	fmt.Println("🛡️ CloudTrail Threat Hunting & Anomaly Audit Engine")
	fmt.Println("==================================================")

	var events []CloudTrailEvent
	if err := json.Unmarshal([]byte(cloudTrailLogsJSON), &events); err != nil {
		fmt.Printf("Error unmarshaling logs: %v\n", err)
		return
	}

	var findings []AnomalyFinding

	// Keep track of event frequencies to identify rapid multi-stage privilege escalation
	// Maps: Actor ARN -> Slice of Events (Name + Time)
	actorChains := make(map[string][]struct {
		Name string
		Time time.Time
	})

	for _, event := range events {
		parsedTime, err := time.Parse(time.RFC3339, event.EventTime)
		if err != nil {
			parsedTime = time.Now()
		}

		// Track actions per actor for sequence mapping
		actorARN := event.UserIdentity.ARN
		actorChains[actorARN] = append(actorChains[actorARN], struct {
			Name string
			Time time.Time
		}{Name: event.EventName, Time: parsedTime})

		// Rule 1: ConsoleLogin without MFA
		if event.EventName == "ConsoleLogin" {
			mfa := event.UserIdentity.SessionContext.Attributes.MFAUsed
			if mfa == "false" || mfa == "" {
				findings = append(findings, AnomalyFinding{
					Type:        "DEFENSE BYPASS",
					Description: "Console login succeeded without MFA enforcement.",
					ActorARN:    actorARN,
					SourceIP:    event.SourceIPAddress,
					Time:        event.EventTime,
				})
			}
		}

		// Rule 2: Defense Evasion - CloudTrail Alteration
		if event.EventName == "StopLogging" || event.EventName == "DeleteTrail" || event.EventName == "UpdateTrail" {
			findings = append(findings, AnomalyFinding{
				Type:        "LOG TAMPERING",
				Description: fmt.Sprintf("Defense evasion indicator: Action '%s' executed on audit logging service.", event.EventName),
				ActorARN:    actorARN,
				SourceIP:    event.SourceIPAddress,
				Time:        event.EventTime,
			})
		}

		// Rule 3: KMS AccessDenied Decrypt probing
		if event.EventSource == "kms.amazonaws.com" && event.ErrorCode == "AccessDenied" {
			if strings.Contains(strings.ToLower(event.EventName), "decrypt") {
				findings = append(findings, AnomalyFinding{
					Type:        "RECONNAISSANCE / DATA PROBING",
					Description: "Multiple unauthorized attempts to decrypt KMS keys (AccessDenied).",
					ActorARN:    actorARN,
					SourceIP:    event.SourceIPAddress,
					Time:        event.EventTime,
				})
			}
		}
	}

	// Rule 4: Multi-stage Privilege Escalation Analysis (Sequence correlation)
	// Check if the same actor executes 'CreateUser' then 'AttachUserPolicy' within 5 minutes.
	for actor, chain := range actorChains {
		for i := 0; i < len(chain)-1; i++ {
			if chain[i].Name == "CreateUser" {
				// Scan subsequent events within 5 minutes
				for j := i + 1; j < len(chain); j++ {
					if chain[j].Name == "AttachUserPolicy" {
						diff := chain[j].Time.Sub(chain[i].Time)
						if diff < 5*time.Minute {
							findings = append(findings, AnomalyFinding{
								Type:        "PRIVILEGE ESCALATION SEQUENCE",
								Description: fmt.Sprintf("Critical pattern: 'CreateUser' followed by 'AttachUserPolicy' by same user within %.1f seconds.", diff.Seconds()),
								ActorARN:    actor,
								SourceIP:    "Multi-session / Correlated",
								Time:        chain[j].Time.Format(time.RFC3339),
							})
						}
					}
				}
			}
		}
	}

	// Print results
	if len(findings) == 0 {
		fmt.Println("Scan complete. No anomalous sequences or security indicators identified.")
	} else {
		fmt.Printf("Hunting Complete: Found %d critical security events / anomalies:\n\n", len(findings))
		for _, f := range findings {
			fmt.Printf("[%s] Time: %s | Source IP: %s\n", f.Type, f.Time, f.SourceIP)
			fmt.Printf("   - Actor:  %s\n", f.ActorARN)
			fmt.Printf("   - Details: %s\n\n", f.Description)
		}
	}
}
