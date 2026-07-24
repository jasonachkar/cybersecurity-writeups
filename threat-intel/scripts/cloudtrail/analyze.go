// Package cloudtrail is a bounded educational analyzer for AWS CloudTrail
// event fixtures. It is not a production detection product and does not
// claim AWS-equivalent evaluation.
package cloudtrail

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"time"
)

// Event is a subset of a CloudTrail management event used by this teaching analyzer.
type Event struct {
	EventTime           time.Time      `json:"-"`
	EventTimeRaw        string         `json:"eventTime"`
	EventName           string         `json:"eventName"`
	EventSource         string         `json:"eventSource"`
	AWSRegion           string         `json:"awsRegion"`
	SourceIPAddress     string         `json:"sourceIPAddress"`
	ErrorCode           string         `json:"errorCode,omitempty"`
	ErrorMessage        string         `json:"errorMessage,omitempty"`
	UserIdentity        UserIdentity   `json:"userIdentity"`
	ResponseElements    map[string]any `json:"responseElements"`
	AdditionalEventData map[string]any `json:"additionalEventData"`
}

// UserIdentity identifies the caller.
type UserIdentity struct {
	Type        string `json:"type"`
	PrincipalID string `json:"principalId"`
	ARN         string `json:"arn"`
	AccountID   string `json:"accountId"`
}

// Finding is a high-signal observation that requires investigation.
type Finding struct {
	Type        string
	Description string
	ActorARN    string
	SourceIP    string
	EventName   string
	Time        string
}

// Options configures sequence and threshold detection.
type Options struct {
	PrivilegeEscalationWindow time.Duration
	KMSDecryptDenyThreshold   int
}

// DefaultOptions returns conservative teaching defaults.
func DefaultOptions() Options {
	return Options{
		PrivilegeEscalationWindow: 15 * time.Minute,
		KMSDecryptDenyThreshold:   3,
	}
}

// ParseEvents unmarshals CloudTrail JSON and rejects malformed timestamps.
func ParseEvents(raw []byte) ([]Event, error) {
	var events []Event
	if err := json.Unmarshal(raw, &events); err != nil {
		return nil, fmt.Errorf("decode cloudtrail events: %w", err)
	}
	for i := range events {
		if strings.TrimSpace(events[i].EventTimeRaw) == "" {
			return nil, fmt.Errorf("event %d: missing eventTime", i)
		}
		parsed, err := time.Parse(time.RFC3339, events[i].EventTimeRaw)
		if err != nil {
			return nil, fmt.Errorf("event %d: malformed eventTime %q: %w", i, events[i].EventTimeRaw, err)
		}
		events[i].EventTime = parsed
		if events[i].ResponseElements == nil {
			events[i].ResponseElements = map[string]any{}
		}
		if events[i].AdditionalEventData == nil {
			events[i].AdditionalEventData = map[string]any{}
		}
	}
	return events, nil
}

// Analyze returns findings for the supplied events.
func Analyze(events []Event, opts Options) []Finding {
	if opts.PrivilegeEscalationWindow <= 0 {
		opts.PrivilegeEscalationWindow = DefaultOptions().PrivilegeEscalationWindow
	}
	if opts.KMSDecryptDenyThreshold <= 0 {
		opts.KMSDecryptDenyThreshold = DefaultOptions().KMSDecryptDenyThreshold
	}

	var findings []Finding
	findings = append(findings, analyzeConsoleLogins(events)...)
	findings = append(findings, analyzePrivilegeChains(events, opts.PrivilegeEscalationWindow)...)
	findings = append(findings, analyzeKMSDecryptDenies(events, opts.KMSDecryptDenyThreshold)...)
	findings = append(findings, analyzeLogTampering(events)...)
	return findings
}

func actorARN(event Event) string {
	return strings.TrimSpace(event.UserIdentity.ARN)
}

func analyzeConsoleLogins(events []Event) []Finding {
	var findings []Finding
	for _, event := range events {
		if event.EventName != "ConsoleLogin" {
			continue
		}
		actor := actorARN(event)
		if actor == "" {
			findings = append(findings, Finding{
				Type:        "malformed-actor",
				Description: "ConsoleLogin event is missing a usable userIdentity.arn",
				EventName:   event.EventName,
				SourceIP:    event.SourceIPAddress,
				Time:        event.EventTimeRaw,
			})
			continue
		}

		loginResult, ok := event.ResponseElements["ConsoleLogin"].(string)
		if !ok || loginResult != "Success" {
			// Failed or incomplete login is not a successful non-MFA login.
			continue
		}

		mfaRaw, hasMFA := event.AdditionalEventData["MFAUsed"]
		mfa, mfaIsString := mfaRaw.(string)
		switch {
		case !hasMFA || !mfaIsString:
			findings = append(findings, Finding{
				Type:        "console-login-mfa-metadata-missing",
				Description: "Successful ConsoleLogin lacks explicit MFAUsed metadata; investigate session assurance separately",
				ActorARN:    actor,
				SourceIP:    event.SourceIPAddress,
				EventName:   event.EventName,
				Time:        event.EventTimeRaw,
			})
		case strings.EqualFold(mfa, "No") || strings.EqualFold(mfa, "false"):
			findings = append(findings, Finding{
				Type:        "console-login-without-mfa",
				Description: "Successful ConsoleLogin reported MFAUsed=No",
				ActorARN:    actor,
				SourceIP:    event.SourceIPAddress,
				EventName:   event.EventName,
				Time:        event.EventTimeRaw,
			})
		}
	}
	return findings
}

func analyzePrivilegeChains(events []Event, window time.Duration) []Finding {
	byActor := map[string][]Event{}
	for _, event := range events {
		actor := actorARN(event)
		if actor == "" {
			continue
		}
		byActor[actor] = append(byActor[actor], event)
	}

	var findings []Finding
	for actor, actorEvents := range byActor {
		sorted := append([]Event(nil), actorEvents...)
		sort.SliceStable(sorted, func(i, j int) bool {
			return sorted[i].EventTime.Before(sorted[j].EventTime)
		})

		for i := 0; i < len(sorted); i++ {
			if sorted[i].EventName != "CreateUser" {
				continue
			}
			for j := i + 1; j < len(sorted); j++ {
				diff := sorted[j].EventTime.Sub(sorted[i].EventTime)
				if diff < 0 {
					// Chronological sort makes this unreachable; guard anyway.
					continue
				}
				if diff > window {
					break
				}
				if sorted[j].EventName == "AttachUserPolicy" || sorted[j].EventName == "PutUserPolicy" {
					findings = append(findings, Finding{
						Type: "privilege-escalation-sequence",
						Description: fmt.Sprintf(
							"CreateUser followed by %s within %s for the same actor; investigate for unauthorized privilege growth",
							sorted[j].EventName,
							window,
						),
						ActorARN:  actor,
						SourceIP:  sorted[j].SourceIPAddress,
						EventName: sorted[j].EventName,
						Time:      sorted[j].EventTimeRaw,
					})
					break
				}
			}
		}
	}
	return findings
}

func analyzeKMSDecryptDenies(events []Event, threshold int) []Finding {
	counts := map[string][]Event{}
	for _, event := range events {
		if event.EventSource != "kms.amazonaws.com" || event.EventName != "Decrypt" {
			continue
		}
		if event.ErrorCode != "AccessDenied" && event.ErrorCode != "AccessDeniedException" {
			continue
		}
		actor := actorARN(event)
		if actor == "" {
			continue
		}
		counts[actor] = append(counts[actor], event)
	}

	var findings []Finding
	for actor, denied := range counts {
		if len(denied) < threshold {
			// A single denied decrypt is not "multiple attempts".
			continue
		}
		last := denied[len(denied)-1]
		findings = append(findings, Finding{
			Type: "kms-decrypt-denied-threshold",
			Description: fmt.Sprintf(
				"%d AccessDenied Decrypt attempts for the same actor met the configured threshold of %d",
				len(denied),
				threshold,
			),
			ActorARN:  actor,
			SourceIP:  last.SourceIPAddress,
			EventName: "Decrypt",
			Time:      last.EventTimeRaw,
		})
	}
	return findings
}

func analyzeLogTampering(events []Event) []Finding {
	interesting := map[string]struct{}{
		"StopLogging":                 {},
		"DeleteTrail":                 {},
		"UpdateTrail":                 {},
		"PutEventSelectors":           {},
		"DeleteEventDataStore":        {},
		"StopEventDataStoreIngestion": {},
	}

	var findings []Finding
	for _, event := range events {
		if _, ok := interesting[event.EventName]; !ok {
			continue
		}
		actor := actorARN(event)
		findings = append(findings, Finding{
			Type: "cloudtrail-admin-event",
			Description: fmt.Sprintf(
				"High-signal CloudTrail administrative event %s observed; investigate intent and change authorization. This analyzer does not assert the event is malicious by itself.",
				event.EventName,
			),
			ActorARN:  actor,
			SourceIP:  event.SourceIPAddress,
			EventName: event.EventName,
			Time:      event.EventTimeRaw,
		})
	}
	return findings
}
