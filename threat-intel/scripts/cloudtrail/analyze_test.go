package cloudtrail_test

import (
	"strings"
	"testing"
	"time"

	cloudtrail "github.com/jasonachkar/cybersecurity-writeups/threat-intel/scripts/cloudtrail"
)

func findingTypes(findings []cloudtrail.Finding) []string {
	out := make([]string, 0, len(findings))
	for _, finding := range findings {
		out = append(out, finding.Type)
	}
	return out
}

func hasType(findings []cloudtrail.Finding, want string) bool {
	for _, finding := range findings {
		if finding.Type == want {
			return true
		}
	}
	return false
}

func TestParseEventsRejectsMalformedTimestamp(t *testing.T) {
	_, err := cloudtrail.ParseEvents([]byte(`[
		{"eventTime":"not-a-time","eventName":"ConsoleLogin","userIdentity":{"arn":"arn:aws:iam::111:user/a"}}
	]`))
	if err == nil {
		t.Fatal("expected malformed eventTime to fail")
	}
}

func TestAnalyzeConsoleLoginCases(t *testing.T) {
	tests := []struct {
		name    string
		raw     string
		want    string
		notWant string
	}{
		{
			name: "successful login with MFA",
			raw: `[
			  {"eventTime":"2026-07-01T12:00:00Z","eventName":"ConsoleLogin","sourceIPAddress":"203.0.113.10",
			   "userIdentity":{"arn":"arn:aws:iam::111122223333:user/alice"},
			   "responseElements":{"ConsoleLogin":"Success"},
			   "additionalEventData":{"MFAUsed":"Yes"}}
			]`,
			notWant: "console-login-without-mfa",
		},
		{
			name: "successful login without MFA",
			raw: `[
			  {"eventTime":"2026-07-01T12:00:00Z","eventName":"ConsoleLogin","sourceIPAddress":"203.0.113.10",
			   "userIdentity":{"arn":"arn:aws:iam::111122223333:user/alice"},
			   "responseElements":{"ConsoleLogin":"Success"},
			   "additionalEventData":{"MFAUsed":"No"}}
			]`,
			want: "console-login-without-mfa",
		},
		{
			name: "failed login without MFA metadata is not treated as success",
			raw: `[
			  {"eventTime":"2026-07-01T12:00:00Z","eventName":"ConsoleLogin","sourceIPAddress":"203.0.113.10",
			   "userIdentity":{"arn":"arn:aws:iam::111122223333:user/alice"},
			   "responseElements":{"ConsoleLogin":"Failure"},
			   "errorCode":"FailedAuthentication"}
			]`,
			notWant: "console-login-without-mfa",
		},
		{
			name: "missing MFA metadata on success",
			raw: `[
			  {"eventTime":"2026-07-01T12:00:00Z","eventName":"ConsoleLogin","sourceIPAddress":"203.0.113.10",
			   "userIdentity":{"arn":"arn:aws:iam::111122223333:user/alice"},
			   "responseElements":{"ConsoleLogin":"Success"},
			   "additionalEventData":{}}
			]`,
			want: "console-login-mfa-metadata-missing",
		},
		{
			name: "malformed additional data type",
			raw: `[
			  {"eventTime":"2026-07-01T12:00:00Z","eventName":"ConsoleLogin","sourceIPAddress":"203.0.113.10",
			   "userIdentity":{"arn":"arn:aws:iam::111122223333:user/alice"},
			   "responseElements":{"ConsoleLogin":"Success"},
			   "additionalEventData":{"MFAUsed":true}}
			]`,
			want: "console-login-mfa-metadata-missing",
		},
		{
			name: "empty ARN",
			raw: `[
			  {"eventTime":"2026-07-01T12:00:00Z","eventName":"ConsoleLogin",
			   "userIdentity":{"arn":""},
			   "responseElements":{"ConsoleLogin":"Success"},
			   "additionalEventData":{"MFAUsed":"No"}}
			]`,
			want: "malformed-actor",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			events, err := cloudtrail.ParseEvents([]byte(tt.raw))
			if err != nil {
				t.Fatalf("ParseEvents: %v", err)
			}
			findings := cloudtrail.Analyze(events, cloudtrail.DefaultOptions())
			if tt.want != "" && !hasType(findings, tt.want) {
				t.Fatalf("missing %s in %v", tt.want, findingTypes(findings))
			}
			if tt.notWant != "" && hasType(findings, tt.notWant) {
				t.Fatalf("unexpected %s in %v", tt.notWant, findingTypes(findings))
			}
		})
	}
}

func TestPrivilegeEscalationSequence(t *testing.T) {
	raw := `[
	  {"eventTime":"2026-07-01T12:05:00Z","eventName":"AttachUserPolicy","sourceIPAddress":"203.0.113.10",
	   "userIdentity":{"arn":"arn:aws:iam::111122223333:user/alice"}},
	  {"eventTime":"2026-07-01T12:00:00Z","eventName":"CreateUser","sourceIPAddress":"203.0.113.10",
	   "userIdentity":{"arn":"arn:aws:iam::111122223333:user/alice"}}
	]`
	events, err := cloudtrail.ParseEvents([]byte(raw))
	if err != nil {
		t.Fatal(err)
	}
	findings := cloudtrail.Analyze(events, cloudtrail.Options{
		PrivilegeEscalationWindow: 15 * time.Minute,
		KMSDecryptDenyThreshold:   3,
	})
	if !hasType(findings, "privilege-escalation-sequence") {
		t.Fatalf("expected sorted CreateUser→AttachUserPolicy chain, got %v", findingTypes(findings))
	}
}

func TestPrivilegeEscalationOutsideWindow(t *testing.T) {
	raw := `[
	  {"eventTime":"2026-07-01T12:00:00Z","eventName":"CreateUser",
	   "userIdentity":{"arn":"arn:aws:iam::111122223333:user/alice"}},
	  {"eventTime":"2026-07-01T13:00:00Z","eventName":"AttachUserPolicy",
	   "userIdentity":{"arn":"arn:aws:iam::111122223333:user/alice"}}
	]`
	events, err := cloudtrail.ParseEvents([]byte(raw))
	if err != nil {
		t.Fatal(err)
	}
	findings := cloudtrail.Analyze(events, cloudtrail.Options{
		PrivilegeEscalationWindow: 15 * time.Minute,
		KMSDecryptDenyThreshold:   3,
	})
	if hasType(findings, "privilege-escalation-sequence") {
		t.Fatal("chain outside window should not match")
	}
}

func TestNegativeTimeDifferencePrevention(t *testing.T) {
	// Same actor, Attach before Create chronologically after sort should not
	// create a reverse chain.
	raw := `[
	  {"eventTime":"2026-07-01T12:00:00Z","eventName":"AttachUserPolicy",
	   "userIdentity":{"arn":"arn:aws:iam::111122223333:user/alice"}},
	  {"eventTime":"2026-07-01T12:10:00Z","eventName":"CreateUser",
	   "userIdentity":{"arn":"arn:aws:iam::111122223333:user/alice"}}
	]`
	events, err := cloudtrail.ParseEvents([]byte(raw))
	if err != nil {
		t.Fatal(err)
	}
	findings := cloudtrail.Analyze(events, cloudtrail.DefaultOptions())
	if hasType(findings, "privilege-escalation-sequence") {
		t.Fatal("reverse chronological Attach→Create must not correlate")
	}
}

func TestKMSDecryptThresholdAndSingleAttempt(t *testing.T) {
	single := `[
	  {"eventTime":"2026-07-01T12:00:00Z","eventName":"Decrypt","eventSource":"kms.amazonaws.com",
	   "errorCode":"AccessDenied","userIdentity":{"arn":"arn:aws:iam::111122223333:user/alice"}}
	]`
	events, err := cloudtrail.ParseEvents([]byte(single))
	if err != nil {
		t.Fatal(err)
	}
	findings := cloudtrail.Analyze(events, cloudtrail.DefaultOptions())
	if hasType(findings, "kms-decrypt-denied-threshold") {
		t.Fatal("single AccessDenied decrypt must not claim multiple attempts")
	}

	repeated := `[
	  {"eventTime":"2026-07-01T12:00:00Z","eventName":"Decrypt","eventSource":"kms.amazonaws.com","errorCode":"AccessDenied","userIdentity":{"arn":"arn:aws:iam::111122223333:user/alice"}},
	  {"eventTime":"2026-07-01T12:01:00Z","eventName":"Decrypt","eventSource":"kms.amazonaws.com","errorCode":"AccessDenied","userIdentity":{"arn":"arn:aws:iam::111122223333:user/alice"}},
	  {"eventTime":"2026-07-01T12:02:00Z","eventName":"Decrypt","eventSource":"kms.amazonaws.com","errorCode":"AccessDenied","userIdentity":{"arn":"arn:aws:iam::111122223333:user/alice"}}
	]`
	events, err = cloudtrail.ParseEvents([]byte(repeated))
	if err != nil {
		t.Fatal(err)
	}
	findings = cloudtrail.Analyze(events, cloudtrail.DefaultOptions())
	if !hasType(findings, "kms-decrypt-denied-threshold") {
		t.Fatal("expected thresholded decrypt findings")
	}
}

func TestActorSeparation(t *testing.T) {
	raw := `[
	  {"eventTime":"2026-07-01T12:00:00Z","eventName":"CreateUser","userIdentity":{"arn":"arn:aws:iam::111122223333:user/alice"}},
	  {"eventTime":"2026-07-01T12:01:00Z","eventName":"AttachUserPolicy","userIdentity":{"arn":"arn:aws:iam::111122223333:user/bob"}}
	]`
	events, err := cloudtrail.ParseEvents([]byte(raw))
	if err != nil {
		t.Fatal(err)
	}
	findings := cloudtrail.Analyze(events, cloudtrail.DefaultOptions())
	if hasType(findings, "privilege-escalation-sequence") {
		t.Fatal("different actors must not form a chain")
	}
}

func TestLogTamperingClassification(t *testing.T) {
	raw := `[
	  {"eventTime":"2026-07-01T12:00:00Z","eventName":"UpdateTrail","userIdentity":{"arn":"arn:aws:iam::111122223333:user/alice"}}
	]`
	events, err := cloudtrail.ParseEvents([]byte(raw))
	if err != nil {
		t.Fatal(err)
	}
	findings := cloudtrail.Analyze(events, cloudtrail.DefaultOptions())
	if !hasType(findings, "cloudtrail-admin-event") {
		t.Fatal("expected high-signal admin classification")
	}
	for _, finding := range findings {
		if finding.Type == "cloudtrail-admin-event" && finding.EventName != "UpdateTrail" {
			t.Fatalf("event name not preserved: %s", finding.EventName)
		}
		if finding.Type == "cloudtrail-admin-event" && !strings.Contains(finding.Description, "does not assert the event is malicious") {
			t.Fatalf("description overclaims malice: %s", finding.Description)
		}
	}
}
