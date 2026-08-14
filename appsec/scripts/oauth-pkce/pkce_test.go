package oauthpkce_test

import (
	"testing"

	oauthpkce "github.com/jasonachkar/cybersecurity-writeups/appsec/scripts/oauth-pkce"
)

func TestValidatePKCES256(t *testing.T) {
	const vectorVerifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
	const vectorChallenge = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"
	const wrongVerifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXa"
	const invalidCharacterVerifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjX!"

	tests := []struct {
		name      string
		verifier  string
		challenge string
		method    string
		want      bool
	}{
		{"RFC 7636 S256 vector is accepted", vectorVerifier, vectorChallenge, "S256", true},
		{"wrong verifier is rejected", wrongVerifier, vectorChallenge, "S256", false},
		{"plain method downgrade is rejected", vectorVerifier, vectorVerifier, "plain", false},
		{"method names are not normalized", vectorVerifier, vectorChallenge, "s256", false},
		{"short verifier is rejected", "too-short", vectorChallenge, "S256", false},
		{"non-unreserved character is rejected", invalidCharacterVerifier, vectorChallenge, "S256", false},
		{"malformed stored challenge is rejected", vectorVerifier, "not-base64url!", "S256", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := oauthpkce.ValidatePKCES256(tt.verifier, tt.challenge, tt.method)
			if got != tt.want {
				t.Fatalf("ValidatePKCES256() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestGeneratedVerifierRoundTrip(t *testing.T) {
	verifier, err := oauthpkce.GenerateRandomVerifier(64)
	if err != nil {
		t.Fatalf("GenerateRandomVerifier: %v", err)
	}
	if !oauthpkce.IsValidCodeVerifier(verifier) {
		t.Fatal("generated verifier failed syntax validation")
	}
	challenge, err := oauthpkce.ComputeChallengeS256(verifier)
	if err != nil {
		t.Fatalf("ComputeChallengeS256: %v", err)
	}
	if !oauthpkce.ValidatePKCES256(verifier, challenge, "S256") {
		t.Fatal("generated verifier round trip was rejected")
	}
}
