// Purpose: demonstrate an S256-only OAuth PKCE verifier with executable positive
// and negative checks. It deliberately never prints verifiers or challenges.
package main

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"math/big"
	"os"
	"regexp"
)

const (
	minVerifierLength = 43
	maxVerifierLength = 128
)

var verifierPattern = regexp.MustCompile(`^[A-Za-z0-9\-._~]+$`)

// IsValidCodeVerifier enforces the RFC 7636 length and unreserved-character rules.
func IsValidCodeVerifier(verifier string) bool {
	length := len(verifier)
	return length >= minVerifierLength &&
		length <= maxVerifierLength &&
		verifierPattern.MatchString(verifier)
}

// GenerateRandomVerifier returns an RFC 7636 verifier generated from crypto/rand.
func GenerateRandomVerifier(length int) (string, error) {
	if length < minVerifierLength || length > maxVerifierLength {
		return "", fmt.Errorf(
			"verifier length must be between %d and %d characters",
			minVerifierLength,
			maxVerifierLength,
		)
	}

	const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~"
	alphabetLength := big.NewInt(int64(len(alphabet)))
	verifier := make([]byte, length)
	for index := range verifier {
		randomIndex, err := rand.Int(rand.Reader, alphabetLength)
		if err != nil {
			return "", fmt.Errorf("generate verifier entropy: %w", err)
		}
		verifier[index] = alphabet[randomIndex.Int64()]
	}
	return string(verifier), nil
}

// ComputeChallengeS256 derives BASE64URL(SHA-256(ASCII(code_verifier))).
func ComputeChallengeS256(verifier string) (string, error) {
	if !IsValidCodeVerifier(verifier) {
		return "", errors.New("code_verifier does not satisfy RFC 7636 syntax")
	}
	sum := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(sum[:]), nil
}

func isValidS256Challenge(challenge string) bool {
	decoded, err := base64.RawURLEncoding.Strict().DecodeString(challenge)
	return err == nil && len(decoded) == sha256.Size
}

// ValidatePKCES256 validates one token request against its stored authorization
// transaction. It rejects method downgrade and malformed inputs before performing a
// constant-time comparison of equal-length S256 challenges.
func ValidatePKCES256(codeVerifier, storedChallenge, method string) bool {
	if method != "S256" || !IsValidCodeVerifier(codeVerifier) ||
		!isValidS256Challenge(storedChallenge) {
		return false
	}

	computedChallenge, err := ComputeChallengeS256(codeVerifier)
	if err != nil {
		return false
	}
	return subtle.ConstantTimeCompare(
		[]byte(computedChallenge),
		[]byte(storedChallenge),
	) == 1
}

type check struct {
	name string
	run  func() bool
}

func main() {
	// RFC 7636 Appendix B test vector.
	const vectorVerifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
	const vectorChallenge = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"
	const wrongVerifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXa"
	const invalidCharacterVerifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjX!"

	generatedVerifier, generateErr := GenerateRandomVerifier(64)
	generatedChallenge := ""
	if generateErr == nil {
		generatedChallenge, generateErr = ComputeChallengeS256(generatedVerifier)
	}

	checks := []check{
		{
			name: "RFC 7636 S256 vector is accepted",
			run: func() bool {
				return ValidatePKCES256(vectorVerifier, vectorChallenge, "S256")
			},
		},
		{
			name: "intercepted code with the wrong verifier is rejected",
			run: func() bool {
				return !ValidatePKCES256(wrongVerifier, vectorChallenge, "S256")
			},
		},
		{
			name: "plain method downgrade is rejected",
			run: func() bool {
				return !ValidatePKCES256(vectorVerifier, vectorVerifier, "plain")
			},
		},
		{
			name: "method names are not normalized",
			run: func() bool {
				return !ValidatePKCES256(vectorVerifier, vectorChallenge, "s256")
			},
		},
		{
			name: "short verifier is rejected",
			run: func() bool {
				return !ValidatePKCES256("too-short", vectorChallenge, "S256")
			},
		},
		{
			name: "verifier with a non-unreserved character is rejected",
			run: func() bool {
				return !ValidatePKCES256(
					invalidCharacterVerifier,
					vectorChallenge,
					"S256",
				)
			},
		},
		{
			name: "malformed stored challenge is rejected",
			run: func() bool {
				return !ValidatePKCES256(vectorVerifier, "not-base64url!", "S256")
			},
		},
		{
			name: "generated verifier round trip is accepted",
			run: func() bool {
				return generateErr == nil &&
					IsValidCodeVerifier(generatedVerifier) &&
					ValidatePKCES256(
						generatedVerifier,
						generatedChallenge,
						"S256",
					)
			},
		},
	}

	failures := 0
	for _, item := range checks {
		if item.run() {
			fmt.Printf("PASS: %s\n", item.name)
			continue
		}
		failures++
		fmt.Printf("FAIL: %s\n", item.name)
	}

	if failures > 0 {
		fmt.Printf("PKCE validation failed: %d of %d checks failed\n", failures, len(checks))
		os.Exit(1)
	}
	fmt.Printf("PKCE validation passed: %d checks; no verifier values logged\n", len(checks))
}
