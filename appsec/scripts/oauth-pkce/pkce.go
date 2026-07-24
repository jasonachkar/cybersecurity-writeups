// Package oauthpkce is a bounded educational S256-only OAuth PKCE verifier.
// It deliberately never logs verifiers or challenges.
package oauthpkce

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"math/big"
	"regexp"
)

const (
	MinVerifierLength = 43
	MaxVerifierLength = 128
)

var verifierPattern = regexp.MustCompile(`^[A-Za-z0-9\-._~]+$`)

// IsValidCodeVerifier enforces the RFC 7636 length and unreserved-character rules.
func IsValidCodeVerifier(verifier string) bool {
	length := len(verifier)
	return length >= MinVerifierLength &&
		length <= MaxVerifierLength &&
		verifierPattern.MatchString(verifier)
}

// GenerateRandomVerifier returns an RFC 7636 verifier generated from crypto/rand.
func GenerateRandomVerifier(length int) (string, error) {
	if length < MinVerifierLength || length > MaxVerifierLength {
		return "", fmt.Errorf(
			"verifier length must be between %d and %d characters",
			MinVerifierLength,
			MaxVerifierLength,
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
