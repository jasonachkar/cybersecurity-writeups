// Purpose: Implements manual parsing and cryptographic validation of JSON Web Tokens (JWT) using standard library RSA signature verification, checking expiration, issuer, and audience claims.
package main

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
	"time"
)

// JWTHeader represents the header section of the token.
type JWTHeader struct {
	Alg string `json:"alg"`
	Typ string `json:"typ"`
}

// JWTPayload represents the claims section of the token.
type JWTPayload struct {
	Issuer   string `json:"iss"`
	Subject  string `json:"sub"`
	Audience string `json:"aud"`
	Expiry   int64  `json:"exp"`
	IssuedAt int64  `json:"iat"`
}

// GenerateKeyPair is a helper to build an RSA key pair for testing signature.
func GenerateKeyPair() (*rsa.PrivateKey, *rsa.PublicKey, error) {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, nil, err
	}
	return priv, &priv.PublicKey, nil
}

// Helper to base64url encode bytes.
func base64URLEncode(b []byte) string {
	return strings.TrimRight(base64.URLEncoding.EncodeToString(b), "=")
}

// Helper to base64url decode a string.
func base64URLDecode(s string) ([]byte, error) {
	// Re-add padding characters if necessary
	switch len(s) % 4 {
	case 2:
		s += "=="
	case 3:
		s += "="
	}
	return base64.URLEncoding.DecodeString(s)
}

// CreateToken generates a signed JWT.
func CreateToken(priv *rsa.PrivateKey, iss, sub, aud string, lifespan time.Duration) (string, error) {
	header := JWTHeader{Alg: "RS256", Typ: "JWT"}
	hBytes, _ := json.Marshal(header)
	hEncoded := base64URLEncode(hBytes)

	now := time.Now()
	payload := JWTPayload{
		Issuer:   iss,
		Subject:  sub,
		Audience: aud,
		Expiry:   now.Add(lifespan).Unix(),
		IssuedAt: now.Unix(),
	}
	pBytes, _ := json.Marshal(payload)
	pEncoded := base64URLEncode(pBytes)

	signingInput := hEncoded + "." + pEncoded

	// Compute SHA-256 hash of signing input
	hash := sha256.Sum256([]byte(signingInput))

	// Sign the hash using RSA-PKCS1v15
	sigBytes, err := rsa.SignPKCS1v15(rand.Reader, priv, crypto.SHA256, hash[:])
	if err != nil {
		return "", err
	}
	sigEncoded := base64URLEncode(sigBytes)

	return signingInput + "." + sigEncoded, nil
}

// ValidateToken parses, decodes, and verifies the JWT claims and RSA signature.
func ValidateToken(tokenStr string, pub *rsa.PublicKey, expectedIss, expectedAud string) (*JWTPayload, error) {
	parts := strings.Split(tokenStr, ".")
	if len(parts) != 3 {
		return nil, fmt.Errorf("invalid token format: must contain header, payload, and signature parts")
	}

	headerSegment := parts[0]
	payloadSegment := parts[1]
	signatureSegment := parts[2]

	// 1. Decode Header
	hBytes, err := base64URLDecode(headerSegment)
	if err != nil {
		return nil, fmt.Errorf("failed to decode header: %v", err)
	}
	var header JWTHeader
	if err := json.Unmarshal(hBytes, &header); err != nil {
		return nil, fmt.Errorf("failed to parse header JSON: %v", err)
	}

	if header.Alg != "RS256" {
		return nil, fmt.Errorf("unsupported algorithm: %s (only RS256 is supported)", header.Alg)
	}

	// 2. Decode Payload
	pBytes, err := base64URLDecode(payloadSegment)
	if err != nil {
		return nil, fmt.Errorf("failed to decode payload: %v", err)
	}
	var payload JWTPayload
	if err := json.Unmarshal(pBytes, &payload); err != nil {
		return nil, fmt.Errorf("failed to parse payload JSON: %v", err)
	}

	// 3. Cryptographic Signature Verification
	signingInput := headerSegment + "." + payloadSegment
	sigBytes, err := base64URLDecode(signatureSegment)
	if err != nil {
		return nil, fmt.Errorf("failed to decode signature: %v", err)
	}

	hash := sha256.Sum256([]byte(signingInput))
	err = rsa.VerifyPKCS1v15(pub, crypto.SHA256, hash[:], sigBytes)
	if err != nil {
		return nil, fmt.Errorf("cryptographic signature verification failed: invalid signature")
	}

	// 4. Validate Claims
	now := time.Now().Unix()
	if payload.Expiry < now {
		return nil, fmt.Errorf("token expired: expiry time %v is in the past (current time %v)", payload.Expiry, now)
	}

	if payload.Issuer != expectedIss {
		return nil, fmt.Errorf("issuer mismatch: expected '%s', got '%s'", expectedIss, payload.Issuer)
	}

	if payload.Audience != expectedAud {
		return nil, fmt.Errorf("audience mismatch: expected '%s', got '%s'", expectedAud, payload.Audience)
	}

	return &payload, nil
}

func main() {
	fmt.Println("==================================================")
	fmt.Println("RSA-256 JWT Token Creator & Validator")
	fmt.Println("==================================================")

	// Step 1: Initialize RSA Cryptographic Keys
	privKey, pubKey, err := GenerateKeyPair()
	if err != nil {
		fmt.Printf("Failed to generate RSA keys: %v\n", err)
		return
	}
	fmt.Println("[INFO] Cryptographic RSA-2048 keys initialized successfully.")

	// Set parameters
	issuer := "https://auth.company.com"
	audience := "api://internal-service"
	subject := "user_id_99218"

	// Test 1: Validate valid token
	fmt.Println("\n--- Scenario 1: Creating and validating a valid token ---")
	validToken, err := CreateToken(privKey, issuer, subject, audience, 10*time.Minute)
	if err != nil {
		fmt.Printf("Failed to create token: %v\n", err)
		return
	}
	fmt.Printf("Generated Token: %s...\n", validToken[:50])

	payload, err := ValidateToken(validToken, pubKey, issuer, audience)
	if err != nil {
		fmt.Printf("Validation error: %v\n", err)
	} else {
		fmt.Printf("Validation Success! Subject: %s, Expiry: %v\n", payload.Subject, time.Unix(payload.Expiry, 0))
	}

	// Test 2: Expired Token
	fmt.Println("\n--- Scenario 2: Validating an expired token ---")
	expiredToken, err := CreateToken(privKey, issuer, subject, audience, -5*time.Minute) // Expiry in past
	if err != nil {
		fmt.Printf("Failed to create expired token: %v\n", err)
		return
	}
	_, err = ValidateToken(expiredToken, pubKey, issuer, audience)
	if err != nil {
		fmt.Printf("Validation Blocked (Expected): %v\n", err)
	} else {
		fmt.Println("CRITICAL BUG: Expired token was accepted!")
	}

	// Test 3: Audience Mismatch
	fmt.Println("\n--- Scenario 3: Validating token with audience mismatch ---")
	badAudienceToken, err := CreateToken(privKey, issuer, subject, "api://attacker-service", 10*time.Minute)
	if err != nil {
		fmt.Printf("Failed to create bad audience token: %v\n", err)
		return
	}
	_, err = ValidateToken(badAudienceToken, pubKey, issuer, audience)
	if err != nil {
		fmt.Printf("Validation Blocked (Expected): %v\n", err)
	} else {
		fmt.Println("CRITICAL BUG: Token with audience mismatch was accepted!")
	}

	// Test 4: Signature Tampering (Algorithm swap or modifications)
	fmt.Println("\n--- Scenario 4: Validating a tampered token ---")
	tokenParts := strings.Split(validToken, ".")
	// Decode payload, modify it, and rebuild token without updating signature
	pBytes, _ := base64URLDecode(tokenParts[1])
	var pData map[string]interface{}
	json.Unmarshal(pBytes, &pData)
	pData["sub"] = "admin_user_override" // Attacker escalates privileges
	modPBytes, _ := json.Marshal(pData)
	tokenParts[1] = base64URLEncode(modPBytes)
	tamperedToken := strings.Join(tokenParts, ".")

	_, err = ValidateToken(tamperedToken, pubKey, issuer, audience)
	if err != nil {
		fmt.Printf("Validation Blocked (Expected): %v\n", err)
	} else {
		fmt.Println("CRITICAL BUG: Tampered token signature check was bypassed!")
	}
}
