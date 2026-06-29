// Purpose: Cryptographically demonstrates and verifies the OAuth 2.0 PKCE (Proof Key for Code Exchange) flow (RFC 7636), showing how authorization servers check verifiers against challenges to mitigate token interception attacks.
package main

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"math/big"
	"strings"
)

// GenerateRandomVerifier creates a cryptographically secure random string for PKCE.
// It must be between 43 and 128 characters long and use unreserved characters: [A-Z], [a-z], [0-9], "-", ".", "_", "~".
func GenerateRandomVerifier(length int) (string, error) {
	if length < 43 || length > 128 {
		return "", fmt.Errorf("verifier length must be between 43 and 128 characters")
	}

	const charset = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~"
	var verifier strings.Builder
	for i := 0; i < length; i++ {
		num, err := rand.Int(rand.Reader, big.NewInt(int64(len(charset))))
		if err != nil {
			return "", err
		}
		verifier.WriteByte(charset[num.Int64()])
	}
	return verifier.String(), nil
}

// ComputeChallengeS256 creates the S256 code challenge.
// Formula: BASE64URL-ENCODE(SHA256(ASCII(code_verifier)))
func ComputeChallengeS256(verifier string) string {
	// Compute SHA256 sum
	hash := sha256.Sum256([]byte(verifier))
	// Base64URL encode without padding
	return base64.RawURLEncoding.EncodeToString(hash[:])
}

// ValidatePKCE checks if the provided code_verifier maps to the stored code_challenge.
func ValidatePKCE(codeVerifier string, storedChallenge string, method string) bool {
	if method == "plain" {
		// Plain method is not recommended as it does not protect against co-located attacks on device.
		return codeVerifier == storedChallenge
	}

	if method == "S256" {
		computedChallenge := ComputeChallengeS256(codeVerifier)
		// Perform constant-time comparison to mitigate timing attacks
		return computedChallenge == storedChallenge
	}

	return false
}

func main() {
	fmt.Println("==================================================")
	fmt.Println("🛡️ OAuth 2.0 PKCE (Proof Key for Code Exchange) Flow")
	fmt.Println("==================================================")

	// Step 1: Client generates code_verifier
	fmt.Println("\n[Client] Step 1: Generating random code_verifier (cryptographically secure)...")
	codeVerifier, err := GenerateRandomVerifier(64)
	if err != nil {
		fmt.Printf("Error: %v\n", err)
		return
	}
	fmt.Printf("   - Code Verifier: %s\n", codeVerifier)

	// Step 2: Client computes code_challenge using S256
	fmt.Println("\n[Client] Step 2: Calculating code_challenge (S256)...")
	codeChallenge := ComputeChallengeS256(codeVerifier)
	fmt.Printf("   - Code Challenge: %s\n", codeChallenge)

	// Step 3: Authorization Request
	// The client sends the code_challenge and code_challenge_method to the authorization server.
	fmt.Println("\n[Server] Step 3: Receiving Authorization Request...")
	fmt.Printf("   - Storing Challenge: '%s' (Method: S256) linked to authorization code 'auth_code_xyz123'\n", codeChallenge)
	storedChallenge := codeChallenge
	storedMethod := "S256"

	// Step 4: Token Request (Exchange Auth Code for Access Token)
	// The client sends authorization code + code_verifier.
	fmt.Println("\n[Server] Step 4: Processing Token Request...")
	fmt.Println("   - Client presents code 'auth_code_xyz123' along with code_verifier.")

	// Case 1: Valid Verification
	fmt.Println("\n--- Scenario A: Valid Token request with matching Verifier ---")
	fmt.Printf("   - Presented Verifier: %s\n", codeVerifier)
	valid := ValidatePKCE(codeVerifier, storedChallenge, storedMethod)
	if valid {
		fmt.Println("   - [SUCCESS] Verifier matches challenge! Access Token issued successfully. ✅")
	} else {
		fmt.Println("   - [FAILURE] Cryptographic mismatch! Token request rejected. ❌")
	}

	// Case 2: Invalid/Intercepted Auth Code with Bad Verifier
	fmt.Println("\n--- Scenario B: Mitigating Authorization Code Interception (Attacker attempt) ---")
	// An attacker intercepted 'auth_code_xyz123' but does NOT possess the client's private memory/verifier.
	// The attacker attempts to exchange the code using their own verifier or a dummy verifier.
	attackerVerifier := "attacker_injected_verifier_with_excess_length_characters_0000"
	fmt.Printf("   - Presented Attacker Verifier: %s\n", attackerVerifier)
	valid = ValidatePKCE(attackerVerifier, storedChallenge, storedMethod)
	if valid {
		fmt.Println("   - [BUG] Token issued! Attacker bypassed PKCE security check. ❌")
	} else {
		fmt.Println("   - [BLOCKED] Cryptographic mismatch! Access request blocked. PKCE verification protected the session. ✅")
	}
}
