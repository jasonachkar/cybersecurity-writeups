// Purpose: Simulates an IDOR (Insecure Direct Object Reference) audit scan on REST endpoints, demonstrating how automated scanners query resources using different authorization headers to discover access isolation breaches.
package main

import (
	"encoding/json"
	"fmt"
)

// APIResponse represents the JSON output from a simulated API gateway or controller.
type APIResponse struct {
	StatusCode int
	Body       string
}

// UserSession holds identity headers and access levels.
type UserSession struct {
	Username string
	AuthToken string
	IsAdmin   bool
}

// AccountData represents the data payload returned by the database.
type AccountData struct {
	AccountID string `json:"account_id"`
	Owner     string `json:"owner"`
	Balance   string `json:"balance"`
	Email     string `json:"email"`
}

// SimulatedDatabase holds mock accounts mapped by ID.
var SimulatedDatabase = map[string]AccountData{
	"acc-101": {AccountID: "acc-101", Owner: "alice", Balance: "$5,240.00", Email: "alice@company.com"},
	"acc-102": {AccountID: "acc-102", Owner: "bob", Balance: "$1,820.00", Email: "bob@company.com"},
	"acc-103": {AccountID: "acc-103", Owner: "alice", Balance: "$12,400.00", Email: "alice-personal@company.com"},
	"acc-104": {AccountID: "acc-104", Owner: "charlie", Balance: "$900.50", Email: "charlie@company.com"},
}

// SimulatedSecureEndpoint represents an API controller with proper authorization checks.
// It checks if the logged-in user is the owner of the resource or an administrator.
func SimulatedSecureEndpoint(accountID string, token string) APIResponse {
	// Authenticate session based on token
	user, exists := AuthenticateToken(token)
	if !exists {
		return APIResponse{StatusCode: 401, Body: "Unauthorized: Invalid Session Token"}
	}

	// Fetch from database
	data, found := SimulatedDatabase[accountID]
	if !found {
		return APIResponse{StatusCode: 404, Body: "Not Found"}
	}

	// AUTHORIZATION CHECK (Defense against IDOR)
	if data.Owner != user.Username && !user.IsAdmin {
		return APIResponse{StatusCode: 403, Body: "Forbidden: Access denied to requested resource ID"}
	}

	resBytes, _ := json.Marshal(data)
	return APIResponse{StatusCode: 200, Body: string(resBytes)}
}

// SimulatedInsecureEndpoint represents a vulnerable controller that suffers from IDOR.
// It fetches the data from database based on the path parameter without validating if the session has access.
func SimulatedInsecureEndpoint(accountID string, token string) APIResponse {
	// Authenticate session based on token (authenticates WHO the user is, but fails to check AUTHORIZATION)
	_, exists := AuthenticateToken(token)
	if !exists {
		return APIResponse{StatusCode: 401, Body: "Unauthorized: Invalid Session Token"}
	}

	// Fetch from database directly using the input ID (Direct Object Reference)
	data, found := SimulatedDatabase[accountID]
	if !found {
		return APIResponse{StatusCode: 404, Body: "Not Found"}
	}

	// VULNERABILITY: Missing check to verify if the account owner matches the session user.

	resBytes, _ := json.Marshal(data)
	return APIResponse{StatusCode: 200, Body: string(resBytes)}
}

// Simple token authentication mapping.
func AuthenticateToken(token string) (UserSession, bool) {
	switch token {
	case "alice-token-998":
		return UserSession{Username: "alice", AuthToken: token, IsAdmin: false}, true
	case "bob-token-221":
		return UserSession{Username: "bob", AuthToken: token, IsAdmin: false}, true
	case "admin-token-000":
		return UserSession{Username: "admin", AuthToken: token, IsAdmin: true}, true
	}
	return UserSession{}, false
}

func main() {
	fmt.Println("==================================================")
	fmt.Println("API Security IDOR Vulnerability Scanner Simulator")
	fmt.Println("==================================================")

	// In an audit, we test access using two distinct tenant sessions (Alice and Bob)
	sessionA := UserSession{Username: "alice", AuthToken: "alice-token-998"}
	sessionB := UserSession{Username: "bob", AuthToken: "bob-token-221"}

	targetResourceIDs := []string{"acc-101", "acc-102", "acc-103", "acc-104"}

	// 1. Audit Insecure Endpoint
	fmt.Println("\n--- Stage 1: Scanning Vulnerable Endpoint (/api/v1/insecure/accounts/{id}) ---")
	auditEndpoint(SimulatedInsecureEndpoint, sessionA, sessionB, targetResourceIDs)

	// 2. Audit Secure Endpoint
	fmt.Println("\n--- Stage 2: Scanning Secure Endpoint (/api/v1/secure/accounts/{id}) ---")
	auditEndpoint(SimulatedSecureEndpoint, sessionA, sessionB, targetResourceIDs)
}

// auditEndpoint simulates a scanner sending cross-session queries to verify access isolation.
func auditEndpoint(endpointFunc func(string, string) APIResponse, userA, userB UserSession, ids []string) {
	vulnerabilitiesFound := 0

	for _, id := range ids {
		// Fetch with User A (may or may not own it)
		respA := endpointFunc(id, userA.AuthToken)
		
		// Fetch with User B (may or may not own it)
		respB := endpointFunc(id, userB.AuthToken)

		// Analyze for IDOR:
		// If User A receives 200 (contains data), but User B (who is a completely different tenant)
		// also receives 200 OK, we check the owners. If the owner matches User A, and User B got the data,
		// it's an IDOR vulnerability!
		if respA.StatusCode == 200 && respB.StatusCode == 200 {
			var dataA, dataB AccountData
			json.Unmarshal([]byte(respA.Body), &dataA)
			json.Unmarshal([]byte(respB.Body), &dataB)

			// If User A is owner, but User B is allowed to read it
			if dataA.Owner == userA.Username && dataB.Owner == userA.Username {
				fmt.Printf("[CRITICAL IDOR VULNERABILITY] IDOR detected on resource '%s'!\n", id)
				fmt.Printf("   - Owner of resource: '%s'\n", dataA.Owner)
				fmt.Printf("   - Requesting User B ('%s') accessed data successfully!\n", userB.Username)
				fmt.Printf("   - Leaked Data payload: %s\n", respB.Body)
				vulnerabilitiesFound++
			}
		} else {
			fmt.Printf("[SECURE] Resource '%s' accessed by User A (Status: %d), User B (Status: %d)\n", id, respA.StatusCode, respB.StatusCode)
		}
	}

	fmt.Printf("\nScan summary: Identified %d isolation vulnerabilities.\n", vulnerabilitiesFound)
}
