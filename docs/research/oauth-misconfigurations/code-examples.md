# OAuth 2.0 Security Code Examples

This document provides practical code examples for secure OAuth implementation and common vulnerability demonstrations.

## Secure Authorization Code + PKCE Implementation

### Client-Side (JavaScript/TypeScript)

```typescript
// oauth-client.ts - Secure OAuth 2.0 Client Implementation

interface OAuthConfig {
    clientId: string;
    authorizationEndpoint: string;
    tokenEndpoint: string;
    redirectUri: string;
    scopes: string[];
}

interface PKCEPair {
    verifier: string;
    challenge: string;
}

interface TokenResponse {
    access_token: string;
    token_type: string;
    expires_in: number;
    refresh_token?: string;
    scope: string;
}

class SecureOAuthClient {
    private config: OAuthConfig;
    private accessToken: string | null = null;
    private refreshToken: string | null = null;
    private tokenExpiry: Date | null = null;

    constructor(config: OAuthConfig) {
        this.config = config;
    }

    /**
     * Generate PKCE code verifier and challenge
     */
    async generatePKCE(): Promise<PKCEPair> {
        // Generate 32 random bytes (256 bits of entropy)
        const array = new Uint8Array(32);
        crypto.getRandomValues(array);
        
        // Base64URL encode for verifier
        const verifier = this.base64UrlEncode(array);
        
        // SHA-256 hash for challenge
        const encoder = new TextEncoder();
        const data = encoder.encode(verifier);
        const hash = await crypto.subtle.digest('SHA-256', data);
        const challenge = this.base64UrlEncode(new Uint8Array(hash));
        
        return { verifier, challenge };
    }

    /**
     * Generate cryptographically secure state parameter
     */
    generateState(): string {
        const array = new Uint8Array(32);
        crypto.getRandomValues(array);
        return this.base64UrlEncode(array);
    }

    /**
     * Initiate OAuth authorization flow
     */
    async authorize(): Promise<void> {
        const pkce = await this.generatePKCE();
        const state = this.generateState();
        
        // Store PKCE verifier and state securely (in memory only)
        // For production, consider using sessionStorage with encryption
        // or a more secure storage mechanism
        this.storePKCEState(pkce.verifier, state);
        
        const params = new URLSearchParams({
            response_type: 'code',
            client_id: this.config.clientId,
            redirect_uri: this.config.redirectUri,
            scope: this.config.scopes.join(' '),
            state: state,
            code_challenge: pkce.challenge,
            code_challenge_method: 'S256'
        });
        
        window.location.href = `${this.config.authorizationEndpoint}?${params}`;
    }

    /**
     * Handle OAuth callback
     */
    async handleCallback(callbackUrl: string): Promise<TokenResponse> {
        const url = new URL(callbackUrl);
        const code = url.searchParams.get('code');
        const returnedState = url.searchParams.get('state');
        const error = url.searchParams.get('error');
        
        // Check for error response
        if (error) {
            const errorDescription = url.searchParams.get('error_description');
            throw new OAuthError(error, errorDescription || 'Authorization failed');
        }
        
        // Validate required parameters
        if (!code) {
            throw new OAuthError('invalid_response', 'Missing authorization code');
        }
        
        if (!returnedState) {
            throw new OAuthError('invalid_response', 'Missing state parameter');
        }
        
        // Retrieve and validate stored state
        const { verifier, state: storedState } = this.retrievePKCEState();
        
        if (!storedState || storedState !== returnedState) {
            throw new OAuthError('csrf_detected', 'State mismatch - possible CSRF attack');
        }
        
        // Exchange code for tokens
        return await this.exchangeCode(code, verifier);
    }

    /**
     * Exchange authorization code for tokens
     */
    private async exchangeCode(code: string, verifier: string): Promise<TokenResponse> {
        const response = await fetch(this.config.tokenEndpoint, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/x-www-form-urlencoded'
            },
            body: new URLSearchParams({
                grant_type: 'authorization_code',
                code: code,
                redirect_uri: this.config.redirectUri,
                client_id: this.config.clientId,
                code_verifier: verifier
            })
        });
        
        if (!response.ok) {
            const error = await response.json();
            throw new OAuthError(error.error, error.error_description);
        }
        
        const tokens: TokenResponse = await response.json();
        
        // Store tokens securely (in memory)
        this.accessToken = tokens.access_token;
        this.refreshToken = tokens.refresh_token || null;
        this.tokenExpiry = new Date(Date.now() + tokens.expires_in * 1000);
        
        // Clear PKCE state
        this.clearPKCEState();
        
        return tokens;
    }

    /**
     * Refresh access token
     */
    async refreshAccessToken(): Promise<TokenResponse> {
        if (!this.refreshToken) {
            throw new OAuthError('no_refresh_token', 'No refresh token available');
        }
        
        const response = await fetch(this.config.tokenEndpoint, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/x-www-form-urlencoded'
            },
            body: new URLSearchParams({
                grant_type: 'refresh_token',
                refresh_token: this.refreshToken,
                client_id: this.config.clientId
            })
        });
        
        if (!response.ok) {
            const error = await response.json();
            throw new OAuthError(error.error, error.error_description);
        }
        
        const tokens: TokenResponse = await response.json();
        
        // Update stored tokens (token rotation)
        this.accessToken = tokens.access_token;
        if (tokens.refresh_token) {
            this.refreshToken = tokens.refresh_token;
        }
        this.tokenExpiry = new Date(Date.now() + tokens.expires_in * 1000);
        
        return tokens;
    }

    /**
     * Get valid access token (refresh if needed)
     */
    async getAccessToken(): Promise<string> {
        if (!this.accessToken || !this.tokenExpiry) {
            throw new OAuthError('not_authenticated', 'Not authenticated');
        }
        
        // Refresh if token expires in less than 60 seconds
        if (this.tokenExpiry.getTime() - Date.now() < 60000) {
            await this.refreshAccessToken();
        }
        
        return this.accessToken;
    }

    /**
     * Logout and clear tokens
     */
    logout(): void {
        this.accessToken = null;
        this.refreshToken = null;
        this.tokenExpiry = null;
        this.clearPKCEState();
    }

    // Helper methods
    private base64UrlEncode(buffer: Uint8Array): string {
        let binary = '';
        for (let i = 0; i < buffer.length; i++) {
            binary += String.fromCharCode(buffer[i]);
        }
        return btoa(binary)
            .replace(/\+/g, '-')
            .replace(/\//g, '_')
            .replace(/=+$/, '');
    }

    private storePKCEState(verifier: string, state: string): void {
        // In production, consider more secure storage
        // This uses sessionStorage which persists only for the session
        const data = JSON.stringify({ verifier, state, timestamp: Date.now() });
        sessionStorage.setItem('oauth_pkce_state', data);
    }

    private retrievePKCEState(): { verifier: string; state: string } {
        const data = sessionStorage.getItem('oauth_pkce_state');
        if (!data) {
            throw new OAuthError('no_state', 'No stored PKCE state found');
        }
        
        const parsed = JSON.parse(data);
        
        // Check for stale state (older than 10 minutes)
        if (Date.now() - parsed.timestamp > 10 * 60 * 1000) {
            this.clearPKCEState();
            throw new OAuthError('state_expired', 'OAuth state expired');
        }
        
        return { verifier: parsed.verifier, state: parsed.state };
    }

    private clearPKCEState(): void {
        sessionStorage.removeItem('oauth_pkce_state');
    }
}

class OAuthError extends Error {
    code: string;
    
    constructor(code: string, message: string) {
        super(message);
        this.code = code;
        this.name = 'OAuthError';
    }
}

// Usage example
const oauthClient = new SecureOAuthClient({
    clientId: 'your-client-id',
    authorizationEndpoint: 'https://auth.example.com/authorize',
    tokenEndpoint: 'https://auth.example.com/token',
    redirectUri: 'https://yourapp.com/callback',
    scopes: ['openid', 'profile', 'email']
});
```

---

## Secure JWT Validation

### Server-Side (Node.js/TypeScript)

```typescript
// jwt-validator.ts - Secure JWT Validation

import jwt, { JwtPayload, VerifyOptions } from 'jsonwebtoken';
import jwksClient from 'jwks-rsa';

interface TokenValidationConfig {
    issuer: string;
    audience: string;
    jwksUri: string;
    algorithms: string[];
}

interface ValidatedToken extends JwtPayload {
    sub: string;
    iss: string;
    aud: string | string[];
    exp: number;
    iat: number;
}

class JWTValidator {
    private config: TokenValidationConfig;
    private jwksClient: jwksClient.JwksClient;

    constructor(config: TokenValidationConfig) {
        this.config = config;
        
        // Initialize JWKS client with caching
        this.jwksClient = jwksClient({
            jwksUri: config.jwksUri,
            cache: true,
            cacheMaxEntries: 5,
            cacheMaxAge: 600000, // 10 minutes
            rateLimit: true,
            jwksRequestsPerMinute: 10
        });
    }

    /**
     * Validate and decode JWT token
     */
    async validateToken(token: string): Promise<ValidatedToken> {
        // First, decode without verification to get the header
        const decoded = jwt.decode(token, { complete: true });
        
        if (!decoded || typeof decoded === 'string') {
            throw new TokenValidationError('INVALID_TOKEN', 'Unable to decode token');
        }

        // Validate algorithm is in allowed list
        if (!this.config.algorithms.includes(decoded.header.alg)) {
            throw new TokenValidationError(
                'INVALID_ALGORITHM',
                `Algorithm ${decoded.header.alg} not allowed`
            );
        }

        // Block "none" algorithm explicitly
        if (decoded.header.alg === 'none') {
            throw new TokenValidationError(
                'INVALID_ALGORITHM',
                'Algorithm "none" is not allowed'
            );
        }

        // Get signing key
        const key = await this.getSigningKey(decoded.header.kid);

        // Verify token
        const options: VerifyOptions = {
            algorithms: this.config.algorithms as jwt.Algorithm[],
            issuer: this.config.issuer,
            audience: this.config.audience,
            complete: false,
            ignoreExpiration: false,
            ignoreNotBefore: false
        };

        try {
            const payload = jwt.verify(token, key, options) as ValidatedToken;
            
            // Additional claim validation
            this.validateClaims(payload);
            
            return payload;
        } catch (error) {
            if (error instanceof jwt.TokenExpiredError) {
                throw new TokenValidationError('TOKEN_EXPIRED', 'Token has expired');
            }
            if (error instanceof jwt.JsonWebTokenError) {
                throw new TokenValidationError('INVALID_TOKEN', error.message);
            }
            if (error instanceof jwt.NotBeforeError) {
                throw new TokenValidationError('TOKEN_NOT_ACTIVE', 'Token not yet valid');
            }
            throw error;
        }
    }

    /**
     * Get signing key from JWKS
     */
    private async getSigningKey(kid?: string): Promise<string> {
        return new Promise((resolve, reject) => {
            this.jwksClient.getSigningKey(kid, (err, key) => {
                if (err) {
                    reject(new TokenValidationError(
                        'KEY_NOT_FOUND',
                        `Unable to find signing key: ${err.message}`
                    ));
                    return;
                }
                
                const signingKey = key?.getPublicKey();
                if (!signingKey) {
                    reject(new TokenValidationError(
                        'KEY_NOT_FOUND',
                        'No public key found'
                    ));
                    return;
                }
                
                resolve(signingKey);
            });
        });
    }

    /**
     * Validate additional claims
     */
    private validateClaims(payload: ValidatedToken): void {
        // Ensure required claims are present
        const requiredClaims = ['sub', 'iss', 'aud', 'exp', 'iat'];
        for (const claim of requiredClaims) {
            if (!(claim in payload)) {
                throw new TokenValidationError(
                    'MISSING_CLAIM',
                    `Required claim "${claim}" is missing`
                );
            }
        }

        // Validate iat is not in the future
        const now = Math.floor(Date.now() / 1000);
        if (payload.iat > now + 60) { // Allow 60 second clock skew
            throw new TokenValidationError(
                'INVALID_IAT',
                'Token issued in the future'
            );
        }

        // Validate token is not too old (optional, configurable)
        const maxAge = 24 * 60 * 60; // 24 hours
        if (now - payload.iat > maxAge) {
            throw new TokenValidationError(
                'TOKEN_TOO_OLD',
                'Token was issued too long ago'
            );
        }
    }
}

class TokenValidationError extends Error {
    code: string;

    constructor(code: string, message: string) {
        super(message);
        this.code = code;
        this.name = 'TokenValidationError';
    }
}

// Usage
const validator = new JWTValidator({
    issuer: 'https://auth.example.com',
    audience: 'your-api-audience',
    jwksUri: 'https://auth.example.com/.well-known/jwks.json',
    algorithms: ['RS256', 'ES256'] // Explicit allowlist
});

// Express middleware example
async function authMiddleware(req: any, res: any, next: any) {
    const authHeader = req.headers.authorization;
    
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
        return res.status(401).json({ error: 'Missing authorization header' });
    }
    
    const token = authHeader.substring(7);
    
    try {
        const payload = await validator.validateToken(token);
        req.user = payload;
        next();
    } catch (error) {
        if (error instanceof TokenValidationError) {
            return res.status(401).json({ 
                error: error.code, 
                message: error.message 
            });
        }
        return res.status(500).json({ error: 'Internal server error' });
    }
}
```

---

## Secure Redirect URI Validation

### Server-Side (Python)

```python
# redirect_uri_validator.py - Secure Redirect URI Validation

from urllib.parse import urlparse, parse_qs, urlencode
from typing import List, Optional
import re

class RedirectURIValidator:
    """
    Secure redirect URI validator for OAuth 2.0 authorization servers.
    
    Implements strict validation according to OAuth 2.0 security best practices.
    """
    
    def __init__(self, registered_uris: List[str]):
        """
        Initialize validator with list of registered redirect URIs.
        
        Args:
            registered_uris: List of exactly registered redirect URIs
        """
        self.registered_uris = set(self._normalize_uri(uri) for uri in registered_uris)
    
    def validate(self, redirect_uri: str) -> bool:
        """
        Validate redirect URI against registered URIs.
        
        Args:
            redirect_uri: The redirect URI to validate
            
        Returns:
            True if valid, False otherwise
        """
        if not redirect_uri:
            return False
        
        # Check for dangerous patterns BEFORE parsing
        if self._has_dangerous_patterns(redirect_uri):
            return False
        
        try:
            normalized = self._normalize_uri(redirect_uri)
        except ValueError:
            return False
        
        # Exact match only
        return normalized in self.registered_uris
    
    def _normalize_uri(self, uri: str) -> str:
        """
        Normalize URI for comparison.
        
        Raises ValueError for malformed URIs.
        """
        parsed = urlparse(uri)
        
        # Require scheme
        if not parsed.scheme:
            raise ValueError("Missing scheme")
        
        # Only allow https (or http for localhost in development)
        if parsed.scheme not in ('https', 'http'):
            raise ValueError(f"Invalid scheme: {parsed.scheme}")
        
        if parsed.scheme == 'http' and parsed.hostname not in ('localhost', '127.0.0.1'):
            raise ValueError("HTTP only allowed for localhost")
        
        # Require host
        if not parsed.netloc:
            raise ValueError("Missing host")
        
        # Reject fragments
        if parsed.fragment:
            raise ValueError("Fragments not allowed in redirect URI")
        
        # Reject userinfo (user:pass@host)
        if '@' in parsed.netloc.split(':')[0]:
            raise ValueError("Userinfo not allowed in redirect URI")
        
        # Normalize path
        path = parsed.path or '/'
        
        # Reject path traversal
        if '..' in path or '//' in path:
            raise ValueError("Path traversal not allowed")
        
        # Reconstruct normalized URI (without query string for comparison)
        normalized = f"{parsed.scheme}://{parsed.netloc.lower()}{path}"
        
        # Remove trailing slash for consistency (optional)
        normalized = normalized.rstrip('/')
        
        return normalized
    
    def _has_dangerous_patterns(self, uri: str) -> bool:
        """
        Check for dangerous patterns that might bypass validation.
        """
        dangerous_patterns = [
            r'[\x00-\x1f]',           # Control characters
            r'%00',                    # Null byte
            r'%2e%2e',                 # Encoded ..
            r'%252e',                  # Double encoded .
            r'\\',                     # Backslash
            r'@[^/]',                  # @ not followed by / (URL confusion)
            r'\s',                     # Whitespace
        ]
        
        for pattern in dangerous_patterns:
            if re.search(pattern, uri, re.IGNORECASE):
                return True
        
        return False


class RedirectURIValidatorWithQueryParams(RedirectURIValidator):
    """
    Extended validator that allows specific query parameters.
    
    Use this only if your application requires dynamic query parameters.
    """
    
    def __init__(self, registered_uris: List[str], allowed_params: List[str]):
        """
        Args:
            registered_uris: List of registered base URIs
            allowed_params: List of allowed query parameter names
        """
        super().__init__(registered_uris)
        self.allowed_params = set(allowed_params)
    
    def validate(self, redirect_uri: str) -> bool:
        """Validate URI allowing specific query parameters."""
        if not redirect_uri:
            return False
        
        if self._has_dangerous_patterns(redirect_uri):
            return False
        
        try:
            parsed = urlparse(redirect_uri)
            
            # Validate query parameters
            if parsed.query:
                query_params = parse_qs(parsed.query)
                for param in query_params.keys():
                    if param not in self.allowed_params:
                        return False
            
            # Validate base URI
            base_uri = self._normalize_uri(
                f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
            )
            
            return base_uri in self.registered_uris
            
        except ValueError:
            return False


# Usage examples
if __name__ == "__main__":
    # Initialize with registered URIs
    validator = RedirectURIValidator([
        "https://app.example.com/callback",
        "https://app.example.com/oauth/callback"
    ])
    
    # Test cases
    test_cases = [
        # Valid
        ("https://app.example.com/callback", True),
        ("https://app.example.com/oauth/callback", True),
        
        # Invalid - not registered
        ("https://attacker.com/callback", False),
        ("https://app.example.com/other", False),
        
        # Invalid - path traversal
        ("https://app.example.com/callback/../admin", False),
        ("https://app.example.com/callback/..%2f..%2fadmin", False),
        
        # Invalid - URL confusion
        ("https://app.example.com@attacker.com/callback", False),
        ("https://attacker.com\\@app.example.com/callback", False),
        
        # Invalid - fragment
        ("https://app.example.com/callback#evil", False),
        
        # Invalid - HTTP (non-localhost)
        ("http://app.example.com/callback", False),
    ]
    
    for uri, expected in test_cases:
        result = validator.validate(uri)
        status = "✓" if result == expected else "✗"
        print(f"{status} {uri}: {result} (expected {expected})")
```

---

## State Parameter Implementation

### Server-Side State Management (Node.js)

```typescript
// state-manager.ts - Secure State Parameter Management

import crypto from 'crypto';
import { Redis } from 'ioredis';

interface StateData {
    state: string;
    codeVerifier: string;
    redirectUri: string;
    clientId: string;
    nonce?: string;
    createdAt: number;
    metadata?: Record<string, any>;
}

class OAuthStateManager {
    private redis: Redis;
    private prefix: string;
    private ttlSeconds: number;

    constructor(redis: Redis, options?: { prefix?: string; ttlSeconds?: number }) {
        this.redis = redis;
        this.prefix = options?.prefix || 'oauth:state:';
        this.ttlSeconds = options?.ttlSeconds || 600; // 10 minutes default
    }

    /**
     * Generate and store new OAuth state
     */
    async createState(
        sessionId: string,
        codeVerifier: string,
        redirectUri: string,
        clientId: string,
        metadata?: Record<string, any>
    ): Promise<string> {
        // Generate cryptographically secure state
        const state = crypto.randomBytes(32).toString('base64url');
        const nonce = crypto.randomBytes(16).toString('base64url');
        
        const stateData: StateData = {
            state,
            codeVerifier,
            redirectUri,
            clientId,
            nonce,
            createdAt: Date.now(),
            metadata
        };
        
        // Store state bound to session
        const key = this.getKey(sessionId, state);
        await this.redis.setex(key, this.ttlSeconds, JSON.stringify(stateData));
        
        return state;
    }

    /**
     * Validate and consume state (one-time use)
     */
    async validateAndConsume(
        sessionId: string,
        state: string
    ): Promise<StateData> {
        if (!state || !sessionId) {
            throw new StateValidationError('MISSING_STATE', 'State or session missing');
        }
        
        const key = this.getKey(sessionId, state);
        
        // Get and delete atomically (one-time use)
        const data = await this.redis.getdel(key);
        
        if (!data) {
            throw new StateValidationError(
                'INVALID_STATE',
                'State not found or already used'
            );
        }
        
        const stateData: StateData = JSON.parse(data);
        
        // Verify state hasn't been tampered with
        if (stateData.state !== state) {
            throw new StateValidationError(
                'STATE_MISMATCH',
                'State value mismatch'
            );
        }
        
        // Check expiration (defense in depth)
        const age = Date.now() - stateData.createdAt;
        if (age > this.ttlSeconds * 1000) {
            throw new StateValidationError('STATE_EXPIRED', 'State has expired');
        }
        
        return stateData;
    }

    /**
     * Clean up expired states for a session
     */
    async cleanupSession(sessionId: string): Promise<void> {
        const pattern = `${this.prefix}${sessionId}:*`;
        const keys = await this.redis.keys(pattern);
        if (keys.length > 0) {
            await this.redis.del(...keys);
        }
    }

    private getKey(sessionId: string, state: string): string {
        return `${this.prefix}${sessionId}:${state}`;
    }
}

class StateValidationError extends Error {
    code: string;

    constructor(code: string, message: string) {
        super(message);
        this.code = code;
        this.name = 'StateValidationError';
    }
}

// Express route example
import express from 'express';
import session from 'express-session';

const app = express();
const redis = new Redis();
const stateManager = new OAuthStateManager(redis);

// Initiate OAuth flow
app.get('/auth/login', async (req, res) => {
    const sessionId = req.session.id;
    
    // Generate PKCE
    const verifier = crypto.randomBytes(32).toString('base64url');
    const challenge = crypto
        .createHash('sha256')
        .update(verifier)
        .digest('base64url');
    
    // Create state
    const state = await stateManager.createState(
        sessionId,
        verifier,
        'https://app.example.com/auth/callback',
        'your-client-id',
        { returnTo: req.query.returnTo }
    );
    
    // Build authorization URL
    const params = new URLSearchParams({
        response_type: 'code',
        client_id: 'your-client-id',
        redirect_uri: 'https://app.example.com/auth/callback',
        scope: 'openid profile email',
        state,
        code_challenge: challenge,
        code_challenge_method: 'S256'
    });
    
    res.redirect(`https://auth.example.com/authorize?${params}`);
});

// Handle OAuth callback
app.get('/auth/callback', async (req, res) => {
    const { code, state, error, error_description } = req.query;
    
    if (error) {
        return res.status(400).json({ error, error_description });
    }
    
    try {
        // Validate state
        const stateData = await stateManager.validateAndConsume(
            req.session.id,
            state as string
        );
        
        // Exchange code for tokens using stateData.codeVerifier
        // ...
        
        // Redirect to original destination
        const returnTo = stateData.metadata?.returnTo || '/';
        res.redirect(returnTo);
        
    } catch (error) {
        if (error instanceof StateValidationError) {
            return res.status(400).json({
                error: error.code,
                message: error.message
            });
        }
        throw error;
    }
});
```

---

## Vulnerability Demonstrations

### Demonstration: Redirect URI Bypass Attempts

```python
# redirect_uri_attacks.py - Common attack patterns for testing

attack_vectors = [
    # Path traversal
    "https://app.example.com/callback/../admin",
    "https://app.example.com/callback/..%2f..%2fadmin",
    "https://app.example.com/callback/..\\..\\admin",
    
    # Subdomain attacks
    "https://evil.app.example.com/callback",
    "https://app.example.com.evil.com/callback",
    
    # URL confusion
    "https://app.example.com@evil.com/callback",
    "https://app.example.com%40evil.com/callback",
    "https://evil.com\\@app.example.com/callback",
    
    # Protocol confusion
    "javascript://app.example.com/callback",
    "data:text/html,<script>alert(1)</script>",
    
    # Fragment injection
    "https://app.example.com/callback#redirect=https://evil.com",
    
    # Parameter pollution
    "https://app.example.com/callback?redirect=https://evil.com",
    "https://app.example.com/callback?token=",
    
    # Encoding tricks
    "https://app.example.com/callback%00.evil.com",
    "https://app.example.com/callback\u0000.evil.com",
    
    # Case manipulation
    "https://APP.EXAMPLE.COM/callback",
    "https://app.example.com/CALLBACK",
    
    # Port manipulation
    "https://app.example.com:443/callback",
    "https://app.example.com:8443/callback",
    
    # IP address
    "https://192.168.1.1/callback",
    "https://0x7f000001/callback",
    
    # Localhost bypass
    "https://localhost/callback",
    "https://127.0.0.1/callback",
    "https://[::1]/callback",
]

def test_redirect_uri_validation(validator, base_uri: str):
    """Test validator against common attack vectors."""
    print(f"Testing validator with base: {base_uri}")
    print("-" * 60)
    
    for attack in attack_vectors:
        try:
            result = validator.validate(attack)
            status = "BLOCKED" if not result else "ALLOWED"
            print(f"{status}: {attack}")
        except Exception as e:
            print(f"ERROR: {attack} -> {e}")
    
    print()
```

### Demonstration: JWT Attack Patterns

```python
# jwt_attacks.py - JWT vulnerability demonstrations

import jwt
import json
import base64

def demonstrate_alg_none_attack(token: str, target_claims: dict):
    """
    Demonstrate algorithm "none" attack.
    
    This attack works when the server doesn't properly validate
    the algorithm header and accepts unsigned tokens.
    """
    # Create header with alg: none
    header = {"alg": "none", "typ": "JWT"}
    
    # Encode header and payload
    header_b64 = base64.urlsafe_b64encode(
        json.dumps(header).encode()
    ).rstrip(b'=').decode()
    
    payload_b64 = base64.urlsafe_b64encode(
        json.dumps(target_claims).encode()
    ).rstrip(b'=').decode()
    
    # Token with empty signature
    malicious_token = f"{header_b64}.{payload_b64}."
    
    return malicious_token


def demonstrate_algorithm_confusion(
    public_key: str,
    target_claims: dict
):
    """
    Demonstrate RS256 to HS256 algorithm confusion attack.
    
    If a server is configured for RS256 but uses a library that
    accepts the algorithm from the token header, an attacker can:
    1. Get the public key (often publicly available)
    2. Sign token with HS256 using the public key as the secret
    3. Server verifies using public key, accepts token
    """
    # Sign with HS256 using public key as secret
    malicious_token = jwt.encode(
        target_claims,
        public_key,  # Using public key as HMAC secret
        algorithm="HS256"
    )
    
    return malicious_token


def demonstrate_claim_injection(original_token: str):
    """
    Demonstrate what happens when claims aren't validated.
    
    Even without forging signatures, understanding claim structure
    helps identify what to look for in implementations.
    """
    # Decode without verification (for analysis only)
    parts = original_token.split('.')
    
    header = json.loads(base64.urlsafe_b64decode(parts[0] + '=='))
    payload = json.loads(base64.urlsafe_b64decode(parts[1] + '=='))
    
    print("Token Analysis:")
    print(f"  Algorithm: {header.get('alg')}")
    print(f"  Subject: {payload.get('sub')}")
    print(f"  Issuer: {payload.get('iss')}")
    print(f"  Audience: {payload.get('aud')}")
    print(f"  Expiration: {payload.get('exp')}")
    print(f"  Scopes: {payload.get('scope', payload.get('scp', 'N/A'))}")
    
    # Check for security issues
    issues = []
    if not payload.get('exp'):
        issues.append("Missing expiration claim")
    if not payload.get('iss'):
        issues.append("Missing issuer claim")
    if not payload.get('aud'):
        issues.append("Missing audience claim")
    if header.get('alg') == 'none':
        issues.append("Algorithm is 'none'")
    if header.get('alg') == 'HS256' and 'RS256' in str(payload.get('iss', '')):
        issues.append("Possible algorithm confusion")
    
    if issues:
        print("\nPotential Issues:")
        for issue in issues:
            print(f"  ⚠ {issue}")
    
    return header, payload
```

---

## Testing Checklist Code

```python
# oauth_security_test.py - OAuth security testing utilities

from dataclasses import dataclass
from typing import List, Optional
from enum import Enum

class Severity(Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"

@dataclass
class Finding:
    title: str
    severity: Severity
    description: str
    remediation: str
    evidence: Optional[str] = None

class OAuthSecurityTester:
    """OAuth security testing framework."""
    
    def __init__(self, auth_endpoint: str, token_endpoint: str):
        self.auth_endpoint = auth_endpoint
        self.token_endpoint = token_endpoint
        self.findings: List[Finding] = []
    
    def test_redirect_uri_validation(self, valid_uri: str, client_id: str):
        """Test redirect_uri validation."""
        # Test cases would go here
        pass
    
    def test_pkce_enforcement(self, client_id: str):
        """Test if PKCE is required for public clients."""
        pass
    
    def test_state_validation(self, client_id: str):
        """Test state parameter validation."""
        pass
    
    def test_token_endpoint_auth(self, client_id: str):
        """Test token endpoint authentication requirements."""
        pass
    
    def generate_report(self) -> str:
        """Generate security assessment report."""
        report = ["# OAuth Security Assessment Report\n"]
        
        for severity in Severity:
            findings = [f for f in self.findings if f.severity == severity]
            if findings:
                report.append(f"\n## {severity.value} Findings\n")
                for finding in findings:
                    report.append(f"### {finding.title}\n")
                    report.append(f"**Description:** {finding.description}\n")
                    report.append(f"**Remediation:** {finding.remediation}\n")
                    if finding.evidence:
                        report.append(f"**Evidence:** {finding.evidence}\n")
        
        return "\n".join(report)
```

---

## Related Documentation

- [README.md](README.md) - Main OAuth security tutorial
